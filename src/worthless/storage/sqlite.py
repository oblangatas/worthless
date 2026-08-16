"""Interrupt-safe ``aiosqlite.connect`` wrapper.

``aiosqlite.Connection.__await__`` starts a **non-daemon** worker thread and
only *then* enters ``_connect()``, which is where aiosqlite installs its own
``except BaseException: self.stop()`` guard::

    def __await__(self):
        self._thread.start()          # <-- worker is alive from here
        return self._connect().__await__()

A ``KeyboardInterrupt`` (Ctrl-C, or the SIGINT/SIGTERM rollback in
``worthless lock``) delivered *inside* ``Thread.start()`` therefore lands in a
gap that neither guard covers:

* ``_connect()`` never runs, so ``stop()`` is never queued and the worker
  blocks on ``tx.get()`` forever;
* ``Connection.__del__`` returns early because it checks ``self._connection``,
  which is still ``None`` — the connection never opened, only the thread;
* the worker is non-daemon, so ``threading._shutdown`` joins it *forever*.

The process then ignores SIGINT **and** SIGTERM and needs ``SIGKILL``. That is
the hang ``tests/chaos/test_lock_interrupt_chaos.py`` reports as a regression.

:func:`connect` closes the gap by delivering the stop sentinel ourselves on
every failure path. The success path is untouched — ``async with`` still ends
in ``Connection.close()``, which stops the worker and awaits its future.

``worthless wrap`` grew a bespoke variant of this guard first; prefer this
helper for new call sites.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite

__all__ = ["connect", "open_connection"]


def _daemonize_worker(conn: aiosqlite.Connection) -> aiosqlite.Connection:
    """Mark the connection's worker thread as a daemon, before it starts.

    WOR-882. The stop sentinel below is the CLEAN shutdown path and stays the
    primary mechanism. This is the backstop for the paths it cannot reach.

    ``aiosqlite.Connection`` builds its worker in ``__init__`` but only starts it
    in ``__await__``, so there is a window here to flip the flag. It matters
    because the worker loop leaves only on the sentinel::

        while True:
            future, function = tx.get()      # parks here forever otherwise
            ...
            if result is _STOP_RUNNING_SENTINEL:
                break

    A non-daemon worker still parked there is joined by ``threading._shutdown``
    at interpreter exit, so a single missed sentinel means the process can never
    terminate — it ignores SIGINT and SIGTERM and needs SIGKILL. That was
    observed on a real ``worthless lock`` child: main thread in ``_shutdown``,
    worker in ``_connection_worker_thread``, after cleanup had already printed
    ``Cancelled.``.

    Guaranteeing the sentinel on *every* window is not tractable — a late
    interrupt during ``asyncio.run`` teardown can leave a suspended async
    generator that is never resumed, so its ``except BaseException`` never runs.
    Daemon status makes the hang structurally impossible instead of chasing each
    window: the interpreter simply stops waiting.

    Safety: this only changes behaviour when the process is ALREADY exiting. The
    success path still ends in ``Connection.close()``, which queues the sentinel
    and awaits it, so the worker has exited before shutdown and there is nothing
    to abandon. A write interrupted by interpreter exit is an uncommitted SQLite
    transaction, which rolls back — the same guarantee as any process kill.

    Uses a private attribute because aiosqlite exposes no public accessor; the
    ``getattr`` keeps a future rename from breaking the open path outright.
    """
    thread = getattr(conn, "_thread", None)
    if thread is not None:
        thread.daemon = True
    return conn


async def open_connection(db_path: str, **kwargs: Any) -> aiosqlite.Connection:
    """Open a connection the *caller* owns, without leaking the worker thread.

    Drop-in for ``db = await aiosqlite.connect(path)``. Use this when the
    connection outlives the scope that opens it — the proxy lifespan holds one
    for the whole process — so :func:`connect`'s ``async with`` shape does not
    fit. Only the *open* is guarded; closing stays the caller's job, and
    ``Connection.close()`` already stops the worker on its own.
    """
    conn = _daemonize_worker(aiosqlite.connect(db_path, **kwargs))
    try:
        return await conn
    except BaseException:
        # Same sentinel-on-failure contract as connect(); see its comment for
        # why the returned future is deliberately not awaited.
        conn.stop()
        raise


@asynccontextmanager
async def connect(db_path: str, **kwargs: Any) -> AsyncIterator[aiosqlite.Connection]:
    """``aiosqlite.connect`` that cannot leak its worker thread on an interrupt.

    Drop-in for ``async with aiosqlite.connect(path) as db``. See the module
    docstring for the window this closes.
    """
    conn = _daemonize_worker(aiosqlite.connect(db_path, **kwargs))
    try:
        async with conn as db:
            yield db
    except BaseException:
        # Idempotent by construction: if close() already stopped the worker the
        # sentinel lands on a queue nobody reads, which costs one tuple. We do
        # NOT await the returned future — the loop may already be tearing down,
        # and unblocking the thread is the only thing that matters here.
        conn.stop()
        raise

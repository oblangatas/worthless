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

This module is the only implementation of the guard. ``worthless wrap`` carried
a hand-rolled variant until worthless-aydz folded it in here. Use :func:`connect`
for scoped callers, and :func:`open_connection` when the connection must outlive
the scope that opens it — as the proxy lifespan's does.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite

__all__ = ["connect", "open_connection"]


async def open_connection(db_path: str, **kwargs: Any) -> aiosqlite.Connection:
    """Open a connection the *caller* owns, without leaking the worker thread.

    Drop-in for ``db = await aiosqlite.connect(path)``. Use this when the
    connection outlives the scope that opens it — the proxy lifespan holds one
    for the whole process — so :func:`connect`'s ``async with`` shape does not
    fit. Only the *open* is guarded; closing stays the caller's job, and
    ``Connection.close()`` already stops the worker on its own.
    """
    conn = aiosqlite.connect(db_path, **kwargs)
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
    conn = aiosqlite.connect(db_path, **kwargs)
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

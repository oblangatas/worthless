"""WOR-882: an aiosqlite worker must never be able to outlive the interpreter.

The hang this pins down (captured from a real wedged ``worthless lock`` child):

    Thread 0x16be17000 (most recent call first):
      File ".../aiosqlite/core.py", line 59 in _connection_worker_thread
    Current thread 0x1f4f71f00 (most recent call first):
      File ".../threading.py", line 1567 in _shutdown

The main thread finished its work — it printed ``Cancelled.`` — and then parked
in ``threading._shutdown()``, which joins every **non-daemon** thread before the
interpreter may exit. The thread it waits on is aiosqlite's connection worker,
blocked on ``tx.get()`` in its ``while True`` loop. In aiosqlite 0.22.1 that loop
leaves only when a queued function returns ``_STOP_RUNNING_SENTINEL``:

    while True:
        future, function = tx.get()      # <- parked here, forever
        ...
        if result is _STOP_RUNNING_SENTINEL:
            break

So the process cannot exit and needs SIGKILL.

``storage.sqlite.connect`` already delivers that sentinel on every path it can
see (WOR-864 / PR #500). The gap is the paths it CANNOT see: if a late interrupt
lands while ``asyncio.run`` is tearing down, a suspended async generator may
never be resumed, its ``except BaseException`` never runs, and no sentinel is
ever queued.

Rather than chase every such window — the race is ~1-in-600 and load-dependent,
so no test can gate on reproducing it — pin the property that makes the hang
structurally impossible: the worker is a daemon, so ``threading._shutdown``
never joins it. The sentinel remains the clean path; daemon is the backstop that
turns "hangs forever" into "exits".
"""

from __future__ import annotations

import asyncio
import threading

import aiosqlite
import pytest

from worthless.storage.sqlite import connect, open_connection


def _aiosqlite_worker_threads() -> list[threading.Thread]:
    """Live threads running aiosqlite's connection worker."""
    return [
        t
        for t in threading.enumerate()
        if t.is_alive()
        and getattr(t, "_target", None) is not None
        and getattr(t._target, "__name__", "") == "_connection_worker_thread"
    ]


@pytest.mark.asyncio
async def test_connect_worker_is_daemon(tmp_path) -> None:
    """A connection opened through the wrapper must not block interpreter exit."""
    async with connect(str(tmp_path / "a.db")) as db:
        await db.execute("CREATE TABLE t (x INTEGER)")
        workers = _aiosqlite_worker_threads()
        assert workers, "expected a live aiosqlite worker while the connection is open"
        for t in workers:
            assert t.daemon, (
                "aiosqlite worker thread is NOT a daemon. threading._shutdown() will "
                "join it at interpreter exit, so any path that fails to deliver the "
                "stop sentinel wedges the process forever (WOR-882)."
            )


@pytest.mark.asyncio
async def test_open_connection_worker_is_daemon(tmp_path) -> None:
    """Same guarantee for the caller-owned variant used by the proxy lifespan."""
    db = await open_connection(str(tmp_path / "b.db"))
    try:
        workers = _aiosqlite_worker_threads()
        assert workers, "expected a live aiosqlite worker while the connection is open"
        for t in workers:
            assert t.daemon, "open_connection worker thread is NOT a daemon (WOR-882)"
    finally:
        await db.close()


def test_abandoned_connection_cannot_block_shutdown(tmp_path) -> None:
    """The real shape of the bug: nobody ever delivers the stop sentinel.

    Simulates an interrupted teardown — the connection is opened and then simply
    abandoned, exactly as happens when a suspended async generator is never
    resumed. On today's code the worker survives as a non-daemon thread and
    ``threading._shutdown`` would join it forever.
    """

    async def _open_and_abandon() -> aiosqlite.Connection:
        # Through the wrapper, because that is what the lock path uses. Raw
        # ``aiosqlite.connect`` is deliberately out of scope: one product call
        # site still uses it (``cli/commands/wrap.py``), and it carries its own
        # bespoke sentinel guard predating this helper.
        return await open_connection(str(tmp_path / "c.db"))

    loop = asyncio.new_event_loop()
    try:
        db = loop.run_until_complete(_open_and_abandon())
    finally:
        loop.close()

    survivors = [t for t in _aiosqlite_worker_threads() if not t.daemon]
    try:
        assert not survivors, (
            f"{len(survivors)} non-daemon aiosqlite worker thread(s) survived an "
            "abandoned connection. threading._shutdown() joins these at exit, which "
            "is the WOR-882 hang: the process never terminates and needs SIGKILL."
        )
    finally:
        db._stop_running() if hasattr(db, "_stop_running") else db.stop()

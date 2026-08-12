"""Interrupt-safety of :func:`worthless.storage.sqlite.connect`.

Regression pin for the ``worthless lock`` hang surfaced by
``tests/chaos/test_lock_interrupt_chaos.py``: a SIGINT/SIGTERM arriving while
aiosqlite is starting its connection worker left that **non-daemon** thread
blocked on ``tx.get()`` forever, so ``threading._shutdown`` joined it forever
and the process ignored both SIGINT and SIGTERM (only SIGKILL cleared it).

The captured production stack was::

    File ".../aiosqlite/core.py", line 181, in __aenter__
    File ".../aiosqlite/core.py", line 177, in __await__
        self._thread.start()
    File ".../threading.py", line 935, in start
    KeyboardInterrupt
    ...
    Current thread (most recent call first):
      File ".../threading.py", line 1567 in _shutdown

so the test raises the interrupt from exactly there rather than approximating
it with a failure in the ``async with`` body (which aiosqlite's ``__aexit__``
already handles correctly).
"""

from __future__ import annotations

import threading
import time

import aiosqlite
import pytest

from worthless.storage.sqlite import connect as sqlite_connect

WORKER_NAME = "_connection_worker_thread"
JOIN_TIMEOUT = 5.0


def _workers() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if WORKER_NAME in t.name]


async def test_interrupt_during_thread_start_does_not_leak_worker(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KeyboardInterrupt inside ``Thread.start()`` must still stop the worker.

    Without the guard the worker never receives ``_STOP_RUNNING_SENTINEL`` and
    stays alive, which is what wedges interpreter shutdown.
    """
    db_path = str(tmp_path / "interrupt.db")

    # Keep every Connection we create so the cleanup below can always unblock
    # its worker — a regression must fail this assertion, never hang the suite.
    created: list[aiosqlite.Connection] = []
    real_connect = aiosqlite.connect

    def _spy_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        created.append(conn)
        return conn

    monkeypatch.setattr(aiosqlite, "connect", _spy_connect)

    real_start = threading.Thread.start

    def _start_then_interrupt(self: threading.Thread) -> None:
        real_start(self)
        if WORKER_NAME in self.name:
            raise KeyboardInterrupt  # exactly where the captured stack died

    monkeypatch.setattr(threading.Thread, "start", _start_then_interrupt)

    before = {t.ident for t in _workers()}
    try:
        with pytest.raises(KeyboardInterrupt):
            async with sqlite_connect(db_path):
                pytest.fail("connection body must not be reached")
    finally:
        monkeypatch.undo()

        def _leaked() -> list[threading.Thread]:
            return [t for t in _workers() if t.ident not in before and t.is_alive()]

        # The stop sentinel is queued, not awaited, so poll briefly rather than
        # assuming the worker has already drained it on a loaded host.
        deadline = time.monotonic() + JOIN_TIMEOUT
        leaked = _leaked()
        while leaked and time.monotonic() < deadline:
            time.sleep(0.01)
            leaked = _leaked()
        names = [t.name for t in leaked]

        # Belt-and-braces: never let a regression leave a non-daemon thread
        # behind to wedge this test process at exit.
        for conn in created:
            conn.stop()

    assert not names, f"aiosqlite worker thread leaked after interrupt: {names}"

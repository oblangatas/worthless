"""Interrupt-safety of the :mod:`worthless.storage.sqlite` open guards.

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

so the tests raise the interrupt from exactly there rather than approximating
it with a failure in the ``async with`` body (which aiosqlite's ``__aexit__``
already handles correctly).

Both shapes are pinned, because the window belongs to ``Connection.__await__``
and not to any one call style: :func:`~worthless.storage.sqlite.connect` for
scoped callers, and :func:`~worthless.storage.sqlite.open_connection` for the
proxy lifespan, which holds its connection for the whole process lifetime.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator

import aiosqlite
import pytest

from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.storage.sqlite import connect as sqlite_connect

WORKER_NAME = "_connection_worker_thread"
JOIN_TIMEOUT = 5.0


def _workers() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if WORKER_NAME in t.name]


@pytest.fixture
def worker_watch(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[], None]]:
    """Watch for aiosqlite workers that outlive the code under test.

    Yields the assertion to run once the failure has propagated: it polls for a
    worker started during the test that is still alive, and fails if it finds
    one.

    Teardown queues the stop sentinel on every Connection handed out, so a
    regression fails the assertion instead of wedging this test process at
    exit — the exact failure mode under test must never be the way it reports.
    """
    # Keep every Connection we create so the cleanup below can always unblock
    # its worker — a regression must fail an assertion, never hang the suite.
    created: list[aiosqlite.Connection] = []
    real_connect = aiosqlite.connect

    def _spy_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        created.append(conn)
        return conn

    before = {t.ident for t in _workers()}
    monkeypatch.setattr(aiosqlite, "connect", _spy_connect)

    def _assert_no_worker_leaked() -> None:
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

        assert not names, f"aiosqlite worker thread leaked after interrupt: {names}"

    try:
        yield _assert_no_worker_leaked
    finally:
        monkeypatch.undo()
        for conn in created:
            conn.stop()


@pytest.fixture
def armed_interrupt(
    monkeypatch: pytest.MonkeyPatch, worker_watch: Callable[[], None]
) -> Callable[[], None]:
    """:func:`worker_watch` plus a ``KeyboardInterrupt`` inside ``Thread.start()``.

    Interrupts the *open* — the window where ``_connection`` is still None, so
    neither ``__del__`` nor ``close()`` will stop the worker for us.
    """
    real_start = threading.Thread.start

    def _start_then_interrupt(self: threading.Thread) -> None:
        real_start(self)
        if WORKER_NAME in self.name:
            raise KeyboardInterrupt  # exactly where the captured stack died

    monkeypatch.setattr(threading.Thread, "start", _start_then_interrupt)
    return worker_watch


class _InterruptingSupervisor:
    """Sidecar supervisor stand-in that interrupts startup at ``connect()``.

    Stands in for the real interrupt: a user pressing Ctrl-C while the proxy
    waits on the sidecar, which is the slowest step in startup and so the most
    likely moment to be interrupted.
    """

    async def connect(self) -> None:
        raise KeyboardInterrupt

    async def aclose(self) -> None:  # pragma: no cover — startup never completes
        return None


async def test_interrupt_during_thread_start_does_not_leak_worker(
    tmp_path, armed_interrupt: Callable[[], None]
) -> None:
    """A KeyboardInterrupt inside ``Thread.start()`` must still stop the worker.

    Without the guard the worker never receives ``_STOP_RUNNING_SENTINEL`` and
    stays alive, which is what wedges interpreter shutdown.
    """
    with pytest.raises(KeyboardInterrupt):
        async with sqlite_connect(str(tmp_path / "interrupt.db")):
            pytest.fail("connection body must not be reached")

    armed_interrupt()


async def test_proxy_lifespan_interrupt_does_not_leak_worker(
    tmp_path, armed_interrupt: Callable[[], None]
) -> None:
    """The proxy's long-lived connection is guarded on open too.

    ``_lifespan`` opens ``app.state.db`` first and keeps it for the whole
    process, so the scoped ``connect()`` helper does not fit — it awaits the
    connection directly and must guard that await itself. Neither
    ``Connection.__del__`` nor ``Connection.close()`` rescues this: both return
    early while ``_connection`` is still None, which it is when the interrupt
    lands before the sqlite connect ever runs.
    """
    settings = ProxySettings(
        db_path=str(tmp_path / "lifespan-interrupt.db"),
        fernet_key=bytearray(b"x" * 32),
        allow_insecure=True,
    )
    app = create_app(settings)

    with pytest.raises(KeyboardInterrupt):
        async with app.router.lifespan_context(app):
            pytest.fail("lifespan startup must not yield after an interrupt")

    armed_interrupt()


async def test_proxy_startup_interrupt_after_open_does_not_leak_worker(
    tmp_path, worker_watch: Callable[[], None]
) -> None:
    """An interrupt *after* the open, mid-startup, must also stop the worker.

    Guarding the open alone is not enough, and the reason inverts. Once the
    connection is open, ``__del__`` *would* stop the worker — but only if the
    Connection becomes unreferenced, and ``app.state.db`` holds a reference for
    as long as the app is alive. Startup raising before the yield also means the
    shutdown half never runs, so nothing closes it either.

    The interrupt is raised from ``ipc.connect()``, the slowest step in startup
    and the one a waiting user is most likely to interrupt. ``app`` is
    deliberately kept alive through the assertion below: that reference is the
    whole point of the test.
    """
    settings = ProxySettings(
        db_path=str(tmp_path / "startup-interrupt.db"),
        fernet_key=bytearray(b"x" * 32),
        allow_insecure=True,
    )
    app = create_app(settings)
    # Displace the autouse FakeIPCSupervisor, which is injected pre-connected
    # and would skip the connect() call entirely.
    app.state.ipc_supervisor = _InterruptingSupervisor()
    app.state.ipc_supervisor_preconnected = False

    with pytest.raises(KeyboardInterrupt):
        async with app.router.lifespan_context(app):
            pytest.fail("lifespan startup must not yield after an interrupt")

    # Proves the interrupt landed past the open, in the window __del__ cannot
    # rescue — and keeps `app` referenced while the leak check runs.
    assert app.state.db is not None

    worker_watch()

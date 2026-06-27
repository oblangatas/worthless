"""Tests for worthless._async.run_sync — the sync-to-async bridge used by
CLI commands that may run inside or outside an event loop."""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time

import pytest

from worthless._async import run_sync


@pytest.fixture(autouse=True)
def _drain_run_sync_workers():
    """Wait for any daemon ``worthless-run_sync`` worker threads to die
    before pytest moves to the next test. Timed-out workers from this
    module leak briefly until their (short) coroutines complete; without
    this drain, unrelated tests like ``test_deploy_start`` see >1 alive
    threads and trip the BPO-34394 single-threaded-entry safety check."""
    yield
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        alive = [t for t in threading.enumerate() if t.name == "worthless-run_sync"]
        if not alive:
            return
        time.sleep(0.02)
    # Deadline exceeded — fail loudly rather than silently leaving stuck workers
    # that can poison subsequent tests (BPO-34394 single-threaded-entry check).
    stuck = [t for t in threading.enumerate() if t.name == "worthless-run_sync"]
    if stuck:
        raise RuntimeError(
            f"worthless-run_sync worker(s) still alive after 5 s drain window: "
            f"{[t.ident for t in stuck]}. These threads will poison later tests."
        )


class TestRunSyncTimeout:
    """The ``timeout`` parameter on ``run_sync`` was added so callers can cap
    how long a single async roundtrip is allowed to block the sync entry
    point. The plumbing must actually fire when exceeded — otherwise the
    parameter is a footgun (silently ignored)."""

    @pytest.mark.asyncio
    async def test_timeout_in_threaded_path_raises(self) -> None:
        """When called from within a running event loop, run_sync dispatches
        to a worker thread and forwards ``timeout`` to ``Future.result``.
        A coroutine that sleeps longer than the timeout must raise
        ``concurrent.futures.TimeoutError``."""

        async def _sleeper() -> None:
            await asyncio.sleep(0.3)

        with pytest.raises(concurrent.futures.TimeoutError):
            run_sync(_sleeper(), timeout=0.1)


class TestRunSyncAdversarial:
    """Probes for hostile coroutines and re-entry patterns. The threaded
    path uses a single-worker ThreadPoolExecutor scoped to the call — the
    worker thread must not survive the call or leak across invocations,
    and re-entry from inside a driven coroutine must not deadlock."""

    @pytest.mark.asyncio
    async def test_caller_recovers_when_coroutine_ignores_cancellation(self) -> None:
        """If a coroutine swallows ``CancelledError`` and keeps running, the
        ``Future.result(timeout=…)`` call still returns control to the
        caller as ``concurrent.futures.TimeoutError``. The dangling work
        is the coroutine's problem, not the caller's — what matters is the
        caller does not block forever past the declared timeout."""

        async def _stubborn() -> str:
            try:
                await asyncio.sleep(0.3)
            except asyncio.CancelledError:
                await asyncio.sleep(0.3)
            return "done"

        start = time.monotonic()
        with pytest.raises(concurrent.futures.TimeoutError):
            run_sync(_stubborn(), timeout=0.1)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"run_sync caller blocked for {elapsed:.2f}s past timeout — "
            "stubborn coroutine pinned the caller thread"
        )

    def test_reentrant_run_sync_does_not_deadlock(self) -> None:
        """A coroutine driven by run_sync may itself call run_sync (e.g. via
        a sync helper that internally bridges to async). The outer call has
        no running loop, so it uses asyncio.run; the inner call sees a
        running loop and tunnels through a fresh ThreadPoolExecutor. Both
        must complete without deadlock."""

        async def _inner() -> int:
            return 42

        async def _outer() -> int:
            return run_sync(_inner())

        result = run_sync(_outer())
        assert result == 42

    @pytest.mark.asyncio
    async def test_exception_propagates_through_threaded_path(self) -> None:
        """When the wrapped coroutine raises, run_sync must re-raise the
        ORIGINAL exception (not wrap it, not swallow it). This validates
        the error path of the new pool.shutdown(wait=False) wiring — the
        shutdown must not mask the failure."""

        async def _raiser() -> None:
            raise ValueError("intentional failure under test")

        with pytest.raises(ValueError, match="intentional failure under test"):
            run_sync(_raiser())

    @pytest.mark.asyncio
    async def test_negative_timeout_raises_immediately(self) -> None:
        """A negative timeout cannot ever be satisfied — Future.result(-1)
        raises TimeoutError before the worker has any chance to complete.
        This pins the contract for sentinel/misuse values rather than
        leaving the behaviour ambiguous."""

        async def _trivial() -> int:
            return 1

        with pytest.raises(concurrent.futures.TimeoutError):
            run_sync(_trivial(), timeout=-1.0)

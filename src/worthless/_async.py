"""Run an async coroutine to completion from a sync caller, regardless of
whether an event loop is already running.

Plain ``asyncio.run`` raises ``RuntimeError`` when invoked from a context
that already has a running loop (MCP server lazy bootstrap, pytest-asyncio
embeddings, etc). This helper probes for a live loop and tunnels through
a thread when one is found, so sync entry points that need a single async
roundtrip do not crash inside reusable code.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")


def run_sync(coro: Awaitable[T], timeout: float | None = None) -> T:
    """Drive ``coro`` to completion and return its result.

    If the calling thread already has a running event loop, the coroutine
    is dispatched to a daemon worker thread that runs ``asyncio.run`` in a
    fresh loop; otherwise ``asyncio.run`` is invoked directly on the
    current thread.

    This function is thread-safe; concurrent callers each get their own
    worker thread and event loop.

    The threaded path uses a daemon ``threading.Thread`` rather than a
    ``ThreadPoolExecutor`` so that a timed-out worker does not register
    an ``atexit`` hook blocking process exit. On timeout the caller
    receives ``concurrent.futures.TimeoutError`` immediately; the daemon
    worker continues running until the coroutine finishes naturally
    (Python cannot kill threads) and is reaped by the interpreter on
    process exit. CLI callers can safely rely on ``timeout``; long-running
    services should still avoid coroutines that ignore cancellation.

    ``timeout`` is only enforced on the threaded path. Direct-path calls
    (no running loop detected) ignore ``timeout`` and run to completion.
    A negative ``timeout`` raises ``TimeoutError`` without starting the
    coroutine; the coroutine is closed to suppress the RuntimeWarning.

    Exceptions propagate to the caller unchanged.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]

    result_box: dict[str, T] = {}
    error_box: dict[str, BaseException] = {}

    def _worker() -> None:
        try:
            result_box["v"] = asyncio.run(coro)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 — must capture and re-raise on caller thread
            error_box["e"] = exc

    if timeout is not None and timeout < 0:
        getattr(coro, "close", lambda: None)()  # suppress "never awaited" RuntimeWarning
        raise concurrent.futures.TimeoutError
    worker = threading.Thread(target=_worker, daemon=True, name="worthless-run_sync")
    worker.start()
    worker.join(timeout=timeout)
    if worker.is_alive():
        raise concurrent.futures.TimeoutError
    if "e" in error_box:
        raise error_box["e"]
    return result_box["v"]

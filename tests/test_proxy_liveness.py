"""The proxy shuts down when its supervisor dies (worthless-yfxm).

``up`` and ``wrap`` hold the write end of a liveness pipe and hand the proxy
the read end as ``WORTHLESS_LIVENESS_FD``. When the supervisor dies, even by
``kill -9``, the kernel closes the write end and the read end hits EOF.
"""

from __future__ import annotations

import asyncio
import os
import signal

import pytest

from worthless.proxy import app as proxy_app


async def _wait_for(pred, timeout: float = 1.0) -> bool:  # type: ignore[no-untyped-def]
    for _ in range(int(timeout / 0.01)):
        if pred():
            return True
        await asyncio.sleep(0.01)
    return pred()


@pytest.fixture
def kills(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    """Record os.kill calls instead of signalling the test process."""
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(proxy_app.os, "kill", lambda pid, sig: calls.append((pid, sig)))
    return calls


async def test_proxy_sigterms_itself_when_the_supervisor_closes_the_pipe(
    monkeypatch: pytest.MonkeyPatch, kills: list[tuple[int, int]]
) -> None:
    read_fd, write_fd = os.pipe()
    monkeypatch.setenv("WORTHLESS_LIVENESS_FD", str(read_fd))
    fd = proxy_app._watch_liveness_fd()
    try:
        assert fd == read_fd
        await asyncio.sleep(0.05)
        assert kills == [], "fired while the supervisor still holds the pipe"
        os.close(write_fd)
        write_fd = -1
        assert await _wait_for(lambda: bool(kills)), "no shutdown after the pipe closed"
        assert kills == [(os.getpid(), signal.SIGTERM)]
    finally:
        asyncio.get_running_loop().remove_reader(read_fd)
        for f in (read_fd, write_fd):
            if f >= 0:
                os.close(f)


async def test_proxy_ignores_bytes_on_the_pipe(
    monkeypatch: pytest.MonkeyPatch, kills: list[tuple[int, int]]
) -> None:
    """Only EOF means the supervisor died; data on the pipe is not a shutdown."""
    read_fd, write_fd = os.pipe()
    monkeypatch.setenv("WORTHLESS_LIVENESS_FD", str(read_fd))
    proxy_app._watch_liveness_fd()
    try:
        os.write(write_fd, b"x")
        await asyncio.sleep(0.05)
        assert kills == []
    finally:
        asyncio.get_running_loop().remove_reader(read_fd)
        os.close(read_fd)
        os.close(write_fd)


async def test_proxy_watches_nothing_without_a_liveness_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy started by hand or by a service manager has no pipe to watch."""
    monkeypatch.delenv("WORTHLESS_LIVENESS_FD", raising=False)
    assert proxy_app._watch_liveness_fd() is None

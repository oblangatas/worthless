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
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings


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


@pytest.mark.parametrize("kind", ["regular-file", "closed-fd", "not-a-number"])
async def test_proxy_ignores_a_liveness_fd_that_is_not_a_pipe(
    kind: str,
    monkeypatch: pytest.MonkeyPatch,
    kills: list[tuple[int, int]],
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    """A stale or bogus value must not stop a healthy proxy or fail its startup.

    On kqueue a regular file always reads as EOF, so trusting it would
    SIGTERM the proxy at once.
    """
    fd = -1
    if kind == "regular-file":
        f = tmp_path / "f"
        f.write_bytes(b"")
        fd = os.open(f, os.O_RDONLY)
        raw = str(fd)
    elif kind == "closed-fd":
        r, w = os.pipe()
        os.close(r)
        os.close(w)
        raw = str(r)
    else:
        raw = "not-a-number"
    monkeypatch.setenv("WORTHLESS_LIVENESS_FD", raw)
    try:
        assert proxy_app._watch_liveness_fd() is None
        await asyncio.sleep(0.05)
        assert kills == []
    finally:
        if fd >= 0:
            os.close(fd)


@pytest.mark.parametrize("dies", ["before-startup", "while-serving"])
async def test_the_proxy_lifespan_shuts_down_when_the_supervisor_dies(
    dies: str,
    monkeypatch: pytest.MonkeyPatch,
    kills: list[tuple[int, int]],
    tmp_db_path: str,
    fernet_key: bytes,
) -> None:
    """The real lifespan installs the watch; only EOF on the pipe stops the proxy."""
    read_fd, write_fd = os.pipe()
    if dies == "before-startup":
        os.close(write_fd)
        write_fd = -1
    monkeypatch.setenv("WORTHLESS_LIVENESS_FD", str(read_fd))
    app = create_app(
        ProxySettings(db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True)
    )
    try:
        async with app.router.lifespan_context(app):
            if write_fd >= 0:
                await asyncio.sleep(0.05)
                assert kills == [], "fired while the supervisor still holds the pipe"
                os.close(write_fd)
                write_fd = -1
            assert await _wait_for(lambda: bool(kills)), "a dead supervisor went unnoticed"
        assert kills == [(os.getpid(), signal.SIGTERM)]
    finally:
        for f in (read_fd, write_fd):
            if f >= 0:
                os.close(f)

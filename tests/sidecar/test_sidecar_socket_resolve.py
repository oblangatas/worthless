"""Tests for sidecar socket discovery helpers (WOR-749 stale-socket fix)."""

from __future__ import annotations

import asyncio
import socket
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from worthless.ipc.client import IPCBackendError
from worthless.sidecar.health import (
    find_sidecar_socket_for_open,
    list_sidecar_sockets,
    probe_socket,
    probe_socket_async,
)


def _short_tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="wh-", dir="/tmp"))


def _bind_unix(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
    finally:
        sock.close()


def test_list_sidecar_sockets_newest_first() -> None:
    tmp_path = _short_tmp()
    try:
        run_root = tmp_path / "run"
        old_sock = run_root / "100" / "sidecar.sock"
        new_sock = run_root / "200" / "sidecar.sock"
        _bind_unix(old_sock)
        _bind_unix(new_sock)
        import os

        os.utime(old_sock, (time.time() - 100, time.time() - 100))

        found = list_sidecar_sockets(run_root)
        assert found == [new_sock, old_sock]
    finally:
        import shutil

        shutil.rmtree(tmp_path, ignore_errors=True)


def test_list_sidecar_sockets_skips_non_socket_files(tmp_path: Path) -> None:
    run_root = tmp_path / "run" / "42"
    run_root.mkdir(parents=True)
    (run_root / "sidecar.sock").write_text("x")

    assert list_sidecar_sockets(tmp_path / "run") == []


def test_list_sidecar_sockets_empty_when_run_root_missing(tmp_path: Path) -> None:
    assert list_sidecar_sockets(tmp_path / "no-such-run") == []


def test_probe_socket_false_when_path_missing(tmp_path: Path) -> None:
    assert probe_socket(tmp_path / "missing.sock") is False


def test_probe_socket_false_when_not_socket(tmp_path: Path) -> None:
    plain = tmp_path / "not.sock"
    plain.write_text("x")
    assert probe_socket(plain) is False


def test_probe_socket_true_when_handshake_succeeds() -> None:
    tmp_path = _short_tmp()
    try:
        sock = tmp_path / "good.sock"
        _bind_unix(sock)
        with patch("worthless.sidecar.health._probe", new=AsyncMock(return_value=0)):
            assert probe_socket(sock) is True
    finally:
        import shutil

        shutil.rmtree(tmp_path, ignore_errors=True)


def test_probe_socket_false_on_handshake_timeout() -> None:
    tmp_path = _short_tmp()
    try:
        sock = tmp_path / "slow.sock"
        _bind_unix(sock)

        async def _hang(_path: Path) -> int:
            await asyncio.sleep(10)
            return 0

        with patch("worthless.sidecar.health._probe", side_effect=_hang):
            assert probe_socket(sock, timeout=0.05) is False
    finally:
        import shutil

        shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.mark.asyncio
async def test_probe_socket_async_false_when_path_missing(tmp_path: Path) -> None:
    assert await probe_socket_async(tmp_path / "missing.sock") is False


@pytest.mark.asyncio
async def test_probe_socket_async_true_when_handshake_succeeds() -> None:
    tmp_path = _short_tmp()
    try:
        sock = tmp_path / "good.sock"
        _bind_unix(sock)
        with patch("worthless.sidecar.health._probe", new=AsyncMock(return_value=0)):
            assert await probe_socket_async(sock) is True
    finally:
        import shutil

        shutil.rmtree(tmp_path, ignore_errors=True)


def test_list_sidecar_sockets_skips_non_directory_entries() -> None:
    tmp_path = _short_tmp()
    try:
        run_root = tmp_path / "run"
        run_root.mkdir(parents=True)
        (run_root / "stale-pid-file").write_text("99999")
        sock = run_root / "42" / "sidecar.sock"
        _bind_unix(sock)

        assert list_sidecar_sockets(run_root) == [sock]
    finally:
        import shutil

        shutil.rmtree(tmp_path, ignore_errors=True)


class _FakeIPCClient:
    """HELLO succeeds; ``open`` fails on *stale_sock* only (wrong Fernet session)."""

    stale_sock: Path

    def __init__(self, sock: Path, timeout: float = 3.0) -> None:
        self._sock = sock

    async def __aenter__(self) -> _FakeIPCClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def open(self, ciphertext: bytes, key_id: bytes | None = None) -> None:
        if self._sock == self.stale_sock:
            raise IPCBackendError("BACKEND: operation failed")


def test_find_sidecar_socket_skips_stale_fernet_session(tmp_path: Path) -> None:
    """WOR-749: newest socket may HELLO-ok but fail open — try the next socket."""
    run_root = tmp_path / "run"
    stale_sock = run_root / "100" / "sidecar.sock"
    good_sock = run_root / "200" / "sidecar.sock"
    ciphertext = b"encrypted-shard-b"

    _FakeIPCClient.stale_sock = stale_sock

    with (
        patch(
            "worthless.sidecar.health.list_sidecar_sockets",
            return_value=[stale_sock, good_sock],
        ),
        patch(
            "worthless.sidecar.health.probe_socket_async",
            new=AsyncMock(return_value=True),
        ),
        patch("worthless.ipc.client.IPCClient", _FakeIPCClient),
    ):
        picked = asyncio.run(
            find_sidecar_socket_for_open(
                run_root,
                ciphertext=ciphertext,
                key_id=b"openai-deadbeef",
            )
        )

    assert picked == good_sock


def test_find_sidecar_socket_skips_socket_that_fails_hello(tmp_path: Path) -> None:
    """Stale inode: path exists but HELLO fails — try next socket."""
    run_root = tmp_path / "run"
    dead_sock = run_root / "100" / "sidecar.sock"
    good_sock = run_root / "200" / "sidecar.sock"
    ciphertext = b"encrypted-shard-b"

    _FakeIPCClient.stale_sock = dead_sock

    async def _probe(sock: Path, *, timeout: float = 1.8) -> bool:
        return sock == good_sock

    with (
        patch(
            "worthless.sidecar.health.list_sidecar_sockets",
            return_value=[dead_sock, good_sock],
        ),
        patch("worthless.sidecar.health.probe_socket_async", side_effect=_probe),
        patch("worthless.ipc.client.IPCClient", _FakeIPCClient),
    ):
        picked = asyncio.run(
            find_sidecar_socket_for_open(
                run_root,
                ciphertext=ciphertext,
                key_id=b"openai-deadbeef",
            )
        )

    assert picked == good_sock


def test_find_sidecar_socket_raises_when_all_open_fail(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    stale_a = run_root / "100" / "sidecar.sock"
    stale_b = run_root / "200" / "sidecar.sock"
    _FakeIPCClient.stale_sock = stale_a  # both fail: patch open to always fail

    class _AlwaysFailClient(_FakeIPCClient):
        async def open(self, ciphertext: bytes, key_id: bytes | None = None) -> None:
            raise IPCBackendError("BACKEND: operation failed")

    with (
        patch(
            "worthless.sidecar.health.list_sidecar_sockets",
            return_value=[stale_a, stale_b],
        ),
        patch(
            "worthless.sidecar.health.probe_socket_async",
            new=AsyncMock(return_value=True),
        ),
        patch("worthless.ipc.client.IPCClient", _AlwaysFailClient),
    ):
        with pytest.raises(IPCBackendError, match="BACKEND"):
            asyncio.run(
                find_sidecar_socket_for_open(
                    run_root,
                    ciphertext=b"x",
                    key_id=b"k",
                )
            )


def test_find_sidecar_socket_no_live_sockets_raises_file_not_found(tmp_path: Path) -> None:
    run_root = tmp_path / "run"

    with patch("worthless.sidecar.health.list_sidecar_sockets", return_value=[]):
        with pytest.raises(FileNotFoundError, match="no sidecar socket"):
            asyncio.run(
                find_sidecar_socket_for_open(
                    run_root,
                    ciphertext=b"x",
                )
            )

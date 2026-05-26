"""Tests for ``worthless.cli.sidecar_lifecycle`` — WOR-384 Phases A + B."""

from __future__ import annotations

import collections
import base64
import importlib
import logging
import os
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

import worthless.cli.sidecar_lifecycle as _sidecar_lifecycle
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.sidecar_lifecycle import (
    ShareFiles,
    SidecarHandle,
    shutdown_sidecar,
    spawn_sidecar,
    split_to_tmpfs,
)
from worthless.ipc.client import IPCClient


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A fresh Worthless home dir under the test's tmp_path.

    Per-test rather than session-scoped so xdist parallel workers don't
    collide on the per-pid run subdir (each test creates a *fresh* home,
    so the same pid writing into two homes is fine).
    """
    h = tmp_path / ".worthless"
    h.mkdir()
    return h


@pytest.fixture
def key() -> bytearray:
    """A 44-byte placeholder fernet key. Uniform bytes are fine for tests
    that don't care about the XOR roundtrip — the dedicated XOR test uses
    non-uniform bytes to prove the split isn't degenerate."""
    return bytearray(b"A" * 44)


class _FakeProc:
    """Stand-in for ``subprocess.Popen`` used by env-capture tests.

    Models a still-running child: ``poll()`` returns None, ``kill()``/``wait()``
    are no-ops. Stdout/stderr are None so the production failure path's
    ``communicate()`` is bypassed (it isn't reached on the success path
    that env-capture tests exercise).
    """

    def __init__(self, pid: int = 12345) -> None:
        self.pid = pid
        self.stdout: object = None
        self.stderr: object = None

    def poll(self) -> int | None:
        return None

    def kill(self) -> None:  # pragma: no cover — never reached on success path
        pass

    def wait(self, timeout: float | None = None) -> int:  # pragma: no cover
        return 0


class _FakeShutdownProc:
    """Stand-in Popen for Phase-C shutdown tests.

    Models a child that responds to ``terminate()``/``kill()`` deterministically
    without a real process. Set ``terminate_hangs=True`` to simulate a child
    that ignores SIGTERM — ``wait()`` will then raise ``TimeoutExpired`` until
    ``kill()`` is called, after which it returns 0.
    """

    def __init__(self, pid: int = 12345, terminate_hangs: bool = False) -> None:
        self.pid = pid
        self.stdout: object = None
        self.stderr: object = None
        self._terminate_hangs = terminate_hangs
        self._exit_code: int | None = None
        self.terminate_called = False
        self.kill_called = False
        self.wait_timeouts: list[float | None] = []

    def poll(self) -> int | None:
        return self._exit_code

    def terminate(self) -> None:
        self.terminate_called = True
        if not self._terminate_hangs:
            self._exit_code = 0

    def kill(self) -> None:
        self.kill_called = True
        self._exit_code = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if self._exit_code is None:
            # Caller is doing the SIGTERM grace wait but the child is hung.
            raise subprocess.TimeoutExpired(cmd="fake-sidecar", timeout=timeout or 0.0)
        return self._exit_code


def _capturing_popen(captured: dict[str, dict[str, str]], pid: int = 12345) -> object:
    """Return a Popen-shaped callable that records ``kwargs['env']``."""

    def _fake_popen(*args: object, **kwargs: object) -> _FakeProc:
        captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
        return _FakeProc(pid=pid)

    return _fake_popen


def _short_socket_path() -> Path:
    """Return a short, /tmp-rooted AF_UNIX socket path.

    macOS pytest ``tmp_path`` lives under ``/private/var/folders/.../`` —
    typically 90+ bytes — so ``shares.run_dir / "sidecar.sock"`` exceeds
    the 104-byte ``sun_path`` limit. Production code (post WOR-384 fix
    7/8) validates that limit and raises WRTLS-114 before ``Popen``,
    which short-circuits any test that wanted to exercise the body.
    Tests that don't care about the path semantically should use this
    helper to get a short, unique path under ``/tmp``.
    """
    return Path(tempfile.mkdtemp(prefix="wlr-test-", dir="/tmp")) / "sc.sock"  # noqa: S108


def test_split_to_tmpfs_creates_two_shares(home: Path, key: bytearray) -> None:
    shares = split_to_tmpfs(key, home)
    assert shares.share_a_path.exists()
    assert shares.share_b_path.exists()


def test_split_to_tmpfs_xor_yields_original_key(home: Path) -> None:
    # Non-uniform bytes so XOR roundtrip isn't degenerate over a single
    # repeated byte (which would pass even if shard_b were a constant).
    key = bytearray(b"fernet-key-44-bytes-urlsafe-base64-here-padd")
    assert len(key) == 44
    shares = split_to_tmpfs(key, home)
    a = shares.share_a_path.read_bytes()
    b = shares.share_b_path.read_bytes()
    assert len(a) == len(key)
    assert len(b) == len(key)
    reconstructed = bytes(x ^ y for x, y in zip(a, b, strict=True))
    assert reconstructed == bytes(key)


def test_share_files_have_0600_perms_and_owner_uid(home: Path, key: bytearray) -> None:
    shares = split_to_tmpfs(key, home)
    for p in (shares.share_a_path, shares.share_b_path):
        st = p.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600, f"{p} mode={oct(st.st_mode)}"
        assert st.st_uid == os.getuid()


def test_share_dir_is_per_pid_under_home(home: Path, key: bytearray) -> None:
    shares = split_to_tmpfs(key, home)
    expected = home / "run" / str(os.getpid())
    assert shares.run_dir == expected
    assert shares.run_dir.exists()
    assert stat.S_IMODE(shares.run_dir.stat().st_mode) == 0o700


def test_split_to_tmpfs_does_not_log_share_bytes(
    home: Path, key: bytearray, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="worthless")
    shares: ShareFiles = split_to_tmpfs(key, home)
    a_hex = shares.share_a_path.read_bytes().hex()
    b_hex = shares.share_b_path.read_bytes().hex()
    for record in caplog.records:
        msg = record.getMessage()
        assert a_hex not in msg, f"share_a hex leaked: {msg!r}"
        assert b_hex not in msg, f"share_b hex leaked: {msg!r}"
        for arg in record.args or ():
            arg_str = repr(arg)
            assert a_hex not in arg_str
            assert b_hex not in arg_str


@pytest.mark.integration
def test_spawn_and_shutdown_do_not_log_share_bytes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SR-04: spawn_sidecar + shutdown_sidecar log paths/PIDs only, not share bytes.

    Regression guard against a future debug print that accidentally interpolates
    a shard buffer. Drives the full lifecycle and scans every captured record.
    """
    caplog.set_level(logging.DEBUG, logger="worthless")
    with tempfile.TemporaryDirectory(prefix="w-", dir="/tmp") as tmp_dir_str:  # noqa: S108
        short_home = Path(tmp_dir_str) / ".worthless"
        short_home.mkdir()
        fernet_key = bytearray(Fernet.generate_key())
        shares = split_to_tmpfs(fernet_key, short_home)
        a_hex = shares.share_a_path.read_bytes().hex()
        b_hex = shares.share_b_path.read_bytes().hex()
        socket_path = shares.run_dir / "sc.sock"
        if len(str(socket_path)) >= 104:
            pytest.skip(f"tmp path too long for AF_UNIX (len={len(str(socket_path))} >= 104)")
        handle = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())
        shutdown_sidecar(handle)

    for record in caplog.records:
        msg = record.getMessage()
        assert a_hex not in msg, f"share_a hex leaked in log: {msg!r}"
        assert b_hex not in msg, f"share_b hex leaked in log: {msg!r}"
        for arg in record.args or ():
            arg_str = repr(arg)
            assert a_hex not in arg_str
            assert b_hex not in arg_str


# ---------------------------------------------------------------------------
# Phase B: spawn_sidecar tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_spawn_sidecar_returns_handle_with_running_process() -> None:
    """B1: spawn a real sidecar and verify the handle reflects a live process.

    Uses a real Fernet key (not the uniform-byte ``key`` fixture) because the
    sidecar's FernetBackend validates the reconstructed key on startup.
    /tmp-rooted home keeps the socket path under AF_UNIX's 104-byte limit.
    """
    with tempfile.TemporaryDirectory(prefix="w-", dir="/tmp") as tmp_dir_str:  # noqa: S108
        short_home = Path(tmp_dir_str) / ".worthless"
        short_home.mkdir()
        fernet_key = bytearray(base64.urlsafe_b64encode(secrets.token_bytes(32)))
        shares = split_to_tmpfs(fernet_key, short_home)
        socket_path = shares.run_dir / "sc.sock"
        if len(str(socket_path)) >= 104:
            pytest.skip(f"tmp path too long for AF_UNIX (len={len(str(socket_path))} >= 104)")
        handle = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())
        try:
            assert isinstance(handle, SidecarHandle)
            assert handle.proc.poll() is None
            assert handle.socket_path.exists()
            assert handle.allowed_uid == os.getuid()
            assert handle.shares is shares
        finally:
            handle.proc.terminate()
            try:
                handle.proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                handle.proc.kill()
                handle.proc.wait(timeout=2.0)
            if handle.socket_path.exists():
                try:
                    handle.socket_path.unlink()
                except OSError:
                    pass


def test_spawn_sidecar_passes_current_uid_in_env(home: Path, key: bytearray) -> None:
    """B2: env carries the caller-provided uid as the sidecar's allowlist."""
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()
    captured: dict[str, dict[str, str]] = {}

    with (
        patch(
            "worthless.cli.sidecar_lifecycle.subprocess.Popen",
            _capturing_popen(captured),
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._wait_for_ready",
            return_value=True,
        ),
        # C4 added an lstat S_ISSOCK check on socket_path post-ready.
        # The mock _wait_for_ready bypasses real socket creation, so the
        # path doesn't exist — bypass the inode check too.
        patch(
            "worthless.cli.sidecar_lifecycle._verify_socket_inode",
            return_value=None,
        ),
    ):
        handle = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

    assert handle.allowed_uid == os.getuid()
    env = captured["env"]
    assert env["WORTHLESS_SIDECAR_ALLOWED_UID"] == str(os.getuid())
    assert env["WORTHLESS_SIDECAR_SOCKET"] == str(socket_path)
    assert env["WORTHLESS_SIDECAR_SHARE_A"] == str(shares.share_a_path)
    assert env["WORTHLESS_SIDECAR_SHARE_B"] == str(shares.share_b_path)


def test_spawn_sidecar_ready_timeout_env_override_extends_deadline(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``WORTHLESS_SIDECAR_READY_TIMEOUT_SECS`` overrides the kwarg default.

    Real-sidecar tests on slow CI runners (GitHub Actions Ubuntu under
    xdist load) occasionally exceed the 5s prod default for the
    AF_UNIX bind. The env override lets the workflow extend the
    deadline without leaking that knob into prod callers.

    Verified via the WRTLS-114 message, which echoes the active timeout.
    Setting env=0.2 with kwarg=99 must still time out at 0.2s.
    """
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()
    monkeypatch.setenv("WORTHLESS_SIDECAR_READY_TIMEOUT_SECS", "0.2")

    real_popen = subprocess.Popen
    spawned: list[subprocess.Popen[bytes]] = []

    def _sleeper_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        proc = real_popen(  # noqa: S603 — static args, no shell
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=kwargs.get("env"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
        )
        spawned.append(proc)
        return proc

    with patch("worthless.cli.sidecar_lifecycle.subprocess.Popen", _sleeper_popen):
        with pytest.raises(WorthlessError) as exc_info:
            spawn_sidecar(
                socket_path,
                shares,
                allowed_uid=os.getuid(),
                ready_timeout=99.0,  # would mask a broken override if it won
            )

    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    # Message echoes the env-derived timeout, NOT the 99s kwarg.
    assert "0.2s" in exc_info.value.message, (
        f"env override must replace kwarg in WRTLS-114 message; got {exc_info.value.message!r}"
    )
    assert spawned, "Popen replacement was never invoked"


def test_spawn_sidecar_ignores_invalid_ready_timeout_env(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Garbled or non-positive env values fall back to the kwarg default."""
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()
    monkeypatch.setenv("WORTHLESS_SIDECAR_READY_TIMEOUT_SECS", "garbage")

    real_popen = subprocess.Popen

    def _sleeper_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        return real_popen(  # noqa: S603 — static args, no shell
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=kwargs.get("env"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
        )

    with patch("worthless.cli.sidecar_lifecycle.subprocess.Popen", _sleeper_popen):
        with pytest.raises(WorthlessError) as exc_info:
            spawn_sidecar(
                socket_path,
                shares,
                allowed_uid=os.getuid(),
                ready_timeout=0.3,
            )

    # Garbage env value must NOT silently extend the deadline.
    assert "0.3s" in exc_info.value.message, (
        f"invalid env must fall back to kwarg; got {exc_info.value.message!r}"
    )


def test_spawn_sidecar_times_out_with_wrtls_114(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B3: a non-sidecar child that never binds raises WRTLS-114 and is reaped.

    The WORTHLESS_SIDECAR_READY_TIMEOUT_SECS env var is cleared so CI's 20s
    override does not extend the 0.5s kwarg to 20s, making this test ~40× slower.
    """
    monkeypatch.delenv("WORTHLESS_SIDECAR_READY_TIMEOUT_SECS", raising=False)
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()

    real_popen = subprocess.Popen
    spawned: list[subprocess.Popen[bytes]] = []

    def _bogus_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        # Replace the sidecar invocation with a sleeper that won't bind.
        proc = real_popen(  # noqa: S603 — args are static, no shell
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=kwargs.get("env"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
        )
        spawned.append(proc)
        return proc

    with patch("worthless.cli.sidecar_lifecycle.subprocess.Popen", _bogus_popen):
        with pytest.raises(WorthlessError) as exc_info:
            spawn_sidecar(
                socket_path,
                shares,
                allowed_uid=os.getuid(),
                ready_timeout=0.5,
            )

    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert exc_info.value.code.value == 114
    # The bogus child must be reaped, not orphaned.
    assert spawned, "Popen replacement was never invoked"
    proc = spawned[0]
    assert proc.poll() is not None, "bogus child still running after timeout"


def test_spawn_sidecar_passes_drain_timeout_and_log_level(home: Path, key: bytearray) -> None:
    """B4: drain_timeout default and WARNING log level land in the env."""
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()
    captured: dict[str, dict[str, str]] = {}

    with (
        patch(
            "worthless.cli.sidecar_lifecycle.subprocess.Popen",
            _capturing_popen(captured, pid=67890),
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._wait_for_ready",
            return_value=True,
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._verify_socket_inode",
            return_value=None,
        ),
    ):
        spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

    env = captured["env"]
    assert env["WORTHLESS_SIDECAR_DRAIN_TIMEOUT"] == "5.0"
    assert env["WORTHLESS_LOG_LEVEL"] == "WARNING"


# ---------------------------------------------------------------------------
# Phase C: shutdown_sidecar tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_shutdown_sidecar_terminates_and_unlinks() -> None:
    """C1: SIGTERM the sidecar, then verify all on-disk artifacts are gone."""
    with tempfile.TemporaryDirectory(prefix="w-", dir="/tmp") as tmp_dir_str:  # noqa: S108
        short_home = Path(tmp_dir_str) / ".worthless"
        short_home.mkdir()
        fernet_key = bytearray(base64.urlsafe_b64encode(secrets.token_bytes(32)))
        shares = split_to_tmpfs(fernet_key, short_home)
        socket_path = shares.run_dir / "sc.sock"
        if len(str(socket_path)) >= 104:
            pytest.skip(f"tmp path too long for AF_UNIX (len={len(str(socket_path))} >= 104)")
        handle = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

        shutdown_sidecar(handle)

        assert handle.proc.poll() is not None, "process still running after shutdown"
        assert not handle.shares.share_a_path.exists()
        assert not handle.shares.share_b_path.exists()
        assert not handle.socket_path.exists()
        assert not handle.shares.run_dir.exists()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_lifecycle_seal_open_roundtrip_through_real_sidecar() -> None:
    """End-to-end: split → spawn → IPC seal/open → shutdown. Proves the
    share files reconstruct into a Fernet key the sidecar can actually use,
    not just that a process spawns and a socket binds.
    """
    with tempfile.TemporaryDirectory(prefix="w-", dir="/tmp") as tmp_dir_str:  # noqa: S108
        short_home = Path(tmp_dir_str) / ".worthless"
        short_home.mkdir()
        fernet_key = bytearray(Fernet.generate_key())
        plaintext = b"hello-from-end-to-end-test"

        shares = split_to_tmpfs(fernet_key, short_home)
        socket_path = shares.run_dir / "sc.sock"
        if len(str(socket_path)) >= 104:
            pytest.skip(f"tmp path too long for AF_UNIX (len={len(str(socket_path))} >= 104)")

        handle = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())
        try:
            async with IPCClient(socket_path) as client:
                ciphertext = await client.seal(plaintext)
                roundtripped = await client.open(ciphertext)
            assert roundtripped == plaintext
            # Anti-vacuity: a no-op backend that echoed plaintext back would
            # pass the roundtrip check above; this asserts real sealing.
            assert ciphertext != plaintext
        finally:
            shutdown_sidecar(handle)
            assert handle.proc.poll() is not None
            assert not handle.shares.run_dir.exists()


def test_shutdown_sidecar_sigkills_after_grace_window(home: Path, key: bytearray) -> None:
    """C2: a child that ignores SIGTERM is escalated to SIGKILL."""
    shares = split_to_tmpfs(key, home)
    handle = SidecarHandle(
        proc=_FakeShutdownProc(terminate_hangs=True),  # type: ignore[arg-type]
        socket_path=shares.run_dir / "sc.sock",
        shares=shares,
        allowed_uid=os.getuid(),
        drain_timeout=0.25,
        stderr_buf=collections.deque(),
    )
    shutdown_sidecar(handle)
    assert handle.proc.terminate_called  # type: ignore[attr-defined]
    assert handle.proc.kill_called  # type: ignore[attr-defined]
    assert handle.proc.wait_timeouts[0] == 0.25  # type: ignore[attr-defined]
    # SR-02 must hold even when the SIGKILL leg fires — zeroing happens after
    # the kill, not on the graceful-terminate branch only.
    assert all(b == 0 for b in handle.shares.shard_a)
    assert all(b == 0 for b in handle.shares.shard_b)


def test_shutdown_sidecar_zeroes_share_bytearrays(home: Path, key: bytearray) -> None:
    """C3 (SR-02): both shard bytearrays are all-zero after shutdown."""
    shares = split_to_tmpfs(key, home)
    handle = SidecarHandle(
        proc=_FakeShutdownProc(),  # type: ignore[arg-type]
        socket_path=shares.run_dir / "sc.sock",
        shares=shares,
        allowed_uid=os.getuid(),
        drain_timeout=5.0,
        stderr_buf=collections.deque(),
    )
    # Pre-shutdown sanity: both shards carry non-zero content.
    assert any(b != 0 for b in handle.shares.shard_a)
    assert any(b != 0 for b in handle.shares.shard_b)

    shutdown_sidecar(handle)

    assert all(b == 0 for b in handle.shares.shard_a), "shard_a not zeroed"
    assert all(b == 0 for b in handle.shares.shard_b), "shard_b not zeroed"


def test_shutdown_sidecar_is_idempotent(home: Path, key: bytearray) -> None:
    """C4: calling shutdown twice is safe — files already gone, mem already zeroed."""
    shares = split_to_tmpfs(key, home)
    handle = SidecarHandle(
        proc=_FakeShutdownProc(),  # type: ignore[arg-type]
        socket_path=shares.run_dir / "sc.sock",
        shares=shares,
        allowed_uid=os.getuid(),
        drain_timeout=5.0,
        stderr_buf=collections.deque(),
    )
    shutdown_sidecar(handle)
    # Second call must not raise.
    shutdown_sidecar(handle)


# ---------------------------------------------------------------------------
# CodeRabbit regression guards (PR #116 review)
# ---------------------------------------------------------------------------


def test_spawn_sidecar_unlinks_stale_socket_before_spawn(home: Path, key: bytearray) -> None:
    """Stale socket inode must be unlinked before Popen — otherwise the new
    sidecar's bind races against the leftover and ``_wait_for_ready`` can
    return True on the wrong inode.
    """
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()
    socket_path.write_bytes(b"")
    assert socket_path.exists()

    captured: dict[str, object] = {}

    def _inode_checking_popen(*args: object, **kwargs: object) -> _FakeProc:
        captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
        captured["inode_exists_at_popen"] = socket_path.exists()
        return _FakeProc()

    with (
        patch(
            "worthless.cli.sidecar_lifecycle.subprocess.Popen",
            _inode_checking_popen,
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._wait_for_ready",
            return_value=True,
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._verify_socket_inode",
            return_value=None,
        ),
    ):
        spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

    assert "env" in captured
    assert captured["inode_exists_at_popen"] is False, (
        "Popen invoked with stale inode still present"
    )


def test_split_to_tmpfs_cleans_up_on_write_failure(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ``_write_share`` raises mid-sequence (e.g., disk-full on share_b),
    no half-state must survive: share_a is unlinked, run dir is removed,
    and the original exception propagates.
    """
    call_count = {"n": 0}
    real_write_share = importlib.import_module("worthless.cli.sidecar_lifecycle")._write_share

    def _flaky_write(path: Path, data: bytearray) -> None:
        call_count["n"] += 1
        if call_count["n"] == 1:
            real_write_share(path, data)
            return
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("worthless.cli.sidecar_lifecycle._write_share", _flaky_write)

    with pytest.raises(OSError, match="No space left"):
        split_to_tmpfs(key, home)

    run_dir = home / "run" / str(os.getpid())
    assert not run_dir.exists(), "run_dir not cleaned up after partial-write failure"


def test_split_to_tmpfs_zeroes_shards_when_write_fails(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-02: shard bytearrays must be zeroed before split_to_tmpfs re-raises
    on partial-write failure — disk cleanup alone leaves plaintext on the heap.
    """
    captured: list[bytearray] = []
    real_write_share = importlib.import_module("worthless.cli.sidecar_lifecycle")._write_share

    def _flaky_write(path: Path, data: bytearray) -> None:
        captured.append(data)
        if len(captured) == 1:
            real_write_share(path, data)
            return
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("worthless.cli.sidecar_lifecycle._write_share", _flaky_write)

    with pytest.raises(OSError, match="No space left"):
        split_to_tmpfs(key, home)

    assert len(captured) == 2
    for shard in captured:
        assert all(b == 0 for b in shard)


# ---------------------------------------------------------------------------
# QA #2 — spawn_sidecar must reap the child if interrupted during
# _wait_for_ready (e.g., SIGINT mid-poll, BaseException from any source)
# ---------------------------------------------------------------------------


def test_spawn_sidecar_reaps_child_on_keyboardinterrupt_during_wait(
    home: Path, key: bytearray
) -> None:
    """Regression guard for QA #2: if ``_wait_for_ready`` raises (e.g.,
    SIGINT mid-poll causes ``time.sleep`` to raise ``KeyboardInterrupt``),
    the child Popen we just created must be killed and reaped before
    propagating — otherwise the exception leaves an orphan sidecar PID
    that the caller cannot clean up (caller's ``handle is None`` branch
    only knows about share files on disk).
    """
    shares = split_to_tmpfs(key, home)
    socket_path = _short_socket_path()

    # Track kill + wait on a fake Popen.
    class _SpawnFakeProc:
        def __init__(self) -> None:
            self.pid = 33333
            self.stdout: object = None
            self.stderr: object = None
            self._exit_code: int | None = None
            self.kill_called = False
            self.wait_called = False

        def poll(self) -> int | None:
            return self._exit_code

        def kill(self) -> None:
            self.kill_called = True
            self._exit_code = -9

        def wait(self, timeout: float | None = None) -> int:
            self.wait_called = True
            return self._exit_code or 0

        def communicate(
            self, input: object = None, timeout: float | None = None
        ) -> tuple[bytes, bytes]:  # pragma: no cover
            return (b"", b"")

    fake_proc = _SpawnFakeProc()

    def _interrupt_during_wait(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt

    with (
        patch(
            "worthless.cli.sidecar_lifecycle.subprocess.Popen",
            return_value=fake_proc,
        ),
        patch(
            "worthless.cli.sidecar_lifecycle._wait_for_ready",
            side_effect=_interrupt_during_wait,
        ),
    ):
        with pytest.raises(KeyboardInterrupt):
            spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

    assert fake_proc.kill_called, (
        "spawn_sidecar leaked the child Popen on KeyboardInterrupt during wait — "
        "kill() was never called, child PID is now an orphan"
    )
    assert fake_proc.wait_called, (
        "spawn_sidecar killed the child but did not wait() to reap it — "
        "pipes are drained by background threads; wait() prevents zombie"
    )


# ---------------------------------------------------------------------------
# QA #1 (CRITICAL) — bind/listen race
#
# The sidecar uses asyncio.start_unix_server which calls bind() and listen()
# as separate syscalls. Between them, socket_path.exists() returns True but
# connect() fails with ECONNREFUSED. Pre-fix _wait_for_ready returns True at
# the bind moment — proxy's first IPC call can hit ECONNREFUSED. Fix: use a
# connect() probe so we only return True after listen() has run.
#
# This test reproduces the race deterministically by holding the bind/listen
# window open for 500ms in a worker thread, then verifying _wait_for_ready
# does NOT return until listen() actually runs.
# ---------------------------------------------------------------------------


def test_wait_for_ready_blocks_until_listen_not_just_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real-OS race repro: worker holds the bind/listen window for 500ms;
    _wait_for_ready must NOT return True until ``listen()`` actually runs.
    """
    # /tmp-rooted to dodge AF_UNIX 104-byte sun_path limit on macOS.
    with tempfile.TemporaryDirectory(prefix="wlr-", dir="/tmp") as tmp_dir_str:  # noqa: S108
        sock_path = Path(tmp_dir_str) / "race.sock"
        bind_done = threading.Event()
        listen_done = threading.Event()
        exit_signal = threading.Event()

        def fake_sidecar() -> None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.bind(str(sock_path))
                bind_done.set()
                # connect() fails with ECONNREFUSED in this window even though
                # the inode exists.
                time.sleep(0.5)
                s.listen(5)
                listen_done.set()
                exit_signal.wait(timeout=3.0)
            finally:
                try:
                    s.close()
                except OSError:
                    pass
                try:
                    sock_path.unlink()
                except OSError:
                    pass

        # Anti-flake structural check: spy on _can_connect; at least one
        # probe must return False (= we polled during the pre-listen window).
        real_can_connect = _sidecar_lifecycle._can_connect
        probe_results: list[bool] = []

        def _spying_can_connect(path: Path) -> bool:
            result = real_can_connect(path)
            probe_results.append(result)
            return result

        monkeypatch.setattr(_sidecar_lifecycle, "_can_connect", _spying_can_connect)

        thread = threading.Thread(target=fake_sidecar, daemon=True)
        thread.start()

        try:
            assert bind_done.wait(timeout=2.0)
            assert sock_path.exists()
            assert not listen_done.is_set()

            fake_proc = MagicMock()
            fake_proc.poll.return_value = None

            ready = _sidecar_lifecycle._wait_for_ready(
                fake_proc, sock_path, deadline=time.monotonic() + 10.0
            )

            assert ready is True
            assert listen_done.is_set()
            assert any(r is False for r in probe_results), (
                f"no probe observed pre-listen window (probe_results={probe_results})"
            )
            assert probe_results[-1] is True
        finally:
            exit_signal.set()
            thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# QA #3 — Stale run dir from a prior crashed session must auto-recover,
# not raise FileExistsError as an unstructured stack trace.
# ---------------------------------------------------------------------------


def test_split_to_tmpfs_recovers_from_stale_run_dir(
    home: Path, key: bytearray, caplog: pytest.LogCaptureFixture
) -> None:
    """Pre-create a stale run dir at our pid path with leftover content.
    ``split_to_tmpfs`` must clean it up and proceed — not raise.

    POSIX guarantees PID uniqueness while the holder is alive. So if
    ``~/.worthless/run/<my_pid>/`` exists when this process starts, the
    previous holder of this PID is by definition dead — the dir is stale
    and safe to remove. Pre-fix: ``split_to_tmpfs`` raised
    ``FileExistsError`` (a raw OSError). Post-fix: we log a warning and
    clean the stale dir before retrying mkdir.
    """
    import logging as _logging

    stale_run_dir = home / "run" / str(os.getpid())
    stale_run_dir.mkdir(parents=True)
    (stale_run_dir / "share_a.bin").write_bytes(b"stale-stale-stale")
    (stale_run_dir / "share_b.bin").write_bytes(b"prior-prior-prior")
    (stale_run_dir / "sidecar.sock").write_bytes(b"")

    caplog.set_level(_logging.WARNING, logger="worthless")

    shares = split_to_tmpfs(key, home)

    assert shares.share_a_path.exists()
    assert shares.share_b_path.exists()
    assert shares.share_a_path.read_bytes() != b"stale-stale-stale"
    assert shares.share_b_path.read_bytes() != b"prior-prior-prior"
    assert not (stale_run_dir / "sidecar.sock").exists()

    warning_messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("stale" in msg.lower() for msg in warning_messages), (
        f"Expected stale-recovery warning, got: {warning_messages!r}"
    )


# ---------------------------------------------------------------------------
# QA #5 — AF_UNIX sun_path 104-byte limit (macOS) must be validated BEFORE
# spawn so the user gets a clear error rather than a confusing WRTLS-114
# "sidecar did not become ready" timeout when bind() actually failed with
# ENAMETOOLONG.
# ---------------------------------------------------------------------------


def test_spawn_sidecar_falls_back_when_socket_path_too_long(
    home: Path, key: bytearray, caplog: pytest.LogCaptureFixture
) -> None:
    """``sockaddr_un.sun_path`` is 104 bytes on macOS / 108 on Linux. A
    long ``$HOME`` + ``run/<pid>/sidecar.sock`` can exceed this — common
    under pytest deep tmpdirs and dev sandboxes nested under cache dirs.

    Pre-fix: ``spawn_sidecar`` raised WRTLS-114 immediately, breaking
    ``worthless wrap`` on bare-metal Mac / CI runners with deep tmp
    paths. The user-facing symptom was "failed to start sidecar".

    Post-fix: ``spawn_sidecar`` falls back to ``$TMPDIR/wls-<hash>.sock``
    keyed by hash of the original path and logs INFO with the rewrite.
    Per-pid uniqueness is preserved because the natural path (and thus
    the hash input) already embeds the pid.
    """
    shares = split_to_tmpfs(key, home)
    oversized_dir = Path("/tmp") / ("x" * 110)  # noqa: S108
    oversized_path = oversized_dir / "sidecar.sock"
    assert len(str(oversized_path).encode()) > 104, (
        f"test bug: oversized path is only {len(str(oversized_path).encode())} bytes"
    )

    caplog.set_level("INFO", logger="worthless.cli.sidecar_lifecycle")

    # spawn_sidecar still raises WRTLS-114 ("did not become ready") in
    # this test env because there is no real proxy peer. The positive
    # pin that proves the fallback fired is the INFO log: "falling
    # back to <new path>". Asserting the rewrite happened via caplog
    # is more durable than asserting what the error message does NOT
    # contain.
    with pytest.raises(WorthlessError):
        spawn_sidecar(oversized_path, shares, allowed_uid=os.getuid())

    rewrite_log = next(
        (r for r in caplog.records if "falling back to" in r.message),
        None,
    )
    assert rewrite_log is not None, (
        "expected sidecar_lifecycle to log the AF_UNIX fallback; got: "
        + "; ".join(r.message for r in caplog.records)
    )
    # The rewritten path lands under /tmp and is short enough for AF_UNIX.
    new_path_str = rewrite_log.getMessage().rsplit(" ", 1)[-1]
    assert new_path_str.startswith("/tmp/wls-"), (  # noqa: S108 — production fallback is pinned to /tmp
        f"fallback should land under /tmp/wls-*, got: {new_path_str}"
    )
    assert len(new_path_str.encode()) < 104, (
        f"fallback path itself overflows AF_UNIX: {new_path_str}"
    )


def test_spawn_sidecar_accepts_path_within_limit(
    home: Path, key: bytearray, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boundary check: a path of exactly 100 bytes (well under 104) must
    NOT trigger the validator. We patch ``Popen`` and ``_wait_for_ready``
    so this is a pure validator test (no real subprocess).
    """
    from unittest.mock import MagicMock, patch as _patch

    shares = split_to_tmpfs(key, home)
    short_path = Path("/tmp/wlr-100/sidecar.sock")  # noqa: S108
    assert len(str(short_path).encode()) <= 100

    fake_proc = MagicMock()
    fake_proc.poll.return_value = None
    fake_proc.pid = 99999

    with (
        _patch("worthless.cli.sidecar_lifecycle.subprocess.Popen", return_value=fake_proc),
        _patch("worthless.cli.sidecar_lifecycle._wait_for_ready", return_value=True),
        _patch("worthless.cli.sidecar_lifecycle._verify_socket_inode", return_value=None),
    ):
        # Must NOT raise — path is well within the limit.
        handle = spawn_sidecar(short_path, shares, allowed_uid=os.getuid())
        assert handle.socket_path == short_path

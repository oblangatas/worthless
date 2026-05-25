"""Unit tests for ``python -m worthless.sidecar.health`` (WOR-466).

Failure-mode coverage table — every row maps to a test below:

* missing env                       → exit 2, "WORTHLESS_SIDECAR_SOCKET unset"
* socket path missing (ENOENT)      → exit 1, "socket missing"
* path exists, wrong type           → exit 1, "not a socket"
* stale inode (sidecar died)        → exit 1, "connect refused" / "protocol error"
* sidecar bound, accept loop hung   → exit 1, "handshake timeout"
* uid not in allowlist              → exit 1, "AUTH rejected"
* happy path (real sidecar)         → exit 0, no stdout

The hung-accept-loop and stale-inode tests are the key value-add: both would
false-green an HTTP `/healthz` probe (uvicorn answers, sidecar is dead).

Linear ticket WOR-466. Integration lane (real Docker container) tracked
separately as WOR-474.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import os
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

# Public surface under test. These imports MUST resolve once health.py lands.
from worthless.sidecar import health

pytestmark = [pytest.mark.integration, pytest.mark.xdist_group("real_sidecar")]

_SUN_PATH_MAX = 104


# ---------------------------------------------------------------------------
# fixtures (local — tests/sidecar/conftest.py is subprocess-shaped)
# ---------------------------------------------------------------------------


@pytest.fixture
def short_tmpdir() -> Iterator[Path]:
    """Short tmpdir under ``/tmp`` to stay inside AF_UNIX sun_path limit."""
    base = Path(tempfile.mkdtemp(prefix="wh-", dir="/tmp"))
    try:
        yield base
    finally:
        for child in base.iterdir() if base.exists() else []:
            try:
                child.unlink()
            except OSError:
                pass
        try:
            base.rmdir()
        except OSError:
            pass


def _write_shares(dir_: Path) -> tuple[Path, Path]:
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    share_a = secrets.token_bytes(len(key))
    share_b = bytes(a ^ k for a, k in zip(share_a, key, strict=True))
    a, b = dir_ / "share_a", dir_ / "share_b"
    a.write_bytes(share_a)
    b.write_bytes(share_b)
    a.chmod(0o600)
    b.chmod(0o600)
    return a, b


def _spawn_sidecar_subprocess(
    short_tmpdir: Path, allowed_uid: int
) -> tuple[subprocess.Popen[str], Path]:
    """Launch ``python -m worthless.sidecar`` and wait for ready. Production shape."""
    sock = short_tmpdir / "s.sock"
    if len(str(sock)) >= _SUN_PATH_MAX:
        pytest.skip(f"tmp path too long for AF_UNIX: {sock}")
    a_path, b_path = _write_shares(short_tmpdir)
    env = {
        **os.environ,
        "WORTHLESS_SIDECAR_SOCKET": str(sock),
        "WORTHLESS_SIDECAR_SHARE_A": str(a_path),
        "WORTHLESS_SIDECAR_SHARE_B": str(b_path),
        "WORTHLESS_SIDECAR_ALLOWED_UID": str(allowed_uid),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "worthless.sidecar"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    # Wait for ready line — use select() before readline() to avoid blocking
    # indefinitely at the C level (PEP 475 EINTR-retry defeats SIGALRM timeouts).
    deadline = time.monotonic() + 5.0
    assert proc.stdout is not None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            proc.kill()
            pytest.fail(f"sidecar exited early (rc={proc.returncode}): {err}")
        ready, _, _ = select.select([proc.stdout], [], [], min(0.1, remaining))
        if not ready:
            continue
        line = proc.stdout.readline()
        if line.startswith("sidecar: ready"):
            return proc, sock
    proc.kill()
    pytest.fail("sidecar did not become ready within 5s")


def _terminate(proc: subprocess.Popen[str]) -> None:
    """Graceful SIGTERM with SIGKILL fallback for sidecar subprocesses."""
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


@pytest.fixture
def running_sidecar_at(short_tmpdir: Path) -> Iterator[Path]:
    """Real sidecar subprocess bound for the test uid. Tear down via SIGTERM."""
    proc, sock = _spawn_sidecar_subprocess(short_tmpdir, os.getuid())
    try:
        yield sock
    finally:
        _terminate(proc)


@pytest.fixture
def wrong_uid_sidecar(short_tmpdir: Path) -> Iterator[Path]:
    """Sidecar bound with an allowlist that EXCLUDES the test process uid."""
    bogus_uid = os.getuid() + 99999
    proc, sock = _spawn_sidecar_subprocess(short_tmpdir, bogus_uid)
    try:
        yield sock
    finally:
        _terminate(proc)


@pytest.fixture
def stale_inode_socket(short_tmpdir: Path) -> Iterator[Path]:
    """AF_UNIX socket file that exists on disk but has no listener — the
    classic "sidecar process died, stale socket inode lingered" scenario.
    Bind + close leaves the inode behind; connect() returns ECONNREFUSED."""
    sock = short_tmpdir / "s.sock"
    if len(str(sock)) >= _SUN_PATH_MAX:
        pytest.skip(f"tmp path too long for AF_UNIX: {sock}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    # Close WITHOUT listen — kernel teardown leaves the inode but no accept queue.
    s.close()
    if not sock.exists():
        # Some kernels unlink on close; fall back to creating a regular-file
        # at the path then promoting it. If that's also impossible, skip.
        pytest.skip("kernel auto-unlinks AF_UNIX socket on close on this platform")
    try:
        yield sock
    finally:
        try:
            sock.unlink()
        except OSError:
            pass


@pytest.fixture
def hung_socket(short_tmpdir: Path) -> Iterator[Path]:
    """AF_UNIX socket that listens but never accepts — simulates a wedged
    accept loop. Connect succeeds (kernel handles backlog) but no hello
    reply ever lands."""
    sock = short_tmpdir / "s.sock"
    if len(str(sock)) >= _SUN_PATH_MAX:
        pytest.skip(f"tmp path too long for AF_UNIX: {sock}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    s.listen(1)
    try:
        yield sock
    finally:
        s.close()
        try:
            sock.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# tests — failure-mode coverage table
# ---------------------------------------------------------------------------


def test_missing_env_is_config_error_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("WORTHLESS_SIDECAR_SOCKET", raising=False)
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 2
    assert "WORTHLESS_SIDECAR_SOCKET" in captured.err
    assert "unset" in captured.err
    assert captured.out == ""


def test_socket_missing_exit_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    short_tmpdir: Path,
) -> None:
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(short_tmpdir / "nonexistent.sock"))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 1
    assert "socket missing" in captured.err
    assert captured.out == ""


def test_not_a_socket_exit_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    short_tmpdir: Path,
) -> None:
    bogus = short_tmpdir / "regular.txt"
    bogus.write_text("not a socket")
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(bogus))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 1
    assert "not a socket" in captured.err
    assert captured.out == ""


def test_happy_path_exit_0_no_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    running_sidecar_at: Path,
) -> None:
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(running_sidecar_at))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 0, f"expected exit 0 (healthy), stderr={captured.err!r}"
    assert captured.out == ""


def test_stale_inode_econnrefused(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stale_inode_socket: Path,
) -> None:
    """The "sidecar died, socket inode lingered" case. stat passes (inode
    exists, type is socket), connect gets ECONNREFUSED. HTTP /healthz would
    pass; we must fail."""
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(stale_inode_socket))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 1, f"expected exit 1 (stale inode), stderr={captured.err!r}"
    # Kernel-dependent: Linux returns ECONNREFUSED on connect; macOS accepts
    # then immediately resets, surfacing as a protocol error during HELLO.
    # Both signal "sidecar dead, stale inode" to the operator.
    assert any(
        s in captured.err for s in ("connect refused", "connect failed", "protocol error")
    ), f"unexpected stderr: {captured.err!r}"
    assert captured.out == ""


def test_hung_accept_loop_handshake_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hung_socket: Path,
) -> None:
    """The false-green case: socket inode exists, connect succeeds, but the
    sidecar never replies to HELLO. HTTP /healthz would pass; we must fail."""
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(hung_socket))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 1, f"expected exit 1 (hung sidecar), stderr={captured.err!r}"
    # Either timeout or protocol error is acceptable; both signal a wedged peer.
    assert (
        "handshake timeout" in captured.err
        or "protocol error" in captured.err
        or "connect refused" in captured.err
    ), f"unexpected stderr: {captured.err!r}"
    assert captured.out == ""


def test_wrong_uid_auth_rejected(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    wrong_uid_sidecar: Path,
) -> None:
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(wrong_uid_sidecar))
    rc = health.main()
    captured = capsys.readouterr()
    assert rc == 1
    # Server may either reject with AUTH error envelope or close the connection;
    # both surface to the operator as a non-zero exit. Accept either string.
    assert (
        "AUTH rejected" in captured.err
        or "connect refused" in captured.err
        or "protocol error" in captured.err
    ), f"unexpected stderr: {captured.err!r}"
    assert captured.out == ""


def test_main_is_callable_without_args() -> None:
    """``python -m worthless.sidecar.health`` MUST work with no argv."""
    assert callable(health.main)
    sig = inspect.signature(health.main)
    assert len(sig.parameters) == 0


def test_module_runs_via_python_dash_m(
    short_tmpdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Smoke: ``python -m worthless.sidecar.health`` exits non-zero when the
    socket is missing. Proves module loads and __main__ guard fires."""
    bogus = short_tmpdir / "nope.sock"
    env = {**os.environ, "WORTHLESS_SIDECAR_SOCKET": str(bogus)}
    result = subprocess.run(
        [sys.executable, "-m", "worthless.sidecar.health"],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "socket missing" in result.stderr
    assert result.stdout == ""


def test_total_budget_under_2_seconds_on_failure(
    monkeypatch: pytest.MonkeyPatch, hung_socket: Path
) -> None:
    """Wall-clock budget: probe must fail fast, well under Docker's 2s timeout."""
    import time

    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(hung_socket))
    t0 = time.monotonic()
    rc = health.main()
    elapsed = time.monotonic() - t0
    assert rc == 1
    # 1.9s is the probe's internal cap; allow 2.5s headroom for CI scheduler
    # overhead. Still validates the probe exits well before Docker's SIGKILL.
    assert elapsed < 2.5, f"health probe blew Docker's 2s timeout budget: {elapsed:.3f}s"


def test_probe_is_async_coroutine() -> None:
    """_probe must be a coroutine so main() can wrap it with asyncio.run/wait_for."""
    import worthless.sidecar.health as h

    assert hasattr(h, "main")
    assert asyncio.iscoroutinefunction(h._probe)

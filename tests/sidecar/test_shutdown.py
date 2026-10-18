"""Sidecar startup / shutdown hardening tests (WOR-308 slices 1-2).

Mix of two test styles:

* **Subprocess** (slice 1) — spawn the real ``python -m worthless.sidecar``
  to exercise the full env-config → bind → signal-shutdown path. Catches
  bugs that only surface across the process boundary (stale sockets,
  rc codes, stderr messages).
* **In-process** (slice 2) — call ``start_sidecar`` directly and drive
  it with a tracked ``asyncio.Event`` standing in for ``SIGTERM``.
  Lets us assert drain-deadline behavior without flaky signal-timing
  gymnastics. Signal wiring itself is already covered by slice 1.

See ``engineering/ipc-contract.md`` for the env contract and exit codes.
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from worthless.ipc.client import IPCClient
from worthless.sidecar import __main__ as sidecar_main
from worthless.sidecar.__main__ import _drain_server
from worthless.sidecar.backends.base import Backend
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

pytestmark = [pytest.mark.integration, pytest.mark.xdist_group("real_sidecar")]

_SUN_PATH_MAX = 104
_READY_TIMEOUT_S = 5.0


def _spawn_sidecar(env: dict[str, str]) -> subprocess.Popen[str]:
    """Launch ``python -m worthless.sidecar`` with line-buffered text IO."""
    return subprocess.Popen(
        [sys.executable, "-m", "worthless.sidecar"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def _wait_for_ready(proc: subprocess.Popen[str], timeout: float = _READY_TIMEOUT_S) -> str:
    """Block until the sidecar prints its ``sidecar: ready …`` line or dies.

    Uses ``select.select`` before each ``readline()`` call so the loop honours
    its timeout even when the child stalls before writing to stdout.

    A plain ``readline()`` blocks at the C-library level; Python 3's PEP 475
    EINTR-retry means a SIGALRM-based timeout (pytest-timeout signal mode)
    does not reliably interrupt it.  Under xdist this caused workers to hang
    for up to 30 s × (tests + reruns) per module, exceeding the 20-minute CI
    job budget.  ``select`` with a short poll interval is interruptible and
    keeps the effective timeout at ``_READY_TIMEOUT_S``.

    Returns the ready line on success. On timeout or early exit, kills the
    process and fails the test with the captured stderr so the failure mode
    is legible.
    """
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            err = proc.stderr.read() if proc.stderr else ""
            pytest.fail(
                f"sidecar exited before ready (rc={proc.returncode})\n"
                f"stdout:\n{out}\nstderr:\n{err}"
            )
        ready, _, _ = select.select([proc.stdout], [], [], min(0.1, remaining))
        if not ready:
            continue
        line = proc.stdout.readline()
        if line.startswith("sidecar: ready"):
            return line
    proc.kill()
    proc.wait(timeout=2)
    pytest.fail(f"sidecar did not print ready line within {timeout}s")


def _terminate(proc: subprocess.Popen[str]) -> tuple[int, str, str]:
    """SIGTERM the process, wait, return (rc, stdout, stderr)."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=2)
    return proc.returncode, out, err


# ---------------------------------------------------------------------------
# Unit tests for _wait_for_ready (WOR-582 select() fix)
#
# These tests exercise the helper in isolation using tiny synthetic
# subprocesses.  They prove the select()-based timeout actually fires —
# without them the only evidence is "CI didn't get killed this time."
# ---------------------------------------------------------------------------


def test_wait_for_ready_times_out_on_silent_process() -> None:
    """Timeout fires within ≤ timeout + 0.5 s on a process that never writes.

    Before the WOR-582 fix, readline() blocked at the C level and this
    test would hang for the full pytest-timeout budget (30 s) before the
    signal timeout fired.  With select(), the loop exits within ~timeout s.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    t0 = time.monotonic()
    with pytest.raises((pytest.fail.Exception, SystemExit), match="did not print ready"):
        _wait_for_ready(proc, timeout=0.5)
    elapsed = time.monotonic() - t0
    # select() polls every 0.1 s; allow generous headroom for slow CI runners.
    assert elapsed < 2.0, (
        f"_wait_for_ready hung for {elapsed:.2f}s — select() timeout is not firing.\n"
        "This indicates the WOR-582 regression: readline() is blocking at the C level."
    )


def test_wait_for_ready_succeeds_after_delayed_ready_line() -> None:
    """Helper returns the ready line when the process writes it after a delay.

    Validates the polling loop does not exit early on the first select()
    timeout interval — it must keep polling until the line arrives.
    """
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import time, sys; "
                "time.sleep(0.25); "
                "print('sidecar: ready sock=/tmp/x uid=0', flush=True); "
                "time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        # Generous timeout: the helper returns the instant the line appears, so
        # a large bound never slows the happy path. It only guards against a
        # fresh Python subprocess starting slowly under full-suite CPU
        # saturation (-n auto) — a 5s clock false-failed there. Stays under the
        # 30s pytest-timeout and the child's 30s post-print sleep.
        line = _wait_for_ready(proc, timeout=25.0)
        assert line.startswith("sidecar: ready"), f"unexpected line: {line!r}"
    finally:
        proc.kill()
        proc.wait(timeout=2)


def test_wait_for_ready_fails_on_early_process_exit() -> None:
    """Helper reports the exit code and stderr when the process dies early.

    Verifies the ``proc.poll()`` branch — the helper must not hang waiting
    for output that will never arrive after the process exits.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stderr.write('boom\\n'); sys.exit(2)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    with pytest.raises((pytest.fail.Exception, SystemExit), match="exited before ready"):
        _wait_for_ready(proc, timeout=5.0)


def test_startup_removes_stale_socket_file_after_sigkill(
    sidecar_env: tuple[Path, dict[str, str]],
) -> None:
    """A sidecar killed mid-flight leaves a socket inode; the next start recovers.

    Scenario: operator restarts the container, but the prior process died from
    SIGKILL (OOM, docker stop --signal=KILL, kernel panic). The socket inode
    remains on the volume. A fresh bind would fail with EADDRINUSE. The
    hardened startup path probes the socket; since no server is listening
    (connect → ECONNREFUSED), it unlinks and rebinds.
    """
    sock, env = sidecar_env

    first = _spawn_sidecar(env)
    try:
        _wait_for_ready(first)
        assert sock.exists(), "socket inode should exist after ready line"
        first.send_signal(signal.SIGKILL)
        first.wait(timeout=5)
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=2)

    assert sock.exists(), "SIGKILL must leave stale socket inode (preconditions)"

    second = _spawn_sidecar(env)
    try:
        _wait_for_ready(second)
        assert sock.exists()
        rc, out, err = _terminate(second)
        assert rc == 0, f"second sidecar should shut down cleanly.\nstdout:{out}\nstderr:{err}"
    finally:
        if second.poll() is None:
            second.kill()
            second.wait(timeout=2)


def test_startup_refuses_bind_when_live_sidecar_present(
    sidecar_env: tuple[Path, dict[str, str]],
) -> None:
    """Two simultaneous sidecars on the same socket: the second must fail fast.

    Contract: exit code ``2`` (bind failure) and a human-readable
    ``already running`` hint on stderr so supervisors can disambiguate a
    genuine port-clash from a config error.
    """
    sock, env = sidecar_env

    first = _spawn_sidecar(env)
    try:
        _wait_for_ready(first)
        second = _spawn_sidecar(env)
        try:
            rc = second.wait(timeout=5)
            out = second.stdout.read() if second.stdout else ""
            err = second.stderr.read() if second.stderr else ""
        finally:
            if second.poll() is None:
                second.kill()
                second.wait(timeout=2)

        assert rc == 2, f"expected rc=2 for duplicate bind, got {rc}\nstdout:{out}\nstderr:{err}"
        assert "already running" in err.lower(), (
            f"stderr should mention 'already running'.\nstderr:{err}"
        )
    finally:
        if first.poll() is None:
            first.send_signal(signal.SIGTERM)
            try:
                first.wait(timeout=5)
            except subprocess.TimeoutExpired:
                first.kill()
                first.wait(timeout=2)


# ---------------------------------------------------------------------------
# Slice 2 — drain deadline (in-process tests)
# ---------------------------------------------------------------------------


def _make_fernet_backend() -> FernetBackend:
    """Build a real FernetBackend with a fresh random key."""
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    a = secrets.token_bytes(len(key))
    b = bytes(x ^ k for x, k in zip(a, key, strict=True))
    return FernetBackend(shares=(a, b))


class _DelegatingBackend(Backend):
    """Forwards every Backend method to ``self._inner``.

    Subclasses override only the method they want to perturb (slow seal,
    stalling seal) instead of re-implementing the open/attest pass-throughs.
    """

    caps = ("seal", "open", "attest")

    def __init__(self, inner: FernetBackend) -> None:
        self._inner = inner

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        return await self._inner.seal(plaintext, context)

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        return await self._inner.open(ciphertext, context, key_id)

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        return await self._inner.attest(nonce, purpose)


class _SlowSealBackend(_DelegatingBackend):
    """Sleeps ``delay`` seconds before each seal."""

    def __init__(self, inner: FernetBackend, delay: float) -> None:
        super().__init__(inner)
        self._delay = delay

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        await asyncio.sleep(self._delay)
        return await self._inner.seal(plaintext, context)


class _StallingSealBackend(_DelegatingBackend):
    """Hangs forever on ``seal`` — simulates a stuck handler for drain tests."""

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        await asyncio.sleep(3600)
        return b""  # unreachable


@pytest_asyncio.fixture
async def in_process_sock() -> AsyncIterator[Path]:
    """Short-path AF_UNIX socket for in-process server tests (no subprocess)."""
    base = Path(tempfile.mkdtemp(prefix="w-", dir="/tmp"))
    sock = base / "s.sock"
    if len(str(sock)) >= _SUN_PATH_MAX:
        pytest.skip(f"tmp path too long for AF_UNIX: {sock}")
    try:
        yield sock
    finally:
        try:
            if sock.exists():
                sock.unlink()
            base.rmdir()
        except OSError:
            pass


async def test_drain_completes_inflight_request_before_timeout(
    in_process_sock: Path,
) -> None:
    """A normal in-flight request should finish before drain forces cancellation.

    Models the SIGTERM-during-real-traffic case: operator stops the
    sidecar while a 200 ms seal is on the wire. The response must
    arrive intact; the drain reaper must not chop it.
    """
    backend = _SlowSealBackend(_make_fernet_backend(), delay=0.2)
    server = await start_sidecar(
        socket_path=in_process_sock,
        backend=backend,
        allowed_uids=[os.getuid()],
    )
    stop = asyncio.Event()
    drain = asyncio.create_task(_drain_server(server, stop, drain_timeout=2.0))
    try:
        async with IPCClient(in_process_sock) as client:
            seal_task = asyncio.create_task(client.seal(b"hello"))
            await asyncio.sleep(0.05)  # let the request reach the server
            stop.set()
            ct = await asyncio.wait_for(seal_task, timeout=1.5)
            assert ct, "expected ciphertext from drained-but-completed seal"
        await asyncio.wait_for(drain, timeout=2.0)
    finally:
        if not drain.done():
            drain.cancel()
            try:
                await drain
            except (asyncio.CancelledError, Exception):
                pass


async def test_drain_cancels_stalled_handler_after_timeout(
    in_process_sock: Path,
) -> None:
    """A handler that never returns must be cancelled when drain expires.

    Without this, ``await server.wait_closed()`` would block forever and
    the sidecar would hang the whole container on shutdown. The drain
    reaper must cancel tracked handler tasks once the deadline trips and
    return control within ``drain_timeout + 1 s``.
    """
    backend = _StallingSealBackend(_make_fernet_backend())
    server = await start_sidecar(
        socket_path=in_process_sock,
        backend=backend,
        allowed_uids=[os.getuid()],
    )
    stop = asyncio.Event()
    drain_timeout = 0.3
    drain = asyncio.create_task(_drain_server(server, stop, drain_timeout=drain_timeout))
    try:
        async with IPCClient(in_process_sock) as client:
            seal_task = asyncio.create_task(client.seal(b"x"))
            await asyncio.sleep(0.05)
            t0 = asyncio.get_event_loop().time()
            stop.set()
            await asyncio.wait_for(drain, timeout=drain_timeout + 2.0)
            elapsed = asyncio.get_event_loop().time() - t0
            assert drain_timeout <= elapsed < drain_timeout + 1.5, (
                f"drain elapsed {elapsed:.3f}s, want >= {drain_timeout}s and "
                f"< {drain_timeout + 1.5}s"
            )
            # Forcibly cancelled handler closes the socket; client sees error.
            with pytest.raises(Exception):  # noqa: B017,PT011 - any failure mode acceptable
                await asyncio.wait_for(seal_task, timeout=0.5)
    finally:
        if not drain.done():
            drain.cancel()
            try:
                await drain
            except (asyncio.CancelledError, Exception):
                pass


# ---------------------------------------------------------------------------
# Parent-death watch (worthless-dhfn): kill -9 on ``worthless up`` must not
# leave an orphaned sidecar holding both key shares on disk.
# ---------------------------------------------------------------------------

# A stand-in for ``worthless up``: spawns the sidecar with its own pid as
# WORTHLESS_SIDECAR_PARENT_PID, prints the sidecar pid, then idles until killed.
_FAKE_SUPERVISOR = """
import os, subprocess, sys, time
env = dict(os.environ, WORTHLESS_SIDECAR_PARENT_PID=str(os.getpid()))
p = subprocess.Popen([sys.executable, "-m", "worthless.sidecar"], env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(p.pid, flush=True)
time.sleep(60)
"""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_until(pred, timeout: float) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


def test_sidecar_exits_and_removes_shares_when_parent_is_killed(
    sidecar_env: tuple[Path, dict[str, str]],
) -> None:
    sock, env = sidecar_env
    base = sock.parent
    sup = subprocess.Popen(
        [sys.executable, "-c", _FAKE_SUPERVISOR], env=env, stdout=subprocess.PIPE, text=True
    )
    sidecar_pid = 0
    idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert sup.stdout is not None
        sidecar_pid = int(sup.stdout.readline())
        assert _wait_until(sock.exists, _READY_TIMEOUT_S), "sidecar never bound its socket"
        # An idle connection, like the still-running proxy's, holds the drain
        # open for the full 5s drain timeout; the shares must go before that.
        idle.connect(str(sock))

        sup.kill()
        sup.wait(timeout=5)

        assert _wait_until(lambda: not base.exists(), 2.0), (
            f"orphaned sidecar left key material behind: {sorted(base.iterdir())}"
        )
        # Reparented, so not our child: poll with kill(0) instead of wait().
        assert _wait_until(lambda: not _pid_alive(sidecar_pid), 10.0)
    finally:
        idle.close()
        if sup.poll() is None:
            sup.kill()
            sup.wait(timeout=2)
        if sidecar_pid and _pid_alive(sidecar_pid):
            os.kill(sidecar_pid, signal.SIGKILL)


def test_sidecar_keeps_serving_while_parent_is_alive(
    sidecar_env: tuple[Path, dict[str, str]],
) -> None:
    sock, env = sidecar_env
    proc = _spawn_sidecar({**env, "WORTHLESS_SIDECAR_PARENT_PID": str(os.getpid())})
    try:
        _wait_for_ready(proc)
        time.sleep(2.0)  # four watcher polls
        assert proc.poll() is None, "sidecar quit although its parent is alive"
        assert sock.exists()
    finally:
        _terminate(proc)


def test_sidecar_refuses_to_start_when_parent_already_gone(
    sidecar_env: tuple[Path, dict[str, str]],
) -> None:
    """Parent died during spawn: the sidecar must not bind, and must wipe the shares."""
    sock, env = sidecar_env
    proc = _spawn_sidecar({**env, "WORTHLESS_SIDECAR_PARENT_PID": str(os.getpid() + 999_999)})
    rc, out, err = _terminate_after_exit(proc)
    assert rc == 0, f"rc={rc}\nstdout:{out}\nstderr:{err}"
    assert "sidecar: ready" not in out
    assert not sock.parent.exists(), sorted(sock.parent.iterdir())


def _terminate_after_exit(proc: subprocess.Popen[str]) -> tuple[int, str, str]:
    try:
        out, err = proc.communicate(timeout=_READY_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=2)
        pytest.fail(f"sidecar did not exit after detecting a dead parent\nstderr:{err}")
    return proc.returncode, out, err


async def test_watch_parent_sets_stop_when_ppid_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sidecar_main.os, "getppid", lambda: 1)
    stop = asyncio.Event()
    orphaned = await asyncio.wait_for(
        sidecar_main._watch_parent(4242, stop, interval=0.01), timeout=1.0
    )
    assert orphaned is True
    assert stop.is_set()


async def test_watch_parent_returns_quietly_on_normal_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sidecar_main.os, "getppid", lambda: 4242)
    stop = asyncio.Event()
    task = asyncio.create_task(sidecar_main._watch_parent(4242, stop, interval=0.01))
    await asyncio.sleep(0.05)
    assert not task.done(), "watcher fired although the parent is unchanged"
    stop.set()
    assert await asyncio.wait_for(task, timeout=1.0) is False


# In-process twins of the subprocess tests above, so coverage sees _run.


def _use_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str], parent: str) -> None:
    for k, v in env.items():
        if k.startswith("WORTHLESS_SIDECAR_"):
            monkeypatch.setenv(k, v)
    monkeypatch.setenv("WORTHLESS_SIDECAR_PARENT_PID", parent)


async def test_run_rejects_non_numeric_parent_pid(
    sidecar_env: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    sock, env = sidecar_env
    _use_env(monkeypatch, env, "not-a-pid")
    assert await sidecar_main._run() == 1
    assert any(sock.parent.iterdir()), "a config error must not wipe the shares"


async def test_run_wipes_without_binding_when_parent_already_gone(
    sidecar_env: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    sock, env = sidecar_env
    _use_env(monkeypatch, env, str(os.getppid() + 999_999))
    assert await sidecar_main._run() == 0
    assert not sock.parent.exists()


async def test_run_wipes_and_exits_when_parent_dies_while_serving(
    sidecar_env: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    sock, env = sidecar_env
    real_ppid = os.getppid()
    _use_env(monkeypatch, env, str(real_ppid))
    monkeypatch.setattr(sidecar_main, "_PARENT_POLL_S", 0.01)
    monkeypatch.setattr(sidecar_main, "_DEFAULT_DRAIN_TIMEOUT_S", 0.1)
    monkeypatch.delenv("WORTHLESS_SIDECAR_DRAIN_TIMEOUT", raising=False)
    run = asyncio.create_task(sidecar_main._run())
    try:
        for _ in range(200):
            if sock.exists():
                break
            await asyncio.sleep(0.01)
        assert sock.exists(), "in-process sidecar never bound"
        monkeypatch.setattr(sidecar_main.os, "getppid", lambda: real_ppid + 1)
        assert await asyncio.wait_for(run, timeout=5.0) == 0
        assert not sock.parent.exists()
    finally:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        if not run.done():
            run.cancel()


def test_remove_key_material_keeps_a_dir_that_holds_other_files(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    a, b, s = run_dir / "a", run_dir / "b", run_dir / "s.sock"
    for p in (a, b, s):
        p.write_bytes(b"x")
    (run_dir / "unrelated").write_text("keep")
    sidecar_main._remove_key_material(a, b, s)
    assert sorted(p.name for p in run_dir.iterdir()) == ["unrelated"]


async def test_run_wipes_when_parent_dies_after_a_signal_won_the_race(
    sidecar_env: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl+C / shutdown_sidecar sets stop first, then the supervisor dies mid-drain.

    The watcher returns on stop without seeing the dead parent; nobody else
    is left to unlink the shares (PR 713 review, Cursor Bugbot).
    """
    sock, env = sidecar_env
    real_ppid = os.getppid()
    _use_env(monkeypatch, env, str(real_ppid))
    monkeypatch.setattr(sidecar_main, "_PARENT_POLL_S", 60.0)  # watcher never re-polls
    run = asyncio.create_task(sidecar_main._run())
    try:
        for _ in range(200):
            if sock.exists():
                break
            await asyncio.sleep(0.01)
        assert sock.exists(), "in-process sidecar never bound"
        monkeypatch.setattr(sidecar_main.os, "getppid", lambda: real_ppid + 1)
        os.kill(os.getpid(), signal.SIGTERM)  # caught by _run's loop handler
        assert await asyncio.wait_for(run, timeout=10.0) == 0
        assert not sock.parent.exists(), sorted(sock.parent.iterdir())
    finally:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        if not run.done():
            run.cancel()

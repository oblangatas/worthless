"""End-to-end checks that a second ``worthless up`` detects the first daemon.

The daemon writes the listening process's self-reported PID to the PID file,
so a second invocation reads a live PID and refuses with "already running".
Previously the CLI wrote whatever ``subprocess.Popen(...).pid`` returned,
which could drift from the real uvicorn process and cause duplicate proxies
to spawn on the same port (and orphan uvicorn on ``worthless down``).

These tests spawn real subprocesses to lock that behavior end-to-end. The
unit-level coverage of the polling helper lives in ``test_health_polling.py``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import psutil
import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.process import check_pid, pid_path, poll_health, read_pid

from tests._fakes import WOR309_SUBPROCESS_FOLLOWUP

pytestmark = [
    pytest.mark.integration,
    pytest.mark.real_ipc,
    pytest.mark.timeout(30),
    pytest.mark.skip(reason=WOR309_SUBPROCESS_FOLLOWUP),
]


def _ephemeral_port() -> int:
    """Reserve a port by letting the kernel pick a free one, then release it.

    The older ``18900 + os.getpid() % 100`` pattern collides with orphaned
    daemons from prior runs (different PID, same `% 100`) — the new daemon
    gets EADDRINUSE or, worse, the test reads the orphan's ``/healthz`` and
    sees a stale PID. Binding-then-closing on port 0 asks the kernel for a
    unique ephemeral port; the short TIME_WAIT window before we re-bind is
    acceptable for these tests (we're the only thing racing for it).
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _assert_port_unused(port: int) -> None:
    """Fail loudly if something is already bound to *port*.

    A previous-run orphan on the same port would silently answer `/healthz`
    and poison assertions that compare pidfile vs self-reported PID. Catch
    it at spawn time rather than letting the test fail 30 seconds later
    with a confusing PID mismatch.
    """
    try:
        resp = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.3)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return
    raise AssertionError(
        f"port {port} is already in use (healthz responded {resp.status_code}) — "
        "kill leftover processes before running these tests"
    )


def _kill_pidfile(pf: Path) -> None:
    """Best-effort cleanup: signal the process tree, unlink the pid file."""
    if not pf.exists():
        return
    info = read_pid(pf)
    if info is not None:
        pid = info[0]
        # Kill the recorded PID and its descendants via psutil — the same
        # pattern production uses in `platform.kill_tree`. Avoid
        # ``os.killpg(os.getpgid(pid), ...)`` here: the pidfile PID can be
        # stale, and on Unix a recycled PID can share a process group with
        # unrelated workloads. A tree-kill scoped to the recorded root is
        # both sufficient for test cleanup and safe against recycling.
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc = None
        if proc is not None:
            for child in reversed(proc.children(recursive=True)):
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    pf.unlink(missing_ok=True)


@pytest.fixture()
def cli_env(tmp_path: Path) -> dict[str, str]:
    """Isolated WORTHLESS_HOME env for subprocess invocations."""
    home = ensure_home(tmp_path / ".worthless")
    return {
        **os.environ,
        "WORTHLESS_HOME": str(home.base_dir),
    }


@pytest.fixture()
def cli_home(cli_env: dict[str, str]) -> Path:
    return Path(cli_env["WORTHLESS_HOME"])


@pytest.fixture()
def worthless_bin() -> str:
    found = shutil.which("worthless")
    if found is None:
        pytest.skip("worthless CLI not found on PATH")
    return found


class TestDuplicateProxyDetection:
    """WOR-228 — second `worthless up` must detect the first and refuse."""

    def test_second_up_rejected_when_first_alive(
        self,
        worthless_bin: str,
        cli_env: dict[str, str],
        cli_home: Path,
    ) -> None:
        port = _ephemeral_port()
        _assert_port_unused(port)
        first = subprocess.run(
            [worthless_bin, "up", "--daemon", "--port", str(port)],
            env=cli_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        pf = pid_path(ensure_home(cli_home))
        try:
            if first.returncode != 0:
                # The binary is on PATH (checked in fixture) — if it can't
                # start a daemon here, that's a real regression, not an env
                # issue. Fail loudly rather than mask it as a skip.
                pytest.fail(f"first daemon failed to start: {first.stderr}")
            # Close the race: don't fire the second `up` until the proxy
            # actually binds the port. subprocess.run returning is not
            # sufficient — the parent may detach before uvicorn is ready.
            assert poll_health(port, timeout=10.0), "first daemon never became healthy"

            second = subprocess.run(
                [worthless_bin, "up", "--daemon", "--port", str(port)],
                env=cli_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert second.returncode != 0, (
                f"second up should fail — got {second.returncode}\n"
                f"stdout: {second.stdout}\nstderr: {second.stderr}"
            )
            combined = (second.stdout + second.stderr).lower()
            assert "already running" in combined, (
                f"expected 'already running' message, got:\n{combined}"
            )
        finally:
            _kill_pidfile(pf)

    def test_second_up_clean_after_crash(
        self,
        worthless_bin: str,
        cli_env: dict[str, str],
        cli_home: Path,
    ) -> None:
        """After the proxy crashes the next `up` must start cleanly."""
        port = _ephemeral_port()
        _assert_port_unused(port)
        first = subprocess.run(
            [worthless_bin, "up", "--daemon", "--port", str(port)],
            env=cli_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        pf = pid_path(ensure_home(cli_home))
        try:
            if first.returncode != 0:
                # The binary is on PATH (checked in fixture) — if it can't
                # start a daemon here, that's a real regression, not an env
                # issue. Fail loudly rather than mask it as a skip.
                pytest.fail(f"first daemon failed to start: {first.stderr}")
            assert poll_health(port, timeout=10.0)
            info = read_pid(pf)
            assert info is not None
            first_pid = info[0]

            # Kill the real listening process — simulating an unclean crash.
            try:
                psutil.Process(first_pid).kill()
            except psutil.NoSuchProcess:
                pytest.skip("daemon vanished before we could kill it")
            deadline = time.monotonic() + 5.0
            while check_pid(first_pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            assert not check_pid(first_pid), "crashed process still alive"

            second = subprocess.run(
                [worthless_bin, "up", "--daemon", "--port", str(port)],
                env=cli_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert second.returncode == 0, (
                f"second up should succeed after crash — got {second.returncode}\n"
                f"stdout: {second.stdout}\nstderr: {second.stderr}"
            )
            assert poll_health(port, timeout=10.0)
            info_after = read_pid(pf)
            assert info_after is not None
            assert info_after[0] != first_pid, "new daemon reused crashed PID"
        finally:
            _kill_pidfile(pf)

    def test_pidfile_contains_listening_process(
        self,
        worthless_bin: str,
        cli_env: dict[str, str],
        cli_home: Path,
    ) -> None:
        """The PID in the file must belong to a process actually bound to the port.

        Directly pins the fix: writing `proc.pid` (the wrapper/shim) could record
        a PID that does not own the listening socket. Writing the self-reported
        PID guarantees this invariant.
        """
        port = _ephemeral_port()
        _assert_port_unused(port)
        first = subprocess.run(
            [worthless_bin, "up", "--daemon", "--port", str(port)],
            env=cli_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        pf = pid_path(ensure_home(cli_home))
        try:
            if first.returncode != 0:
                # The binary is on PATH (checked in fixture) — if it can't
                # start a daemon here, that's a real regression, not an env
                # issue. Fail loudly rather than mask it as a skip.
                pytest.fail(f"first daemon failed to start: {first.stderr}")
            assert poll_health(port, timeout=10.0)

            info = read_pid(pf)
            assert info is not None
            pid = info[0]

            # Walk the recorded process + its descendants; one of them must
            # own a LISTEN socket on `port`. Writing the shim PID would
            # typically put the listener outside this subtree on some
            # platforms — the self-reported PID always matches.
            try:
                proc = psutil.Process(pid)
            except psutil.NoSuchProcess:
                pytest.fail("PID file references a dead process")

            candidates = [proc, *proc.children(recursive=True)]
            listening = False
            for candidate in candidates:
                try:
                    for conn in candidate.net_connections(kind="tcp"):
                        if (
                            conn.status == psutil.CONN_LISTEN
                            and conn.laddr
                            and conn.laddr.port == port
                        ):
                            listening = True
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if listening:
                    break
            assert listening, (
                f"PID {pid} (and descendants) is not the process bound to "
                f"port {port} — WOR-228 regression"
            )
        finally:
            _kill_pidfile(pf)

    def test_down_leaves_no_listener(
        self,
        worthless_bin: str,
        cli_env: dict[str, str],
        cli_home: Path,
    ) -> None:
        """``worthless down`` must clear the listening socket.

        Before the fix, ``down`` called ``kill_tree(shim_pid)`` against a
        dead shim PID and returned successfully while leaving uvicorn
        orphaned on the port. A successful ``down`` exit code is not
        enough — verify the port is actually free.
        """
        port = _ephemeral_port()
        _assert_port_unused(port)
        first = subprocess.run(
            [worthless_bin, "up", "--daemon", "--port", str(port)],
            env=cli_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        pf = pid_path(ensure_home(cli_home))
        try:
            if first.returncode != 0:
                pytest.fail(f"first daemon failed to start: {first.stderr}")
            assert poll_health(port, timeout=10.0)

            down = subprocess.run(
                [worthless_bin, "down"],
                env=cli_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert down.returncode == 0, (
                f"down should succeed — got {down.returncode}\n"
                f"stdout: {down.stdout}\nstderr: {down.stderr}"
            )

            # Poll briefly — kill_tree signals are async. Use HTTP because
            # macOS denies unprivileged callers of psutil.net_connections()
            # without a PID argument. A ConnectError means the socket is
            # gone, which is exactly what we care about.
            deadline = time.monotonic() + 5.0
            still_listening = True
            while time.monotonic() < deadline:
                try:
                    httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5)
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    still_listening = False
                    break
                time.sleep(0.1)
            assert not still_listening, (
                f"after `down`, something is still serving /healthz on port {port}"
            )
        finally:
            _kill_pidfile(pf)

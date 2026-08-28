"""Tests for the ``worthless down`` command."""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home
from worthless.cli.console import WorthlessConsole
from worthless.cli.commands.up import start_supervised_proxy
from worthless.cli.process import (
    check_pid,
    pid_path,
    poll_health,
    read_pid,
    write_pid,
)

from tests.fixtures.dirty_home import make_bootstrapped_home

runner = CliRunner()

_DOWN_FERNET_ENV = "dGVzdC1rZXktdGVzdC1rZXktdGVzdGtleTE="


def _down_env(home: Path) -> dict[str, str]:
    """Env for ``down`` tests — bootstrapped home + env Fernet bypasses keyring."""
    return {
        "WORTHLESS_HOME": str(home),
        "WORTHLESS_FERNET_KEY": _DOWN_FERNET_ENV,
    }


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    """Post-bootstrap home with secure fernet.key (mode 0o600 on Unix)."""
    return make_bootstrapped_home(tmp_path / ".worthless").base_dir


# ---------------------------------------------------------------------------
# Idempotent: nothing running → exit 0
# ---------------------------------------------------------------------------


class TestDownNotRunning:
    """down with no running proxy is idempotent (exit 0)."""

    def test_no_pid_file(self, home_dir: Path) -> None:
        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_stale_pid_cleaned(self, home_dir: Path) -> None:
        pid_file = home_dir / "proxy.pid"
        # Use a PID in valid range but not alive (high but under _MAX_VALID_PID)
        write_pid(pid_file, 3_999_999, 8787)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert "stale" in result.output.lower()
        assert not pid_file.exists()

    @pytest.mark.adversarial
    def test_corrupt_pid_cleaned(self, home_dir: Path) -> None:
        pid_file = home_dir / "proxy.pid"
        pid_file.write_text("garbage\n")

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# Graceful shutdown: SIGTERM → process exits
# ---------------------------------------------------------------------------


class TestDownGraceful:
    """down sends SIGTERM to process group and cleans PID file."""

    def test_sigterm_succeeds(self, home_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """kill_tree succeeds, process dies, PID file cleaned, exit 0."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        killed = False

        def mock_kill_tree(pid: int) -> None:
            nonlocal killed
            killed = True

        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", mock_kill_tree)
        monkeypatch.setattr(
            "worthless.cli.commands.down.check_pid",
            lambda pid: not killed,
        )
        monkeypatch.setattr("worthless.cli.commands.down._POLL_INTERVAL", 0.01)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# Force kill: SIGTERM ignored → SIGKILL after timeout
# ---------------------------------------------------------------------------


class TestDownForceKill:
    """down escalates to SIGKILL when SIGTERM is ignored."""

    def test_force_kill_after_timeout(
        self, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        calls: list[tuple[int, bool]] = []  # (pid, force)

        def mock_kill_tree(pid: int, *, force: bool = False) -> None:
            calls.append((pid, force))

        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", mock_kill_tree)
        # Process stays alive through the poll window
        monkeypatch.setattr("worthless.cli.commands.down.check_pid", lambda pid: True)
        monkeypatch.setattr("worthless.cli.commands.down._TERM_TIMEOUT", 0.1)
        monkeypatch.setattr("worthless.cli.commands.down._POLL_INTERVAL", 0.02)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()
        # First call: graceful (force=False), second: force kill (force=True)
        assert (12345, False) in calls
        assert (12345, True) in calls

    @pytest.mark.adversarial
    def test_process_dies_between_timeout_and_force_kill(
        self, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Process dies after timeout but before force kill lands."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        # kill_tree with force=True finds process already dead (no-op via psutil)
        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", lambda pid, **kw: None)
        monkeypatch.setattr("worthless.cli.commands.down.check_pid", lambda pid: True)
        monkeypatch.setattr("worthless.cli.commands.down._TERM_TIMEOUT", 0.1)
        monkeypatch.setattr("worthless.cli.commands.down._POLL_INTERVAL", 0.02)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@pytest.mark.adversarial
class TestDownErrors:
    """down handles permission and OS errors."""

    def test_permission_error_on_kill(
        self, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PermissionError (PID reuse, different user) → structured error, exit 1."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        def _deny(pid: int, **_kw: object) -> None:
            raise PermissionError("access denied")

        monkeypatch.setattr("worthless.cli.commands.down.check_pid", lambda pid: True)
        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", _deny)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 1
        assert "WRTLS" in result.output

    def test_process_dies_during_sigterm(
        self, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Process dies between check and kill → treated as success."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        # kill_tree returns silently (psutil.NoSuchProcess handled internally)
        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", lambda pid: None)
        monkeypatch.setattr("worthless.cli.commands.down._POLL_INTERVAL", 0.01)

        # check_pid: alive once (initial check), then dead after kill
        call_count = 0

        def dying_pid(pid: int) -> bool:
            nonlocal call_count
            call_count += 1
            return call_count <= 1

        monkeypatch.setattr("worthless.cli.commands.down.check_pid", dying_pid)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# Adversarial: dangerous PID values and PID file tampering
# ---------------------------------------------------------------------------


@pytest.mark.adversarial
class TestDownDangerousPids:
    """Adversarial PID values that could cause collateral damage."""

    @pytest.mark.parametrize(
        ("raw_content", "description"),
        [
            (b"0\n8787\n", "PID 0 — would signal caller's process group"),
            (b"1\n8787\n", "PID 1 — init/launchd must never be signaled"),
            (b"-1\n8787\n", "Negative PID — would signal process groups"),
            (b"99999999999999\n8787\n", "Huge PID — beyond OS range"),
        ],
        ids=["pid-zero", "pid-one", "negative-pid", "huge-pid"],
    )
    def test_dangerous_pid_rejected(
        self, home_dir: Path, raw_content: bytes, description: str
    ) -> None:
        pid_file = home_dir / "proxy.pid"
        fd = os.open(str(pid_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw_content)
        finally:
            os.close(fd)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0, description
        assert not pid_file.exists()


@pytest.mark.adversarial
class TestDownPidFileTampering:
    """PID file content manipulation attacks."""

    def test_null_bytes_in_pid_file(self, home_dir: Path) -> None:
        """Null bytes in PID file must not crash or confuse parsing."""
        pid_file = home_dir / "proxy.pid"
        pid_file.write_bytes(b"123\x004567\n8787\n")

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod 000 is no-op on Windows")
    def test_unreadable_pid_file(self, home_dir: Path) -> None:
        """PID file with 000 permissions must not crash (PermissionError path)."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)
        pid_file.chmod(0o000)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0

    def test_empty_pid_file(self, home_dir: Path) -> None:
        """Empty (0-byte) PID file must not crash."""
        pid_file = home_dir / "proxy.pid"
        pid_file.write_bytes(b"")

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()

    def test_pid_valid_but_no_port(self, home_dir: Path) -> None:
        """PID file with valid PID but missing port field."""
        pid_file = home_dir / "proxy.pid"
        pid_file.write_text("12345\n")

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()

    def test_symlink_pid_file(self, home_dir: Path, tmp_path: Path) -> None:
        """Symlinked PID file should be handled safely."""
        real_file = tmp_path / "real.pid"
        write_pid(real_file, 99999999, 8787)

        pid_file = home_dir / "proxy.pid"
        pid_file.symlink_to(real_file)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        # The symlink itself should be removed
        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# Windows platform branch
# ---------------------------------------------------------------------------


class TestDownWindows:
    """down command Windows branch via monkeypatch."""

    def test_uses_win32_kill_on_windows(
        self, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On Windows, kill_tree uses psutil instead of os.killpg."""
        pid_file = home_dir / "proxy.pid"
        write_pid(pid_file, 12345, 8787)

        monkeypatch.setattr("worthless.cli.platform.IS_WINDOWS", True)

        kill_calls: list[int] = []

        def mock_kill_tree(pid: int) -> None:
            kill_calls.append(pid)

        monkeypatch.setattr("worthless.cli.commands.down.kill_tree", mock_kill_tree)

        # check_pid: alive once, then dead after kill_tree called
        def check_pid_dying(pid: int) -> bool:
            return len(kill_calls) == 0

        monkeypatch.setattr("worthless.cli.commands.down.check_pid", check_pid_dying)
        monkeypatch.setattr("worthless.cli.commands.down._POLL_INTERVAL", 0.01)

        result = runner.invoke(app, ["down"], env=_down_env(home_dir))
        assert result.exit_code == 0
        assert not pid_file.exists()
        assert 12345 in kill_calls


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Integration: real process lifecycle
# ---------------------------------------------------------------------------


def _worthless_bin() -> str:
    """The console script for THIS interpreter's venv.

    Deliberately not a bare ``shutil.which("worthless")``: outside ``uv run``
    that resolves whatever install happens to be first on PATH — a globally
    installed worthless, not the code under test. Verified: it returned
    ~/.local/bin/worthless while the worktree's venv sat unused.
    """
    candidate = Path(sys.executable).parent / "worthless"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("worthless")
    assert found is not None, "worthless console script not found"
    return found


def _free_port() -> int:
    """An ephemeral port the OS just confirmed is free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_in_use(port: int) -> bool:
    """True when something is accepting connections on 127.0.0.1:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


@pytest.mark.integration
@pytest.mark.timeout(60)
class TestDownIntegration:
    """Real background-proxy -> down lifecycle with actual processes.

    Rewritten for worthless-0q7k. This previously drove ``up --daemon`` and
    carried ``pytest.skip(f"Daemon failed to start: ...")`` in its body. Once
    daemon mode became a hard refusal (WRTLS-115, up.py:704) that skip fired
    on every run: the test reported SKIPPED, never FAILED, and nobody looked.
    So "after `down`, nothing is still listening" was covered by nothing while
    the suite stayed green.

    It now drives ``start_supervised_proxy`` — the path the default command
    actually uses (default_command.py:199) — and asserts rather than skips.
    """

    def test_supervised_proxy_then_down_frees_the_port(self, tmp_path: Path) -> None:
        """Start the proxy the supported way, `down` it, prove the port is free."""
        home = ensure_home(tmp_path / ".worthless")
        env = {**os.environ, "WORTHLESS_HOME": str(home.base_dir)}
        port = _free_port()
        log_file = home.base_dir / "proxy.log"
        pf = pid_path(home)
        pid = None

        try:
            pid = start_supervised_proxy(home, port, log_file, WorthlessConsole(quiet=True))
            assert pid is not None, "supervised start returned no PID"
            assert poll_health(port, timeout=30.0), (
                f"proxy never became healthy on {port}; log:\n"
                f"{log_file.read_text() if log_file.exists() else '<no log>'}"
            )
            assert _port_in_use(port), "health passed but nothing is listening"

            down_result = subprocess.run(
                [_worthless_bin(), "down"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert down_result.returncode == 0, f"down failed: {down_result.stderr}"

            # The point of this test: the port must actually be released.
            # check_pid alone is not enough — a wedged child can hold the
            # socket after the parent is reaped.
            for _ in range(40):
                if not _port_in_use(port):
                    break
                time.sleep(0.25)
            else:
                pytest.fail(f"port {port} still has a listener after `down`")

            assert not check_pid(pid), "proxy process should be dead after down"
            assert not pf.exists(), "PID file should be cleaned after down"
        finally:
            if pf.exists():
                info = read_pid(pf)
                if info:
                    try:
                        os.killpg(os.getpgid(info[0]), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                pf.unlink(missing_ok=True)
            if pid is not None and check_pid(pid):
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Integration: real process lifecycle
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestDownJson:
    """down --json outputs machine-readable format."""

    def test_json_not_running(self, home_dir: Path) -> None:
        result = runner.invoke(app, ["--json", "down"], env=_down_env(home_dir))
        assert result.exit_code == 0

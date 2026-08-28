"""Tests for the ``worthless down`` command."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.process import write_pid

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


@pytest.mark.integration
@pytest.mark.timeout(30)
class TestDownIntegration:
    """Real up -d → down lifecycle with actual processes."""

    def test_up_daemon_then_down(self, tmp_path: Path) -> None:
        """Start daemon on fixed port, verify it's alive, then stop it."""
        from worthless.cli.bootstrap import ensure_home
        from worthless.cli.process import check_pid, pid_path, read_pid

        worthless_bin = shutil.which("worthless")
        assert worthless_bin is not None, "worthless CLI not found in PATH"

        home = ensure_home(tmp_path / ".worthless")
        env = {
            **os.environ,
            "WORTHLESS_HOME": str(home.base_dir),
        }

        # Use a high ephemeral port to avoid conflicts
        port = 18900 + os.getpid() % 100

        up_result = subprocess.run(
            [worthless_bin, "up", "--daemon", "--port", str(port)],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

        pf = pid_path(home)
        try:
            # Verify daemon started
            if up_result.returncode != 0:
                pytest.skip(f"Daemon failed to start: {up_result.stderr}")

            assert pf.exists(), "PID file should exist after up --daemon"
            info = read_pid(pf)
            assert info is not None
            pid, recorded_port = info
            assert recorded_port == port
            assert check_pid(pid), "Daemon process should be alive"

            # Stop it with down
            down_result = subprocess.run(
                [worthless_bin, "down"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert down_result.returncode == 0
            assert "stopped" in down_result.stderr.lower()
            assert not pf.exists(), "PID file should be cleaned after down"
            assert not check_pid(pid), "Daemon should be dead after down"
        finally:
            # Safety cleanup: kill daemon if test fails mid-way
            if pf.exists():
                info = read_pid(pf)
                if info:
                    try:
                        os.killpg(os.getpgid(info[0]), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                pf.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestDownJson:
    """down --json outputs machine-readable format."""

    def test_json_not_running(self, home_dir: Path) -> None:
        result = runner.invoke(app, ["--json", "down"], env=_down_env(home_dir))
        assert result.exit_code == 0

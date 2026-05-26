"""Tests for the ``worthless up`` command."""

from __future__ import annotations

import collections
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.up import _resolve_port
from worthless.cli.process import (
    check_pid,
    cleanup_stale_pid,
    pid_path,
    read_pid,
    write_pid,
)
from worthless.cli.sidecar_lifecycle import ShareFiles, SidecarHandle

runner = CliRunner()


def _stub_sidecar_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the Phase D sidecar lifecycle hooks for foreground tests.

    These tests pre-date Phase D and only mock ``spawn_proxy``. The real
    ``split_to_tmpfs`` + ``spawn_sidecar`` would touch tmpfs and try to
    launch ``python -m worthless.sidecar`` — too heavy for unit-level
    coverage. Stub them with no-ops; per-Phase-D tests cover the wiring.
    """

    def _fake_split(_key, home_dir: Path) -> ShareFiles:
        run_dir = home_dir / "run" / "test"
        run_dir.mkdir(parents=True, exist_ok=True)
        return ShareFiles(
            share_a_path=run_dir / "share_a.bin",
            share_b_path=run_dir / "share_b.bin",
            shard_a=bytearray(b"\x00" * 22),
            shard_b=bytearray(b"\x00" * 22),
            run_dir=run_dir,
        )

    def _fake_spawn_sidecar(socket_path, shares, allowed_uid, **_):
        proc = MagicMock()
        proc.poll.return_value = None  # alive throughout
        proc.pid = 99001
        return SidecarHandle(
            proc=proc,
            socket_path=socket_path,
            shares=shares,
            allowed_uid=allowed_uid,
            drain_timeout=5.0,
            stderr_buf=collections.deque(),
        )

    monkeypatch.setattr("worthless.cli.commands.up.split_to_tmpfs", _fake_split)
    monkeypatch.setattr("worthless.cli.commands.up.spawn_sidecar", _fake_spawn_sidecar)
    monkeypatch.setattr("worthless.cli.commands.up.shutdown_sidecar", lambda _h: None)


class TestUpDefaultPort:
    """up starts proxy on default port 8787."""

    def test_default_port(self):
        assert _resolve_port(port_arg=None) == 8787

    def test_port_override(self):
        assert _resolve_port(port_arg=9999) == 9999

    def test_env_override(self):
        with patch.dict(os.environ, {"WORTHLESS_PORT": "5555"}):
            assert _resolve_port(port_arg=None) == 5555

    def test_arg_overrides_env(self):
        with patch.dict(os.environ, {"WORTHLESS_PORT": "5555"}):
            assert _resolve_port(port_arg=9999) == 9999

    def test_non_integer_env_raises_clean_error(self):
        """``WORTHLESS_PORT=abc`` previously crashed every command that
        called resolve_port (``lock``, ``up``, ``wrap``, default flow)
        with a raw ``ValueError`` traceback. Post-fix: clean
        ``WorthlessError`` with a single-line CLI message."""
        from worthless.cli.errors import ErrorCode, WorthlessError

        with patch.dict(os.environ, {"WORTHLESS_PORT": "not-a-port"}):
            try:
                _resolve_port(port_arg=None)
            except WorthlessError as exc:
                assert exc.code == ErrorCode.BOOTSTRAP_FAILED
                assert "WORTHLESS_PORT" in str(exc)
                assert "not-a-port" in str(exc)
            else:
                raise AssertionError("expected WorthlessError, got no exception")


class TestUpPidFile:
    """up writes PID file at expected location."""

    def test_pid_file_path(self, tmp_path: Path):
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        result = pid_path(home)
        assert result == home.base_dir / "proxy.pid"


class TestUpStalePid:
    """up detects stale PID file and reclaims."""

    def test_stale_pid_reclaimed(self, tmp_path: Path):
        pid_path = tmp_path / "proxy.pid"
        write_pid(pid_path, 99999999, 8787)
        assert cleanup_stale_pid(pid_path) is True
        assert not pid_path.exists()


class TestUpLivePid:
    """up with live PID errors with PORT_IN_USE."""

    def test_live_pid_detected(self, tmp_path: Path):
        pid_path = tmp_path / "proxy.pid"
        write_pid(pid_path, os.getpid(), 8787)
        assert cleanup_stale_pid(pid_path) is False


class TestUpDaemon:
    """up -d returns immediately (daemon mode indicator)."""

    def test_daemon_flag_parsed(self):
        """Verify _resolve_port and daemon flag are independent."""
        assert _resolve_port(port_arg=8787) == 8787


class TestUpPidFileErrorBranches:
    """Error branches in PID file management."""

    def test_read_pid_corrupt_file(self, tmp_path: Path) -> None:
        """Corrupt PID file returns None."""
        pid_path = tmp_path / "proxy.pid"
        pid_path.write_text("garbage\n")
        assert read_pid(pid_path) is None

    def test_read_pid_missing_file(self, tmp_path: Path) -> None:
        """Missing PID file returns None."""
        assert read_pid(tmp_path / "nonexistent.pid") is None

    def test_cleanup_stale_pid_corrupt_reclaims(self, tmp_path: Path) -> None:
        """Corrupt PID file is treated as reclaimable."""
        pid_path = tmp_path / "proxy.pid"
        pid_path.write_text("not a pid\n")
        assert cleanup_stale_pid(pid_path) is True
        assert not pid_path.exists()

    def test_check_pid_nonexistent(self) -> None:
        """check_pid returns False for a PID that doesn't exist."""
        assert check_pid(99999999) is False

    def test_write_read_roundtrip(self, tmp_path: Path) -> None:
        """write_pid and read_pid round-trip correctly."""
        pid_path = tmp_path / "proxy.pid"
        write_pid(pid_path, 12345, 8787)
        info = read_pid(pid_path)
        assert info == (12345, 8787)


class TestUpDaemonFlow:
    """up --daemon currently rejects with WRTLS-110 (Phase D: foreground only).

    Daemon + sidecar IPC handle inheritance is unsolved. Until that lands,
    ``-d`` raises before any subprocess is spawned, so callers cannot
    accidentally end up with a running proxy that has no sidecar.
    """

    def test_daemon_mode_rejected(self, home_with_key) -> None:
        result = runner.invoke(
            app,
            ["up", "--daemon"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        out = result.output.lower()
        assert "daemon" in out
        assert "foreground" in out


class TestUpErrorBranches:
    """Error branch coverage for up command failure paths."""

    def test_up_get_home_failure_exits_clean(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """OSError in get_home -> exit_code=1."""

        def _boom():
            raise OSError("permission denied")

        monkeypatch.setattr(
            "worthless.cli.commands.up.get_home",
            _boom,
        )

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(tmp_path / "nonexistent")},
        )
        assert result.exit_code == 1

    def test_up_foreground_spawn_failure_exits_clean(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RuntimeError in spawn_proxy -> exit_code=1 with WRTLS."""
        _stub_sidecar_lifecycle(monkeypatch)

        def _boom(**_kw):
            raise RuntimeError("bind failed")

        monkeypatch.setattr(
            "worthless.cli.commands.up.spawn_proxy",
            _boom,
        )

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output

    def test_up_foreground_health_timeout_exits_clean(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """poll_health_pid returns None -> exit_code=1, proxy terminated."""
        _stub_sidecar_lifecycle(monkeypatch)

        mock_proxy = MagicMock()
        mock_proxy.pid = 99999
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.up.spawn_proxy",
            lambda **_kw: (mock_proxy, 8787),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.up.poll_health_pid",
            lambda *_a, **_kw: None,
        )

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output
        mock_proxy.terminate.assert_called()

    # Daemon-spawn-failure and daemon-health-timeout cases collapse into the
    # single "daemon rejected" path (covered by
    # ``TestUpDaemonFlow::test_daemon_mode_rejected``). Reinstate when
    # daemon + sidecar IPC handle inheritance lands.


class TestUpStalePidReclaim:
    """up detects stale PID and reclaims via the CLI path."""

    def test_stale_pid_reclaimed_via_cli(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Existing stale PID file is reclaimed, proxy starts normally."""
        _stub_sidecar_lifecycle(monkeypatch)

        pid_file = pid_path(home_with_key)
        write_pid(pid_file, 99999999, 8787)

        mock_proxy = MagicMock()
        mock_proxy.pid = 11111
        # poll() returns 0 (exited) so the supervise loop exits cleanly.
        mock_proxy.poll.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.up.spawn_proxy",
            lambda **_kw: (mock_proxy, 8787),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.up.poll_health_pid",
            lambda *_a, **_kw: 11111,
        )
        # Prevent blocking on proxy.wait()
        mock_proxy.wait.return_value = 0

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        assert "Reclaimed" in result.output

    def test_live_pid_blocks_startup(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        """Existing live PID file prevents starting a new proxy."""
        pid_file = pid_path(home_with_key)
        write_pid(pid_file, os.getpid(), 8787)  # current process = alive

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS-107" in result.output


class TestUpExceptionHandlers:
    """Cover the WorthlessError and generic Exception handlers."""

    def test_worthless_error_in_up_exits_clean(
        self, monkeypatch: pytest.MonkeyPatch, home_with_key
    ) -> None:
        """WorthlessError raised inside up -> exit_code=1."""
        from worthless.cli.errors import ErrorCode, WorthlessError

        def _boom():
            raise WorthlessError(ErrorCode.UNKNOWN, "test error")

        monkeypatch.setattr("worthless.cli.commands.up.get_home", _boom)

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1

    def test_generic_exception_in_up_exits_clean(
        self, monkeypatch: pytest.MonkeyPatch, home_with_key
    ) -> None:
        """Generic Exception raised inside up -> exit_code=1."""

        def _boom():
            raise ValueError("unexpected")

        monkeypatch.setattr("worthless.cli.commands.up.get_home", _boom)

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1


# ------------------------------------------------------------------
# WOR-73: CliRunner tests for `up` command
# ------------------------------------------------------------------


class TestUpStartsProxyBackground:
    """WOR-73: up starts proxy in background via CliRunner."""

    def test_up_starts_proxy_background(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CliRunner invokes `up`, mocked subprocess confirms proxy launch."""
        _stub_sidecar_lifecycle(monkeypatch)

        mock_proxy = MagicMock()
        mock_proxy.pid = 12345
        # poll() returns 0 immediately so the supervise loop exits cleanly.
        mock_proxy.poll.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.up.spawn_proxy",
            lambda **_kw: (mock_proxy, 8787),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.up.poll_health_pid",
            lambda *_a, **_kw: 12345,
        )
        mock_proxy.wait.return_value = 0

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0, f"up failed: {result.output}"
        # Proxy was actually spawned (spawn_proxy was called)
        # The mock_proxy.wait was called, confirming the proxy lifecycle ran
        mock_proxy.wait.assert_called()


# ------------------------------------------------------------------
# worthless-9lu: Duplicate `up -d` detection integration tests
# ------------------------------------------------------------------


class TestUpDuplicateDetection:
    """Integration tests proving duplicate daemon/foreground detection."""

    def test_duplicate_daemon_rejected(self, home_with_key) -> None:
        """Phase D: `up -d` is rejected with WRTLS-110 (daemon mode disabled).

        Pre-Phase-D this test asserted WRTLS-107 from the live-PID check, but
        daemon-mode rejection now happens first (no point doing pidfile work
        for a flag we will never honor).
        """
        # Plant a PID file with our own (live) PID — irrelevant under Phase D
        # because daemon rejection is the first guard in the command body.
        pid_file = pid_path(home_with_key)
        write_pid(pid_file, os.getpid(), 8787)

        result = runner.invoke(
            app,
            ["up", "--daemon"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1, f"Expected rejection, got: {result.output}"
        out = result.output.lower()
        assert "daemon" in out
        assert "foreground" in out

    def test_duplicate_daemon_stale_reclaimed_then_starts(self, home_with_key) -> None:
        """Phase D: even with stale pid, `up -d` is rejected before reclaim."""
        pid_file = pid_path(home_with_key)
        write_pid(pid_file, 99999999, 8787)

        result = runner.invoke(
            app,
            ["up", "--daemon"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        out = result.output.lower()
        assert "daemon" in out
        assert "foreground" in out

    def test_duplicate_foreground_rejected(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Foreground `up` exits 1 with WRTLS-107 when a live PID file exists."""
        pid_file = pid_path(home_with_key)
        write_pid(pid_file, os.getpid(), 8787)

        result = runner.invoke(
            app,
            ["up"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1, f"Expected rejection, got: {result.output}"
        assert "WRTLS-107" in result.output
        assert "already running" in result.output.lower()

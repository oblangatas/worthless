"""Integration tests for launchd/systemd backends (mocked OS tools)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pwd
import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import launchd, systemd, templates
from worthless.cli.commands.service._common import ServiceState, ServiceStatus
from worthless.cli.errors import ErrorCode, WorthlessError


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    (base / "fernet.key").write_bytes(b"x" * 32)
    return WorthlessHome(base_dir=base)


class TestLaunchdBackend:
    def test_install_writes_plist_and_bootstraps(self, home: WorthlessHome, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        plist = tmp_path / "dev.worthless.proxy.plist"
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=binary),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=False),
            patch.object(launchd, "verify_proxy_health"),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.install(home)

        assert plist.is_file()
        content = plist.read_text()
        assert "dev.worthless.proxy" in content
        assert str(binary) in content
        assert "WORTHLESS_SERVICE_MANAGED" in content
        assert ["launchctl", "bootstrap", "gui/501", str(plist)] in calls
        assert ["launchctl", "kickstart", "-k", "gui/501/dev.worthless.proxy"] in calls

    def test_detect_not_installed(self, home: WorthlessHome, tmp_path: Path) -> None:
        with patch.object(launchd, "plist_path", return_value=tmp_path / "missing.plist"):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.NOT_INSTALLED

    def test_detect_stopped_unloaded(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text("plist")
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=tmp_path / "worthless"),
            patch.object(launchd, "_is_loaded", return_value=False),
        ):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.STOPPED
        assert status.healthy is False

    def test_detect_running_healthy(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text("plist")
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=tmp_path / "worthless"),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(launchd, "poll_health", return_value=True),
        ):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.RUNNING
        assert status.healthy is True

    def test_detect_failed_unhealthy(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text("plist")
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(
                launchd,
                "resolve_worthless_binary",
                side_effect=WorthlessError(ErrorCode.BOOTSTRAP_FAILED, "x"),
            ),
            patch("worthless.cli.process.poll_health", return_value=False),
        ):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.FAILED
        assert status.binary is None

    def test_install_bootouts_loaded(self, home: WorthlessHome, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        plist = tmp_path / "dev.worthless.proxy.plist"
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=binary),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(launchd, "verify_proxy_health"),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.install(home)

        assert any("bootout" in str(c) for c in calls)


class TestSystemdBackend:
    def test_install_writes_unit_enables_linger(self, home: WorthlessHome, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        unit = tmp_path / "worthless-proxy.service"
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            result.stdout = "Linger=yes" if args[:3] == ["loginctl", "show-user"] else "active"
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "resolve_worthless_binary", return_value=binary),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            patch.object(systemd, "verify_proxy_health"),
            patch.dict("os.environ", {"USER": "testuser"}, clear=False),
        ):
            systemd.install(home)

        assert unit.is_file()
        content = unit.read_text()
        assert f"ExecStart={binary} up" in content
        assert "WORTHLESS_SERVICE_MANAGED=1" in content
        assert ["systemctl", "--user", "daemon-reload"] in calls
        assert ["systemctl", "--user", "enable", "--now", "worthless-proxy.service"] in calls

    def test_install_enables_linger(self, home: WorthlessHome, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        unit = tmp_path / "worthless-proxy.service"
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            result.stdout = "Linger=no" if args[:2] == ["loginctl", "show-user"] else "active"
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "resolve_worthless_binary", return_value=binary),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            patch.object(systemd, "verify_proxy_health"),
            patch.dict("os.environ", {"USER": "testuser"}, clear=False),
        ):
            systemd.install(home)

        assert ["loginctl", "enable-linger", "testuser"] in calls

    def test_detect_not_installed(self, home: WorthlessHome, tmp_path: Path) -> None:
        with patch.object(systemd, "unit_path", return_value=tmp_path / "missing.service"):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.NOT_INSTALLED

    def test_detect_stopped_when_inactive(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text("unit")
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="inactive"),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.STOPPED

    def test_systemd_detect_running(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text("unit")
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="active"),
            patch.object(systemd, "poll_health", return_value=True),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.RUNNING
        assert status.healthy is True

    def test_systemd_detect_failed(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text("unit")
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="failed"),
            patch.object(systemd, "poll_health", return_value=False),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.FAILED


def _owned_launchd_plist(home: WorthlessHome, tmp_path: Path) -> Path:
    plist = tmp_path / "dev.worthless.proxy.plist"
    plist.write_text(
        templates.render_launchd_plist(
            binary="/usr/local/bin/worthless",
            worthless_home=str(home.base_dir),
            log_path=str(home.base_dir / "proxy.log"),
        )
    )
    return plist


def _owned_systemd_unit(home: WorthlessHome, tmp_path: Path) -> Path:
    unit = tmp_path / "worthless-proxy.service"
    unit.write_text(
        templates.render_systemd_unit(
            binary="/usr/local/bin/worthless",
            worthless_home=str(home.base_dir),
        )
    )
    return unit


class TestOwnedUnitMutators:
    def test_launchd_uninstall_owned_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _owned_launchd_plist(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.uninstall(home)

        assert not plist.is_file()
        assert any("bootout" in str(c) for c in calls)

    def test_launchd_start_owned_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _owned_launchd_plist(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=False),
            patch.object(launchd, "verify_proxy_health"),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.start(home)

        assert ["launchctl", "bootstrap", "gui/501", str(plist)] in calls

    def test_launchd_restart_owned_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _owned_launchd_plist(home, tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "start") as mock_start,
        ):
            launchd.restart(home)
        mock_start.assert_called_once_with(home)

    def test_launchd_stop_owned_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _owned_launchd_plist(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.stop()

        assert ["launchctl", "bootout", "gui/501", str(plist)] in calls

    def test_launchd_stop_missing_plist_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.plist"
        with (
            patch.object(launchd, "plist_path", return_value=missing),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.stop()
        assert exc_info.value.code == ErrorCode.PROXY_NOT_RUNNING

    def test_launchd_start_missing_plist_raises(self, home: WorthlessHome, tmp_path: Path) -> None:
        missing = tmp_path / "missing.plist"
        with (
            patch.object(launchd, "plist_path", return_value=missing),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.start(home)
        assert exc_info.value.code == ErrorCode.PROXY_NOT_RUNNING

    def test_systemd_uninstall_owned_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
        ):
            systemd.uninstall(home)

        assert not unit.is_file()
        assert ["systemctl", "--user", "disable", "--now", "worthless-proxy.service"] in calls

    def test_systemd_start_owned_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            patch.object(systemd, "verify_proxy_health"),
        ):
            systemd.start(home)

        assert ["systemctl", "--user", "start", "worthless-proxy.service"] in calls

    def test_systemd_restart_owned_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            patch.object(systemd, "verify_proxy_health"),
        ):
            systemd.restart(home)

        assert ["systemctl", "--user", "restart", "worthless-proxy.service"] in calls

    def test_systemd_stop_owned_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
        ):
            systemd.stop()

        assert ["systemctl", "--user", "stop", "worthless-proxy.service"] in calls

    def test_systemd_start_missing_unit_raises(self, home: WorthlessHome, tmp_path: Path) -> None:
        missing = tmp_path / "missing.service"
        with (
            patch.object(systemd, "unit_path", return_value=missing),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.start(home)
        assert exc_info.value.code == ErrorCode.PROXY_NOT_RUNNING


class TestTailLogs:
    def test_launchd_tail_file(self, home: WorthlessHome, tmp_path: Path) -> None:
        log_path = home.base_dir / "proxy.log"
        log_path.write_text("line1\n")
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with patch.object(launchd, "run_cmd", side_effect=fake_run):
            launchd.tail_logs(home, follow=False)

        assert calls[0][:3] == ["tail", "-n", "200"]
        assert str(log_path) in calls[0]

    def test_launchd_tail_missing_log_raises(self, home: WorthlessHome) -> None:
        with pytest.raises(WorthlessError) as exc_info:
            launchd.tail_logs(home, follow=False)
        assert exc_info.value.code == ErrorCode.PROXY_NOT_RUNNING

    def test_systemd_journalctl(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text("unit")
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            assert kwargs.get("capture") is False
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
        ):
            systemd.tail_logs(home, follow=True)

        assert "journalctl" in calls[0]
        assert "-f" in calls[0]

    def test_systemd_tail_missing_unit_raises(self, home: WorthlessHome, tmp_path: Path) -> None:
        with (
            patch.object(systemd, "unit_path", return_value=tmp_path / "missing.service"),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.tail_logs(home, follow=False)
        assert exc_info.value.code == ErrorCode.PROXY_NOT_RUNNING


class TestInstalledPortRoundTrip:
    """Install with --port must survive status without WORTHLESS_PORT in the shell."""

    def test_systemd_status_uses_installed_port_not_default(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        unit = tmp_path / "worthless-proxy.service"
        custom_port = 9000
        calls: list[int] = []

        def fake_run(args: list[str], **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "Linger=yes" if args[:3] == ["loginctl", "show-user"] else "active"
            return result

        def capture_health(port: int, timeout: float = 1.0) -> bool:
            calls.append(port)
            return True

        monkeypatch.delenv("WORTHLESS_PORT", raising=False)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "resolve_worthless_binary", return_value=binary),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            patch.object(systemd, "verify_proxy_health"),
            patch.object(systemd, "poll_health", side_effect=capture_health),
            patch.dict("os.environ", {"USER": "testuser"}, clear=False),
        ):
            systemd.install(home, port=custom_port)
            assert "Environment=WORTHLESS_PORT=9000" in unit.read_text()
            assert systemd.installed_port() == custom_port
            status = systemd.detect_status(home, systemd.installed_port() or 8787)
            assert status.port == custom_port
            assert calls == [custom_port]

    def test_launchd_status_uses_installed_port_not_default(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        plist = tmp_path / "dev.worthless.proxy.plist"
        custom_port = 9000
        calls: list[int] = []

        def fake_run(args: list[str], **kwargs):
            result = MagicMock()
            result.returncode = 0
            return result

        def capture_health(port: int, timeout: float = 1.0) -> bool:
            calls.append(port)
            return True

        monkeypatch.delenv("WORTHLESS_PORT", raising=False)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=binary),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(launchd, "verify_proxy_health"),
            patch.object(launchd, "poll_health", side_effect=capture_health),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.install(home, port=custom_port)
            assert "<key>WORTHLESS_PORT</key>" in plist.read_text()
            assert launchd.installed_port() == custom_port
            status = launchd.detect_status(home, launchd.installed_port() or 8787)
            assert status.port == custom_port
            assert calls == [custom_port]

    def test_service_status_cli_uses_installed_port(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from worthless.cli.app import app

        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/bin/worthless",
                worthless_home=str(home.base_dir),
                port=9000,
            )
        )
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = 9000
        mock_backend.detect_status.return_value = ServiceStatus(
            state=ServiceState.RUNNING,
            unit_path=unit,
            binary="/usr/bin/worthless",
            port=9000,
            healthy=True,
        )
        runtime = MagicMock(running=True, source="health", pid=42)

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("WORTHLESS_PORT", raising=False)
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="systemd",
            ),
            patch("worthless.cli.commands.service.detect_proxy_runtime", return_value=runtime),
            patch("worthless.cli.commands.service.get_home") as mock_home,
            patch("worthless.cli.commands.service.resolve_port", return_value=8787),
        ):
            mock_home.return_value.base_dir = home.base_dir
            result = CliRunner().invoke(
                app,
                ["--json", "service", "status"],
                env={"WORTHLESS_HOME": str(home.base_dir)},
            )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["port"] == 9000
        mock_backend.detect_status.assert_called_once()
        assert mock_backend.detect_status.call_args.args[1] == 9000


class TestVerifyProxyHealthIntegration:
    def test_install_health_failure(self, home: WorthlessHome, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        plist = tmp_path / "dev.worthless.proxy.plist"

        def fake_run(args: list[str], **kwargs):
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=binary),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            patch.object(launchd, "_is_loaded", return_value=False),
            patch.object(
                launchd,
                "verify_proxy_health",
                side_effect=WorthlessError(ErrorCode.PROXY_UNREACHABLE, "nope"),
            ),
            patch.object(launchd.os, "getuid", return_value=501),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.install(home)
        assert exc_info.value.code == ErrorCode.PROXY_UNREACHABLE


class TestSystemdSessionUser:
    def test_session_user_prefers_user_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("USER", "testuser")
        monkeypatch.delenv("LOGNAME", raising=False)
        getlogin = MagicMock(side_effect=OSError(25, "Inappropriate ioctl for device"))
        monkeypatch.setattr(systemd.os, "getlogin", getlogin)
        assert systemd._session_user() == "testuser"
        getlogin.assert_not_called()

    def test_session_user_falls_back_to_pw_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("LOGNAME", raising=False)
        monkeypatch.setattr(systemd.os, "getlogin", MagicMock(side_effect=OSError(25)))
        monkeypatch.setattr(systemd.os, "getuid", lambda: 1000)

        fake_passwd = type("Passwd", (), {"pw_name": "runner"})()
        monkeypatch.setattr(pwd, "getpwuid", lambda uid: fake_passwd)
        assert systemd._session_user() == "runner"

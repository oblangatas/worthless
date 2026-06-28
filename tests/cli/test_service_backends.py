"""Integration tests for launchd/systemd backends (mocked OS tools)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pwd
import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import launchd, systemd, templates
from worthless.cli.commands.service._common import ServiceState, refuse_foreign_unit
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
        plist = _owned_launchd_plist(home, tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "resolve_worthless_binary", return_value=tmp_path / "worthless"),
            patch.object(launchd, "_is_loaded", return_value=False),
        ):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.STOPPED
        assert status.healthy is False

    def test_detect_running_healthy(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _owned_launchd_plist(home, tmp_path)
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
        plist = _owned_launchd_plist(home, tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "_is_loaded", return_value=True),
            patch.object(
                launchd,
                "resolve_worthless_binary",
                side_effect=WorthlessError(ErrorCode.BOOTSTRAP_FAILED, "x"),
            ),
            patch.object(launchd, "poll_health", return_value=False),
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

    def test_detect_ignores_plist_for_other_home(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text(
            templates.render_launchd_plist(
                binary="/usr/local/bin/worthless",
                worthless_home=str(tmp_path / "other-home"),
                log_path=str(tmp_path / "other-home" / "proxy.log"),
            )
        )
        with patch.object(launchd, "plist_path", return_value=plist):
            status = launchd.detect_status(home, 8787)
        assert status.state == ServiceState.NOT_INSTALLED


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
            result.stdout = "Linger=yes" if args[:2] == ["loginctl", "show-user"] else "active"
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
        unit = _owned_systemd_unit(home, tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="inactive"),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.STOPPED

    def test_systemd_detect_running(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="active"),
            patch.object(systemd, "poll_health", return_value=True),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.RUNNING
        assert status.healthy is True

    def test_systemd_detect_failed(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "_active_state", return_value="failed"),
            patch.object(systemd, "poll_health", return_value=False),
        ):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.FAILED

    def test_detect_ignores_unit_for_other_home(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(tmp_path / "other-home"),
            )
        )
        with patch.object(systemd, "unit_path", return_value=unit):
            status = systemd.detect_status(home, 8787)
        assert status.state == ServiceState.NOT_INSTALLED


def _foreign_launchd_plist(tmp_path: Path) -> Path:
    plist = tmp_path / "dev.worthless.proxy.plist"
    plist.write_text(
        templates.render_launchd_plist(
            binary="/usr/local/bin/worthless",
            worthless_home=str(tmp_path / "other-home"),
            log_path=str(tmp_path / "other-home" / "proxy.log"),
        )
    )
    return plist


def _foreign_systemd_unit(tmp_path: Path) -> Path:
    unit = tmp_path / "worthless-proxy.service"
    unit.write_text(
        templates.render_systemd_unit(
            binary="/usr/local/bin/worthless",
            worthless_home=str(tmp_path / "other-home"),
        )
    )
    return unit


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


class TestRefuseForeignUnit:
    def test_noop_when_unit_missing(self, home: WorthlessHome, tmp_path: Path) -> None:
        refuse_foreign_unit(tmp_path / "missing.plist", home)

    def test_noop_when_unit_owned_by_home(self, home: WorthlessHome, tmp_path: Path) -> None:
        refuse_foreign_unit(_owned_launchd_plist(home, tmp_path), home)

    def test_unreadable_unit_raises_clean_error(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _owned_systemd_unit(home, tmp_path)
        unit.chmod(0o000)
        try:
            with pytest.raises(WorthlessError) as exc_info:
                refuse_foreign_unit(unit, home)
            assert exc_info.value.code == ErrorCode.INVALID_INPUT
            assert "Cannot read service unit" in exc_info.value.message
        finally:
            unit.chmod(0o600)


@pytest.mark.adversarial
class TestForeignUnitMutators:
    """Install/uninstall/start/stop must not touch another WORTHLESS_HOME's unit."""

    def test_launchd_install_refuses_foreign_plist(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        plist = _foreign_launchd_plist(tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.install(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT
        assert "other-home" in plist.read_text()

    def test_launchd_uninstall_refuses_foreign_plist(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        plist = _foreign_launchd_plist(tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(launchd, "plist_path", return_value=plist),
            patch.object(launchd, "run_cmd", side_effect=fake_run),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.uninstall(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT
        assert not calls
        assert plist.is_file()

    def test_launchd_stop_refuses_foreign_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _foreign_launchd_plist(tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.stop(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    def test_launchd_start_refuses_foreign_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = _foreign_launchd_plist(tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.start(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    def test_launchd_restart_refuses_foreign_plist(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        plist = _foreign_launchd_plist(tmp_path)
        with (
            patch.object(launchd, "plist_path", return_value=plist),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.restart(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    def test_systemd_install_refuses_foreign_unit(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        unit = _foreign_systemd_unit(tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.install(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT
        assert "other-home" in unit.read_text()

    def test_systemd_uninstall_refuses_foreign_unit(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        unit = _foreign_systemd_unit(tmp_path)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **kwargs):
            calls.append(args)
            result = MagicMock()
            result.returncode = 0
            return result

        with (
            patch.object(systemd, "unit_path", return_value=unit),
            patch.object(systemd, "run_cmd", side_effect=fake_run),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.uninstall(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT
        assert not any("disable" in str(c) for c in calls)
        assert unit.is_file()

    def test_systemd_stop_refuses_foreign_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _foreign_systemd_unit(tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.stop(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    def test_systemd_start_refuses_foreign_unit(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = _foreign_systemd_unit(tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.start(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    def test_systemd_restart_refuses_foreign_unit(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        unit = _foreign_systemd_unit(tmp_path)
        with (
            patch.object(systemd, "unit_path", return_value=unit),
            pytest.raises(WorthlessError) as exc_info,
        ):
            systemd.restart(home)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT


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
            patch.object(launchd, "verify_proxy_health"),
            patch.object(launchd.os, "getuid", return_value=501),
        ):
            launchd.restart(home)

        assert ["launchctl", "bootout", "gui/501", str(plist)] in calls
        assert ["launchctl", "bootstrap", "gui/501", str(plist)] in calls
        assert ["launchctl", "kickstart", "-k", "gui/501/dev.worthless.proxy"] in calls

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
            launchd.stop(home)

        assert ["launchctl", "bootout", "gui/501", str(plist)] in calls

    def test_launchd_stop_missing_plist_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.plist"
        with (
            patch.object(launchd, "plist_path", return_value=missing),
            pytest.raises(WorthlessError) as exc_info,
        ):
            launchd.stop(home)
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
            systemd.stop(home)

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

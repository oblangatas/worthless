"""Integration tests for launchd/systemd backends (mocked OS tools)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pwd
import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import launchd, systemd
from worthless.cli.commands.service._common import ServiceState


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

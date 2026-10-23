"""worthless-8kn5 + worthless-tkv1: no dead-end "enable linger" advice.

8kn5 (confirmed live, WOR-861): a Linux user with no local login session (SSH,
a container) is refused by polkit for ``loginctl enable-linger``. ``service
install`` then stopped with WRTLS-119 telling them to run the very command that
had just been refused. The unit works fine while they are logged in; without
lingering it just won't start at boot or survive logout. So install, and say
what an administrator must do for boot.

tkv1 (P1, PR #599 review): ``doctor`` told everyone with a unit file — including
WSL users with systemd off — to run ``loginctl enable-linger``, which cannot
work when systemd isn't running.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.doctor.checks import service_health
from worthless.cli.commands.service import _print_service_banner, systemd
from worthless.cli.errors import ErrorCode, WorthlessError


def _fake_loginctl(*, linger: bool, refuse: bool, calls: list):
    def fake_run(args: list[str], **kwargs):
        calls.append(args)
        if args[:2] == ["loginctl", "show-user"]:
            return MagicMock(returncode=0, stdout=f"Linger={'yes' if linger else 'no'}")
        if args[0] == "loginctl" and "enable-linger" in args and refuse:
            raise subprocess.CalledProcessError(1, args, stderr="Access denied")
        return MagicMock(returncode=0, stdout="active")

    return fake_run


@pytest.fixture
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    return WorthlessHome(base_dir=base)


def _install(home: WorthlessHome, tmp_path: Path, fake_run) -> tuple[Path, object]:
    binary = tmp_path / "worthless"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    unit = tmp_path / "worthless-proxy.service"
    with (
        patch.object(systemd, "systemd_is_running", return_value=True),
        patch.object(systemd, "is_wsl", return_value=False),
        patch.object(systemd, "unit_path", return_value=unit),
        patch.object(systemd, "resolve_worthless_binary", return_value=binary),
        patch.object(systemd, "run_cmd", side_effect=fake_run),
        patch.object(systemd, "report_proxy_health"),
        patch.object(systemd.pwd, "getpwuid", return_value=MagicMock(pw_name="sshuser")),
    ):
        lingering = systemd.install(home)
    return unit, lingering


class TestInstallWhenLingerIsRefused:
    def test_install_still_succeeds_and_says_linger_is_off(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        calls: list = []
        unit, lingering = _install(
            home, tmp_path, _fake_loginctl(linger=False, refuse=True, calls=calls)
        )
        assert lingering is False
        assert unit.is_file(), "the unit works while the user is logged in — keep it"
        assert ["systemctl", "--user", "enable", "--now", "worthless-proxy.service"] in calls

    def test_never_waits_on_a_password_prompt(self, home: WorthlessHome, tmp_path: Path) -> None:
        """Over SSH polkit would ask for a password; nobody is there to answer."""
        calls: list = []
        _install(home, tmp_path, _fake_loginctl(linger=False, refuse=False, calls=calls))
        assert ["loginctl", "--no-ask-password", "enable-linger", "sshuser"] in calls

    def test_already_lingering_reports_on_without_asking(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        calls: list = []
        _, lingering = _install(
            home, tmp_path, _fake_loginctl(linger=True, refuse=False, calls=calls)
        )
        assert lingering is True
        assert not any("enable-linger" in c for c in calls)


class TestNoSessionAtAll:
    """`docker exec` / cron: linger refused AND no user manager to talk to."""

    def test_says_what_an_admin_must_run_and_leaves_no_unit(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(systemd, "_user_bus", lambda: tmp_path / "no-manager" / "bus")
        calls: list = []
        loginctl = _fake_loginctl(linger=False, refuse=True, calls=calls)

        def fake_run(args: list[str], **kwargs):
            if args[:2] == ["systemctl", "--user"]:
                calls.append(args)
                if "daemon-reload" in args:
                    raise subprocess.CalledProcessError(
                        1, args, stderr="Failed to connect to bus: No such file or directory"
                    )
                return MagicMock(returncode=0, stdout="")
            return loginctl(args, **kwargs)

        with pytest.raises(WorthlessError) as exc:
            _install(home, tmp_path, fake_run)
        said = " ".join(str(exc.value).split())
        assert exc.value.code == ErrorCode.SERVICE_INSTALL_FAILED
        assert "sudo loginctl enable-linger sshuser" in said
        assert "worthless up" in said
        assert "machinectl" not in said and "su`" not in said, "containers can't log in"
        assert not (tmp_path / "worthless-proxy.service").exists(), "rollback removes the unit"

    def test_a_systemctl_failure_with_linger_on_is_not_blamed_on_linger(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        calls: list = []
        loginctl = _fake_loginctl(linger=True, refuse=False, calls=calls)

        def fake_run(args: list[str], **kwargs):
            if args[:2] == ["systemctl", "--user"] and "daemon-reload" in args:
                raise subprocess.CalledProcessError(1, args, stderr="boom")
            return loginctl(args, **kwargs)

        with pytest.raises(subprocess.CalledProcessError):
            _install(home, tmp_path, fake_run)


def _banner(*, lingering: bool) -> tuple[str, str]:
    console = MagicMock()
    console.json_mode = False
    with patch("worthless.cli.commands.service.is_wsl", return_value=False):
        _print_service_banner(
            console, platform="systemd", port=8787, after_install=True, lingering=lingering
        )
    hints = " ".join(str(c) for c in console.print_hint.call_args_list)
    warnings = " ".join(str(c) for c in console.print_warning.call_args_list)
    return hints, warnings


class TestTheBannerTellsTheTruth:
    def test_refused_linger_says_what_an_admin_must_run(self) -> None:
        hints, warnings = _banner(lingering=False)
        assert "Lingering is now on" not in hints + warnings
        assert "sudo loginctl enable-linger" in warnings
        assert "logged in" in warnings

    def test_granted_linger_keeps_todays_disclosure(self) -> None:
        hints, _ = _banner(lingering=True)
        assert "Lingering is now on" in hints


def test_the_lock_question_does_not_promise_lingering(home: WorthlessHome) -> None:
    """On these machines it can't be turned on, so the question must not say it will."""
    from worthless.cli.commands import lock as lock_mod

    with (
        patch.object(lock_mod, "is_wsl", return_value=False),
        patch.object(lock_mod, "current_platform_backend_name", return_value="systemd"),
    ):
        question = lock_mod._offer_question(8787, home)
    said = " ".join(str(question).split())
    assert "tries to turn on lingering" in said
    assert "it turns on lingering" not in said


class TestDoctorAdviceFitsTheMachine:
    @pytest.mark.parametrize(
        ("wsl", "phrase"), [(True, "/etc/wsl.conf"), (False, "worthless service uninstall")]
    )
    def test_systemd_off_never_says_enable_linger(self, wsl: bool, phrase: str) -> None:
        with patch.object(service_health, "is_wsl", return_value=wsl):
            finding = service_health._systemd_off_finding()
        assert finding["kind"] == "systemd_not_running"
        assert "enable-linger" not in finding["remediation"]
        assert phrase in finding["remediation"]

    def test_linger_off_names_the_admin_fallback(self) -> None:
        finding = service_health._linger_finding(False)
        assert "sudo loginctl enable-linger" in finding["remediation"]


class TestReviewFixes:
    """Security review + brutus on PR #734."""

    def test_the_admin_command_names_the_real_account_not_the_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """USER/LOGNAME can say anything after `sudo -u` or in a container; the
        unit belongs to the real uid, so that is who lingering must be for."""
        monkeypatch.setenv("USER", "someone-else")
        with patch.object(systemd.pwd, "getpwuid", return_value=MagicMock(pw_name="realuser")):
            assert systemd._account_name() == "realuser"

    def test_an_odd_account_name_is_quoted_for_the_shell(self) -> None:
        with patch.object(systemd.pwd, "getpwuid", return_value=MagicMock(pw_name="a b;rm")):
            assert systemd._account_name() == "'a b;rm'"

    def test_doctor_never_says_dollar_user(self) -> None:
        """An admin's shell expands $USER to the ADMIN's name — lingering for the
        wrong account, and the user stays unfixed."""
        with patch.object(systemd.pwd, "getpwuid", return_value=MagicMock(pw_name="realuser")):
            remediation = service_health._linger_finding(False)["remediation"]
        assert "$USER" not in remediation
        assert "sudo loginctl enable-linger realuser" in remediation

    def test_the_banner_does_not_claim_a_cause_it_does_not_know(self) -> None:
        _, warnings = _banner(lingering=False)
        assert "usually" in warnings
        assert "every user service" in warnings, "say once that linger is account-wide"

    def test_su_or_sudo_gets_told_to_log_in_directly(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`su - user` / `sudo -u user` leave XDG_RUNTIME_DIR unset, so systemctl
        --user fails even with the manager running; linger would not help."""
        bus = tmp_path / "run" / "bus"
        bus.parent.mkdir()
        bus.touch()  # the user's manager IS running; this shell just can't reach it
        monkeypatch.setattr(systemd, "_user_bus", lambda: bus)
        calls: list = []
        loginctl = _fake_loginctl(linger=False, refuse=True, calls=calls)

        def fake_run(args: list[str], **kwargs):
            if args[:2] == ["systemctl", "--user"] and "daemon-reload" in args:
                raise subprocess.CalledProcessError(1, args, stderr="Failed to connect to bus")
            return loginctl(args, **kwargs)

        with pytest.raises(WorthlessError) as exc:
            _install(home, tmp_path, fake_run)
        said = " ".join(str(exc.value).split())
        assert "machinectl shell" in said and "su" in said

    def test_json_says_whether_it_survives_logout(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Agents read --json: "installed": true alone reads as "protected after logout"."""
        backend = MagicMock()
        backend.install.return_value = False
        with (
            patch("worthless.cli.commands.service._backend", return_value=backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="systemd",
            ),
            patch(
                "worthless.cli.commands.service.resolve_worthless_binary",
                return_value=Path("/usr/local/bin/worthless"),
            ),
            patch("worthless.cli.commands.service.preflight_service_install"),
            patch("worthless.cli.commands.service.get_home", return_value=home),
        ):
            result = CliRunner().invoke(app, ["--json", "service", "install", "--yes"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["lingering"] is False

    def test_linger_is_checked_and_turned_on_for_the_real_account(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bugbot: the advice used the real account but the check used USER, so
        after an admin enabled linger, a stale USER still read it as off."""
        monkeypatch.setenv("USER", "stale")
        calls: list = []
        _install(home, tmp_path, _fake_loginctl(linger=False, refuse=False, calls=calls))
        assert ["loginctl", "show-user", "sshuser", "-p", "Linger"] in calls
        assert ["loginctl", "--no-ask-password", "enable-linger", "sshuser"] in calls
        assert not any("stale" in arg for call in calls for arg in call)

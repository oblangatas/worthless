"""CLI tests for ``worthless service`` — backends mocked."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import ServiceState, ServiceStatus
from worthless.cli.errors import ErrorCode, WorthlessError
from tests.fixtures.dirty_home import write_secure_fernet_key

runner = CliRunner()


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    base = tmp_path / ".worthless"
    base.mkdir()
    write_secure_fernet_key(base / "fernet.key", b"x" * 32)
    return base


class TestServiceInstall:
    def test_install_success_json(self, home_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        mock_backend = MagicMock()
        mock_backend.plist_path.return_value = home_dir / "sh.worthless.proxy.plist"
        mock_backend.unit_path = MagicMock()  # unused on darwin

        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="launchd",
            ),
            patch(
                "worthless.cli.commands.service.resolve_worthless_binary",
                return_value=Path("/usr/local/bin/worthless"),
            ),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value = WorthlessHome(base_dir=home_dir)
            result = runner.invoke(
                app,
                ["--json", "service", "install", "--yes"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["installed"] is True
        assert payload["platform"] == "launchd"
        mock_backend.install.assert_called_once()

    def test_status_not_installed(self, home_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = None
        mock_backend.detect_status.return_value = ServiceStatus(
            state=ServiceState.NOT_INSTALLED,
            unit_path=None,
            binary=None,
            port=8787,
            healthy=False,
        )

        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="systemd",
            ),
            patch(
                "worthless.cli.commands.service.detect_proxy_runtime",
                return_value=MagicMock(running=False, source=None, pid=None),
            ),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["--json", "service", "status"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["state"] == "not_installed"
        assert payload["healthy"] is False

    def test_install_preflight_fails_without_fernet(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
            patch(
                "worthless.cli.commands.service.preflight_service_install",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no fernet"),
            ),
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "install", "--yes"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code != 0
        mock_backend.install.assert_not_called()

    def test_windows_rejected(self) -> None:
        with patch("worthless.cli.commands.service.fail_if_windows") as mock_fail:
            from worthless.cli.errors import ErrorCode, WorthlessError

            mock_fail.side_effect = WorthlessError(ErrorCode.PLATFORM_UNSUPPORTED, "nope")
            result = runner.invoke(app, ["service", "status"])
        assert result.exit_code != 0

    def test_uninstall_json(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["--json", "service", "uninstall", "--yes"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["installed"] is False
        mock_backend.uninstall.assert_called_once()

    def test_stop_invokes_backend(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        mock_home = MagicMock()
        mock_home.base_dir = home_dir
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home", return_value=mock_home),
        ):
            result = runner.invoke(
                app,
                ["service", "stop"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        mock_backend.stop.assert_called_once_with(mock_home)

    def test_start_invokes_backend(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "start"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        mock_backend.start.assert_called_once()

    def test_start_banner_states_persistence_guarantee(self, home_dir: Path) -> None:
        """WOR-726: the banner must tell the user the proxy now survives crashes
        — the thing that distinguishes it from `worthless up`. It must also show
        the port the INSTALLED unit binds, not the ambient WORTHLESS_PORT of this
        shell (CodeRabbit). It must NOT claim "survives reboot": WOR-725 has
        never verified that."""
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = 9191
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
            patch("worthless.cli.commands.service.is_wsl", return_value=False),
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "start"],
                env={"WORTHLESS_HOME": str(home_dir), "WORTHLESS_PORT": "8787"},
            )
        assert result.exit_code == 0, result.output
        assert "Auto-restarts" in result.output
        # Deliberately NOT asserting "survives reboot". WOR-725 has never verified
        # that on any platform, and on WSL it is measurably false by default: with
        # stock settings WSL stops the distro ~15 s after the last WSL window
        # closes (proven on real WSL2, run 35055982192). A test that pins an
        # unverified promise is a test that keeps it shipping.
        assert "survives reboot" not in result.output
        assert "wslconfig" not in result.output.lower(), "no WSL advice off WSL"
        # Installed port (9191) wins over the shell's WORTHLESS_PORT (8787).
        assert "9191" in result.output
        assert "8787" not in result.output

    def test_banner_on_wsl_warns_the_proxy_stops_with_the_terminal(self, home_dir: Path) -> None:
        """WOR-853: on real WSL the distro, and the service, stop ~15 s after the
        last terminal closes unless .wslconfig sets instanceIdleTimeout=-1. The
        banner must not let a WSL user believe otherwise."""
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = 8787
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
            patch("worthless.cli.commands.service.is_wsl", return_value=True),
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(app, ["service", "start"], env={"WORTHLESS_HOME": str(home_dir)})
        assert result.exit_code == 0, result.output
        assert "instanceIdleTimeout=-1" in result.output

    def test_restart_invokes_backend(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "restart"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        mock_backend.restart.assert_called_once()

    def test_logs_invokes_backend(self, home_dir: Path) -> None:
        mock_backend = MagicMock()
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "logs", "--follow"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        mock_backend.tail_logs.assert_called_once()
        assert mock_backend.tail_logs.call_args.kwargs.get("follow") is True

    def test_status_human_mode(self, home_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = None
        mock_backend.detect_status.return_value = ServiceStatus(
            state=ServiceState.RUNNING,
            unit_path=home_dir / "worthless-proxy.service",
            binary="/usr/bin/worthless",
            port=8787,
            healthy=True,
            detail="",
        )
        runtime = MagicMock(running=True, source="health", pid=123)
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="systemd",
            ),
            patch("worthless.cli.commands.service.detect_proxy_runtime", return_value=runtime),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(
                app,
                ["service", "status"],
                env={"WORTHLESS_HOME": str(home_dir)},
            )
        assert result.exit_code == 0, result.output
        # Console renders to stderr; `output` is the mixed stream (typer >=0.26).
        assert "running" in result.output.lower()


class TestLingerIsDisclosed:
    """We switch on account-level state and never switch it off. Say so.

    `_ensure_linger` runs `loginctl enable-linger` during a systemd install, so
    the service survives logout. `worthless service uninstall` does not reverse
    it, and deliberately so: linger is account-wide, other user services may
    depend on it, and turning off state we may not have created is exactly the
    mistake the install rollback's `created_here` guard exists to avoid.

    Review (karen, 2026-10-08) called the silence the unfixed half of the
    consent defect. Disclosure is the fix; a precise undo is worthless-fzas.
    """

    def test_start_does_not_claim_it_enabled_linger(self, home_dir: Path) -> None:
        """`service start` never calls _ensure_linger, so it must not take credit.

        Review (Cursor Bugbot, 2026-10-08): the banner is shared, and the first
        version of this hint fired on start too.
        """
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = 8787
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="systemd",
            ),
            patch("worthless.cli.commands.service.is_wsl", return_value=False),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(app, ["service", "start"], env={"WORTHLESS_HOME": str(home_dir)})

        assert result.exit_code == 0, result.output
        assert "Lingering is now on" not in result.output

    def test_wsl_is_not_told_the_service_survives_logout(self, home_dir: Path) -> None:
        """WSL runs the systemd backend but the proxy dies with the terminal.

        Review (Cursor Bugbot, 2026-10-08): putting "survives logout" directly
        under the 15-second warning contradicts it. Linger does not outlive
        WSL's idle shutdown.
        """
        with (
            patch("worthless.cli.commands.service.is_wsl", return_value=True),
        ):
            from worthless.cli.commands.service import _print_service_banner

            console = MagicMock()
            console.json_mode = False
            _print_service_banner(console, platform="systemd", port=8787, after_install=True)

        said = " ".join(str(c) for c in console.print_hint.call_args_list)
        assert "Lingering is now on" not in said
        warned = " ".join(str(c) for c in console.print_warning.call_args_list)
        assert "15 seconds" in warned, "the WSL warning itself must still appear"

    def test_systemd_install_says_uninstall_leaves_linger_on(self) -> None:
        """The install path IS where _ensure_linger runs, so it must disclose."""
        with patch("worthless.cli.commands.service.is_wsl", return_value=False):
            from worthless.cli.commands.service import _print_service_banner

            console = MagicMock()
            console.json_mode = False
            _print_service_banner(console, platform="systemd", port=8787, after_install=True)

        said = " ".join(str(c) for c in console.print_hint.call_args_list)
        assert "Lingering is now on" in said
        assert "leaves it on" in said
        assert "disable-linger" in said

    def test_launchd_does_not_mention_linger(self, home_dir: Path) -> None:
        """launchd has no such concept; the hint must not leak to macOS."""
        mock_backend = MagicMock()
        mock_backend.installed_port.return_value = 8787
        with (
            patch("worthless.cli.commands.service._backend", return_value=mock_backend),
            patch(
                "worthless.cli.commands.service.current_platform_backend_name",
                return_value="launchd",
            ),
            patch("worthless.cli.commands.service.get_home") as mock_home,
        ):
            mock_home.return_value.base_dir = home_dir
            result = runner.invoke(app, ["service", "start"], env={"WORTHLESS_HOME": str(home_dir)})

        assert result.exit_code == 0, result.output
        assert "linger" not in result.output.lower()

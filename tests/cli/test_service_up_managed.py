"""``worthless up`` behavior under ``WORTHLESS_SERVICE_MANAGED=1``."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner()


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    (base / "fernet.key").write_bytes(b"x" * 32)
    return WorthlessHome(base_dir=base)


class TestServiceManagedUp:
    def test_up_exits_zero_when_port_already_healthy(self, home: WorthlessHome) -> None:
        pid_file = home.base_dir / "proxy.pid"
        pid_file.write_text("4242 8787\n")
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.pid_path", return_value=pid_file),
            patch("worthless.cli.commands.up.read_pid", return_value=(4242, 8787)),
            patch("worthless.cli.commands.up.check_pid", return_value=True),
            patch("worthless.cli.commands.up.poll_health", return_value=True) as mock_health,
            patch("worthless.cli.commands.up._start_foreground") as mock_start,
        ):
            result = runner.invoke(
                app,
                ["up"],
                env={"WORTHLESS_HOME": str(home.base_dir), "WORTHLESS_SERVICE_MANAGED": "1"},
            )

        assert result.exit_code == 0
        mock_health.assert_called_once()
        mock_start.assert_not_called()

    def test_up_does_not_noop_on_foreign_healthz_without_pidfile(self, home: WorthlessHome) -> None:
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.pid_path", return_value=home.base_dir / "proxy.pid"),
            patch("worthless.cli.commands.up.read_pid", return_value=None),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up._start_foreground") as mock_start,
        ):
            result = runner.invoke(
                app,
                ["up"],
                env={"WORTHLESS_HOME": str(home.base_dir), "WORTHLESS_SERVICE_MANAGED": "1"},
            )

        assert result.exit_code == 0
        mock_start.assert_called_once()

    def test_up_still_starts_when_managed_but_port_down(self, home: WorthlessHome) -> None:
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.poll_health", return_value=False),
            patch("worthless.cli.commands.up._start_foreground") as mock_start,
            patch("worthless.cli.commands.up.pid_path", return_value=home.base_dir / "proxy.pid"),
            patch("worthless.cli.commands.up.read_pid", return_value=None),
        ):
            result = runner.invoke(
                app,
                ["up"],
                env={"WORTHLESS_HOME": str(home.base_dir), "WORTHLESS_SERVICE_MANAGED": "1"},
            )

        assert result.exit_code == 0
        mock_start.assert_called_once()

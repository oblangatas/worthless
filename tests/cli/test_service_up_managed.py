"""``worthless up`` behavior under ``WORTHLESS_SERVICE_MANAGED=1``."""

from __future__ import annotations

import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner()


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    fernet = base / "fernet.key"
    fernet.write_bytes(b"x" * 32)
    fernet.chmod(0o600)
    return WorthlessHome(base_dir=base)


class TestServiceManagedUp:
    def test_up_exits_zero_when_port_already_healthy(self, home: WorthlessHome) -> None:
        pid_file = home.base_dir / "proxy.pid"
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.poll_health", return_value=True) as mock_health,
            patch("worthless.cli.commands.up.poll_health_pid", return_value=4242),
            patch("worthless.cli.commands.up.pid_path", return_value=pid_file),
            patch("worthless.cli.commands.up.read_pid", return_value=(4242, 8787)),
            patch("worthless.cli.commands.up.check_pid", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=True),
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

    @pytest.mark.adversarial
    def test_up_starts_when_healthy_orphan_without_pidfile(self, home: WorthlessHome) -> None:
        """worthless-6gkb: /healthz up but no pidfile → must spawn sidecar+proxy."""
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
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

    @pytest.mark.adversarial
    def test_up_starts_when_healthz_ok_but_sidecar_dead(self, home: WorthlessHome) -> None:
        """Proxy-only orphan: /healthz + pidfile but sidecar IPC dead → respawn."""
        pid_file = home.base_dir / "proxy.pid"
        with (
            patch("worthless.cli.commands.up.get_home", return_value=home),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=4242),
            patch("worthless.cli.commands.up.pid_path", return_value=pid_file),
            patch("worthless.cli.commands.up.read_pid", return_value=(4242, 8787)),
            patch("worthless.cli.commands.up.check_pid", return_value=True),
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


class TestManagedSidecarHealthy:
    def test_false_when_no_sockets(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _managed_sidecar_healthy

        assert _managed_sidecar_healthy(home) is False

    def test_true_when_newest_socket_probes_ok(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _managed_sidecar_healthy

        run_root = home.base_dir / "run"
        sock = run_root / "4242" / "sidecar.sock"
        sock.parent.mkdir(parents=True)

        with (
            patch("worthless.cli.commands.up.list_sidecar_sockets", return_value=[sock]),
            patch("worthless.cli.commands.up.probe_socket", return_value=True) as mock_probe,
        ):
            assert _managed_sidecar_healthy(home) is True

        mock_probe.assert_called_once_with(sock)

    def test_false_when_newest_socket_fails_probe(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _managed_sidecar_healthy

        run_root = home.base_dir / "run"
        sock = run_root / "4242" / "sidecar.sock"
        sock.parent.mkdir(parents=True)

        with (
            patch("worthless.cli.commands.up.list_sidecar_sockets", return_value=[sock]),
            patch("worthless.cli.commands.up.probe_socket", return_value=False),
        ):
            assert _managed_sidecar_healthy(home) is False

    def test_uses_decrypt_open_when_enrollments_exist(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _managed_sidecar_healthy

        run_root = home.base_dir / "run"
        sock = run_root / "4242" / "sidecar.sock"
        sock.parent.mkdir(parents=True)
        (home.base_dir / "worthless.db").touch()

        with (
            patch("worthless.cli.commands.up.list_sidecar_sockets", return_value=[sock]),
            patch(
                "worthless.cli.commands.up.asyncio.run",
                side_effect=[(b"cipher", b"alias"), sock],
            ) as mock_run,
            patch("worthless.cli.commands.up.probe_socket") as mock_probe,
        ):
            assert _managed_sidecar_healthy(home) is True

        assert mock_run.call_count == 2
        mock_probe.assert_not_called()


class TestServiceManagedSessionOwnsPort:
    def test_false_when_not_service_managed(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _service_managed_session_owns_port

        with patch("worthless.cli.commands.up.is_service_managed", return_value=False):
            assert _service_managed_session_owns_port(home, 8787) is False

    def test_true_when_health_sidecar_pid_all_match(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _service_managed_session_owns_port

        pid_file = home.base_dir / "proxy.pid"
        with (
            patch("worthless.cli.commands.up.is_service_managed", return_value=True),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=True),
            patch("worthless.cli.commands.up.pid_path", return_value=pid_file),
            patch("worthless.cli.commands.up.read_pid", return_value=(4242, 8787)),
            patch("worthless.cli.commands.up.check_pid", return_value=True),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=4242),
        ):
            assert _service_managed_session_owns_port(home, 8787) is True

    def test_false_when_sidecar_unhealthy(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _service_managed_session_owns_port

        with (
            patch("worthless.cli.commands.up.is_service_managed", return_value=True),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
        ):
            assert _service_managed_session_owns_port(home, 8787) is False


class TestReclaimManagedProxyWithoutSidecar:
    def test_noop_when_not_service_managed(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _reclaim_managed_proxy_without_sidecar

        console = MagicMock()
        with patch("worthless.cli.commands.up.is_service_managed", return_value=False):
            _reclaim_managed_proxy_without_sidecar(home, 8787, home.base_dir / "proxy.pid", console)
        console.print_warning.assert_not_called()

    def test_cleans_stale_pid_when_port_down(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _reclaim_managed_proxy_without_sidecar

        pid_file = home.base_dir / "proxy.pid"
        console = MagicMock()
        with (
            patch("worthless.cli.commands.up.is_service_managed", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
            patch("worthless.cli.commands.up.poll_health", return_value=False),
            patch("worthless.cli.commands.up.cleanup_stale_pid") as mock_cleanup,
        ):
            _reclaim_managed_proxy_without_sidecar(home, 8787, pid_file, console)
        mock_cleanup.assert_called_once_with(pid_file)

    @pytest.mark.adversarial
    def test_kills_proxy_orphan_when_sidecar_dead(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _reclaim_managed_proxy_without_sidecar

        pid_file = home.base_dir / "proxy.pid"
        console = MagicMock()
        with (
            patch("worthless.cli.commands.up.is_service_managed", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up.read_pid", return_value=(9999, 8787)),
            patch("worthless.cli.commands.up.check_pid", return_value=False),
            patch("worthless.cli.commands.up.cleanup_stale_pid") as mock_cleanup,
            patch("worthless.cli.commands.up.os.kill") as mock_kill,
            patch("worthless.cli.commands.up.shutil.rmtree"),
        ):
            _reclaim_managed_proxy_without_sidecar(home, 8787, pid_file, console)
        mock_kill.assert_not_called()
        mock_cleanup.assert_called_once_with(pid_file)
        console.print_warning.assert_not_called()

    @pytest.mark.adversarial
    def test_sends_sigterm_to_live_orphan_proxy(self, home: WorthlessHome) -> None:
        from worthless.cli.commands.up import _reclaim_managed_proxy_without_sidecar

        pid_file = home.base_dir / "proxy.pid"
        console = MagicMock()
        with (
            patch("worthless.cli.commands.up.is_service_managed", return_value=True),
            patch("worthless.cli.commands.up._managed_sidecar_healthy", return_value=False),
            patch("worthless.cli.commands.up.poll_health", return_value=True),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=9999),
            patch("worthless.cli.commands.up.read_pid", return_value=(9999, 8787)),
            patch("worthless.cli.commands.up.check_pid", side_effect=[True, True, False, False]),
            patch("worthless.cli.commands.up.cleanup_stale_pid"),
            patch("worthless.cli.commands.up.os.kill") as mock_kill,
            patch("worthless.cli.commands.up.time.sleep"),
            patch("worthless.cli.commands.up.shutil.rmtree"),
        ):
            _reclaim_managed_proxy_without_sidecar(home, 8787, pid_file, console)
        mock_kill.assert_called_once_with(9999, signal.SIGTERM)
        console.print_warning.assert_called_once()

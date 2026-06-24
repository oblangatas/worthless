"""Integration tests for ``start_supervised_proxy`` and default-command proxy phase.

Linear: WOR-717 (supervised default start).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState
from worthless.cli.commands.up import start_daemon, start_supervised_proxy
from worthless.cli.default_command import _ensure_proxy_running


class TestStartSupervisedProxyIntegration:
    """``start_supervised_proxy`` spawns detached ``worthless up``, not ``start_daemon``."""

    def test_spawns_detached_worthless_up_with_home_and_port(
        self,
        home_with_key: WorthlessHome,
        tmp_path,
    ) -> None:
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return MagicMock(pid=99999)

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=4242),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            console = MagicMock()
            log_file = home_with_key.base_dir / "proxy.log"
            pid = start_supervised_proxy(home_with_key, 8787, log_file, console)

        assert captured["cmd"] == [str(binary), "up", "--port", "8787"]
        assert captured["kwargs"]["start_new_session"] is True
        assert captured["kwargs"]["env"]["WORTHLESS_HOME"] == str(home_with_key.base_dir)
        assert captured["kwargs"]["env"]["WORTHLESS_PORT"] == "8787"
        assert pid == 4242

    def test_never_invokes_start_daemon(
        self,
        home_with_key: WorthlessHome,
        tmp_path,
    ) -> None:
        daemon_called = False

        def fake_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 1

        def fake_popen(cmd, **kwargs):
            return MagicMock(pid=1)

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            patch("worthless.cli.commands.up.start_daemon", fake_daemon),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=42),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(
                home_with_key,
                8787,
                home_with_key.base_dir / "proxy.log",
                MagicMock(),
            )

        assert not daemon_called
        assert start_daemon is not None  # legacy escape hatch remains importable


class TestDefaultProxyPhaseIntegration:
    """Default command proxy phase must respect unified runtime detection."""

    @pytest.mark.integration
    def test_skips_supervised_start_when_service_reports_healthy(
        self,
        home_with_key: WorthlessHome,
    ) -> None:
        supervised_called = False

        def fake_supervised(*args, **kwargs):
            nonlocal supervised_called
            supervised_called = True
            return 1

        runtime = ProxyRuntimeState(
            running=True,
            pid=None,
            port=8787,
            source="service",
            service_state=ServiceState.RUNNING,
        )

        with (
            patch(
                "worthless.cli.default_command.detect_proxy_runtime",
                return_value=runtime,
            ),
            patch(
                "worthless.cli.default_command.start_supervised_proxy",
                fake_supervised,
            ),
        ):
            running, _pid, port = _ensure_proxy_running(home_with_key, MagicMock())

        assert running is True
        assert port == 8787
        assert not supervised_called

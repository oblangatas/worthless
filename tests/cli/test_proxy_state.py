"""Tests for unified proxy + service runtime detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import ServiceState, ServiceStatus
from worthless.cli.commands.service.proxy_state import detect_proxy_runtime
from worthless.cli.process import write_pid


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    (base / "fernet.key").write_bytes(b"x" * 32)
    return WorthlessHome(base_dir=base)


class TestDetectProxyRuntime:
    def test_pidfile_live(self, home: WorthlessHome) -> None:
        pf = home.base_dir / "proxy.pid"
        write_pid(pf, 99999, 8787)
        with patch("worthless.cli.commands.service.proxy_state.check_pid", return_value=True):
            runtime = detect_proxy_runtime(home)
        assert runtime.running is True
        assert runtime.source == "pidfile"
        assert runtime.pid == 99999

    def test_health_fallback(self, home: WorthlessHome) -> None:
        with patch("worthless.cli.commands.service.proxy_state.poll_health", return_value=True):
            runtime = detect_proxy_runtime(home)
        assert runtime.running is True
        assert runtime.source == "health"

    def test_service_stopped(self, home: WorthlessHome, tmp_path: Path) -> None:
        stopped = ServiceStatus(
            state=ServiceState.STOPPED,
            unit_path=tmp_path / "worthless-proxy.service",
            binary="/usr/bin/worthless",
            port=8787,
            healthy=False,
        )
        with (
            patch("worthless.cli.commands.service.proxy_state.poll_health", return_value=False),
            patch(
                "worthless.cli.commands.service.proxy_state.current_platform_backend_name",
                return_value="systemd",
            ),
            patch(
                "worthless.cli.commands.service.systemd.detect_status",
                return_value=stopped,
            ),
        ):
            runtime = detect_proxy_runtime(home)
        assert runtime.running is False
        assert runtime.service_state == ServiceState.STOPPED

    def test_service_healthy_via_backend(self, home: WorthlessHome) -> None:
        healthy = ServiceStatus(
            state=ServiceState.RUNNING,
            unit_path=None,
            binary="/usr/bin/worthless",
            port=8787,
            healthy=True,
        )
        with (
            patch("worthless.cli.commands.service.proxy_state.poll_health", return_value=False),
            patch(
                "worthless.cli.commands.service.proxy_state.current_platform_backend_name",
                return_value="launchd",
            ),
            patch(
                "worthless.cli.commands.service.launchd.detect_status",
                return_value=healthy,
            ),
        ):
            runtime = detect_proxy_runtime(home)
        assert runtime.running is True
        assert runtime.source == "service"
        assert runtime.service_state == ServiceState.RUNNING

"""Unified proxy + service runtime detection (WOR-193)."""

from __future__ import annotations

from dataclasses import dataclass

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import ServiceState, current_platform_backend_name
from worthless.cli.errors import WorthlessError
from worthless.cli.process import check_pid, pid_path, poll_health, read_pid, resolve_port


@dataclass(frozen=True)
class ProxyRuntimeState:
    """Where we learned proxy liveness from."""

    running: bool
    pid: int | None
    port: int
    source: str  # pidfile | health | service | none
    service_state: ServiceState | None = None


def detect_proxy_runtime(home: WorthlessHome, *, port: int | None = None) -> ProxyRuntimeState:
    """PID file → health probe → platform service state."""
    actual_port = resolve_port(port)
    pf = pid_path(home)

    if pf.exists():
        info = read_pid(pf)
        if info is not None:
            pid, recorded_port = info
            if check_pid(pid):
                return ProxyRuntimeState(
                    running=True,
                    pid=pid,
                    port=recorded_port,
                    source="pidfile",
                )
            pf.unlink(missing_ok=True)
            actual_port = recorded_port

    if poll_health(actual_port, timeout=1.0):
        return ProxyRuntimeState(
            running=True,
            pid=None,
            port=actual_port,
            source="health",
        )

    try:
        platform = current_platform_backend_name()
        if platform == "launchd":
            from worthless.cli.commands.service import launchd as backend
        else:
            from worthless.cli.commands.service import systemd as backend

        status = backend.detect_status(home, actual_port)
        if status.healthy:
            return ProxyRuntimeState(
                running=True,
                pid=None,
                port=actual_port,
                source="service",
                service_state=status.state,
            )
        if status.state != ServiceState.NOT_INSTALLED:
            return ProxyRuntimeState(
                running=False,
                pid=None,
                port=actual_port,
                source="service",
                service_state=status.state,
            )
    except WorthlessError:
        pass

    return ProxyRuntimeState(
        running=False,
        pid=None,
        port=0,
        source="none",
    )

"""Unified proxy + service runtime detection (WOR-193)."""

from __future__ import annotations

from dataclasses import dataclass

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import (
    ServiceState,
    ServiceStatus,
    current_platform_backend_name,
)
from worthless.cli.errors import WorthlessError
from worthless.cli.platform import is_wsl
from worthless.cli.process import check_pid, pid_path, poll_health, read_pid, resolve_port


@dataclass(frozen=True)
class ProxyRuntimeState:
    """Where we learned proxy liveness from."""

    running: bool
    pid: int | None
    port: int
    source: str  # pidfile | health | service | none
    service_state: ServiceState | None = None


def _detect_service_status(home: WorthlessHome, port: int) -> ServiceStatus | None:
    try:
        platform = current_platform_backend_name()
        if platform == "launchd":
            from worthless.cli.commands.service import launchd as backend
        else:
            from worthless.cli.commands.service import systemd as backend

        return backend.detect_status(home, port)
    except WorthlessError:
        return None


def detect_proxy_runtime(home: WorthlessHome, *, port: int | None = None) -> ProxyRuntimeState:
    """PID file → platform service state (when installed) → health probe."""
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

    status = _detect_service_status(home, actual_port)
    if status is not None and status.state != ServiceState.NOT_INSTALLED:
        if status.state in (ServiceState.STOPPED, ServiceState.FAILED):
            return ProxyRuntimeState(
                running=False,
                pid=None,
                port=actual_port,
                source="service",
                service_state=status.state,
            )
        if status.healthy:
            return ProxyRuntimeState(
                running=True,
                pid=None,
                port=actual_port,
                source="service",
                service_state=status.state,
            )

    if poll_health(actual_port, timeout=1.0):
        return ProxyRuntimeState(
            running=True,
            pid=None,
            port=actual_port,
            source="health",
            service_state=status.state if status is not None else None,
        )

    if status is not None and status.state != ServiceState.NOT_INSTALLED:
        return ProxyRuntimeState(
            running=False,
            pid=None,
            port=actual_port,
            source="service",
            service_state=status.state,
        )

    return ProxyRuntimeState(
        running=False,
        pid=None,
        port=0,
        source="none",
    )


def survives_restart(home: WorthlessHome, port: int) -> bool:
    """True only when the background service is installed AND running.

    A proxy started by `worthless up` or plain `worthless` is up now but does
    not come back after a restart (WOR-860). Anything short of a running
    service, including "can't tell", reads as False: this decides whether we
    promise survival, so the cautious answer is the default.
    """
    status = _detect_service_status(home, port)
    return status is not None and status.state == ServiceState.RUNNING


def restart_note(survives: bool) -> str:
    """The one sentence `status`, `verify` and the editor all say about restarts.

    WOR-860 option C: one wording, many surfaces, so they cannot drift. It
    never mentions the terminal: plain `worthless` starts a DETACHED proxy that
    outlives it; only a restart is certain to end a non-service proxy. When the
    service runs, say when it is set to start, never "survives a restart"
    (proven per platform in CI, not promised by this text).
    """
    if not survives:
        return (
            "Not after a restart: the proxy isn't a background service. "
            "Keep it running: `worthless service install`"
        )
    if current_platform_backend_name() == "launchd":
        return "Runs as a background service that starts when you log in."
    if is_wsl():
        return (
            "Runs as a background service that starts with this WSL distro. "
            "WSL stops it about 15 seconds after your last WSL window closes "
            "unless %USERPROFILE%\\.wslconfig sets instanceIdleTimeout=-1."
        )
    return "Runs as a background service that starts when this computer starts."

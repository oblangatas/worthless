"""Linux systemd user-unit backend for ``worthless service`` (WOR-175)."""

from __future__ import annotations

import os
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import templates
from worthless.cli.commands.service._common import (
    ServiceState,
    ServiceStatus,
    atomic_write_text,
    resolve_worthless_binary,
    run_cmd,
    service_paths,
    verify_proxy_health,
)
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.process import poll_health, resolve_port

SYSTEMD_UNIT = templates.SYSTEMD_UNIT_NAME


def _session_user() -> str:
    """Resolve login name without eager ``os.getlogin()`` (CI has no tty)."""
    for key in ("USER", "LOGNAME"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    try:
        return os.getlogin()
    except OSError:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name


def unit_path() -> Path:
    return Path(templates.systemd_unit_path(str(Path.home())))


def _systemctl(*args: str, check: bool = True):
    return run_cmd(["systemctl", "--user", *args], check=check)


def _linger_enabled() -> bool:
    user = _session_user()
    result = run_cmd(
        ["loginctl", "show-user", user, "-p", "Linger"],
        check=False,
    )
    if result.returncode != 0:
        return False
    return "Linger=yes" in (result.stdout or "")


def _ensure_linger() -> None:
    if _linger_enabled():
        return
    run_cmd(["loginctl", "enable-linger", _session_user()])


def installed_port() -> int | None:
    """Return WORTHLESS_PORT from the installed unit, if present."""
    path = unit_path()
    if not path.is_file():
        return None
    prefix = "Environment=WORTHLESS_PORT="
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return int(stripped[len(prefix) :])
    return None


def _active_state() -> str:
    result = _systemctl("is-active", SYSTEMD_UNIT, check=False)
    if result.returncode != 0 and not (result.stdout or "").strip():
        return "inactive"
    return (result.stdout or "").strip()


def detect_status(home: WorthlessHome, port: int) -> ServiceStatus:
    path = unit_path()
    if not path.is_file():
        return ServiceStatus(
            state=ServiceState.NOT_INSTALLED,
            unit_path=None,
            binary=None,
            port=port,
            healthy=False,
        )
    try:
        binary = str(resolve_worthless_binary())
    except WorthlessError:
        binary = None
    active = _active_state()
    if active != "active":
        state = ServiceState.STOPPED if active in ("inactive", "dead") else ServiceState.FAILED
        return ServiceStatus(
            state=state,
            unit_path=path,
            binary=binary,
            port=port,
            healthy=False,
            detail=f"systemd reports {active!r}.",
        )
    healthy = poll_health(port, timeout=1.0)
    return ServiceStatus(
        state=ServiceState.RUNNING if healthy else ServiceState.FAILED,
        unit_path=path,
        binary=binary,
        port=port,
        healthy=healthy,
        detail="" if healthy else "Unit active but /healthz failed.",
    )


def install(home: WorthlessHome, *, port: int | None = None) -> None:
    binary = resolve_worthless_binary()
    _, worthless_home = service_paths(home)
    actual_port = resolve_port(port)
    content = templates.render_systemd_unit(
        binary=str(binary),
        worthless_home=worthless_home,
        port=actual_port if port is not None or os.environ.get("WORTHLESS_PORT") else None,
    )
    path = unit_path()
    atomic_write_text(path, content, mode=0o600)
    _ensure_linger()
    _systemctl("daemon-reload")
    _systemctl("enable", "--now", SYSTEMD_UNIT)
    verify_proxy_health(actual_port)


def uninstall(home: WorthlessHome) -> None:
    path = unit_path()
    if path.is_file():
        _systemctl("disable", "--now", SYSTEMD_UNIT, check=False)
        path.unlink(missing_ok=True)
        _systemctl("daemon-reload", check=False)


def stop() -> None:
    if not unit_path().is_file():
        raise WorthlessError(ErrorCode.PROXY_NOT_RUNNING, "Service is not installed.")
    _systemctl("stop", SYSTEMD_UNIT)


def start(home: WorthlessHome) -> None:
    if not unit_path().is_file():
        raise WorthlessError(
            ErrorCode.PROXY_NOT_RUNNING,
            "Service is not installed. Run `worthless service install` first.",
        )
    _systemctl("start", SYSTEMD_UNIT)
    verify_proxy_health(resolve_port(None))


def restart(home: WorthlessHome) -> None:
    if not unit_path().is_file():
        raise WorthlessError(
            ErrorCode.PROXY_NOT_RUNNING,
            "Service is not installed. Run `worthless service install` first.",
        )
    _systemctl("restart", SYSTEMD_UNIT)
    verify_proxy_health(resolve_port(None))


def tail_logs(home: WorthlessHome, *, follow: bool) -> None:
    if not unit_path().is_file():
        raise WorthlessError(ErrorCode.PROXY_NOT_RUNNING, "Service is not installed.")
    args = ["journalctl", "--user", "-u", SYSTEMD_UNIT, "-n", "200", "--no-pager"]
    if follow:
        args.append("-f")
    run_cmd(args, check=True, capture=False)

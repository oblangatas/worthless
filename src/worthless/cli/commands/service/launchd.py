"""macOS LaunchAgent backend for ``worthless service`` (WOR-174)."""

from __future__ import annotations

import os
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import templates
from worthless.cli.commands.service._common import (
    ServiceState,
    ServiceStatus,
    atomic_write_text,
    refuse_foreign_unit,
    resolve_worthless_binary,
    run_cmd,
    service_paths,
    unit_file_matches_home,
    verify_proxy_health,
)
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.process import poll_health, resolve_port


def plist_path() -> Path:
    return Path(templates.launchd_plist_path(str(Path.home())))


def _launchctl_domain() -> str:
    return f"gui/{os.getuid()}"


def _service_target() -> str:
    return f"{_launchctl_domain()}/{templates.LAUNCHD_LABEL}"


def installed_port() -> int | None:
    """Return WORTHLESS_PORT from the installed plist, if present."""
    path = plist_path()
    if not path.is_file():
        return None
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "<key>WORTHLESS_PORT</key>":
            continue
        if index + 1 >= len(lines):
            break
        value_line = lines[index + 1].strip()
        if value_line.startswith("<string>") and value_line.endswith("</string>"):
            return int(value_line[len("<string>") : -len("</string>")])
    return None


def _is_loaded() -> bool:
    result = run_cmd(
        ["launchctl", "print", _service_target()],
        check=False,
    )
    return result.returncode == 0


def detect_status(home: WorthlessHome, port: int) -> ServiceStatus:
    path = plist_path()
    if not unit_file_matches_home(path, home):
        return ServiceStatus(
            state=ServiceState.NOT_INSTALLED,
            unit_path=None,
            binary=None,
            port=port,
            healthy=False,
        )
    binary: str | None = None
    try:
        binary = str(resolve_worthless_binary())
    except WorthlessError:
        binary = None
    if not _is_loaded():
        return ServiceStatus(
            state=ServiceState.STOPPED,
            unit_path=path,
            binary=binary,
            port=port,
            healthy=False,
            detail="LaunchAgent installed but not loaded.",
        )
    healthy = poll_health(port, timeout=1.0)
    return ServiceStatus(
        state=ServiceState.RUNNING if healthy else ServiceState.FAILED,
        unit_path=path,
        binary=binary,
        port=port,
        healthy=healthy,
        detail="" if healthy else "LaunchAgent loaded but /healthz failed.",
    )


def install(home: WorthlessHome, *, port: int | None = None) -> None:
    path = plist_path()
    refuse_foreign_unit(path, home)
    binary = resolve_worthless_binary()
    log_path, worthless_home = service_paths(home)
    actual_port = resolve_port(port)
    content = templates.render_launchd_plist(
        binary=str(binary),
        worthless_home=worthless_home,
        log_path=str(log_path),
        port=actual_port if port is not None or os.environ.get("WORTHLESS_PORT") else None,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, content, mode=0o600)

    if _is_loaded():
        run_cmd(["launchctl", "bootout", _launchctl_domain(), str(path)], check=False)

    run_cmd(["launchctl", "bootstrap", _launchctl_domain(), str(path)])
    run_cmd(["launchctl", "kickstart", "-k", _service_target()])
    verify_proxy_health(actual_port)


def uninstall(home: WorthlessHome) -> None:
    path = plist_path()
    refuse_foreign_unit(path, home)
    if _is_loaded():
        run_cmd(["launchctl", "bootout", _launchctl_domain(), str(path)], check=False)
    if path.is_file():
        path.unlink()


def stop(home: WorthlessHome) -> None:
    path = plist_path()
    refuse_foreign_unit(path, home)
    if not path.is_file():
        raise WorthlessError(ErrorCode.PROXY_NOT_RUNNING, "Service is not installed.")
    run_cmd(["launchctl", "bootout", _launchctl_domain(), str(path)], check=False)


def start(home: WorthlessHome) -> None:
    path = plist_path()
    refuse_foreign_unit(path, home)
    if not path.is_file():
        raise WorthlessError(
            ErrorCode.PROXY_NOT_RUNNING,
            "Service is not installed. Run `worthless service install` first.",
        )
    if not _is_loaded():
        run_cmd(["launchctl", "bootstrap", _launchctl_domain(), str(path)])
    run_cmd(["launchctl", "kickstart", "-k", _service_target()])
    verify_proxy_health(resolve_port(None))


def restart(home: WorthlessHome) -> None:
    """Unload and rebootstrap the LaunchAgent so env/plist state is re-read."""
    path = plist_path()
    refuse_foreign_unit(path, home)
    if not path.is_file():
        raise WorthlessError(
            ErrorCode.PROXY_NOT_RUNNING,
            "Service is not installed. Run `worthless service install` first.",
        )
    if _is_loaded():
        run_cmd(["launchctl", "bootout", _launchctl_domain(), str(path)], check=False)
    run_cmd(["launchctl", "bootstrap", _launchctl_domain(), str(path)])
    run_cmd(["launchctl", "kickstart", "-k", _service_target()])
    verify_proxy_health(resolve_port(None))


def tail_logs(home: WorthlessHome, *, follow: bool) -> None:
    log_path, _ = service_paths(home)
    if not log_path.is_file():
        raise WorthlessError(
            ErrorCode.PROXY_NOT_RUNNING,
            f"No log file at {log_path}. Start the service first.",
        )
    args = ["tail", "-n", "200"]
    if follow:
        args.append("-f")
    args.append(str(log_path))
    run_cmd(args, check=True, capture=False)

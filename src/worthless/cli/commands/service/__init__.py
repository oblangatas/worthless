"""``worthless service`` — persistent proxy via launchd (macOS) or systemd (Linux)."""

from __future__ import annotations

import json
import sys

import typer

from worthless.cli.bootstrap import get_home
from worthless.cli.commands.service import launchd, systemd
from worthless.cli.commands.service._common import (
    ServiceState,
    current_platform_backend_name,
    preflight_service_install,
    resolve_worthless_binary,
)
from worthless.cli.commands.service.proxy_state import detect_proxy_runtime
from worthless.cli.console import get_console
from worthless.cli.errors import error_boundary
from worthless.cli.platform import fail_if_windows
from worthless.cli.process import resolve_port


def _backend():
    name = current_platform_backend_name()
    if name == "launchd":
        return launchd
    return systemd


def register_service_commands(app: typer.Typer) -> None:
    """Register the ``service`` subcommand group."""
    service_group = typer.Typer(
        help="Install and manage a persistent proxy (launchd on macOS, systemd on Linux).",
        no_args_is_help=True,
    )
    app.add_typer(service_group, name="service")

    @service_group.command("install")
    @error_boundary
    def service_install(
        port: int | None = typer.Option(
            None, "--port", "-p", help="Proxy port (default: WORTHLESS_PORT or 8787)"
        ),
        yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    ) -> None:
        """Write platform unit, enable, start, and verify /healthz."""
        fail_if_windows()
        console = get_console()
        home = get_home()
        backend = _backend()
        binary = resolve_worthless_binary()
        actual_port = resolve_port(port)

        if not yes and not console.json_mode:
            platform = current_platform_backend_name()
            if not typer.confirm(
                f"Install worthless proxy as a {platform} user service on port {actual_port}?",
                default=True,
            ):
                raise typer.Exit(code=0)

        preflight_service_install(home)
        backend.install(home, port=port)
        if console.json_mode:
            if backend is launchd:
                unit = str(launchd.plist_path())
            else:
                unit = str(systemd.unit_path())
            sys.stdout.write(
                json.dumps(
                    {
                        "installed": True,
                        "platform": current_platform_backend_name(),
                        "binary": str(binary),
                        "port": actual_port,
                        "unit_path": unit,
                    }
                )
                + "\n"
            )
        else:
            console.print_success(
                f"Service installed ({current_platform_backend_name()}). "
                f"Proxy healthy on 127.0.0.1:{actual_port}."
            )

    @service_group.command("uninstall")
    @error_boundary
    def service_uninstall(
        yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    ) -> None:
        """Stop service, deregister, and remove unit/plist."""
        fail_if_windows()
        console = get_console()
        home = get_home()
        if not yes and not console.json_mode:
            if not typer.confirm("Remove the worthless user service?", default=False):
                raise typer.Exit(code=0)
        _backend().uninstall(home)
        if console.json_mode:
            sys.stdout.write(json.dumps({"installed": False}) + "\n")
        else:
            console.print_success("Service uninstalled.")

    @service_group.command("status")
    @error_boundary
    def service_status() -> None:
        """Report service install state and proxy health."""
        fail_if_windows()
        console = get_console()
        home = get_home()
        backend = _backend()
        port = backend.installed_port() or resolve_port(None)
        status = backend.detect_status(home, port)
        runtime = detect_proxy_runtime(home, port=port)
        if console.json_mode:
            sys.stdout.write(
                json.dumps(
                    {
                        "state": status.state.value,
                        "healthy": status.healthy,
                        "port": status.port,
                        "unit_path": str(status.unit_path) if status.unit_path else None,
                        "binary": status.binary,
                        "detail": status.detail,
                        "platform": current_platform_backend_name(),
                        "proxy": {
                            "running": runtime.running,
                            "source": runtime.source,
                            "pid": runtime.pid,
                        },
                    },
                    indent=2,
                )
                + "\n"
            )
            return
        label = {
            ServiceState.NOT_INSTALLED: "not installed",
            ServiceState.STOPPED: "stopped",
            ServiceState.RUNNING: "running",
            ServiceState.FAILED: "failed",
        }[status.state]
        console.print_hint(f"Service: {label} ({current_platform_backend_name()})")
        if status.unit_path:
            console.print_hint(f"  Unit: {status.unit_path}")
        if status.binary:
            console.print_hint(f"  Binary: {status.binary}")
        console.print_hint(f"  Port: {status.port}")
        console.print_hint(f"  Health: {'ok' if status.healthy else 'fail'}")
        if status.detail:
            console.print_warning(status.detail)

    @service_group.command("start")
    @error_boundary
    def service_start() -> None:
        """Start an installed service."""
        fail_if_windows()
        _backend().start(get_home())
        get_console().print_success("Service started.")

    @service_group.command("stop")
    @error_boundary
    def service_stop() -> None:
        """Stop an installed service without removing it."""
        fail_if_windows()
        _backend().stop()
        get_console().print_success("Service stopped.")

    @service_group.command("restart")
    @error_boundary
    def service_restart() -> None:
        """Restart an installed service."""
        fail_if_windows()
        _backend().restart(get_home())
        get_console().print_success("Service restarted.")

    @service_group.command("logs")
    @error_boundary
    def service_logs(
        follow: bool = typer.Option(False, "--follow", "-f", help="Tail continuously"),
    ) -> None:
        """Show service logs (file on macOS, journal on Linux)."""
        fail_if_windows()
        _backend().tail_logs(get_home(), follow=follow)

"""Typer application — CLI entry point for ``worthless``."""

from __future__ import annotations

import sys
import traceback
from importlib.metadata import version as pkg_version

import typer

from worthless.cli.console import WorthlessConsole, get_console, set_console
from worthless.cli.default_command import run_default
from worthless.cli.errors import WorthlessError, set_debug
from worthless.cli.notice import maybe_show_as_is_notice
from worthless.cli.platform import fail_if_windows


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"worthless {pkg_version('worthless')}")
        raise typer.Exit()


app = typer.Typer(
    name="worthless",
    help=(
        "Protect your API keys in 90 seconds.\n\n"
        "Run 'worthless' with no arguments to auto-detect keys, "
        "lock them, and start the proxy."
    ),
    no_args_is_help=False,
    invoke_without_command=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error output"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
    debug: bool = typer.Option(False, "--debug", help="Show full tracebacks on error"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve prompts"),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Worthless — make leaked API keys worthless."""
    set_debug(debug)
    console = WorthlessConsole(quiet=quiet, json_mode=json_output)
    set_console(console)

    # Show the AS-IS / no-warranty notice once per install (WOR-488).
    maybe_show_as_is_notice(console)

    # When no subcommand is given, run the magic default pipeline.
    if ctx.invoked_subcommand is None:
        try:
            fail_if_windows()
            interactive = hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
            run_default(interactive=interactive, yes=yes, json_mode=json_output)
        except WorthlessError as exc:
            if debug:
                traceback.print_exc(file=sys.stderr)
            else:
                get_console().print_error(exc)
            raise typer.Exit(code=exc.exit_code) from exc


# -- Register command modules --------------------------------------------------
from worthless.cli.commands.lock import register_lock_commands  # noqa: E402

register_lock_commands(app)

from worthless.cli.commands.unlock import register_unlock_commands  # noqa: E402

register_unlock_commands(app)

from worthless.cli.commands.scan import register_scan_commands  # noqa: E402

register_scan_commands(app)

from worthless.cli.commands.status import register_status_commands  # noqa: E402

register_status_commands(app)

from worthless.cli.commands.wrap import register_wrap_commands  # noqa: E402

register_wrap_commands(app)

from worthless.cli.commands.up import register_up_commands  # noqa: E402

register_up_commands(app)

from worthless.cli.commands.down import register_down_commands  # noqa: E402

register_down_commands(app)

try:
    from worthless.cli.commands.mcp import register_mcp_commands  # noqa: E402

    register_mcp_commands(app)
except ImportError:
    pass  # mcp extra not installed — worthless[mcp]

from worthless.cli.commands.revoke import register_revoke_commands  # noqa: E402

register_revoke_commands(app)

from worthless.cli.commands.uninstall import register_uninstall_commands  # noqa: E402

register_uninstall_commands(app)

from worthless.cli.commands.restore import register_restore_commands  # noqa: E402

register_restore_commands(app)

# Both subcommand groups landed in parallel: 8rqs added `providers` for
# the multi-provider registry; main added `doctor` for orphan-row purging
# (HF7). Keep both registrations.
from worthless.cli.commands.providers import register_providers_commands  # noqa: E402

register_providers_commands(app)

from worthless.cli.commands.doctor import register_doctor_commands  # noqa: E402

register_doctor_commands(app)

from worthless.cli.commands.service import register_service_commands  # noqa: E402

register_service_commands(app)

"""Default command — bare ``worthless`` magic pipeline.

When the user runs ``worthless`` with no subcommand, this module
detects the current state and does the right thing:

1. **Enrollment**: scan .env/.env.local → show detected keys → prompt → lock
2. **Proxy**: start sidecar-supervised proxy if not running → poll health
3. **Status**: print one-line summary
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import sys
from pathlib import Path

import typer

from worthless.cli.bootstrap import WorthlessHome, acquire_lock, get_home
from worthless.cli.commands.lock import _lock_keys
from worthless.cli._repo_factory import open_repo
from worthless.cli.commands.up import start_supervised_proxy
from worthless.cli.process import poll_health, resolve_port
from worthless.cli.console import get_console
from worthless.cli.dotenv_rewriter import build_enrolled_locations, scan_env_keys
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState, detect_proxy_runtime

logger = logging.getLogger(__name__)

# Maximum keys to show before collapsing with "(+ N more)"
_MAX_DISPLAY_KEYS = 5


def find_env_file() -> Path | None:
    """Find .env or .env.local in the current directory.

    Returns the first that exists, or None.
    """
    for name in (".env", ".env.local"):
        p = Path(name)
        if p.exists() and not p.is_symlink():
            return p
    return None


def _has_enrolled_keys(home: WorthlessHome) -> bool:
    """Check if any keys are enrolled in the database."""
    if not home.db_path.exists():
        return False
    try:
        conn = sqlite3.connect(str(home.db_path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM shards").fetchone()
            return row is not None and row[0] > 0
        finally:
            conn.close()
    except Exception:
        return False


def _proxy_is_running(home: WorthlessHome) -> tuple[bool, int | None, int]:
    """Check proxy liveness via PID file, health probe, or service state."""
    runtime = detect_proxy_runtime(home)
    if runtime.running:
        return True, runtime.pid, runtime.port
    return False, None, 0


def _raise_if_service_requires_start(runtime: ProxyRuntimeState, console) -> None:
    """Stop default command when a platform service is installed but not running."""
    if runtime.service_state == ServiceState.STOPPED:
        console.print_hint(
            "  Proxy not running. Service is installed but stopped — run `worthless service start`."
        )
        raise typer.Exit(code=2)
    if runtime.service_state == ServiceState.FAILED:
        console.print_hint(
            "  Proxy not running. Service failed — "
            "run `worthless service status` or `worthless service restart`."
        )
        raise typer.Exit(code=2)


def show_detected_keys(
    keys: list[tuple[str, str, str]],
    console,
) -> None:
    """Display detected keys — var name + provider only, NO key characters.

    Collapses after ``_MAX_DISPLAY_KEYS`` with a "(+ N more)" line.

    Each key tuple is ``(var_name, value, provider)``.  The *value* is
    intentionally never displayed (SR-NEW-15).
    """
    shown = keys[:_MAX_DISPLAY_KEYS]
    for var_name, _value, provider in shown:
        console.print_hint(f"    {var_name:<24s} {provider}")

    remaining = len(keys) - _MAX_DISPLAY_KEYS
    if remaining > 0:
        console.print_hint(f"    (+ {remaining} more)")


def _report_json(home: WorthlessHome) -> None:
    """Print read-only JSON state report and exit."""
    enrolled = _has_enrolled_keys(home)
    running, pid, port = _proxy_is_running(home)

    data = {
        "enrolled": enrolled,
        "proxy": {
            "running": running,
            "pid": pid,
            "port": port if running else None,
        },
    }
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    sys.stdout.flush()


def _run_enrollment_if_needed(
    home: WorthlessHome,
    console,
    *,
    interactive: bool,
    yes: bool,
) -> None:
    """Phase 1: scan, show, and optionally lock keys from a local .env."""
    if _has_enrolled_keys(home):
        return

    env_path = find_env_file()
    if env_path is None:
        console.print_warning(
            "No .env found. Run 'worthless lock --env <path>' in a project with API keys."
        )
        raise typer.Exit()

    async def _scan_with_enrollments():
        if not home.db_path.exists():
            return scan_env_keys(env_path)
        try:
            async with open_repo(home) as repo:
                await repo.initialize()
                enrollments = await repo.list_enrollments()
                enrolled_locations = build_enrolled_locations(enrollments)
                return scan_env_keys(env_path, enrolled_locations=enrolled_locations)
        except Exception:
            logger.debug("enrollment query failed, scanning without enrollments", exc_info=True)
            return scan_env_keys(env_path)

    keys = asyncio.run(_scan_with_enrollments())

    if not keys:
        console.print_warning("No API keys found in .env.")
        raise typer.Exit()

    console.print_hint(f"\n  Found {len(keys)} API key{'s' if len(keys) != 1 else ''}:")
    show_detected_keys(keys, console)
    console.print_hint("")

    if not interactive and not yes:
        console.print_hint("Run 'worthless --yes' or 'worthless lock' to protect these keys.")
        raise typer.Exit()

    if not yes:
        confirmed = typer.confirm("  Lock these keys?", default=False)
        if not confirmed:
            raise typer.Exit()

    with acquire_lock(home):
        total = len(keys)
        count = _lock_keys(env_path, home, quiet=True)

    if count < total:
        console.print_warning(f"  {count} of {total} keys protected. Re-run to retry the rest.")
    elif count > 0:
        console.print_hint(f"\n  {count} key{'s' if count != 1 else ''} protected.")


def _ensure_proxy_running(home: WorthlessHome, console) -> tuple[bool, int | None, int]:
    """Phase 2: start sidecar-supervised proxy if needed; return (running, pid, port)."""
    runtime = detect_proxy_runtime(home)
    if runtime.running:
        return True, runtime.pid, runtime.port
    _raise_if_service_requires_start(runtime, console)

    actual_port = resolve_port(None)
    log_file = home.base_dir / "proxy.log"

    console.print_hint(f"\n  Starting proxy on 127.0.0.1:{actual_port}...")

    try:
        start_supervised_proxy(home, actual_port, log_file, console)
    except (typer.Exit, SystemExit) as exc:
        raise WorthlessError(
            ErrorCode.PROXY_UNREACHABLE,
            "Proxy failed to start. Try 'worthless up' for details.",
        ) from exc

    healthy = poll_health(actual_port, timeout=10.0)
    if not healthy:
        console.print_warning(
            "  Proxy started but health check failed. Check ~/.worthless/proxy.log"
        )
        return False, None, 0

    return True, None, actual_port


def run_default(
    *,
    interactive: bool = True,
    yes: bool = False,
    json_mode: bool = False,
) -> None:
    """Execute the default command pipeline.

    Parameters
    ----------
    interactive:
        True when stdin is a TTY.  When False, no prompts are issued
        and the pipeline only reports state.
    yes:
        Auto-approve lock + proxy start (but never service install).
    json_mode:
        Print structured JSON state and exit.  Never triggers writes.
    """
    console = get_console()

    try:
        home = get_home()
    except WorthlessError:
        raise
    except Exception as exc:
        raise WorthlessError(
            ErrorCode.BOOTSTRAP_FAILED,
            f"Failed to initialize: {exc}",
        ) from exc

    # --json is purely observational — no writes, no prompts
    if json_mode:
        _report_json(home)
        return

    try:
        _run_enrollment_if_needed(home, console, interactive=interactive, yes=yes)
    except typer.Exit:
        return

    running, _pid, port = _ensure_proxy_running(home, console)

    if running:
        console.print_hint(f"\n  Proxy healthy on 127.0.0.1:{port}")
    console.print_hint("")

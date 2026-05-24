"""Status command — show enrolled keys and proxy health.

Trust-fix (2026-05-08 verification gauntlet): also reads
``$WORTHLESS_HOME/last-lock-status.json``. When the sentinel reports
DEGRADED state (lock-core succeeded but the OpenClaw integration stage
failed), status emits a ``[WARN]`` row AND exits non-zero so the
"five-minute-later" trust failure mode is closed: a stale terminal
session that swallowed the original ``lock`` exit code still gets
told the truth on the next ``worthless status`` invocation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import typer

from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.cli.console import get_console
from worthless.cli.errors import error_boundary
from worthless.cli.keystore import PLACEHOLDER_FERNET_KEY
from worthless.cli.orphans import FIX_PHRASE, is_orphan
from worthless.cli.process import check_proxy_health, read_pid
from worthless.cli.sentinel import is_partial, read_sentinel
from worthless.storage.repository import EnrollmentRecord, ShardRepository

# Backward-compatible alias — the canonical home is now
# ``worthless.cli.process.check_proxy_health``. Kept so existing
# imports from ``worthless.cli.commands.status`` (mcp/server.py,
# tests) keep working without churn.
_check_proxy_health = check_proxy_health


def _resolve_home_for_status() -> WorthlessHome | None:
    """Load an existing home for status without hiding storage corruption."""
    env_home = os.environ.get("WORTHLESS_HOME")
    if env_home:
        base = Path(env_home)
        return ensure_home(base) if base.exists() else None

    default = Path.home() / ".worthless"
    return ensure_home(default) if default.exists() else None


def _list_enrolled_keys(home: WorthlessHome) -> list[dict[str, str]]:
    """List enrolled aliases with PROTECTED/BROKEN state.

    BROKEN = every enrollment for this alias references a deleted ``.env``
    line. PROTECTED = at least one enrollment is healthy (recovery is
    still possible from that ``.env``). HF5 / worthless-gmky.

    Loads via the shared async ``ShardRepository.list_enrollments()`` so
    ``provider`` arrives denormalized on each record (HF5 storage change).
    """
    keys: list[dict[str, str]] = []
    if not home.db_path.exists():
        return keys

    # Reading plaintext metadata only — no decrypt path triggered. Safe
    # to use the placeholder Fernet key (matches scan.py's pattern).
    try:
        repo = ShardRepository(str(home.db_path), bytearray(PLACEHOLDER_FERNET_KEY))
        enrollments = asyncio.run(repo.list_enrollments())
    except Exception:
        return keys

    # Also enumerate shards so aliases with no enrollment row still appear
    # (edge state: shard exists, enrollment row was deleted out-of-band).
    conn = sqlite3.connect(str(home.db_path))
    try:
        cursor = conn.execute("SELECT key_alias, provider FROM shards ORDER BY key_alias")
        all_aliases = {alias: provider for alias, provider in cursor.fetchall()}
    except sqlite3.OperationalError:
        all_aliases = {}
    finally:
        conn.close()

    by_alias: dict[str, list[EnrollmentRecord]] = {}
    for e in enrollments:
        by_alias.setdefault(e.key_alias, []).append(e)

    for alias, provider in all_aliases.items():
        rows = by_alias.get(alias, [])
        if not rows:
            status = "PROTECTED"  # shard-without-enrollment edge — not HF5 scope
        elif all(is_orphan(e) for e in rows):
            status = "BROKEN"
        else:
            status = "PROTECTED"
        keys.append({"alias": alias, "provider": provider, "status": status})

    return keys


def _discover_proxy_port(home: WorthlessHome) -> int | None:
    """Find proxy port from PID file or WORTHLESS_PORT env var."""
    # Check env var first
    port_env = os.environ.get("WORTHLESS_PORT")
    if port_env:
        try:
            return int(port_env)
        except ValueError:
            pass

    # Check PID file (format: "pid\nport\n")
    pid_file = home.base_dir / "proxy.pid"
    if pid_file.exists():
        info = read_pid(pid_file)
        if info is not None:
            return info[1]

    return None


def register_status_commands(app: typer.Typer) -> None:
    """Register the status command on the Typer app."""

    @app.command()
    @error_boundary
    def status(
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit machine-readable JSON (alias for the top-level --json).",
        ),
    ) -> None:
        """Show enrolled keys and proxy health."""
        console = get_console()

        home = _resolve_home_for_status()

        # Enrolled keys
        keys: list[dict[str, str]] = []
        if home is not None:
            keys = _list_enrolled_keys(home)

        # Proxy health
        proxy_info: dict[str, Any] = {"healthy": False, "port": None, "mode": None}
        if home is not None:
            port = _discover_proxy_port(home)
            if port is not None:
                proxy_info = _check_proxy_health(port)

        # Trust-fix sentinel (2026-05-08 gauntlet): persistent DEGRADED
        # state survives the terminal session that ran `worthless lock`.
        # If the last lock/unlock left a partial state, status MUST tell
        # the user — the original exit code may have been swallowed by CI
        # or shell-script `; my-app` chaining.
        sentinel: dict[str, Any] | None = None
        if home is not None:
            sentinel = read_sentinel(home.base_dir)
        degraded = is_partial(sentinel)

        # Output. Sub-command --json mirrors scan/wrap; honors top-level --json too.
        if console.json_mode or json_output:
            result = {
                "keys": keys,
                "proxy": proxy_info,
                "sentinel": sentinel,
                "degraded": degraded,
            }
            sys.stdout.write(json.dumps(result, default=str) + "\n")
            sys.stdout.flush()
        else:
            if not keys:
                console.print_warning("No keys enrolled.")
            else:
                lines = ["Enrolled keys:"]
                for k in keys:
                    lines.append(f"  {k['alias']}  {k['provider']}  {k['status']}")
                sys.stderr.write("\n".join(lines) + "\n\n")
                # HF5: if any row is BROKEN, point the user at doctor.
                # Phrase tokens come from cli/orphans.py — single source of
                # truth shared with unlock/doctor/scan.
                if any(k["status"] == "BROKEN" for k in keys):
                    sys.stderr.write(
                        f"Can't restore the keys marked BROKEN — their .env "
                        f"line was deleted. Run `{FIX_PHRASE}` to clean up.\n\n"
                    )

            if proxy_info["healthy"]:
                sys.stderr.write(
                    f"Proxy: running on 127.0.0.1:{proxy_info['port']}"
                    f" (mode: {proxy_info['mode']})\n"
                )
                sys.stderr.write(f"Requests proxied: {proxy_info['requests_proxied']}\n")
            else:
                sys.stderr.write("Proxy: not running\n")

            if degraded:
                sys.stderr.write(
                    "\n[WARN] OpenClaw integration is broken — "
                    "your agent traffic may NOT be gated by worthless.\n"
                    "       Run `worthless doctor` to repair, or "
                    "`worthless unlock` to roll back.\n"
                )
            sys.stderr.flush()

        # Trust-fix exit: degraded sentinel = non-zero exit so callers
        # (CI scripts, shell pipelines, agents polling status) get the
        # signal even if they ignored the original lock exit code.
        raise typer.Exit(code=73 if degraded else 0)

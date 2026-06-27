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


def _bind_confirmation_message(sentinel: dict | None) -> str | None:
    """WOR-658: render the bind_confirmation block as a one-line user-facing
    reason (or ``None`` if absent or status=pass).

    Tolerates absence — old (pre-WOR-658) sentinels lack the field.
    """
    if not sentinel:
        return None
    bc = sentinel.get("bind_confirmation")
    if not isinstance(bc, dict):
        return None
    status = bc.get("status")
    if status == "fail":
        return (
            "Proof-of-routing FAILED — the test request didn't reach the "
            "proxy through the rewritten OpenClaw entry."
        )
    if status == "skipped":
        reason = bc.get("reason")
        if reason in ("proxy_unrecognised", "proxy_unrecognised_after"):
            return "The service answering /healthz isn't a worthless proxy — routing wasn't proven."
        if reason in ("proxy_unhealthy_before", "proxy_unhealthy_after"):
            return "Proof-of-routing inconclusive — proxy wasn't healthy."
        if reason in ("proxy_check_raised_before", "proxy_check_raised_after"):
            return "Proof-of-routing inconclusive — proxy health check errored."
        if reason == "proxy_restarted":
            return "Proof-of-routing inconclusive — proxy restarted mid-confirm."
        if reason == "synthetic_unreachable":
            return "Proof-of-routing inconclusive — test request never reached the proxy."
    return None  # status=pass, no_aliases, or shape we don't recognise — stay quiet


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


def _status_verdict(
    keys: list[dict[str, str]], proxy_healthy: bool, degraded: bool
) -> tuple[str, str | None]:
    """WOR-779: derive the worst-component verdict. Returns ``(enum, header)``.

    Honest tiering — status is cwd-independent: it sees enrolled keys + the
    proxy, NEVER this folder's ``.env``. So it must not claim about plaintext
    (``scan`` owns that). The two axes are kept separate:

      * confidentiality  — is a stolen ``.env`` worthless? (locked / BROKEN)
      * availability      — can apps reach the keys right now? (proxy up/down)

    🔴 ``at_risk`` is reserved for a real failure (degraded routing). A locked
    key with the proxy down is SAFE AT REST — that's 🟡 ``protected_at_rest``,
    never 🔴: calling an availability outage a security risk trains the user
    to ignore red. A BROKEN enrollment is data-loss (🟡 ``attention``), not a
    leak. The verdict is derived, so a green banner is unreachable when any
    component is bad.
    """
    if not keys:
        return "empty", None

    n = len(keys)
    noun = "key" if n == 1 else "keys"

    if degraded:
        return "at_risk", "🔴 At risk — OpenClaw routing is broken (details below)."

    broken = sum(1 for k in keys if k["status"] == "BROKEN")
    if broken:
        b_noun = "key" if broken == 1 else "keys"
        return "attention", (
            f"🟡 Attention — {broken} {b_noun} can't be restored "
            f"(the .env line is gone) — see below."
        )

    if proxy_healthy:
        return "protected", f"🟢 You're protected — {n} {noun} locked, proxy up."

    return "protected_at_rest", (
        f"🟡 Protected at rest — {n} {noun} locked (a stolen .env is worthless), "
        f"but the proxy is down so your apps can't reach them. Run `worthless up`."
    )


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
        quiet_flag: bool = typer.Option(
            False,
            "--quiet",
            help="Suppress the reassurance prose; keep the exit code.",
        ),
    ) -> None:
        """Show enrolled keys and proxy health."""
        console = get_console()
        quiet = console.quiet or quiet_flag

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

        # WOR-779: derive the worst-component verdict from what status can
        # honestly see (enrolled keys + proxy + sentinel). The exit code below
        # stays 0/73 — the verdict header carries the 🟢/🟡 nuance a binary
        # exit can't, while machines read the `verdict` enum from --json.
        verdict, header = _status_verdict(keys, bool(proxy_info["healthy"]), degraded)

        # Output. Sub-command --json mirrors scan/wrap; honors top-level --json too.
        if console.json_mode or json_output:
            result = {
                "verdict": verdict,
                "keys": keys,
                "proxy": proxy_info,
                "sentinel": sentinel,
                "degraded": degraded,
            }
            sys.stdout.write(json.dumps(result, default=str) + "\n")
            sys.stdout.flush()
        elif not quiet:
            # WOR-779: lead with the glanceable verdict, then the detail.
            if header:
                sys.stderr.write(header + "\n\n")

            if not keys:
                # Keep the "No keys enrolled" signal AND nudge to lock
                # (the post-install / fresh-install confidence gap).
                console.print_warning(
                    "No keys enrolled — nothing protected yet. "
                    "Run `worthless lock` to protect your API keys."
                )
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

            # WOR-658: surface the bind-confirmation verdict from the sentinel
            # so the user gets a specific reason, not just generic DEGRADED.
            # Tolerates old (pre-WOR-658) sentinels that lack the field.
            bind_reason = _bind_confirmation_message(sentinel)

            if degraded:
                sys.stderr.write(
                    "\n[WARN] OpenClaw integration is broken — "
                    "your agent traffic may NOT be gated by worthless.\n"
                )
                if bind_reason:
                    sys.stderr.write(f"       {bind_reason}\n")
                sys.stderr.write(
                    "       Run `worthless doctor` to repair, or `worthless unlock` to roll back.\n"
                )
            elif bind_reason:
                # Not DEGRADED but the bind-confirmation skipped inconclusively
                # (e.g. proxy_unrecognised — a squatter on the port). Surface
                # it so the user knows routing wasn't proven.
                sys.stderr.write(f"\n[WARN] {bind_reason}\n")

            # WOR-779: honesty disclaimer. status is cwd-independent — it never
            # read this folder's .env, so a green verdict must NOT imply it did.
            # Point the user at the surface that actually checks for plaintext.
            if keys:
                sys.stderr.write(
                    "\nChecks enrolled keys + proxy. To scan this folder's .env "
                    "for stray plaintext: `worthless scan`.\n"
                )
            sys.stderr.flush()

        # Trust-fix exit: degraded sentinel = non-zero exit so callers
        # (CI scripts, shell pipelines, agents polling status) get the
        # signal even if they ignored the original lock exit code.
        raise typer.Exit(code=73 if degraded else 0)

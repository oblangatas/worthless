"""Worthless MCP server — management tools over stdio transport."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiosqlite
from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]  # optional dep

from worthless.cli.bootstrap import (
    WorthlessHome,
    acquire_lock,
    get_home,
    resolve_home,
)
from worthless.cli.errors import ErrorCode, WorthlessError

mcp = FastMCP("worthless")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_home() -> WorthlessHome:
    """Return WorthlessHome or raise a clear error."""
    home = resolve_home()
    if home is None:
        raise WorthlessError(
            ErrorCode.BOOTSTRAP_FAILED,
            "Worthless is not initialized. Run `worthless lock` first.",
        )
    return home


async def _query_spend(db_path: Path, alias: str | None) -> list[dict[str, Any]]:
    """Aggregate spend_log rows, optionally filtered by alias."""
    query = """
        SELECT key_alias, provider,
               COALESCE(SUM(tokens), 0) AS total_tokens,
               COUNT(*) AS request_count
        FROM spend_log
    """
    params: tuple[str, ...] = ()
    if alias:
        query += " WHERE key_alias = ?"
        params = (alias,)
    query += " GROUP BY key_alias, provider"

    async with aiosqlite.connect(str(db_path)) as db:
        rows = await db.execute_fetchall(query, params)
        return [
            {
                "alias": r[0],
                "provider": r[1],
                "total_tokens": r[2],
                "request_count": r[3],
            }
            for r in rows
        ]


async def _list_orphan_shards(db_path: Path) -> list[str]:
    """Return shard aliases that have NO enrollment row — a mixed/partial state.

    A ``shards`` row with no matching ``enrollments`` row is a lone shard-B: a
    half-written state no other ``doctor`` check looks for (its checks are
    disk-vs-DB and ``.env``-vs-DB). The atomic Pass-1 writes (WOR-646 Part 2)
    and atomic superseded cleanup (worthless-exx5) prevent this on the normal
    and rotation paths, so this is defense-in-depth — it surfaces a legacy row
    or a future regression, not a known live gap. A lone shard is
    cryptographically useless (no shard-A) but should still be reconciled.
    """
    if not db_path.exists():
        return []
    query = (
        "SELECT s.key_alias FROM shards s "
        "LEFT JOIN enrollments e ON s.key_alias = e.key_alias "
        "WHERE e.key_alias IS NULL ORDER BY s.key_alias"
    )
    async with aiosqlite.connect(str(db_path)) as db:
        rows = await db.execute_fetchall(query)
        return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def worthless_status() -> str:
    """Show enrolled keys and proxy health.

    Returns the list of protected key aliases with their providers,
    and whether the local proxy is currently running.
    """
    # Deferred: avoid pulling typer/rich CLI stack at MCP server startup.
    # TODO(WOR-126): move _check_proxy_health, _list_enrolled_keys into
    # worthless.services.status so both CLI and MCP import a shared public API.
    from worthless.cli.commands.status import (
        _check_proxy_health,
        _discover_proxy_port,
        _list_enrolled_keys,
    )

    home = resolve_home()

    keys: list[dict[str, str]] = []
    proxy_info: dict[str, Any] = {"healthy": False, "port": None, "mode": None}
    if home is not None:
        # _list_enrolled_keys calls asyncio.run() internally, raising
        # RuntimeError inside FastMCP's running event loop. Run in a thread
        # executor — the same pattern used by worthless_lock in this file.
        loop = asyncio.get_running_loop()
        keys = await loop.run_in_executor(None, _list_enrolled_keys, home)
        port = _discover_proxy_port(home)
        if port is not None:
            proxy_info = _check_proxy_health(port)

    return json.dumps({"keys": keys, "proxy": proxy_info}, default=str)


@mcp.tool()
async def worthless_scan(
    paths: list[str] | None = None,
    deep: bool = False,
) -> str:
    """Scan files for exposed API keys.

    Detects unprotected API keys in .env files and config files.
    Returns structured findings with provider, location, and protection status.

    Args:
        paths: Files to scan. If empty, scans .env and .env.local in cwd.
        deep: Extended scan — also checks *.yml, *.yaml, *.toml, *.json,
              and live environment variables.
    """
    import time

    from worthless.cli.commands.scan import (
        SCAN_TIME_BUDGET_S,
        _collect_deep_paths,
        _collect_fast_paths,
        _load_db_state_async,
    )
    from worthless.cli.scanner import SkippedFile, scan_files

    explicit = [Path(p) for p in (paths or [])]

    tmp_file: Path | None = None
    try:
        if deep:
            scan_paths, tmp_file = _collect_deep_paths(explicit)
        else:
            scan_paths = _collect_fast_paths(explicit)

        # HF5: scan also returns orphan rows; MCP server only needs enrolled
        # locations for now (orphan-flagging in MCP would be a future bead).
        enrolled, _orphans = await _load_db_state_async()
        enrollment_checker_available = enrolled is not None

        # c5kc: same fail-closed contract as the CLI — bounded per-file read
        # plus a wall-clock deadline so an MCP-driven scan over a huge or slow
        # file can't freeze the calling agent. Skipped files are surfaced so
        # the agent doesn't misread "0 findings" as "clean" on a partial scan.
        #
        # scan_files is synchronous and can run for up to SCAN_TIME_BUDGET_S
        # seconds. Calling it inline would block the FastMCP event loop and
        # starve other concurrent MCP tool calls — offload to a thread executor
        # (same pattern worthless_status / worthless_lock use in this file).
        # ``skipped`` is mutated in-place inside the executor; the reference
        # we read after the await sees the same list.
        skipped: list[SkippedFile] = []
        deadline = time.monotonic() + SCAN_TIME_BUDGET_S
        findings = await asyncio.to_thread(
            scan_files,
            scan_paths,
            enrolled_locations=enrolled,
            deadline=deadline,
            skipped=skipped,
        )

        items = [
            {
                "file": f.file,
                "line": f.line,
                "var_name": f.var_name,
                "provider": f.provider,
                "is_protected": f.is_protected,
                "value_preview": f.value_preview,
            }
            for f in findings
        ]

        protected = sum(1 for f in findings if f.is_protected)
        unprotected = sum(1 for f in findings if not f.is_protected)

        return json.dumps(
            {
                "findings": items,
                "summary": {
                    "total": len(findings),
                    "protected": protected,
                    "unprotected": unprotected,
                },
                "enrollment_checker_available": enrollment_checker_available,
                # Additive fields (c5kc): tell the calling agent which files
                # couldn't be fully scanned and whether the result is partial.
                # Agents should treat scan_incomplete=true as "I don't know if
                # you're clean" — same fail-closed semantics as CLI exit code 2.
                "skipped": [{"file": s.file, "reason": s.reason} for s in skipped],
                "scan_incomplete": bool(skipped),
            }
        )
    finally:
        if tmp_file is not None:
            tmp_file.unlink(missing_ok=True)


@mcp.tool()
async def worthless_lock(env_path: str = ".env") -> str:
    """Protect API keys in a .env file.

    Splits detected keys into shards, stores them encrypted, and replaces
    the originals with format-preserving shard-A values. This is a protective
    mutation — it makes your keys MORE secure.

    Interrupt safety: this MCP path runs the lock in a worker thread, where
    Python delivers no SIGINT/SIGTERM, so the CLI's mid-lock signal rollback
    does NOT apply here. Crash-safety instead comes from atomic writes
    (WOR-646 Part 2). As a backstop, the response carries ``state_consistent``;
    if it is ``false``, an orphan/partial state was detected — run
    ``worthless doctor`` to reconcile before trusting the result.

    Args:
        env_path: Path to the .env file to protect.
    """
    from worthless.cli.commands.lock import _lock_keys

    home = get_home()
    path = Path(env_path)

    # _lock_keys is sync and calls asyncio.run() internally, so run it in a
    # thread to avoid nested event loop errors. dqzj/WOR-646: the orphan-state
    # reconciliation runs INSIDE the same acquire_lock() critical section, so
    # state_consistent/orphan_shards describe exactly the state THIS lock left —
    # not a snapshot another command could have mutated after the lock released
    # (CodeRabbit: the post-lock read was a TOCTOU window).
    def _do_lock() -> tuple[int, list[str]]:
        with acquire_lock(home):
            count = _lock_keys(path, home)
            orphans = asyncio.run(_list_orphan_shards(home.db_path))
            return count, orphans

    loop = asyncio.get_running_loop()
    count, orphans = await loop.run_in_executor(None, _do_lock)

    # The MCP path runs off the main thread, so no interrupt-driven rollback
    # could fire here; surface any mixed state instead of a bare, possibly-
    # misleading success — so the agent is told to run `doctor`, not trust "ok".
    result: dict[str, Any] = {
        "protected_count": count,
        "state_consistent": not orphans,
    }
    if orphans:
        result["orphan_shards"] = orphans
        result["hint"] = "Mixed state detected — run `worthless doctor` to reconcile."
    return json.dumps(result)


@mcp.tool()
async def worthless_spend(alias: str | None = None) -> str:
    """Show token spend history for enrolled keys.

    Returns aggregated spend data from the proxy metering log,
    grouped by key alias and provider.

    Args:
        alias: Filter to a specific key alias. If omitted, returns all.
    """
    home = _require_home()
    spend = await _query_spend(home.db_path, alias)
    return json.dumps({"spend": spend})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

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
    from worthless.cli.commands.scan import (
        _collect_deep_paths,
        _collect_fast_paths,
        _load_db_state_async,
    )
    from worthless.cli.scanner import scan_files

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
        findings = scan_files(scan_paths, enrolled_locations=enrolled)

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

    Args:
        env_path: Path to the .env file to protect.
    """
    from worthless.cli.commands.lock import _lock_keys

    home = get_home()
    path = Path(env_path)

    # _lock_keys is sync and calls asyncio.run() internally,
    # so run it in a thread to avoid nested event loop errors.
    def _do_lock() -> int:
        with acquire_lock(home):
            return _lock_keys(path, home)

    loop = asyncio.get_running_loop()
    count = await loop.run_in_executor(None, _do_lock)

    return json.dumps({"protected_count": count})


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

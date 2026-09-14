"""End-to-end MCP stdio contract test for the Worthless MCP server.

``tests/test_mcp_server.py`` calls the four ``@mcp.tool()`` coroutines
*in-process*. That proves each tool's logic, but it never exercises the part
an agent actually depends on: spawning ``worthless mcp`` and discovering, over a
real MCP stdio handshake, which tools the server advertises.

This module closes that gap. It boots the locally-installed ``worthless`` CLI as
a subprocess (``worthless mcp`` → ``worthless.mcp.server:main`` →
``MCPServer.run(transport="stdio")``), drives a genuine handshake with the
official ``mcp`` Python client (``stdio_client`` + ``ClientSession``:
``initialize`` then ``list_tools``), and pins the public surface to **exactly**
four tools:

    worthless_status, worthless_scan, worthless_lock, worthless_spend

If anyone adds, removes, or renames a tool, this test fails — the MCP contract
can't silently drift. (WOR-783, proof "A1".)

Hermetic: ``tools/list`` needs no API keys and no network beyond the local
stdio pipe to the child process.

Left unmarked on purpose so it runs in CI's default parallel pytest pass
(``-m 'not live and not docker and not user_flow and not real_ipc'``); that job
already installs the ``[mcp]`` extra via ``uv sync --extra mcp``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

# The stdio handshake spawns a child and talks MCP over pipes; if the child
# never speaks, bound the whole exchange so CI fails in seconds rather than
# hanging until the global job timeout.
_HANDSHAKE_TIMEOUT_S = 30.0

# The handshake needs the `mcp` client library (the project's [mcp] extra).
pytest.importorskip("mcp", reason="mcp extra not installed")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402
from mcp.types import CallToolResult, InitializeResult, ListToolsResult  # noqa: E402

# The contract under test: the exact set of management tools the Worthless MCP
# server is allowed to expose. Adding/removing/renaming a tool must be a
# deliberate change to this set, not an accident.
EXPECTED_TOOLS = frozenset(
    {
        "worthless_status",
        "worthless_scan",
        "worthless_lock",
        "worthless_spend",
    }
)


def _worthless_executable() -> Path:
    """Absolute path to the ``worthless`` console script in the *current* venv.

    Deriving it from ``sys.executable`` (rather than a bare ``"worthless"`` on
    PATH) guarantees we spawn the locally-built package under test — never a
    stray PyPI install — and sidesteps ruff S607 (partial executable path).
    """
    bin_dir = Path(sys.executable).parent
    candidate = bin_dir / "worthless"
    if not candidate.exists():
        # Windows lays the console script down as worthless.exe.
        candidate = bin_dir / "worthless.exe"
    return candidate


def _child_env(bin_dir: Path) -> dict[str, str]:
    """Environment for the ``worthless mcp`` child process.

    Inherit the real environment — Windows needs SYSTEMROOT/COMSPEC and every
    platform needs a working base PATH — but strip any ``WORTHLESS_*`` dogfood
    exports so a developer's local config can't change what the child does.
    The venv bin dir is prepended so the console script resolves to the package
    under test rather than a stray install on PATH.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    env["PATH"] = os.pathsep.join([str(bin_dir), env.get("PATH", "")])
    return env


@pytest.mark.asyncio
async def test_mcp_stdio_server_exposes_exactly_the_four_tools() -> None:
    """Spawn ``worthless mcp`` and assert tools/list returns exactly 4 tools.

    This is the automated stand-in for the manual stdio handshake done in the
    WOR-783 session: real subprocess, real MCP ``initialize`` + ``list_tools``,
    real assertion on the advertised tool set.
    """
    worthless_bin = _worthless_executable()
    assert worthless_bin.exists(), (
        f"worthless console script not found at {worthless_bin!s}; "
        "is the package installed in this environment?"
    )

    server = StdioServerParameters(
        command=str(worthless_bin),
        args=["mcp"],
        # tools/list is metadata only, so no secrets are needed — but the child
        # still needs a real base environment to spawn (see _child_env).
        env=_child_env(worthless_bin.parent),
    )

    async def _handshake() -> object:
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                # Real MCP lifecycle: negotiate protocol/capabilities first.
                await session.initialize()
                # Then discover the advertised tool surface.
                return await session.list_tools()

    # Bound the spawn + handshake: a child that never completes the MCP
    # lifecycle fails this test fast instead of hanging the CI job.
    tools_result = await asyncio.wait_for(_handshake(), timeout=_HANDSHAKE_TIMEOUT_S)

    served = {tool.name for tool in tools_result.tools}

    assert served == EXPECTED_TOOLS, (
        "Worthless MCP server tool surface drifted.\n"
        f"  expected: {sorted(EXPECTED_TOOLS)}\n"
        f"  served:   {sorted(served)}\n"
        f"  added:    {sorted(served - EXPECTED_TOOLS)}\n"
        f"  removed:  {sorted(EXPECTED_TOOLS - served)}\n"
        "Update EXPECTED_TOOLS in this test only if the change is intentional."
    )
    # Exactly four — guards against a future tool sharing a name (dedupes in
    # the set above) by checking the raw advertised count too.
    assert len(tools_result.tools) == len(EXPECTED_TOOLS)


@pytest.mark.asyncio
async def test_real_client_calls_tools_and_sees_results_and_errors(tmp_path: Path) -> None:
    """A real MCP client can call the tools and read results and errors (WOR-929).

    Listing names alone stays green through an SDK port that breaks calling
    them. This pins what an agent actually sees: argument schemas, a
    successful result, and an error result.
    """
    worthless_bin = _worthless_executable()
    env = _child_env(worthless_bin.parent)
    # A home that does not exist: status answers "empty", spend refuses.
    env["WORTHLESS_HOME"] = str(tmp_path / "no-home")
    server = StdioServerParameters(command=str(worthless_bin), args=["mcp"], env=env)

    async def _session() -> tuple[
        InitializeResult, ListToolsResult, CallToolResult, CallToolResult
    ]:
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                status = await session.call_tool("worthless_status", {})
                spend = await session.call_tool("worthless_spend", {})
                return init, tools, status, spend

    init, tools, status, spend = await asyncio.wait_for(_session(), timeout=_HANDSHAKE_TIMEOUT_S)

    # Hosts show and log this; mcp 2.x reports "" unless the server says.
    assert (init.server_info.name, init.server_info.version) == ("worthless", version("worthless"))

    schemas = {t.name: t.input_schema for t in tools.tools}
    props = {name: s.get("properties", {}) for name, s in schemas.items()}
    assert set(props["worthless_status"]) == set()
    assert set(props["worthless_scan"]) == {"paths", "deep"}
    assert props["worthless_scan"]["deep"]["default"] is False
    assert set(props["worthless_lock"]) == {"env_path"}
    assert props["worthless_lock"]["env_path"]["default"] == ".env"
    assert set(props["worthless_spend"]) == {"alias"}

    assert status.is_error is False
    payload = json.loads(status.content[0].text)  # type: ignore[union-attr]
    assert payload["verdict"] == "empty"
    assert set(payload) == {"verdict", "header", "keys", "proxy", "sentinel", "degraded"}

    # A tool raising WorthlessError reaches the client as an error result
    # carrying the message — not a protocol error, not a crash.
    assert spend.is_error is True
    assert "Worthless is not initialized" in spend.content[0].text  # type: ignore[union-attr]

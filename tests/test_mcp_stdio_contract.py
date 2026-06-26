"""End-to-end MCP stdio contract test for the Worthless MCP server.

``tests/test_mcp_server.py`` calls the four ``@mcp.tool()`` coroutines
*in-process*. That proves each tool's logic, but it never exercises the part
an agent actually depends on: spawning ``worthless mcp`` and discovering, over a
real MCP stdio handshake, which tools the server advertises.

This module closes that gap. It boots the locally-installed ``worthless`` CLI as
a subprocess (``worthless mcp`` → ``worthless.mcp.server:main`` →
``FastMCP.run(transport="stdio")``), drives a genuine handshake with the
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

import sys
from pathlib import Path

import pytest

# The handshake needs the `mcp` client library (the project's [mcp] extra).
pytest.importorskip("mcp", reason="mcp extra not installed")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

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
        # No secrets needed: tools/list is metadata only. Pass an explicit
        # (empty) env so the child can't inherit dogfood exports that would
        # change behaviour.
        env={"PATH": str(worthless_bin.parent)},
    )

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            # Real MCP lifecycle: negotiate protocol/capabilities first.
            await session.initialize()
            # Then discover the advertised tool surface.
            tools_result = await session.list_tools()

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

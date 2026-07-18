"""End-to-end mount test for the *npm wrapper* — the path a real editor walks.

``tests/test_mcp_stdio_contract.py`` (WOR-783) spawns the inner ``worthless mcp``
Python server directly. That proves the server's tool surface, but it never
exercises the layer an editor/agent actually launches:

    npx worthless-mcp  →  packages/worthless-mcp/index.js  →  uv/uvx bootstrap
    →  uvx "worthless[mcp]==<pinned>" mcp  →  the MCP server over stdio

That wrapper+bootstrap layer is exactly what broke in the 0.3.9 release (npm
shipped ``worthless-mcp@0.3.9`` while PyPI had no ``worthless==0.3.9`` yet, so
every ``npx worthless-mcp`` died with an unsatisfiable-dependency error) — and
no test caught it. This module closes that gap (WOR-809, "the real A1").

It spawns the **wrapper** (``node packages/worthless-mcp/index.js``), drives a
genuine MCP ``initialize`` + ``list_tools`` handshake with the official ``mcp``
client exactly as an editor would, and pins the mounted surface to exactly:

    worthless_status, worthless_scan, worthless_lock, worthless_spend

Proving PR bytes (not a stray PyPI copy): the CI job builds the PR wheel,
pre-seeds it into an isolated uv cache via
``uv tool install "worthless[mcp] @ file://<wheel>"``, then runs this test with
``UV_OFFLINE=1``. Offline + clean cache means the only ``worthless[mcp]`` that
can resolve is the pre-seeded PR wheel — verified with a clean-cache control
that fails offline without the pre-seed.

Skip-guarded by ``WORTHLESS_NPX_MOUNT_TEST`` so the default parallel pytest pass
ignores it: it needs the wrapper's Node runtime, a uv/uvx toolchain, and the
pre-seeded offline cache that only the dedicated ``verify-npm.yml`` job sets up.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

import pytest

# Only runs in the dedicated CI job that builds + pre-seeds the PR wheel and
# provides node + uvx. Everywhere else (the default pytest pass, a laptop) it
# skips rather than failing on missing setup.
if not os.environ.get("WORTHLESS_NPX_MOUNT_TEST"):
    pytest.skip(
        "npx-wrapper mount test runs only under the verify-npm CI job "
        "(set WORTHLESS_NPX_MOUNT_TEST=1 with node + a pre-seeded offline uv cache)",
        allow_module_level=True,
    )

# The handshake needs the `mcp` client library (the project's [mcp] extra).
pytest.importorskip("mcp", reason="mcp extra not installed")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

# A wrapper cold-start does more than the inner server: Node boots, locates
# uvx, and uvx materialises the Python env from cache before the MCP server
# even starts. Give it more headroom than the inner-server contract test (30s),
# but still bound it so a hung bootstrap fails the job in a minute, not hours.
_HANDSHAKE_TIMEOUT_S = 60.0

# The contract: the exact set of tools the wrapper must mount. Identical to the
# inner-server contract on purpose — the wrapper must expose the *same* surface
# the server advertises, with nothing lost or added in the npx→uvx bootstrap.
EXPECTED_TOOLS = frozenset(
    {
        "worthless_status",
        "worthless_scan",
        "worthless_lock",
        "worthless_spend",
    }
)


def _wrapper_entry() -> Path:
    """Absolute path to the npm wrapper's entrypoint under test."""
    return Path(__file__).resolve().parents[1] / "packages" / "worthless-mcp" / "index.js"


def _node() -> str:
    node = shutil.which("node")
    assert node is not None, "node not found on PATH — required to run the npm wrapper"
    return node


def _child_env() -> dict[str, str]:
    """Environment for the wrapper child.

    Inherit the real environment (the wrapper needs PATH to find uvx, and the
    CI job's ``UV_OFFLINE`` / ``UV_CACHE_DIR`` / ``UV_TOOL_DIR`` that pin it to
    the pre-seeded PR wheel), but strip any ``WORTHLESS_*`` dogfood exports so a
    developer's local config can't change what the child does.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}


@pytest.mark.asyncio
async def test_npx_wrapper_mounts_exactly_the_four_tools() -> None:
    """Spawn the real npm wrapper and assert the MCP handshake mounts 4 tools.

    Fails if: the wrapper can't bootstrap uvx / resolve the pinned package
    (the 0.3.9-style break), the server never completes the MCP lifecycle
    (hang → timeout), or the advertised tool set drifts from EXPECTED_TOOLS.
    """
    entry = _wrapper_entry()
    assert entry.exists(), f"wrapper entrypoint not found at {entry!s}"

    server = StdioServerParameters(
        command=_node(),
        args=[str(entry)],
        env=_child_env(),
    )

    async def _handshake() -> object:
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.list_tools()

    tools_result = await asyncio.wait_for(_handshake(), timeout=_HANDSHAKE_TIMEOUT_S)

    served = {tool.name for tool in tools_result.tools}
    assert served == EXPECTED_TOOLS, (
        "npx worthless-mcp mounted a different tool surface than expected.\n"
        f"  expected: {sorted(EXPECTED_TOOLS)}\n"
        f"  served:   {sorted(served)}\n"
        f"  added:    {sorted(served - EXPECTED_TOOLS)}\n"
        f"  removed:  {sorted(EXPECTED_TOOLS - served)}\n"
        "If this is intentional, update EXPECTED_TOOLS here and in "
        "tests/test_mcp_stdio_contract.py together."
    )
    assert len(tools_result.tools) == len(EXPECTED_TOOLS)

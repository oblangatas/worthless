"""The ``mcp`` extra must stay capped below the next major (WOR-868).

``uvx worthless[mcp]`` — what ``npx worthless-mcp`` runs — resolves the extra
fresh from ``pyproject.toml``, ignoring ``uv.lock``. So an unbounded
``mcp>=1.0`` silently picked up ``mcp`` 2.0.0, which deleted the
``mcp.server.fastmcp`` module ``src/worthless/mcp/server.py`` imports, and every
fresh install died at startup with an opaque ``WRTLS-199``.

The developer environment is pinned by ``uv.lock``, so no runtime import test
catches this — the drift only exists at resolve time. This asserts the
constraint itself.
"""

from __future__ import annotations

import re
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# ponytail: regex over the raw text, not a TOML parse — tomllib is 3.11+ and we
# still support 3.10, and this file needs no third-party parser to answer one
# question about one line.
_MCP_REQUIREMENT = re.compile(r'^\s*"(mcp[^"]*)"', re.MULTILINE)


def test_mcp_extra_has_an_upper_bound() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    matches = _MCP_REQUIREMENT.findall(text)
    mcp_spec = next((m for m in matches if m.replace(" ", "").startswith("mcp>")), None)

    assert mcp_spec is not None, f"no pinned `mcp` requirement found; saw: {matches}"
    assert "<" in mcp_spec, (
        f"`mcp` requirement {mcp_spec!r} has no upper bound. mcp 2.0.0 removed "
        "`mcp.server.fastmcp`, so an uncapped range breaks `worthless mcp` on every "
        "fresh `uvx worthless[mcp]` resolve (WOR-868). Lifting the cap requires "
        "porting to the 2.x `mcp.server.mcpserver` API first."
    )

"""`worthless mcp` explains a missing or outdated MCP SDK (WOR-929).

The server needs mcp 2.x. `pip install -U worthless` without the `[mcp]` extra
leaves an old mcp 1.x (or none) in place, and the import failure used to
surface as an opaque WRTLS-199 "internal error".
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app


def test_mcp_without_a_usable_sdk_says_how_to_fix_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force a fresh import of the server, and make the 2.x module unimportable —
    # exactly what an environment holding mcp 1.x (or no mcp) looks like.
    monkeypatch.delitem(sys.modules, "worthless.mcp.server", raising=False)
    monkeypatch.setitem(sys.modules, "mcp.server.mcpserver", None)

    result = CliRunner().invoke(app, ["mcp"])

    assert result.exit_code != 0
    assert "worthless[mcp]" in result.output
    assert "WRTLS-199" not in result.output

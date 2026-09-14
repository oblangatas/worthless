"""`worthless mcp` explains a missing or outdated MCP SDK (WOR-929).

The server needs mcp 2.x. `pip install -U worthless` without the `[mcp]` extra
leaves an old mcp 1.x (or none) in place, and the import failure used to
surface as an opaque WRTLS-199 "internal error".
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version

import pytest

from tests.cli.conftest import runner
from worthless.cli.app import app


def test_mcp_without_a_usable_sdk_says_how_to_fix_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force a fresh import of the server, and make the 2.x module unimportable —
    # exactly what an environment holding mcp 1.x (or no mcp) looks like.
    monkeypatch.delitem(sys.modules, "worthless.mcp.server", raising=False)
    monkeypatch.setitem(sys.modules, "mcp.server.mcpserver", None)

    result = runner.invoke(app, ["mcp"])

    assert result.exit_code != 0
    assert "worthless[mcp]" in result.output
    assert "WRTLS-199" not in result.output
    # Name what IS installed, so a future broken 2.x minor isn't misread as
    # "you don't have 2.x" and sent round a reinstall loop. Without the [mcp]
    # extra (plain dev sync) nothing is installed and the message says so.
    try:
        installed = f"mcp {version('mcp')}"
    except PackageNotFoundError:
        installed = "no mcp"
    assert f"found {installed}" in " ".join(result.output.split())

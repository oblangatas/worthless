"""Regression guard for the one-click install badges in the docs hero.

``docs/index.mdx`` ships "Add to Cursor" / "Install in VS Code" buttons whose
targets are *opaque* encoded deeplinks — a base64 or url-encoding typo would
render a button that silently installs the wrong thing (or nothing). A human
can't eyeball ``config=eyJjb21tYW5k...`` and catch that.

This test decodes every install deeplink in the hero and asserts it still
launches exactly ``npx -y worthless-mcp``. Pure stdlib + a file read, so it
runs in the default pytest pass with no extra setup.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from pathlib import Path


_DOCS_INDEX = Path(__file__).resolve().parents[1] / "docs" / "index.mdx"

# What every install badge must ultimately run. If the wrapper's invocation
# ever legitimately changes, update this one constant.
_EXPECTED_COMMAND = "npx"
_EXPECTED_ARGS = ["-y", "worthless-mcp"]

# Cursor: cursor://anysphere.cursor-deeplink/mcp/install?name=<n>&config=<base64(json)>
_CURSOR_RE = re.compile(
    r"cursor://anysphere\.cursor-deeplink/mcp/install\?name=([^&\s)]+)&config=([A-Za-z0-9+/=_-]+)"
)
# VS Code: vscode:mcp/install?<url-encoded json>
_VSCODE_RE = re.compile(r"vscode:mcp/install\?([^\s)]+)")


def _mdx() -> str:
    assert _DOCS_INDEX.exists(), f"docs hero not found at {_DOCS_INDEX!s}"
    return _DOCS_INDEX.read_text(encoding="utf-8")


def _assert_launches_worthless(cfg: dict, where: str) -> None:
    assert cfg.get("command") == _EXPECTED_COMMAND, (
        f"{where}: command is {cfg.get('command')!r}, expected {_EXPECTED_COMMAND!r}"
    )
    assert cfg.get("args") == _EXPECTED_ARGS, (
        f"{where}: args are {cfg.get('args')!r}, expected {_EXPECTED_ARGS!r}"
    )


def test_cursor_badge_decodes_to_worthless_mcp() -> None:
    matches = _CURSOR_RE.findall(_mdx())
    assert matches, "no 'Add to Cursor' deeplink found in docs/index.mdx"
    for name, b64 in matches:
        assert name == "worthless", f"Cursor deeplink name is {name!r}, expected 'worthless'"
        # base64 may arrive url-encoded (e.g. '=' as %3D); normalise first.
        cfg = json.loads(base64.b64decode(urllib.parse.unquote(b64)))
        _assert_launches_worthless(cfg, f"Cursor badge (config={b64[:16]}...)")


def test_vscode_badge_decodes_to_worthless_mcp() -> None:
    matches = _VSCODE_RE.findall(_mdx())
    assert matches, "no 'Install in VS Code' deeplink found in docs/index.mdx"
    for enc in matches:
        cfg = json.loads(urllib.parse.unquote(enc))
        assert cfg.get("name") == "worthless", (
            f"VS Code deeplink name is {cfg.get('name')!r}, expected 'worthless'"
        )
        _assert_launches_worthless(cfg, "VS Code badge")


def test_claude_code_command_is_present_and_correct() -> None:
    # The Claude Code path is a copy-paste command, not a deeplink — pin its
    # exact form so a future edit can't drop the `-y`/package name.
    assert "claude mcp add worthless -- npx -y worthless-mcp" in _mdx(), (
        "Claude Code install command missing or altered in docs/index.mdx"
    )

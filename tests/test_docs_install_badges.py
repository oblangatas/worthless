"""Regression guard for the one-click install badges in the docs hero.

``docs/index.mdx`` ships "Add to Cursor" / "Install in VS Code" buttons whose
targets are *opaque* encoded deeplinks — a base64 or url-encoding typo would
render a button that silently installs the wrong thing (or nothing). A human
can't eyeball ``config=eyJjb21tYW5k...`` and catch that.

This test finds every install deeplink by its scheme (loosely, so a *malformed*
one is still caught rather than silently skipped) and asserts each one decodes
to exactly ``npx -y worthless-mcp``. Pure stdlib + a file read, so it runs in
the default pytest pass with no extra setup.
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

# Loose, scheme-anchored matchers: capture the WHOLE link up to whitespace, a
# closing markdown paren, or a quote. Deliberately permissive so a typo'd link
# is still matched here and then fails the strict decode below — rather than
# being dropped by a strict regex and passing vacuously.
_CURSOR_LINK_RE = re.compile(r"""cursor://[^\s)"'>]+""")
_VSCODE_LINK_RE = re.compile(r"""vscode:mcp/install\?[^\s)"'>]+""")


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


def _param(link: str, key: str) -> str:
    """Extract a single query parameter's raw value from a deeplink.

    Avoids ``parse_qs`` because it turns ``+`` into a space, which would corrupt
    a base64 ``config`` value. ``unquote`` (not ``unquote_plus``) leaves ``+``
    and ``=`` intact while decoding any ``%xx`` — so both raw and url-encoded
    values round-trip.
    """
    m = re.search(rf"[?&]{re.escape(key)}=([^&\s)\"'>]+)", link)
    assert m, f"deeplink missing {key}=: {link[:70]}"
    return urllib.parse.unquote(m.group(1))


def test_cursor_badges_all_decode() -> None:
    links = _CURSOR_LINK_RE.findall(_mdx())
    assert links, "no 'Add to Cursor' deeplink found in docs/index.mdx"
    for link in links:
        assert _param(link, "name") == "worthless", f"Cursor name wrong: {link[:70]}"
        cfg = json.loads(base64.b64decode(_param(link, "config")))
        _assert_launches_worthless(cfg, f"Cursor badge ({link[:40]}...)")


def test_vscode_badges_all_decode() -> None:
    links = _VSCODE_LINK_RE.findall(_mdx())
    assert links, "no 'Install in VS Code' deeplink found in docs/index.mdx"
    for link in links:
        query = urllib.parse.urlsplit(link).query  # the url-encoded json payload
        cfg = json.loads(urllib.parse.unquote(query))
        assert cfg.get("name") == "worthless", f"VS Code name wrong: {link[:70]}"
        _assert_launches_worthless(cfg, f"VS Code badge ({link[:40]}...)")


def test_claude_code_command_is_present_and_correct() -> None:
    # The Claude Code path is a copy-paste command, not a deeplink — pin its
    # exact form so a future edit can't drop the `-y`/package name.
    assert "claude mcp add worthless -- npx -y worthless-mcp" in _mdx(), (
        "Claude Code install command missing or altered in docs/index.mdx"
    )

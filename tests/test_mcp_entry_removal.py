"""worthless-o74j: surgical removal of the Worthless MCP server entry.

The whole safety claim is "we delete ONLY our entry" — these editor configs hold
the user's OTHER MCP servers, so every test here is really asking: did anything
else change? Removal is opt-in (`worthless uninstall --remove-mcp`); the default
stays read-only (name the file, never edit it).
"""

from __future__ import annotations

import json
from pathlib import Path

from worthless.cli.commands.uninstall import _remove_worthless_mcp_entries

_WORTHLESS = {"command": "npx", "args": ["-y", "worthless-mcp"]}
_GITHUB = {"command": "docker", "args": ["run", "ghcr.io/github/mcp"], "env": {"TOKEN": "keep-me"}}


def _cfg(tmp_path: Path, data: dict, name: str = "mcp.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


def test_removes_only_our_entry_and_leaves_other_servers_intact(tmp_path: Path) -> None:
    """Proof of fix: our entry goes, every other server survives value-identical."""
    p = _cfg(tmp_path, {"mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB}})

    removed = _remove_worthless_mcp_entries(p)

    assert removed == ["worthless"]
    after = json.loads(p.read_text(encoding="utf-8"))
    assert "worthless" not in after["mcpServers"], "our entry was not removed"
    assert after["mcpServers"]["github"] == _GITHUB, "another server was altered"


def test_leaves_unrelated_top_level_keys_untouched(tmp_path: Path) -> None:
    """Everything outside mcpServers is the user's — it must survive verbatim."""
    p = _cfg(
        tmp_path,
        {
            "theme": "dark",
            "editor": {"fontSize": 13, "nested": ["a", "b"]},
            "mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB},
        },
    )

    _remove_worthless_mcp_entries(p)

    after = json.loads(p.read_text(encoding="utf-8"))
    assert after["theme"] == "dark"
    assert after["editor"] == {"fontSize": 13, "nested": ["a", "b"]}


def test_removes_from_a_per_project_block_only(tmp_path: Path) -> None:
    """~/.claude.json shape: per-project mcpServers. Only the matching entry goes."""
    p = _cfg(
        tmp_path,
        {
            "projects": {
                "/work/a": {"mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB}},
                "/work/b": {"mcpServers": {"github": _GITHUB}},
            }
        },
        name=".claude.json",
    )

    removed = _remove_worthless_mcp_entries(p)

    assert removed == ["worthless"]
    after = json.loads(p.read_text(encoding="utf-8"))
    assert "worthless" not in after["projects"]["/work/a"]["mcpServers"]
    assert after["projects"]["/work/a"]["mcpServers"]["github"] == _GITHUB
    assert after["projects"]["/work/b"]["mcpServers"] == {"github": _GITHUB}


def test_no_worthless_entry_is_a_no_op_leaving_the_file_byte_identical(tmp_path: Path) -> None:
    """No entry of ours → touch nothing at all (not even a reformat)."""
    p = _cfg(tmp_path, {"mcpServers": {"github": _GITHUB}})
    before = p.read_bytes()

    removed = _remove_worthless_mcp_entries(p)

    assert removed == []
    assert p.read_bytes() == before, "a no-op run rewrote the file"


def test_malformed_json_is_refused_without_corrupting_the_file(tmp_path: Path) -> None:
    """A config we can't parse is left exactly as-is — never truncated."""
    p = tmp_path / "mcp.json"
    p.write_text(
        '{"mcpServers": {"worthless": {"args": ["worthless-mcp"]},,,BROKEN', encoding="utf-8"
    )
    before = p.read_bytes()

    removed = _remove_worthless_mcp_entries(p)

    assert removed == []
    assert p.read_bytes() == before, "a malformed config was modified"


def test_writes_a_backup_before_editing(tmp_path: Path) -> None:
    """The user's original is recoverable after we edit their config."""
    p = _cfg(tmp_path, {"mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB}})
    original = p.read_text(encoding="utf-8")

    _remove_worthless_mcp_entries(p)

    backup = p.with_suffix(p.suffix + ".worthless.bak")
    assert backup.exists(), "no backup was written before editing"
    assert backup.read_text(encoding="utf-8") == original


def test_refuses_to_follow_a_symlink(tmp_path: Path) -> None:
    """Mirror safe_rewrite's SYMLINK gate: never write through a symlink."""
    real = _cfg(tmp_path, {"mcpServers": {"worthless": _WORTHLESS}}, name="real.json")
    link = tmp_path / "mcp.json"
    link.symlink_to(real)
    before = real.read_bytes()

    removed = _remove_worthless_mcp_entries(link)

    assert removed == []
    assert real.read_bytes() == before, "wrote through a symlink"


def test_preserves_the_files_existing_indent_width(tmp_path: Path) -> None:
    """Editing re-serializes the file, so at least keep the user's indent style.

    Backs the docs claim "your indent width is preserved" — an unpinned claim is
    how overclaims creep back in.
    """
    p = tmp_path / "mcp.json"
    p.write_text(
        json.dumps({"mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB}}, indent=4) + "\n",
        encoding="utf-8",
    )

    _remove_worthless_mcp_entries(p)

    assert '\n    "mcpServers"' in p.read_text(encoding="utf-8"), "4-space indent not preserved"


def test_preserves_the_file_mode(tmp_path: Path) -> None:
    """A config the user tightened to 0600 must not come back world-readable."""
    p = _cfg(tmp_path, {"mcpServers": {"worthless": _WORTHLESS, "github": _GITHUB}})
    p.chmod(0o600)

    _remove_worthless_mcp_entries(p)

    assert (p.stat().st_mode & 0o777) == 0o600

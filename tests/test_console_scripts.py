"""Installing worthless puts only worthless's own commands on your PATH.

Every `[project.scripts]` entry becomes a command in the user's PATH when they
`curl worthless.sh | sh`, `uv tool install` or `pipx install`. Dev-only runners
(`test-unit`, `docs-generate`, ...) shipped that way for several releases
(worthless-nd65): useless to users, and free to collide with another tool's
command of the same name. Developers run pytest and scripts/ directly.
"""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # backport for Python 3.10

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_installed_command_is_a_worthless_command() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]
    # Both tables install commands onto PATH.
    scripts = {**project.get("scripts", {}), **project.get("gui-scripts", {})}

    assert "worthless" in scripts, "the CLI itself must stay installable"
    strays = sorted(
        name for name in scripts if name != "worthless" and not name.startswith("worthless-")
    )
    assert not strays, f"these would land on every user's PATH: {strays}"

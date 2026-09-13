"""The ``mcp`` extra must resolve to exactly the 2.x major (WOR-868, WOR-929).

``uvx worthless[mcp]`` — what ``npx worthless-mcp`` runs — resolves the extra
fresh from ``pyproject.toml``, ignoring ``uv.lock``. So the declared range is
what users actually get, and both edges are load-bearing:

* **Floor.** ``src/worthless/mcp/server.py`` imports ``mcp.server.mcpserver``,
  which 1.x does not have. A range admitting 1.x dies at startup.
* **Ceiling.** An unbounded ``mcp>=1.0`` once silently picked up 2.0.0, which
  deleted the module the server imported, and every fresh install died with an
  opaque ``WRTLS-199``. The same will happen with 3.0.0.

The developer environment is pinned by ``uv.lock``, so no runtime import test
catches this — the drift only exists at resolve time. This asserts the
constraint itself.

Checking merely that a ``<`` appears is not enough: ``mcp>=2.1,<99`` contains
one and still resolves straight to a future 3.x. Bounds have to be read as
versions and compared, or the guard passes through the regression it exists
to prevent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from packaging.version import Version

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# ponytail: regex over the raw text, not a TOML parse — tomllib is 3.11+ and we
# still support 3.10, and this file needs no TOML parser to answer one question
# about one line.
_MCP_REQUIREMENT = re.compile(r'^\s*"(mcp[^"]*)"', re.MULTILINE)

# `<3`, `< 3.0.0`, `<=2.9` match. `>=2.1` does not — a lower bound is not a cap.
_UPPER_BOUND = re.compile(r"<\s*(=?)\s*([0-9][0-9A-Za-z.\-+]*)")
# `>=2.1`, `> 2` match. `<=2.9` does not — the `<` before `=` is excluded.
_LOWER_BOUND = re.compile(r"(?<![<=])>\s*(=?)\s*([0-9][0-9A-Za-z.\-+]*)")

# The server is written against 2.x (mcp.server.mcpserver). 1.x lacks it; 3.x
# is the next major and may break it the same way 2.0.0 broke 1.x code.
_SUPPORTED_MAJOR = Version("2")
_NEXT_MAJOR = Version("3")


def _range_violation(spec: str) -> str | None:
    """Return why `spec` can resolve outside mcp 2.x, or None if it cannot.

    Split out from the test so the bounds can be pinned directly, without
    rewriting pyproject.toml to exercise them.
    """
    low = _LOWER_BOUND.search(spec)
    if low is None:
        return "has no lower bound, so it admits mcp 1.x"
    if Version(low.group(2)) < _SUPPORTED_MAJOR:
        return f"lower bound >{low.group(1)}{low.group(2)} admits mcp 1.x"

    high = _UPPER_BOUND.search(spec)
    if high is None:
        return "has no upper bound at all"
    inclusive, raw = high.group(1) == "=", high.group(2)
    bound = Version(raw)
    if (inclusive and bound >= _NEXT_MAJOR) or (not inclusive and bound > _NEXT_MAJOR):
        return f"upper bound <{high.group(1)}{raw} admits mcp {_NEXT_MAJOR}"
    return None


def test_mcp_extra_resolves_to_2x_only() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    matches = _MCP_REQUIREMENT.findall(text)
    mcp_spec = next((m for m in matches if m.replace(" ", "").startswith("mcp>")), None)

    assert mcp_spec is not None, f"no pinned `mcp` requirement found; saw: {matches}"

    violation = _range_violation(mcp_spec)
    assert violation is None, (
        f"`mcp` requirement {mcp_spec!r} {violation}. The server imports "
        "`mcp.server.mcpserver` (2.x only), and every fresh `uvx worthless[mcp]` "
        "resolve takes the newest version the range allows (WOR-868, WOR-929). "
        "Moving to another major requires porting server.py first."
    )


@pytest.mark.parametrize(
    "spec",
    [
        "mcp>=2.1,<3",
        "mcp>=2,<3.0.0",
        "mcp>= 2.1,< 3",
        "mcp>=2.1,<=2.9",
    ],
)
def test_real_2x_ranges_are_accepted(spec: str) -> None:
    assert _range_violation(spec) is None


@pytest.mark.parametrize(
    "spec",
    [
        "mcp>=2.1",  # no cap — the original WOR-868 breakage, one major on
        "mcp>=2.1,<99",  # a `<` that caps nothing
        "mcp>=2.1,<3.1",  # 3.1 admits 3.0
        "mcp>=2.1,<=3",  # inclusive of the next major
        "mcp>=1.0,<3",  # floor admits 1.x, which lacks mcp.server.mcpserver
        "mcp<3",  # no floor at all
    ],
)
def test_ranges_outside_2x_are_rejected(spec: str) -> None:
    """Every one of these can resolve to an mcp the server cannot run on."""
    assert _range_violation(spec) is not None

"""The ``mcp`` extra must stay capped below the next major (WOR-868).

``uvx worthless[mcp]`` — what ``npx worthless-mcp`` runs — resolves the extra
fresh from ``pyproject.toml``, ignoring ``uv.lock``. So an unbounded
``mcp>=1.0`` silently picked up ``mcp`` 2.0.0, which deleted the
``mcp.server.fastmcp`` module ``src/worthless/mcp/server.py`` imports, and every
fresh install died at startup with an opaque ``WRTLS-199``.

The developer environment is pinned by ``uv.lock``, so no runtime import test
catches this — the drift only exists at resolve time. This asserts the
constraint itself.

Checking merely that a ``<`` appears is not enough: ``mcp>=1.0,<99`` contains
one and still resolves straight to the broken 2.x. The bound has to be read as
a version and compared, or the guard passes through the regression it exists
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

# The exclusive upper bound: `<2`, `< 2.0.0`, `<=1.9` all match. `>=1.0` does
# not — a lower bound is not a cap.
_UPPER_BOUND = re.compile(r"<\s*(=?)\s*([0-9][0-9A-Za-z.\-+]*)")

# mcp 2.0.0 renamed mcp.server.fastmcp -> mcp.server.mcpserver with no shim.
# Anything that can resolve to 2.x breaks `worthless mcp`.
_FIRST_BROKEN = Version("2")


def _cap_violation(spec: str) -> str | None:
    """Return why `spec` fails to cap mcp below 2.x, or None if it is safe.

    Split out from the test so the bounds can be pinned directly, without
    rewriting pyproject.toml to exercise them.
    """
    match = _UPPER_BOUND.search(spec)
    if match is None:
        return "has no upper bound at all"

    inclusive, raw = match.group(1) == "=", match.group(2)
    bound = Version(raw)

    if inclusive:
        # `<=2` admits 2.0.0 itself, which is the broken release.
        if bound >= _FIRST_BROKEN:
            return f"upper bound <={raw} still admits mcp {_FIRST_BROKEN} or newer"
        return None

    if bound > _FIRST_BROKEN:
        return f"upper bound <{raw} still admits mcp {_FIRST_BROKEN}"
    return None


def test_mcp_extra_is_capped_below_2() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    matches = _MCP_REQUIREMENT.findall(text)
    mcp_spec = next((m for m in matches if m.replace(" ", "").startswith("mcp>")), None)

    assert mcp_spec is not None, f"no pinned `mcp` requirement found; saw: {matches}"

    violation = _cap_violation(mcp_spec)
    assert violation is None, (
        f"`mcp` requirement {mcp_spec!r} {violation}. mcp 2.0.0 removed "
        "`mcp.server.fastmcp`, so this breaks `worthless mcp` on every fresh "
        "`uvx worthless[mcp]` resolve (WOR-868). Lifting the cap requires "
        "porting to the 2.x `mcp.server.mcpserver` API first."
    )


@pytest.mark.parametrize(
    "spec",
    [
        "mcp>=1.0,<2",
        "mcp>=1.0,<2.0.0",
        "mcp>=1.0,< 2",
        "mcp>=1.0,<=1.9",
    ],
)
def test_real_caps_are_accepted(spec: str) -> None:
    assert _cap_violation(spec) is None


@pytest.mark.parametrize(
    "spec",
    [
        "mcp>=1.0",  # no cap at all — the original WOR-868 breakage
        "mcp>=1.0,<99",  # the bug this rewrite fixes: a `<` that caps nothing
        "mcp>=1.0,<3",
        "mcp>=1.0,<2.1",  # 2.1 admits 2.x
        "mcp>=1.0,<=2",  # inclusive of the first broken release
    ],
)
def test_fake_caps_are_rejected(spec: str) -> None:
    """Every one of these resolves to a broken mcp. None may pass."""
    assert _cap_violation(spec) is not None

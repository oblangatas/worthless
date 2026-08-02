"""Declared dependency bounds must exclude known-breaking majors (WOR-864).

Why assert the *declared* specifier and not the resolved version: `semgrep` (qa
extra) pins ``mcp==1.23.3`` exactly, so `uv.lock` resolves 1.23.3 whether or not
our own constraint has a ceiling. Every lock-based check therefore passes
identically before and after the fix and proves nothing. What users actually
resolve against is the *published metadata* — this file asserts that.

This is a narrow guard, not a policy that every dependency must be capped. A cap
that nobody raises fails harder than no cap (an unsatisfiable resolve rather than
a possibly-working install), and capping a widely-shared library like ``httpx``
manufactures conflicts with the openai/anthropic SDKs installed alongside us. A
dependency earns an entry below only when all three hold:

    1. it is imported at CLI import time,
    2. it is pre-1.0 (or has already shipped a breaking major), and
    3. a concrete breakage is known and named in ``reason``.
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 backport
    import tomli as tomllib

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

# (extra or None for runtime, distribution, must_allow, must_reject, reason)
BOUNDED_DEPENDENCIES = [
    (
        "mcp",
        "mcp",
        "1.29.0",
        "2.0.0",
        "mcp 2.0.0 renamed mcp.server.fastmcp -> mcp.server.mcpserver with no "
        "compatibility shim, breaking src/worthless/mcp/server.py at import time.",
    ),
]


def _requirements(extra: str | None) -> list[Requirement]:
    data = tomllib.loads(PYPROJECT.read_text())
    project = data["project"]
    raw = project["dependencies"] if extra is None else project["optional-dependencies"][extra]
    return [Requirement(entry) for entry in raw]


@pytest.mark.parametrize(
    ("extra", "distribution", "must_allow", "must_reject", "reason"),
    [pytest.param(*row, id=row[1]) for row in BOUNDED_DEPENDENCIES],
)
def test_declared_bound_excludes_the_breaking_major(
    extra: str | None, distribution: str, must_allow: str, must_reject: str, reason: str
) -> None:
    matches = [r for r in _requirements(extra) if r.name == distribution]
    assert matches, (
        f"{distribution!r} is no longer declared in "
        f"{'[project.dependencies]' if extra is None else f'optional-dependencies.{extra}'}; "
        "drop its row from BOUNDED_DEPENDENCIES or restore the dependency."
    )
    specifier = matches[0].specifier

    assert specifier.contains(Version(must_allow)), (
        f"the declared bound for {distribution} excludes {must_allow}, which we do "
        f"support — the ceiling is too tight. Declared: {specifier}"
    )
    assert not specifier.contains(Version(must_reject)), (
        f"the declared bound for {distribution} still allows {must_reject}. A fresh "
        f"`pip install` resolves it and the install breaks for users.\n"
        f"Declared: {specifier or '<unbounded>'}\nReason: {reason}"
    )

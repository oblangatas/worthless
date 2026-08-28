"""worthless-ip28 — the user-flow lane installs every extra its tests gate on.

A test that calls ``pytest.importorskip("X")`` disappears silently when ``X``
is not installed. It does not fail, it does not warn — the run reports green
with one fewer test. That is how WOR-829's only live proof
(``tests/user_flows/test_mcp_lock_warns_when_proxy_down.py``) sat inert in CI
while the PR showed 45 passing checks: ``user-flows.yml`` synced
``--extra dev --extra test`` and the test gated on ``mcp``.

This guard DERIVES the required extras from the test files themselves rather
than pinning a hardcoded list. A hardcoded list rots the moment someone adds a
gated test — and rots silently, which is the same failure it exists to prevent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
USER_FLOWS = REPO_ROOT / "tests" / "user_flows"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "user-flows.yml"

_IMPORTORSKIP = re.compile(r"""importorskip\(\s*["']([\w.\-]+)["']""")
# The sync line that prepares the interpreter the user-flow tests then run on.
_RUN_SYNC = re.compile(r"^\s*uv sync (?P<flags>.*--extra[^\n]*)$", re.MULTILINE)


def _gated_modules() -> set[str]:
    """Top-level module names the user-flow tests refuse to run without."""
    found: set[str] = set()
    for path in USER_FLOWS.rglob("*.py"):
        for match in _IMPORTORSKIP.finditer(path.read_text(encoding="utf-8")):
            found.add(match.group(1).split(".")[0])
    return found


def _synced_extras() -> set[str]:
    """Extras the workflow installs on the line that runs the tests.

    Deliberately reads the LAST ``uv sync ... --extra`` occurrence: an earlier
    one warms the cache for a keychain probe and is not what the tests run on.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    syncs = _RUN_SYNC.findall(text)
    assert syncs, f"no 'uv sync --extra' line found in {WORKFLOW.name}"
    return set(re.findall(r"--extra\s+([\w\-]+)", syncs[-1]))


def test_user_flow_lane_installs_every_gated_extra() -> None:
    """Every module a user-flow test gates on must be installed by the lane.

    Assumes the extra is named after the module, which holds for ``mcp``. If a
    future gate uses a module whose extra has a different name, this fails
    loudly and someone maps it explicitly — far better than the test vanishing.
    """
    gated = _gated_modules()
    if not gated:
        pytest.skip("no user-flow test gates on an optional import")
    missing = gated - _synced_extras()
    assert not missing, (
        f"user-flows.yml does not install {sorted(missing)}, so the user-flow "
        f"tests gating on {sorted(gated)} will importorskip and vanish while the "
        "lane still reports green (worthless-ip28). Add --extra <name> to the "
        "uv sync on the 'Run user-flow tests' step."
    )


def test_the_wor829_proof_is_one_of_the_gated_tests() -> None:
    """Pins the specific file this guard was written for.

    If that proof is ever renamed or deleted, this fails and whoever did it has
    to decide deliberately, rather than the guard quietly covering nothing.
    """
    proof = USER_FLOWS / "test_mcp_lock_warns_when_proxy_down.py"
    assert proof.exists(), f"{proof.name} is gone — is WOR-829 still proven anywhere?"
    assert "importorskip" in proof.read_text(encoding="utf-8"), (
        f"{proof.name} no longer gates on an optional import; if it now runs "
        "unconditionally that is fine, but this guard should be re-pointed."
    )

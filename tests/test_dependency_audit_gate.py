"""Pin the CI dependency gate to the pre-commit hook it mirrors (worthless-jymn).

`uv-audit` in .pre-commit-config.yaml is `stages: [pre-push]`, so it never runs
for a Dependabot PR, a GitHub web edit, `git push --no-verify`, or a clone that
never ran `pre-commit install`. dependency-audit.yml mirrors it into CI — the
same move docker-security.yml already made for the grype-expiry hook (WOR-852).

The mirror is only worth anything while both sides run the SAME command. If
they drift, one reports clean and the other reports vulnerable, and there is no
way to tell which is right without reading both. These tests pin:

  - the workflow command is byte-identical to the hook entry
  - the audit step can still FAIL (no continue-on-error) — a gate that cannot
    go red is the exact failure worthless-tidv was opened for
  - the trigger keeps its shape: pull_request present and unfiltered, and no
    job-level `if:` — a paths filter left nine PRs BLOCKED when `scan` became
    required (WOR-874), and a skipped job reports SUCCESS to branch protection,
    which turns a gate into a bypass

Hermetic: parses the two YAML files on disk. No network, no runner, no audit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "dependency-audit.yml"
PRE_COMMIT = REPO / ".pre-commit-config.yaml"


def _audit_step() -> dict:
    """The step in dependency-audit.yml that actually runs pip-audit."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["audit"]["steps"]
    matches = [s for s in steps if "pip-audit" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one pip-audit step, got {len(matches)}"
    return matches[0]


def _hook_entry() -> str:
    """The `uv-audit` hook's command, unwrapped from its `sh -c '...'` shell."""
    cfg = yaml.safe_load(PRE_COMMIT.read_text())
    hooks = [h for repo in cfg["repos"] for h in repo.get("hooks", []) if h.get("id") == "uv-audit"]
    assert len(hooks) == 1, "uv-audit hook not found (renamed? then update this test)"
    entry = hooks[0]["entry"]
    # entry is `sh -c '<command>'` — take what is inside the quotes.
    m = re.fullmatch(r"sh -c '(.*)'", entry.strip(), re.DOTALL)
    assert m, f"uv-audit entry is no longer a `sh -c '...'` wrapper: {entry!r}"
    return m.group(1).strip()


def test_ci_command_matches_hook_exactly() -> None:
    """CI and the hook must audit the same thing, or they can disagree."""
    assert _audit_step()["run"].strip() == _hook_entry()


def test_audit_step_can_fail() -> None:
    """A gate that cannot go red is decoration. See worthless-tidv."""
    step = _audit_step()
    assert "continue-on-error" not in step, (
        "continue-on-error makes this gate report green when it fails"
    )
    assert "set +e" not in step["run"], "`set +e` swallows the exit code the gate depends on"


def test_audit_job_has_no_continue_on_error() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "continue-on-error" not in wf["jobs"]["audit"]


@pytest.mark.parametrize("forbidden", ["paths", "paths-ignore"])
def test_pull_request_trigger_is_unfiltered(forbidden: str) -> None:
    """A path filter turns a required check into a deadlock. WOR-874."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    # `on:` parses as the boolean True in YAML 1.1 unless quoted.
    triggers = wf.get("on") or wf.get(True)
    assert "pull_request" in triggers, "the gate must report on every PR"
    pr = triggers["pull_request"] or {}
    assert forbidden not in pr, (
        f"`{forbidden}` on pull_request can leave a required check never reporting"
    )


def test_audit_job_is_unconditional() -> None:
    """A skipped job reports SUCCESS to branch protection — a bypass, not a gate."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "if" not in wf["jobs"]["audit"]

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


def test_audit_step_runs_with_pipefail() -> None:
    """The run is a PIPELINE, and GitHub's default shell has no pipefail.

    `bash -e -c 'false | true'` exits 0. So without this, a `uv export` that
    died partway would hand pip-audit a truncated stream, which audits the
    packages that arrived and exits 0 — a green gate over a fragment. That is
    the failure mode worthless-tidv was opened for. `shell: bash` is the
    documented opt-in to `-eo pipefail`.
    """
    step = _audit_step()
    assert "|" in step["run"], "if this stops being a pipeline, revisit this test"
    assert step.get("shell") == "bash", (
        "a pipeline step without `shell: bash` runs under `bash -e` with no pipefail, "
        "so a failing `uv export` would be masked by pip-audit's exit code"
    )


def test_lock_freshness_is_checked() -> None:
    """`--frozen` audits uv.lock as-is; a desynced lock exports a stale tree."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["audit"]["steps"])
    assert "uv lock --check" in runs, (
        "without a freshness check, `--frozen` happily audits a lock that no longer "
        "matches pyproject.toml, while a different tree actually ships"
    )


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


# ── npm side (worthless-yhcc) ──────────────────────────────────────────────
# The Worker subproject has its own lockfile and was audited by nothing.


def _npm_step() -> dict:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["npm-audit"]["steps"]
    matches = [s for s in steps if "npm audit" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one npm audit step, got {len(matches)}"
    return matches[0]


def test_npm_audit_covers_the_full_tree() -> None:
    """Dev tooling stays in scope — it runs in CI with deploy credentials.

    An earlier version of this job used `--omit=dev`, justified by 5 devDependency
    advisories that would have made a full gate red on arrival. That was false:
    `npm audit fix --package-lock-only` cleared all 5 with package.json unchanged.
    Narrowing a security gate to dodge findings that a one-command refresh fixes
    is looking away, not scoping.
    """
    step = _npm_step()
    assert "--omit=dev" not in step["run"], (
        "wrangler and miniflare execute in CI and on dev machines with deploy "
        "credentials; excluding them from a credential-protection product's "
        "supply-chain gate needs a real cost, and the measured cost is zero"
    )
    assert step.get("working-directory") == "workers/worthless-sh"


def test_npm_lockfile_freshness_is_checked() -> None:
    """`npm audit` reads the lockfile and never checks it matches package.json.

    Add a runtime dependency without relocking and the audit reports 0
    vulnerabilities and exits 0 — green over a tree that is not the tree, which
    is exactly the failure worthless-tidv was opened for.
    """
    wf = yaml.safe_load(WORKFLOW.read_text())
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["npm-audit"]["steps"])
    assert "npm ci" in runs, (
        "without a sync check, a stale package-lock.json passes the audit while a "
        "different dependency tree actually installs"
    )


def test_npm_audit_can_fail() -> None:
    """Same rule as the Python gate: it must be able to go red."""
    step = _npm_step()
    assert "continue-on-error" not in step
    assert "|| true" not in step["run"], "swallowing the exit code makes this decorative"
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "continue-on-error" not in wf["jobs"]["npm-audit"]
    assert "if" not in wf["jobs"]["npm-audit"], (
        "a skipped job reports SUCCESS to branch protection — a bypass, not a gate"
    )


def test_dependabot_covers_the_worker() -> None:
    """Advisories with no update PR never clear — main sat on 5 of them."""
    cfg = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text())
    npm = [u for u in cfg["updates"] if u["package-ecosystem"] == "npm"]
    assert npm, "no npm ecosystem entry: Dependabot raises Worker advisories but never fixes them"
    assert any(u["directory"].rstrip("/").endswith("workers/worthless-sh") for u in npm)

"""npm releases publish through GitHub sign-in (OIDC), not only a token (WOR-921).

npm trusted publishing swaps the job's GitHub id-token for a short-lived
publish credential and adds provenance. It needs two things the workflow
must keep: `id-token: write` on the publish job, and npm >= 11.5.1, which
ships with Node 24. Losing either silently falls back to the long-lived
NPM_TOKEN, which expires, and releases go out without provenance.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "publish-npm.yml"


def _publish_job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["publish"]


def test_publish_job_can_request_a_github_id_token() -> None:
    perms = _publish_job()["permissions"]
    assert perms["id-token"] == "write"
    # Job permissions replace the workflow's, so checkout still needs this.
    assert perms["contents"] == "read"


def test_publish_job_runs_an_npm_that_supports_trusted_publishing() -> None:
    steps = _publish_job()["steps"]
    node = next(s for s in steps if "actions/setup-node" in s.get("uses", ""))
    assert int(str(node["with"]["node-version"]).split(".")[0]) >= 24


def test_a_token_fallback_is_flagged_but_never_blocks_the_release() -> None:
    # 0.3.17 and 0.3.18 fell back to NPM_TOKEN silently. The check must say so
    # on the run, but must not fail it: a failed run holds the GitHub Release.
    steps = _publish_job()["steps"]
    check = next(s for s in steps if s.get("name", "").startswith("Check provenance"))
    assert "dist.attestations" in check["run"]
    assert "::error::" in check["run"]
    assert "exit 1" not in check["run"]
    assert not check.get("continue-on-error")  # fan-in flags continue-on-error jobs


def test_publish_stays_behind_the_release_environment() -> None:
    # The trusted publisher on npmjs.com names this environment; renaming it
    # breaks OIDC publishing.
    assert _publish_job()["environment"] == "npm-publish"

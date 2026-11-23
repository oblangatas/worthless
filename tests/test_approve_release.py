"""scripts/approve-release.sh: one `y` approves a whole release (WOR-1165).

Every test drives the real script against a fake `gh` on PATH. The fake records
every call and refuses `release create`, `workflow run` and `issue create`, so no
test can touch GitHub. TestGuardsCanActuallyFail in test_deploy_static.py mutates
the script and requires the guards below to go red.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
APPROVE_SCRIPT = REPO_ROOT / "scripts" / "approve-release.sh"
TAG_RELEASE_SCRIPT = REPO_ROOT / "scripts" / "tag-release.sh"

TAG = "v9.9.9"
REPO = "acme/widget"
OLD_SHA = "b" * 40
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
# A fixed commit object, so the local tag's sha is known before any repo exists.
_COMMIT = (
    f"tree {_EMPTY_TREE}\nauthor T <t@example.invalid> 0 +0000\n"
    "committer T <t@example.invalid> 0 +0000\n\nrelease\n"
).encode()
SHA = hashlib.sha1(b"commit %d\0" % len(_COMMIT) + _COMMIT).hexdigest()  # noqa: S324


def _tag_repo(path: Path) -> Path:
    """A git repo whose refs/tags/v9.9.9 points at SHA. The script reads it locally."""
    path.mkdir()
    git = ["git", "-C", str(path), "-c", "core.hooksPath=/dev/null"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run(
        [*git, "hash-object", "-w", "-t", "tree", "/dev/null"], check=True, capture_output=True
    )
    made = (
        subprocess.run(
            [*git, "hash-object", "-w", "-t", "commit", "--stdin"],
            input=_COMMIT,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )
    assert made == SHA
    subprocess.run([*git, "update-ref", f"refs/tags/{TAG}", SHA], check=True)
    return path


# Fake gh. Every call is logged to $GH_CALLS as args joined by \x1f, one per line.
#   TAG_SHA     commit the tag resolves to (/commits/<tag>)
#   PUB_RUNS    JSON list served by /actions/runs (the tag's push runs)
#   PENDING     JSON object run-id -> pending_deployments; an environment drops out
#               once it was POSTed as approved for that run, like the real API
#   RN_RUNS     JSON list served by the release-notes.yml runs listing
#   RELEASE_LIVE_AFTER  `gh release view` succeeds once this string is in the log
_GH_SHIM = r"""#!/usr/bin/env bash
printf '%s\x1f' "$@" >>"$GH_CALLS"; printf '\n' >>"$GH_CALLS"
method=GET; path=""; jqf=""; prev=""
for a in "$@"; do
  case "$prev" in -X) method="$a";; --jq) jqf="$a";; esac
  case "$a" in /repos/*|repos/*) [ -z "$path" ] && path="${a#/}";; esac
  prev="$a"
done
# -rc: like real `gh --jq`, strings come out raw and objects compact.
emit() { if [ -n "$jqf" ]; then printf '%s' "$1" | jq -rc "$jqf"; else printf '%s\n' "$1"; fi; }
case "${1:-} ${2:-}" in
  "repo view") echo "acme/widget"; exit 0 ;;
  "release view")
    if [ -n "${RELEASE_LIVE_AFTER:-}" ] && grep -qF -- "$RELEASE_LIVE_AFTER" "$GH_CALLS"; then
      echo "https://github.com/acme/widget/releases/tag/$3"; exit 0
    fi
    echo "release not found" >&2; exit 1 ;;
  "release "*|"workflow "*|"issue "*) echo "shim: refusing gh $*" >&2; exit 99 ;;
esac
pend=${PENDING:-'{}'}
case "$method $path" in
  "POST "*/pending_deployments) echo '[]'; exit 0 ;;
  "GET "*/commits/*) emit "{\"sha\": \"$TAG_SHA\"}"; exit 0 ;;
  "GET "*/actions/workflows/release-notes.yml/runs)
    emit "{\"workflow_runs\": ${RN_RUNS:-[]}}"; exit 0 ;;
  "GET "*/actions/runs/*/pending_deployments)
    rid=$(printf '%s' "$path" | sed -E 's#.*/actions/runs/([^/]+)/pending_deployments#\1#')
    done_ids=$(grep -F "POST" "$GH_CALLS" | grep -F "actions/runs/${rid}/pending_deployments" \
      | grep -oE 'environment_ids\[\]=[0-9]+' | cut -d= -f2 \
      | jq -Rsc 'split("\n") | map(select(. != "") | tonumber)')
    emit "$(jq -cn --argjson p "$pend" --arg r "$rid" --argjson d "$done_ids" \
      '($p[$r] // []) | map(select(.environment.id as $e | ($d | index($e)) | not))')"
    exit 0 ;;
  "GET "*/actions/runs) emit "{\"workflow_runs\": ${PUB_RUNS:-[]}}"; exit 0 ;;
esac
echo "shim: unhandled gh $*" >&2; exit 98
"""


def _run(run_id: int, name: str, wf: str, status: str, conclusion=None, sha: str = SHA) -> dict:
    return {
        "id": run_id,
        "name": name,
        "path": f".github/workflows/{wf}",
        "status": status,
        "conclusion": conclusion,
        "head_sha": sha,
        "event": "push",
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
    }


def _pending(env_id: int, name: str, can: bool = True) -> list[dict]:
    return [{"environment": {"id": env_id, "name": name}, "current_user_can_approve": can}]


def _waiting_release() -> list[dict]:
    """Three gated publishers waiting, the image building, release run waiting."""
    return [
        _run(101, "Publish to PyPI", "publish.yml", "waiting"),
        _run(102, "Publish worthless-mcp to npm", "publish-npm.yml", "waiting"),
        _run(103, "Publish Docker image to GHCR", "publish-docker.yml", "in_progress"),
        _run(104, "Deploy Worker (worthless-sh)", "deploy-worker.yml", "waiting"),
    ]


_PENDING = {
    "101": _pending(11, "pypi"),
    "102": _pending(12, "npm-publish"),
    "104": _pending(14, "worthless-sh-production"),
    "201": _pending(21, "release"),
}

_RN_RUNS = [
    {
        "id": 201,
        "status": "waiting",
        "conclusion": None,
        "event": "workflow_run",
        "display_title": f"Create GitHub Release {TAG} {SHA}",
        "html_url": f"https://github.com/{REPO}/actions/runs/201",
    }
]


def _approve(
    tmp_path: Path,
    *args: str,
    stdin: str = "",
    pub_runs: list[dict] | None = None,
    pending: dict | None = None,
    rn_runs: list[dict] | None = None,
    gh_repo: str | None = REPO,
    api_sha: str = SHA,
):
    repo = _tag_repo(tmp_path / "checkout")
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    gh = shim_dir / "gh"
    gh.write_text(_GH_SHIM)
    gh.chmod(0o755)
    calls = tmp_path / "gh_calls.log"
    calls.write_text("")
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GH_REPO")}
    env.update(
        PATH=f"{shim_dir}{os.pathsep}{env['PATH']}",
        GH_CALLS=str(calls),
        TAG_SHA=api_sha,
        PUB_RUNS=json.dumps(_waiting_release() if pub_runs is None else pub_runs),
        PENDING=json.dumps(_PENDING if pending is None else pending),
        RN_RUNS=json.dumps(_RN_RUNS if rn_runs is None else rn_runs),
        RELEASE_LIVE_AFTER="environment_ids[]=21",
        APPROVE_POLL_SECONDS="0",
    )
    if gh_repo is not None:
        env["GH_REPO"] = gh_repo
    # One polling pass by default: the happy path finishes inside it, and a broken
    # script (a mutation) ends with exit 2 instead of polling for an hour.
    if "--timeout-min" not in args:
        args = (*args, "--timeout-min", "0")
    proc = subprocess.run(
        ["bash", str(APPROVE_SCRIPT), TAG, *args],  # noqa: S607
        cwd=repo,
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    log = [ln.split("\x1f")[:-1] for ln in calls.read_text().splitlines() if ln]
    return proc, log


def _approvals(log: list[list[str]]) -> list[tuple[str, str]]:
    """(run id, environment id) for every approve POST, in order."""
    out = []
    for call in log:
        if "POST" not in call:
            continue
        path = next(a for a in call if "pending_deployments" in a)
        run_id = re.search(r"/runs/([^/]+)/pending_deployments", path).group(1)
        env_id = next(a.split("=", 1)[1] for a in call if a.startswith("environment_ids[]="))
        assert "state=approved" in call, f"approve POST without state=approved: {call}"
        out.append((run_id, env_id))
    return out


class TestApproveRelease:
    def test_lists_every_waiting_environment_with_its_run(self, tmp_path):
        proc, _ = _approve(tmp_path, stdin="n\n")
        for env, run_id in (("pypi", 101), ("npm-publish", 102), ("worthless-sh-production", 104)):
            assert env in proc.stdout, proc.stdout
            assert f"https://github.com/{REPO}/actions/runs/{run_id}" in proc.stdout, proc.stdout
        assert SHA[:12] in proc.stdout, "the commit to check must be shown before approving"

    def test_answering_no_approves_nothing(self, tmp_path):
        proc, log = _approve(tmp_path, stdin="n\n")
        assert "Approve all? [y/N]" in proc.stdout
        assert _approvals(log) == []
        assert proc.returncode == 3, proc.stdout + proc.stderr

    def test_no_answer_at_all_approves_nothing(self, tmp_path):
        proc, log = _approve(tmp_path, stdin="")
        assert _approvals(log) == []
        assert proc.returncode == 3

    def test_one_y_approves_the_publishers_then_the_release(self, tmp_path):
        proc, log = _approve(tmp_path, stdin="y\n")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        approvals = _approvals(log)
        assert sorted(approvals[:3]) == [("101", "11"), ("102", "12"), ("104", "14")]
        assert approvals[3:] == [("201", "21")], (
            "the release environment must be approved after the publishers, without a second prompt"
        )
        assert proc.stdout.count("Approve all?") == 1
        assert f"Release {TAG} is live: https://github.com/{REPO}/releases/tag/{TAG}" in proc.stdout

    def test_yes_flag_never_prompts(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Approve all?" not in proc.stdout
        assert len(_approvals(log)) == 4

    def test_a_failed_publisher_is_named_and_exits_1(self, tmp_path):
        runs = _waiting_release()
        runs[2] = _run(
            103, "Publish Docker image to GHCR", "publish-docker.yml", "completed", "failure"
        )
        proc, log = _approve(tmp_path, "--yes", pub_runs=runs)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        out = proc.stdout + proc.stderr
        assert "Publish Docker image to GHCR" in out
        assert f"https://github.com/{REPO}/actions/runs/103" in out
        assert ("201", "21") not in _approvals(log), "never approve a release a publisher refused"

    def test_a_cancelled_publisher_exits_1(self, tmp_path):
        runs = _waiting_release()
        runs[0] = _run(101, "Publish to PyPI", "publish.yml", "completed", "cancelled")
        proc, _ = _approve(tmp_path, "--yes", pub_runs=runs)
        assert proc.returncode == 1
        assert "Publish to PyPI" in proc.stdout + proc.stderr

    def test_timeout_exits_2_with_a_clear_message(self, tmp_path):
        runs = [
            _run(101, "Publish to PyPI", "publish.yml", "in_progress"),
            _run(102, "Publish worthless-mcp to npm", "publish-npm.yml", "queued"),
        ]
        proc, log = _approve(tmp_path, "--yes", "--timeout-min", "0", pub_runs=runs, rn_runs=[])
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert "Timed out" in proc.stdout + proc.stderr
        assert _approvals(log) == []

    def test_never_creates_a_release_or_dispatches(self, tmp_path):
        _, log = _approve(tmp_path, stdin="y\n")
        for call in log:
            assert call[:2] not in (
                ["release", "create"],
                ["workflow", "run"],
                ["issue", "create"],
            ), call
        code = "\n".join(
            ln for ln in APPROVE_SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")
        )
        assert not re.search(r"\bgh\s+(release\s+create|workflow\s+run|issue\s+create)\b", code)

    def test_a_run_at_another_commit_is_never_approved(self, tmp_path):
        # Newer id than the real run: a re-run of an older tag is the NEWEST run, so
        # only the commit filter keeps it out, not "pick the latest per workflow".
        stale = _run(199, "Publish to PyPI", "publish.yml", "waiting", sha=OLD_SHA)
        pending = {**_PENDING, "199": _pending(9, "pypi")}
        proc, log = _approve(
            tmp_path, "--yes", pub_runs=[*_waiting_release(), stale], pending=pending
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert all(run_id != "199" for run_id, _ in _approvals(log))
        assert re.search(r"skipped: .*runs/199 \(not this tag's push\)", proc.stdout), proc.stdout

    def test_a_dispatched_run_on_the_same_environment_is_never_approved(self, tmp_path):
        # e.g. `gh workflow run deploy-worker.yml --ref v9.9.9`: same tag, same
        # commit, same environment, newest id — but not the tag's push.
        dispatched = {
            **_run(150, "Deploy Worker (worthless-sh)", "deploy-worker.yml", "waiting"),
            "event": "workflow_dispatch",
        }
        pending = {**_PENDING, "150": _pending(14, "worthless-sh-production")}
        proc, log = _approve(
            tmp_path, "--yes", pub_runs=[*_waiting_release(), dispatched], pending=pending
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert all(run_id != "150" for run_id, _ in _approvals(log)), _approvals(log)
        assert ("104", "14") in _approvals(log)
        assert re.search(r"skipped: .*runs/150 \(not this tag's push\)", proc.stdout), proc.stdout

    def test_an_unexpected_environment_is_never_approved(self, tmp_path):
        extra = {
            "environment": {"id": 15, "name": "pypi-staging"},
            "current_user_can_approve": True,
        }
        pending = {**_PENDING, "101": [*_PENDING["101"], extra]}
        proc, log = _approve(tmp_path, "--yes", pending=pending)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert ("101", "15") not in _approvals(log)
        assert ("101", "11") in _approvals(log)
        assert "skipped: pypi-staging" in proc.stdout, proc.stdout

    def test_github_tag_moved_from_the_local_signed_tag_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes", api_sha=OLD_SHA)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert _approvals(log) == []
        assert SHA[:12] in proc.stdout + proc.stderr and OLD_SHA[:12] in proc.stdout + proc.stderr

    def test_expect_sha_mismatch_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes", "--expect-sha", OLD_SHA)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert _approvals(log) == []
        assert OLD_SHA[:12] in proc.stdout + proc.stderr

    def test_expect_sha_match_proceeds(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes", "--expect-sha", SHA)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert len(_approvals(log)) == 4

    def test_a_release_titled_run_that_is_not_a_workflow_run_is_never_approved(self, tmp_path):
        # A PR that edits release-notes.yml runs under the same path and can title
        # itself like a release; only workflow_run runs use the default branch's file.
        rn = [{**_RN_RUNS[0], "event": "pull_request"}]
        proc, log = _approve(tmp_path, "--yes", rn_runs=rn)
        assert ("201", "21") not in _approvals(log)
        assert proc.returncode == 2

    def test_a_release_run_for_an_old_commit_is_never_approved(self, tmp_path):
        rn = [{**_RN_RUNS[0], "display_title": f"Create GitHub Release {TAG} {OLD_SHA}"}]
        proc, log = _approve(tmp_path, "--yes", "--timeout-min", "0", rn_runs=rn)
        assert ("201", "21") not in _approvals(log)
        assert proc.returncode == 2

    def test_an_environment_you_cannot_approve_is_skipped(self, tmp_path):
        pending = {**_PENDING, "102": _pending(12, "npm-publish", can=False)}
        proc, log = _approve(tmp_path, "--yes", "--timeout-min", "0", pending=pending)
        assert ("102", "12") not in _approvals(log)
        assert "npm-publish" in proc.stdout + proc.stderr

    def test_repo_defaults_from_gh_repo_view(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes", gh_repo=None)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert any(c[:2] == ["repo", "view"] for c in log)


def _docker_critical_path_min() -> int:
    """Longest chain of job timeout-minutes through publish-docker.yml's `needs:`."""
    jobs = yaml.safe_load((REPO_ROOT / ".github/workflows/publish-docker.yml").read_text())["jobs"]

    def path(name: str) -> int:
        needs = jobs[name].get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        return int(jobs[name]["timeout-minutes"]) + max((path(n) for n in needs), default=0)

    return max(path(n) for n in jobs)


def test_default_timeout_outlasts_the_slowest_publisher():
    """The release waits on the GHCR image. A default shorter than its worst case
    times out a release that is still going, and the maintainer reads it as broken."""
    default = int(re.search(r"^timeout_min=(\d+)$", APPROVE_SCRIPT.read_text(), re.M).group(1))
    worst = _docker_critical_path_min()
    assert default >= worst + 10, (
        f"--timeout-min defaults to {default}, but publish-docker.yml's job timeouts chain to "
        f"{worst} min before the release run even starts. Keep at least 10 min of margin."
    )


class TestTagReleaseCallsApprove:
    def test_tag_release_hands_off_to_approve_after_the_push(self):
        lines = [
            ln.strip()
            for ln in TAG_RELEASE_SCRIPT.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        push = lines.index('git push origin "$tag"')
        calls = [i for i, ln in enumerate(lines) if 'scripts/approve-release.sh "$tag"' in ln]
        assert calls and calls[0] > push, (
            'tag-release.sh must run scripts/approve-release.sh "$tag" after pushing the tag'
        )
        # The tag is already pushed: a failed approval must not abort under set -e
        # as if tagging failed. It must be guarded and fall back to the GitHub UI.
        call = lines[calls[0]]
        assert call.startswith("if ") or "||" in call, (
            f"the approve call is unguarded under set -eu: {call!r}"
        )

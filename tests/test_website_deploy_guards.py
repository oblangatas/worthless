"""The guards that stand between a merge and wless.io (WOR-757).

Every test here runs the guard's OWN shell, extracted from the workflow file on
disk — never a retyped copy. A hand-copied snippet tests the copy, so the day
someone edits the workflow the test keeps passing against text that no longer
ships.

Each test names the edit that turns it red:

* delete the ``github.event_name`` branch from the concurrency group
  -> ``test_a_pull_request_run_cannot_cancel_a_production_deploy``
* delete the "Refuse to deploy stale website content" step
  -> ``test_the_deploy_refuses_content_main_has_moved_past``
* delete the ``find website -type l`` line
  -> ``test_a_symlink_cannot_ride_into_the_published_tree``
* narrow the expiry pattern back to ``????-??-??T*``
  -> ``test_the_certificate_alarm_accepts_the_shape_the_api_returns``
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-website.yml"
SYNC_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-sync-check.yml"

# GNU `date -d` is not BSD `date -d`. CI is Linux; a developer's Mac is not, so
# the expiry test supplies its own `date` rather than skipping on macOS and
# pretending the guard was exercised.
_GNU_DATE_SHIM = r"""
# Only stand in where the shipped `date -d` does not exist (BSD/macOS). On Linux
# — what CI runs — the real thing must be exercised, or this shim would be
# testing itself.
if [ "$(uname)" != "Linux" ]; then
date() {
    if [ "$1" = "-d" ]; then
        python3 -c 'import datetime as dt, sys
when = dt.datetime.fromisoformat(sys.argv[1][:10])
print(int(when.replace(tzinfo=dt.timezone.utc).timestamp()))' "$2"
    else
        command date "$@"
    fi
}
fi
"""


def _step(workflow: Path, job: str, name_startswith: str) -> tuple[dict, int, list]:
    """Return one step, its position, and its sibling steps — from disk."""
    spec = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    steps = spec["jobs"][job]["steps"]
    for index, step in enumerate(steps):
        if step.get("name", "").startswith(name_startswith):
            return step, index, steps
    raise AssertionError(f"{workflow.name}: no step named {name_startswith!r} in job {job!r}")


def _step_script(workflow: Path, job: str, name_startswith: str) -> str:
    """Return a guard's shell, after checking the guard is actually wired in.

    Reading only `run:` is how a guard gets disabled while its test stays green:
    `if: false`, `continue-on-error: true`, or a condition that excludes the
    event that matters all leave the script byte-identical. A guard that cannot
    fail the job is decoration, so those are assertion failures here, not
    details for a reviewer to notice.
    """
    step, _, _ = _step(workflow, job, name_startswith)

    # `!cancelled()` is the one allowed condition: it makes a nightly assertion
    # run even after an earlier one failed, so it can only ever run MORE often.
    # Every other condition can make the guard sit out the run that mattered.
    assert step.get("if") in (None, "${{ !cancelled() }}"), (
        f"{name_startswith!r} is conditional ({step.get('if')!r}) — it can be skipped silently"
    )
    assert not step.get("continue-on-error"), (
        f"{name_startswith!r} is continue-on-error — it can fail without failing the job"
    )
    return step["run"]


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(cwd),
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )


def test_a_pull_request_run_cannot_cancel_a_production_deploy() -> None:
    """A fixed group name lets a queued PR run evict a waiting deploy.

    GitHub keeps one running and one pending run per concurrency group, and a
    newcomer evicts the pending one. Two runs died that way on 2026-06-13. The
    group must therefore depend on the event, so pull requests and pushes never
    share a lane.
    """
    spec = yaml.safe_load(DEPLOY_WORKFLOW.read_text(encoding="utf-8"))
    group = str(spec["concurrency"]["group"])

    assert "github.event_name" in group, (
        f"pushes and pull requests share one cancellation lane: {group}"
    )
    assert "pull_request" in group, f"pull requests are not carved out of the deploy lane: {group}"
    assert "github-pages" in group, f"deploys no longer serialise on the Pages lane: {group}"


def test_only_main_can_deploy_and_only_by_push_or_a_deliberate_run() -> None:
    """The deploy job's trigger surface is a decision, so pin it.

    Dropping the `refs/heads/main` condition would let any branch publish to
    wless.io, and nothing else in this file reads `jobs.deploy.if`.
    """
    spec = yaml.safe_load(DEPLOY_WORKFLOW.read_text(encoding="utf-8"))
    condition = " ".join(str(spec["jobs"]["deploy"]["if"]).split())

    assert "refs/heads/main" in condition, f"a branch other than main could deploy: {condition}"
    assert "github.event_name == 'push'" in condition, f"pushes no longer deploy: {condition}"
    for event in ("pull_request", "schedule", "issue_comment"):
        assert f"'{event}'" not in condition, f"{event} can reach the deploy job: {condition}"


def test_the_certificate_threshold_leaves_time_to_act() -> None:
    """21 days is the decision: enough runway to involve a human and a DNS change.

    The tests below inject their own threshold, so without this the number in the
    workflow could drift to 1 and every test would stay green.
    """
    step, _, _ = _step(SYNC_WORKFLOW, "sync-check", "A7")

    assert step["env"]["MIN_DAYS"] == "21", (
        f"certificate warning window changed to {step['env']['MIN_DAYS']} days"
    )


def test_the_stale_guard_runs_before_anything_is_published() -> None:
    """A guard that runs after the upload is a comment, not a guard.

    Moving the step below `upload-pages-artifact` / `deploy-pages` leaves its
    shell byte-identical, so a text-only test keeps passing while stale content
    has already gone live.
    """
    _, guard_index, steps = _step(DEPLOY_WORKFLOW, "deploy", "Refuse to deploy stale")
    publishing = [
        index
        for index, step in enumerate(steps)
        if "upload-pages-artifact" in str(step.get("uses", ""))
        or "deploy-pages" in str(step.get("uses", ""))
    ]

    assert publishing, "the deploy job no longer uploads or deploys a Pages artifact"
    assert guard_index < min(publishing), (
        "the stale-content guard runs after publishing has already started"
    )


def test_the_deploy_refuses_content_main_has_moved_past(tmp_path: Path) -> None:
    """Re-running an old run keeps the ORIGINAL commit, so it would republish it.

    That silently rolls wless.io backwards with every check green. The guard
    compares the run's own commit against main and must refuse when main is
    ahead on ``website/``, while still allowing an unrelated later commit.
    """
    script = _step_script(DEPLOY_WORKFLOW, "deploy", "Refuse to deploy stale")

    remote = tmp_path / "remote.git"
    remote.mkdir()
    _git(remote, "init", "--quiet", "--bare")
    _git(remote, "config", "uploadpack.allowAnySHA1InWant", "true")

    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "--quiet")
    _git(seed, "config", "user.email", "t@example.invalid")
    _git(seed, "config", "user.name", "t")
    _git(seed, "config", "commit.gpgsign", "false")
    (seed / "website").mkdir()
    (seed / "website" / "index.html").write_text("v1\n", encoding="utf-8")
    _git(seed, "add", "website/index.html")
    _git(seed, "commit", "--quiet", "-m", "old website")
    old = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=seed,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (seed / "website" / "index.html").write_text("v2\n", encoding="utf-8")
    _git(seed, "commit", "--quiet", "-am", "new website")
    newest = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=seed,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (seed / "README.md").write_text("unrelated\n", encoding="utf-8")
    _git(seed, "add", "README.md")
    _git(seed, "commit", "--quiet", "-m", "unrelated change after the website commit")
    _git(seed, "push", "--quiet", str(remote), "HEAD:refs/heads/main")

    def run_guard(sha: str) -> int:
        """Check out `sha` the way actions/checkout does, then run the step."""
        checkout = tmp_path / f"ci-{sha[:8]}"
        checkout.mkdir()
        _git(checkout, "init", "--quiet")
        _git(checkout, "remote", "add", "origin", str(remote))
        _git(checkout, "fetch", "--quiet", "--depth=1", "origin", sha)
        _git(checkout, "checkout", "--quiet", "FETCH_HEAD")
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script],  # noqa: S607
            cwd=checkout,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", "GITHUB_SHA": sha, "HOME": str(checkout)},
        ).returncode

    assert run_guard(old) != 0, (
        "an older website commit was allowed to republish over newer content"
    )
    assert run_guard(newest) == 0, "the newest website commit was refused"


def test_a_symlink_cannot_ride_into_the_published_tree(tmp_path: Path) -> None:
    """The Pages upload tars with --dereference, so a link publishes its target.

    The publish-safety allowlist walks real files and never sees the link, so
    validation has to reject links itself.
    """
    script = _step_script(DEPLOY_WORKFLOW, "validate", "Validate static website files")
    # Take every line from the find onwards: the guard is an assignment plus the
    # test of it, and running only the assignment would "pass" unconditionally.
    lines = script.splitlines()
    start = next((i for i, line in enumerate(lines) if "-type l" in line), None)
    assert start is not None, "the validate job no longer rejects symlinks under website/"
    guard = "\n".join(lines[start : start + 2])
    assert "test -z" in guard, f"the symlink guard no longer asserts its own result: {guard!r}"

    site = tmp_path / "website"
    site.mkdir()
    (site / "index.html").write_text("<!doctype html>\n", encoding="utf-8")

    def run_guard() -> int:
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", guard],  # noqa: S607
            cwd=tmp_path,
            capture_output=True,
            text=True,
        ).returncode

    assert run_guard() == 0, "a clean tree was rejected"
    (site / "secrets.html").symlink_to(tmp_path / "anything-outside-the-tree")
    assert run_guard() != 0, "a symlink under website/ passed validation"


def _run_a7(
    *,
    gh_body: str = "approved\t2099-01-01",
    gh_rc: int = 0,
    curl_rc: int = 0,
    body: str = "Contact: mailto:security@wless.io\n",
    min_days: str = "21",
) -> subprocess.CompletedProcess[str]:
    """Run the nightly A7 step with the outside world stubbed."""
    script = _step_script(SYNC_WORKFLOW, "sync-check", "A7")
    stubs = f"""
    gh() {{ printf '%s\\n' '{gh_body}'; return {gh_rc}; }}
    curl() {{ printf '%s' '{body}'; return {curl_rc}; }}
    {_GNU_DATE_SHIM}
    """
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", stubs + script],  # noqa: S607
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "REPO": "o/r",
            "MIN_DAYS": min_days,
            "GH_TOKEN": "x",
            "GITHUB_RUN_ID": "1",
        },
    )


@pytest.mark.parametrize(
    ("expires", "alarms"),
    [
        ("2099-01-01", False),  # the API's real shape: a bare calendar date
        ("2099-01-01T12:00:00Z", False),  # a timestamp must keep working
        ("2020-01-01", True),  # already expired
    ],
)
def test_the_certificate_alarm_accepts_the_shape_the_api_returns(
    expires: str, *, alarms: bool
) -> None:
    """The Pages API returns ``"expires_at": "2026-11-16"`` — no time part.

    An earlier version matched only ``????-??-??T*``, so every real expiry fell
    through to the skip branch: the alarm could not fire while the certificate
    quietly ran out. Both shapes must reach the comparison.
    """
    result = _run_a7(gh_body=f"approved\t{expires}")

    if alarms:
        assert result.returncode != 0, f"an expired certificate did not alarm: {result.stdout}"
        assert "::error title=Pages certificate" in result.stdout
    else:
        assert result.returncode == 0, f"unexpected failure: {result.stdout}{result.stderr}"
        assert "Pages certificate state=approved" in result.stdout, (
            f"a valid expiry never reached the comparison: {result.stdout}"
        )


@pytest.mark.parametrize(
    ("case", "kwargs"),
    [
        ("the API call fails", {"gh_rc": 1, "gh_body": ""}),
        ("the API returns no certificate", {"gh_body": "none\tnone"}),
        ("renewal is not healthy", {"gh_body": "bad_authz\t2099-01-01"}),
        ("security.txt is gone", {"curl_rc": 22, "body": ""}),
        ("a cached page answers 200 without the file", {"body": "<html>not found</html>\n"}),
    ],
)
def test_the_nightly_check_fails_closed(case: str, kwargs: dict) -> None:
    """Each of these once passed silently — the failure mode this step exists for.

    An unreadable API answer used to warn and exit 0, so a moved endpoint or a
    token without `pages: read` disarmed the alarm permanently. A failed renewal
    still reported "OK" until the 21-day window, which is June's bad_authz
    incident exactly. And a CDN can answer 200 with a cached error page long
    after the origin stopped serving security.txt.
    """
    result = _run_a7(**kwargs)

    assert result.returncode != 0, f"{case}: the nightly check passed anyway: {result.stdout}"
    assert "::error" in result.stdout, f"{case}: failed without an annotation: {result.stdout}"

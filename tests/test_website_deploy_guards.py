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
date() {
    if [ "$1" = "-d" ]; then
        python3 -c 'import datetime as dt, sys
when = dt.datetime.fromisoformat(sys.argv[1][:10])
print(int(when.replace(tzinfo=dt.timezone.utc).timestamp()))' "$2"
    else
        command date "$@"
    fi
}
"""


def _step_script(workflow: Path, job: str, name_startswith: str) -> str:
    """Return the `run:` block of one step, read from the workflow on disk."""
    spec = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for step in spec["jobs"][job]["steps"]:
        if step.get("name", "").startswith(name_startswith):
            return step["run"]
    raise AssertionError(f"{workflow.name}: no step named {name_startswith!r} in job {job!r}")


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
    assert "github-pages" in group, f"pushes must still serialise on the Pages lane: {group}"


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
    guard = next((line for line in script.splitlines() if "-type l" in line), None)
    assert guard, "the validate job no longer rejects symlinks under website/"

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


@pytest.mark.parametrize(
    ("expires", "min_days", "expect_alarm"),
    [
        ("2099-01-01", "21", False),  # the API's real shape: a bare calendar date
        ("2026-11-16T12:00:00Z", "21", False),  # a timestamp must keep working
        ("2020-01-01", "21", True),  # already expired
        ("", "21", False),  # nothing readable: warn and skip, never crash
    ],
)
def test_the_certificate_alarm_accepts_the_shape_the_api_returns(
    expires: str, min_days: str, expect_alarm: bool
) -> None:
    """The Pages API returns ``"expires_at": "2026-11-16"`` — no time part.

    An earlier version of this step matched only ``????-??-??T*``, so every real
    expiry fell through to the skip branch and the alarm could not fire while
    the certificate quietly ran out. Both shapes must reach the comparison.
    """
    script = _step_script(SYNC_WORKFLOW, "sync-check", "A7")
    stubs = f"""
    gh() {{ printf '%s\\n' '{expires}'; }}
    curl() {{ printf '200'; }}
    {_GNU_DATE_SHIM}
    """
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", stubs + script],  # noqa: S607
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "REPO": "o/r",
            "MIN_DAYS": min_days,
            "GH_TOKEN": "x",
        },
    )

    if expect_alarm:
        assert result.returncode != 0, f"an expired certificate did not alarm: {result.stdout}"
        assert "::error title=Pages certificate" in result.stdout
    else:
        assert result.returncode == 0, f"unexpected failure: {result.stdout}{result.stderr}"
        if expires:
            assert "Pages certificate valid for" in result.stdout, (
                f"a valid expiry never reached the comparison: {result.stdout}"
            )

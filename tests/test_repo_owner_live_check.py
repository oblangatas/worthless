"""Guard for ``scripts/check_repo_owner_live.sh``'s three branches.

That script is the only thing standing between a GitHub account rename and a
silently broken release, and its whole value is in WHICH way it fails:

  * GitHub answers and disagrees  -> exit 1  (a real rename must block)
  * GitHub answers and agrees     -> exit 0
  * GitHub cannot be reached      -> exit 0  (an unknown is not a disagreement;
                                              blocking a release on a network
                                              blip would be worse)

Get that asymmetry backwards in either direction and the script is useless:
fail-open on disagreement and it never catches anything; fail-closed on an
unreachable API and a GitHub outage wedges every release.

No network. ``gh`` is stubbed on PATH, so these run in the default pytest pass
and assert the script's logic rather than GitHub's behaviour.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "check_repo_owner_live.sh"


def _fake_repo(tmp_path: Path, declared: str) -> Path:
    """A minimal repo root the script can run against."""
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(_SCRIPT, tmp_path / "scripts" / _SCRIPT.name)
    (tmp_path / "scripts" / _SCRIPT.name).chmod(0o755)
    (tmp_path / "pyproject.toml").write_text(
        f'[project.urls]\nRepository = "https://github.com/{declared}"\n',
        encoding="utf-8",
    )
    return tmp_path


def _run(repo: Path, gh_reports: str | None) -> subprocess.CompletedProcess[str]:
    """Run the script with ``gh`` stubbed to report ``gh_reports`` (None = absent)."""
    bindir = repo / "fakebin"
    bindir.mkdir(exist_ok=True)
    if gh_reports is not None:
        gh = bindir / "gh"
        # Stub prints the full_name the real `gh api ... --jq .full_name` would.
        gh.write_text(f'#!/bin/sh\nprintf "%s\\n" "{gh_reports}"\n', encoding="utf-8")
        gh.chmod(0o755)

    env = dict(os.environ)
    # Only the stub dir plus core utils — guarantees the real gh is unreachable.
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    return subprocess.run(
        ["sh", "scripts/check_repo_owner_live.sh"],  # noqa: S607 — sh is on PATH everywhere
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )


def test_agreeing_owner_passes(tmp_path: Path) -> None:
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    r = _run(repo, gh_reports="oblangatas/worthless")
    assert r.returncode == 0, r.stdout + r.stderr


def test_renamed_owner_blocks(tmp_path: Path) -> None:
    """The case worthless-jjap exists for: repo is self-consistent but stale."""
    repo = _fake_repo(tmp_path, "shacharm2/worthless")
    r = _run(repo, gh_reports="oblangatas/worthless")

    assert r.returncode == 1, (
        "a repo whose declared owner no longer exists MUST block:\n" + r.stdout + r.stderr
    )
    out = r.stdout + r.stderr
    assert "shacharm2/worthless" in out and "oblangatas/worthless" in out, (
        "the diagnostic must name both the declared and the actual owner"
    )
    # The point of the message is that the operator knows what is already broken.
    assert "403" in out, "must say GHCR is already failing for users"
    assert "pyproject.toml" in out, "must say where to fix it"


def test_unreachable_api_warns_but_does_not_block(tmp_path: Path) -> None:
    """A GitHub outage must not wedge a release. Unknown != disagreement."""
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    r = _run(repo, gh_reports=None)  # gh absent entirely

    assert r.returncode == 0, "an unreachable API must not block:\n" + r.stdout + r.stderr
    assert "WARNING" in (r.stdout + r.stderr), "silence would hide that nothing was verified"


# Real `gh api` HTTP-error bodies. These go to STDOUT, not stderr, and --jq is
# skipped on an error response — so the captured value is non-empty JSON, not "".
# An earlier version of this test stubbed gh writing to stderr, which modelled a
# gh that does not exist: the test passed while the script hard-BLOCKED releases
# on any 404/401/rate-limit, telling the operator to set their repo URL to a JSON
# blob. Captured verbatim from a real `gh api` call.
_GH_404 = (
    '{"message":"Not Found",'
    '"documentation_url":"https://docs.github.com/rest/repos/repos#get-a-repository",'
    '"status":"404"}'
)
_GH_401 = '{"message":"Bad credentials","status":"401"}'
_GH_RATE_LIMIT = '{"message":"API rate limit exceeded","status":"403"}'


@pytest.mark.parametrize(
    ("label", "body"),
    [("404", _GH_404), ("401", _GH_401), ("rate-limit", _GH_RATE_LIMIT)],
)
def test_gh_http_error_body_is_unknown_not_disagreement(
    tmp_path: Path, label: str, body: str
) -> None:
    """An HTTP error must read as unknown, never as a rename.

    This is the failure that matters most: `gh` exits non-zero and prints the
    error JSON to STDOUT. Treating that as "GitHub reports X" blocks every
    release whenever the token is wrong, the repo is private, or we are rate
    limited — and blames a rename that never happened.
    """
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    bindir = repo / "fakebin"
    bindir.mkdir(exist_ok=True)
    gh = bindir / "gh"
    gh.write_text(f"#!/bin/sh\nprintf '%s' '{body}'\nexit 1\n", encoding="utf-8")
    gh.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    r = subprocess.run(
        ["sh", "scripts/check_repo_owner_live.sh"],  # noqa: S607 — sh is on PATH everywhere
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    out = r.stdout + r.stderr
    assert r.returncode == 0, (
        f"a {label} HTTP error must be UNKNOWN, not a blocked release:\n" + out
    )
    assert "WARNING" in out, "an unverified owner must be said out loud"
    assert "message" not in out.lower() or "Not Found" not in out, (
        "the raw API error body must never be presented as the owner GitHub reports"
    )


def test_unparseable_pyproject_is_an_error(tmp_path: Path) -> None:
    """A source of truth we cannot read must not be treated as agreement."""
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    (repo / "pyproject.toml").write_text("[project.urls]\n", encoding="utf-8")
    r = _run(repo, gh_reports="oblangatas/worthless")
    assert r.returncode == 1, "missing Repository URL must fail loudly, not pass"


@pytest.mark.parametrize("quiet", [False, True])
def test_quiet_only_silences_the_success_path(tmp_path: Path, quiet: bool) -> None:
    """--quiet is for callers that only want to hear about problems."""
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    bindir = repo / "fakebin"
    bindir.mkdir(exist_ok=True)
    gh = bindir / "gh"
    gh.write_text('#!/bin/sh\nprintf "oblangatas/worthless\\n"\n', encoding="utf-8")
    gh.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    cmd = ["sh", "scripts/check_repo_owner_live.sh"] + (  # noqa: S607 — sh is on PATH
        ["--quiet"] if quiet else []
    )
    r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True)

    assert r.returncode == 0
    assert (r.stdout.strip() == "") is quiet, "quiet must suppress the success line, and only that"


def test_quiet_does_not_silence_an_unknown(tmp_path: Path) -> None:
    """--quiet is how the tag gate calls this. A silent unknown there is the worst case."""
    repo = _fake_repo(tmp_path, "oblangatas/worthless")
    r = subprocess.run(
        ["sh", "scripts/check_repo_owner_live.sh", "--quiet"],  # noqa: S607 — sh is on PATH
        cwd=repo,
        env={**os.environ, "PATH": f"{repo / 'fakebin'}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert "WARNING" in (r.stdout + r.stderr), (
        "--quiet may hide a SUCCESS line; it must never hide that nothing was verified"
    )

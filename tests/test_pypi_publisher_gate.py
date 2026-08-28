"""Guard for ``scripts/verify-pypi-publisher.sh --check`` — the release gate.

``tag-release.sh`` refuses to create a tag unless this passes, so a false green
here ships a release that dies at upload with ``invalid-publisher``.

PyPI matches its Trusted Publisher on FOUR values: repository_owner, repository,
workflow filename, and environment. The gate originally compared only the owner,
which left the two likelier drifts invisible — renaming ``publish.yml`` or
changing its ``environment:`` breaks the binding without touching the owner at
all. worthless-jjap folded the rest in; these tests pin them.

Everything is stubbed: ``gh`` on PATH, a synthetic repo in tmp_path. No network,
so these run in the default pytest pass alongside everything else.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"

_RECORD = """\
owner=oblangatas
repo=worthless
workflow=publish.yml
environment=pypi
date=2026-08-21
"""

_WORKFLOW = """\
name: Publish to PyPI
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    environment: pypi
    permissions:
      id-token: write
"""


def _repo(
    tmp_path: Path,
    *,
    record: str = _RECORD,
    workflow: str = _WORKFLOW,
    workflow_name: str = "publish.yml",
    owner: str = "oblangatas",
) -> Path:
    """A synthetic repo the gate can run against."""
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for name in ("verify-pypi-publisher.sh", "check_repo_owner_live.sh"):
        shutil.copy(_SCRIPTS / name, tmp_path / "scripts" / name)
        (tmp_path / "scripts" / name).chmod(0o755)

    (tmp_path / "pyproject.toml").write_text(
        f'[project.urls]\nRepository = "https://github.com/{owner}/worthless"\n',
        encoding="utf-8",
    )
    (tmp_path / ".pypi-publisher-confirmed").write_text(record, encoding="utf-8")
    (tmp_path / ".github" / "workflows" / workflow_name).write_text(workflow, encoding="utf-8")

    # `gh` reports the declared owner back, so the live-owner check agrees and
    # these tests isolate the FIELD logic rather than re-testing the owner path.
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    gh = bindir / "gh"
    gh.write_text(f'#!/bin/sh\nprintf "{owner}/worthless\\n"\n', encoding="utf-8")
    gh.chmod(0o755)
    return tmp_path


def _check(repo: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = f"{repo / 'fakebin'}:/usr/bin:/bin"
    return subprocess.run(
        ["sh", "scripts/verify-pypi-publisher.sh", "--check"],  # noqa: S607 — sh is on PATH
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )


def test_matching_record_passes(tmp_path: Path) -> None:
    r = _check(_repo(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "publish.yml" in r.stdout and "pypi" in r.stdout, (
        "a pass must state WHICH workflow and environment it confirmed, or the "
        "operator cannot tell what was actually checked"
    )


def test_renamed_workflow_file_blocks(tmp_path: Path) -> None:
    """PyPI matches on the workflow FILENAME. Renaming it breaks the binding."""
    repo = _repo(tmp_path, workflow_name="publish-pypi.yml")
    r = _check(repo)
    assert r.returncode == 1, "a renamed workflow must block:\n" + r.stdout + r.stderr
    assert "publish.yml" in (r.stdout + r.stderr)


def test_changed_environment_blocks(tmp_path: Path) -> None:
    """PyPI matches on the environment name exactly."""
    repo = _repo(
        tmp_path, workflow=_WORKFLOW.replace("environment: pypi", "environment: pypi-prod")
    )
    r = _check(repo)
    assert r.returncode == 1, "a changed environment must block:\n" + r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "pypi-prod" in out and "invalid-publisher" in out, (
        "the diagnostic must name the new value and the failure it causes"
    )


def test_workflow_without_environment_blocks(tmp_path: Path) -> None:
    """A publisher configured with an environment never matches a job without one."""
    repo = _repo(
        tmp_path, workflow="name: Publish\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
    )
    r = _check(repo)
    assert r.returncode == 1, "a missing environment must block:\n" + r.stdout + r.stderr


def test_legacy_record_without_fields_blocks(tmp_path: Path) -> None:
    """An owner-only record predates field checking and must not pass silently."""
    repo = _repo(tmp_path, record="owner=oblangatas\ndate=2026-08-21\n")
    r = _check(repo)
    assert r.returncode == 1, "an owner-only record must block:\n" + r.stdout + r.stderr
    assert "re-confirm" in (r.stdout + r.stderr).lower()


def test_stale_owner_still_blocks_before_fields_are_read(tmp_path: Path) -> None:
    """The live-owner check must run FIRST — fields are meaningless if the repo moved."""
    repo = _repo(tmp_path, owner="oblangatas")
    # Declared owner is stale; `gh` reports the real one.
    (repo / "pyproject.toml").write_text(
        '[project.urls]\nRepository = "https://github.com/shacharm2/worthless"\n',
        encoding="utf-8",
    )
    r = _check(repo)
    assert r.returncode == 1
    assert "Repo owner moved" in (r.stdout + r.stderr), (
        "the owner failure must surface, not be masked by a later field check"
    )

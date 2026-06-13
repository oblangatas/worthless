"""WOR-589 — pre-push provenance gate.

Proves the hook flags unsigned and wrong-author commits and clears the
canonical identity. The hook lives under ``scripts/hooks`` (not a package),
so it is loaded by path.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_HOOK = (
    Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "check_pushed_commit_provenance.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("provenance_hook", _HOOK)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load()


def _init_repo(path: Path, email: str) -> str:
    def g(*a: str) -> None:
        subprocess.run(
            ["git", *a],  # noqa: S607 — git resolved from PATH by design
            cwd=path,
            check=True,
            capture_output=True,
        )

    g("init", "-q")
    g("config", "user.name", "Test")
    g("config", "user.email", email)
    g("config", "commit.gpgsign", "false")  # unsigned on purpose
    (path / "f.txt").write_text("x")
    g("add", "f.txt")
    g("commit", "-q", "-m", "c")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607 — git resolved from PATH by design
        cwd=path,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_allowlist_accepts_canonical_and_bots() -> None:
    assert hook.is_allowed_author("4841128+shacharm2@users.noreply.github.com")
    assert hook.is_allowed_author("noreply@anthropic.com")
    assert hook.is_allowed_author("noreply@github.com")


def test_allowlist_rejects_stranger() -> None:
    assert not hook.is_allowed_author("evil@example.com")
    assert not hook.is_allowed_author("shacharm@gmail.com")  # the old leaked identity


def test_unsigned_commit_is_flagged(tmp_path) -> None:
    sha = _init_repo(tmp_path, "4841128+shacharm2@users.noreply.github.com")
    problems = hook.check_commit(sha, cwd=str(tmp_path))
    assert any("not validly signed" in p for p in problems)


def test_wrong_author_is_flagged(tmp_path) -> None:
    sha = _init_repo(tmp_path, "evil@example.com")
    problems = hook.check_commit(sha, cwd=str(tmp_path))
    assert any("not the canonical identity" in p for p in problems)
    # unsigned + wrong-author == two distinct problems
    assert len(problems) == 2


def test_all_allowed_bots_pass() -> None:
    # Every explicitly allowlisted bot identity must be accepted.
    for email in hook.ALLOWED_BOT_AUTHORS:
        assert hook.is_allowed_author(email), email


def test_fails_closed_when_git_errors(monkeypatch) -> None:
    # Deterministic, environment-independent: simulate `git rev-list` exiting
    # non-zero. Must RAISE so the hook blocks the push, never silently pass it
    # unchecked (fail closed). Does NOT rely on tmp_path landing outside a repo.
    def _git_fails(*_a, **_k) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["git"], returncode=128, stdout="", stderr="fatal: not a git repository"
        )

    monkeypatch.delenv("PRE_COMMIT_FROM_REF", raising=False)
    monkeypatch.delenv("PRE_COMMIT_TO_REF", raising=False)
    monkeypatch.setattr(hook.subprocess, "run", _git_fails)
    with pytest.raises(RuntimeError):
        hook.pushed_commits()

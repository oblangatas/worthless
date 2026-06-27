"""WOR-590 — CI commit-provenance gate.

Tests the pure evaluation logic against GitHub-API-shaped commit dicts; no
network. The checker lives under ``.github/scripts`` (not a package), loaded
by path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_CHECKER = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "verify_commit_provenance.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("verify_commit_provenance", _CHECKER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


checker = _load()


def _commit(sha: str, *, verified: bool, email: str) -> dict:
    return {
        "sha": sha,
        "commit": {
            "verification": {"verified": verified},
            "author": {"email": email},
        },
    }


CANON = "4841128+shacharm2@users.noreply.github.com"


def test_clean_pr_has_no_violations() -> None:
    commits = [
        _commit("a" * 40, verified=True, email=CANON),
        _commit("b" * 40, verified=True, email="noreply@anthropic.com"),
    ]
    assert checker.evaluate(commits) == []


def test_unverified_commit_flagged() -> None:
    problems = checker.evaluate([_commit("c" * 40, verified=False, email=CANON)])
    assert any("not a verified signed commit" in p for p in problems)


def test_wrong_author_flagged() -> None:
    problems = checker.evaluate([_commit("d" * 40, verified=True, email="shacharm@gmail.com")])
    assert any("not the canonical identity" in p for p in problems)


def test_both_problems_reported_for_one_commit() -> None:
    problems = checker.evaluate([_commit("e" * 40, verified=False, email="evil@example.com")])
    assert len(problems) == 2


def test_allowlist_helper() -> None:
    assert checker.is_allowed_author(CANON)
    assert checker.is_allowed_author("noreply@github.com")
    assert not checker.is_allowed_author("evil@example.com")


def test_empty_commit_list_fails_closed() -> None:
    # An empty/truncated API response must NOT pass a PR uninspected.
    problems = checker.evaluate([])
    assert problems


def test_missing_fields_do_not_crash() -> None:
    # Defensive: a malformed API item must not raise, just flag.
    problems = checker.evaluate([{}])
    assert problems  # unverified + no author == flagged, not an exception

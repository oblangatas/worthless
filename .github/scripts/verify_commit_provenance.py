#!/usr/bin/env python3
"""CI gate: every commit in a PR must be a verified signed commit from an
allowed author (WOR-590).

Server-side counterpart to the WOR-589 pre-push hook. Where the hook checks
local ``git %G?`` (advisory, bypassable with --no-verify), this checks
GitHub's own ``commit.verification.verified`` — the authoritative signal — on
every commit in the PR, and is meant to be a required status check so a PR
cannot merge until it passes.

The allowlist intentionally duplicates the hook's (client vs server are
different checks); keep the two in sync.
"""

from __future__ import annotations

import json
import subprocess
import sys

CANONICAL_AUTHOR = "4841128+shacharm2@users.noreply.github.com"
ALLOWED_BOT_AUTHORS = frozenset(
    {
        "noreply@anthropic.com",  # Claude
        "49699333+dependabot[bot]@users.noreply.github.com",
        "136622811+coderabbitai[bot]@users.noreply.github.com",
        "noreply@github.com",  # GitHub web-flow
    }
)


def is_allowed_author(email: str) -> bool:
    return email == CANONICAL_AUTHOR or email in ALLOWED_BOT_AUTHORS


def evaluate(commits: list[dict]) -> list[str]:
    """Return GitHub-Actions ``::error::`` lines for any bad commit (empty == clean).

    *commits* are items from the ``repos/{repo}/pulls/{pr}/commits`` API.
    """
    problems: list[str] = []
    for item in commits:
        sha = (item.get("sha") or "")[:8] or "????????"
        commit = item.get("commit") or {}
        verified = ((commit.get("verification") or {}).get("verified")) is True
        email = (commit.get("author") or {}).get("email") or ""
        if not verified:
            problems.append(f"::error::commit {sha} is not a verified signed commit")
        if not is_allowed_author(email):
            problems.append(
                f"::error::commit {sha} author {email!r} is not the canonical "
                "identity or a known bot"
            )
    return problems


def _fetch_commits(repo: str, pr: str) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/pulls/{pr}/commits", "--jq", ".[]"],  # noqa: S607 — gh resolved from PATH by design
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: verify_commit_provenance.py <owner/repo> <pr-number>", file=sys.stderr)
        return 2
    problems = evaluate(_fetch_commits(argv[1], argv[2]))
    if not problems:
        print("All PR commits are verified-signed and from an allowed author.")
        return 0
    for line in problems:
        print(line)
    print(
        f"Commit provenance check failed: {len(problems)} problem(s). Every commit "
        "must be a GitHub-verified signed commit from the canonical identity.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""Pre-push hook: reject unsigned or wrong-author commits (WOR-589).

Local defense-in-depth. The ``main`` branch ruleset enforces
``required_signatures`` server-side; this catches bad provenance at push time,
before CI and review burn cycles on commits that can never merge. Advisory by
design: ``git push --no-verify`` bypasses it, and the ruleset is the hard gate.

Checks each commit the push would add:
  1. AUTHOR email is the canonical identity or a known bot (NOT the committer —
     GitHub web-flow merge commits are committed by ``GitHub`` but authored by
     the operator, which is fine).
  2. The commit carries a usable signature (``git %G?`` in {G, U}).
"""

from __future__ import annotations

import os
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
# %G? codes meaning a usable signature: G=good, U=good with unknown validity.
_GOOD_SIG = frozenset({"G", "U"})


def is_allowed_author(email: str) -> bool:
    """True if *email* is the canonical operator identity or an allowed bot."""
    return email == CANONICAL_AUTHOR or email in ALLOWED_BOT_AUTHORS


def _git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(
        ["git", *args],  # noqa: S607 — git resolved from PATH by design
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()


def check_commit(sha: str, cwd: str | None = None) -> list[str]:
    """Return provenance problems for *sha* (empty list == clean)."""
    problems: list[str] = []
    author = _git("show", "-s", "--format=%ae", sha, cwd=cwd)
    if not is_allowed_author(author):
        problems.append(
            f"{sha[:8]}: author {author!r} is not the canonical identity or a known bot"
        )
    sig = _git("show", "-s", "--format=%G?", sha, cwd=cwd) or "N"
    if sig not in _GOOD_SIG:
        problems.append(f"{sha[:8]}: commit is not validly signed (git %G? = {sig})")
    return problems


def pushed_commits(cwd: str | None = None) -> list[str]:
    """Commits this push would add — the pre-commit range, else a safe fallback.

    Fails closed: if git cannot enumerate the range (non-zero exit), raise so
    the hook BLOCKS the push rather than silently passing it unchecked. An
    empty range (zero new commits) is legitimate and returns ``[]``.
    """
    frm = os.environ.get("PRE_COMMIT_FROM_REF") or ""
    to = os.environ.get("PRE_COMMIT_TO_REF") or "HEAD"
    if frm and set(frm) != {"0"}:  # all-zero from-ref == brand-new branch
        rng = f"{frm}..{to}"
    else:
        rng = "origin/main..HEAD"
    proc = subprocess.run(
        ["git", "rev-list", rng],  # noqa: S607 — git resolved from PATH by design
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git rev-list {rng!r} failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout.split()


def main() -> int:
    try:
        shas = pushed_commits()
    except RuntimeError as exc:
        # Fail closed: cannot enumerate the pushed commits -> block the push.
        print(f"pre-push BLOCKED: {exc} -- refusing to pass unchecked.", file=sys.stderr)
        return 1
    violations: list[str] = []
    for sha in shas:
        violations.extend(check_commit(sha))
    if not violations:
        return 0
    print("pre-push BLOCKED: commit provenance check failed (WOR-589)", file=sys.stderr)
    for problem in violations:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "Fix: sign commits (git config commit.gpgsign true; gpg.format ssh) and commit "
        "as the canonical identity, then re-push. Use --no-verify only in a genuine "
        "emergency.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

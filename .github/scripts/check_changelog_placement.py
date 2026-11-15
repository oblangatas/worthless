#!/usr/bin/env python3
"""Fail when a PR adds CHANGELOG lines under a version that already shipped.

Usage:  git diff -U0 <base> <head> -- CHANGELOG.md | check_changelog_placement.py CHANGELOG.md

The CHANGELOG path is the merged result (the PR's merge commit), so this sees
where lines actually land after a merge from ``main``, which is how entries
end up under a released heading when a release is cut while the PR is open
(WOR-957; #688, #691 and #676 all landed this way in one week).

Shipped means the ``v<version>`` git tag exists, not that the heading does.
Between a release PR merging and its tag, fixes that land on ``main`` ship in
that tag, so their notes belong in its section (#732 and #733 for 0.3.16).
Only *added* lines inside a tagged version's section count. Release
headings, compare-link lines and blank lines are exempt. Removals pass: moving
an entry out of a released section is the fix. A deliberate edit to a released
section uses the ``changelog-released-edit`` label, checked in the workflow.
With no tags visible (a shallow checkout) it fails rather than guarding
nothing. Exit 1 with the offending lines; 0 otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
_LINK = re.compile(r"^\[[^\]]+\]: ")
_HEADING = re.compile(r"^## \[([^\]]+)\]")


def _added_lines(diff: str) -> list[int]:
    """New-file line numbers of every ``+`` line in a ``-U0`` diff."""
    added: list[int] = []
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if m:
            start, count = int(m.group(1)), int(m.group(2) or 1)
            added.extend(range(start, start + count))
    return added


def misplaced(changelog: str, diff: str, shipped: set[str]) -> list[tuple[int, str]]:
    """(line number, text) of each added line inside a version whose tag exists."""
    lines = changelog.splitlines()
    closed: set[int] = set()
    in_shipped = False
    for i, line in enumerate(lines, 1):
        heading = _HEADING.match(line)
        if heading:
            in_shipped = heading.group(1) in shipped
        elif in_shipped:
            closed.add(i)
    out = []
    for n in _added_lines(diff):
        text = lines[n - 1] if n <= len(lines) else ""
        if n in closed and text.strip() and not _LINK.match(text):
            out.append((n, text))
    return out


def _shipped() -> set[str]:
    """Versions tagged before this commit.

    A tag on this commit was cut from it, so a re-run after tagging must not flag
    the release's own lines. ``v0.3.8.0`` also closes ``[0.3.8]``.
    """
    tags = subprocess.run(
        ["git", "tag", "--list", "v*", "--no-contains", "HEAD"],  # noqa: S607 — fixed args
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    versions = {t[1:] for t in tags.split()}
    return versions | {v.removesuffix(".0") for v in versions}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    changelog = Path(argv[1]).read_text(encoding="utf-8")
    shipped = _shipped()
    if not shipped:
        print("CHANGELOG: no release tags visible, so nothing can be checked. Fetch tags.")
        return 1
    bad = misplaced(changelog, sys.stdin.read(), shipped)
    if not bad:
        print("CHANGELOG: no line added under a version that already shipped.")
        return 0
    print("CHANGELOG lines added under a version that already shipped:")
    for n, text in bad:
        print(f"  CHANGELOG.md:{n}: {text[:120]}")
    print(
        "\nMove them under '## [Unreleased]' (a release was probably cut while this PR"
        " was open). If editing a released section is deliberate, add the"
        " 'changelog-released-edit' label."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

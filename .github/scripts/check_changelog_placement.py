#!/usr/bin/env python3
"""Fail when a PR adds CHANGELOG lines under a version that already shipped.

Usage:  git diff -U0 <base> <head> -- CHANGELOG.md | check_changelog_placement.py CHANGELOG.md

The CHANGELOG path is the merged result (the PR's merge commit), so this sees
where lines actually land after a merge from ``main``, which is how entries
end up under a released heading when a release is cut while the PR is open
(WOR-957; it happened in #696 and #703).

Only *added* lines below the first released ``## [x.y.z]`` heading count.
Release headings, compare-link lines and blank lines are exempt. A release PR
adds the newest version heading itself, so the section it creates is open to it. Removals pass:
moving an entry out of a released section is the fix. A deliberate edit to a
released section uses the ``changelog-released-edit`` label, checked in the
workflow. Exit 1 with the offending lines; 0 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
_LINK = re.compile(r"^\[[^\]]+\]: ")


def _added_lines(diff: str) -> list[int]:
    """New-file line numbers of every ``+`` line in a ``-U0`` diff."""
    added: list[int] = []
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if m:
            start, count = int(m.group(1)), int(m.group(2) or 1)
            added.extend(range(start, start + count))
    return added


def misplaced(changelog: str, diff: str) -> list[tuple[int, str]]:
    """(line number, text) of each added line that sits under a released version."""
    lines = changelog.splitlines()
    first_release = next(
        (
            i
            for i, line in enumerate(lines, 1)
            if line.startswith("## [") and not line.startswith("## [Unreleased]")
        ),
        None,
    )
    if first_release is None:
        return []
    added = _added_lines(diff)
    # A release PR adds the newest version heading itself; that one section is
    # being written, not edited after shipping, so its lines are allowed.
    open_until = first_release
    if first_release in added:
        later = range(first_release + 1, len(lines) + 1)
        open_until = next((i for i in later if lines[i - 1].startswith("## [")), len(lines) + 1)
    out = []
    for n in added:
        text = lines[n - 1] if n <= len(lines) else ""
        if n < open_until or not text.strip():
            continue
        if text.startswith("## [") or _LINK.match(text):
            continue
        out.append((n, text))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    changelog = Path(argv[1]).read_text(encoding="utf-8")
    bad = misplaced(changelog, sys.stdin.read())
    if not bad:
        print("CHANGELOG: every added line is under [Unreleased].")
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

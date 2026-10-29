"""A CHANGELOG entry added by a PR must land under ``[Unreleased]`` (WOR-957).

If a release is cut while a PR is open, merging ``main`` back in can leave the
PR's entry under the heading that just became a released version. Nothing
noticed: the next release notes miss the change and the old version's notes
claim it. That happened twice in one week (#696, #703).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_CHECKER = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "check_changelog_placement.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("check_changelog_placement", _CHECKER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHANGELOG = """\
# Changelog

## [Unreleased]

### Fixed
- **New fix** (#2)

## [0.3.13] — 2026-10-12

### Security
- **Old fix** (#1)

[0.3.13]: https://example.com/compare/v0.3.12...v0.3.13
"""


def _diff(*added_lines: int) -> str:
    """A ``git diff -U0`` naming one added line per hunk."""
    return "".join(f"@@ -0,0 +{n} @@\n+x\n" for n in added_lines)


def test_entry_under_unreleased_passes() -> None:
    assert _load().misplaced(CHANGELOG, _diff(6)) == []


def test_entry_under_a_released_version_is_caught() -> None:
    assert _load().misplaced(CHANGELOG, _diff(11)) == [(11, "- **Old fix** (#1)")]


def test_hunk_spanning_several_lines_reports_each_line() -> None:
    diff = "@@ -0,0 +10,2 @@\n+a\n+b\n"
    assert [n for n, _ in _load().misplaced(CHANGELOG, diff)] == [10, 11]


def test_release_heading_and_link_lines_are_allowed() -> None:
    """A release PR renames ``[Unreleased]`` and appends a compare link."""
    assert _load().misplaced(CHANGELOG, _diff(8, 13)) == []


def test_release_pr_may_fill_the_section_it_creates() -> None:
    """A release PR adds the newest ``## [x.y.z]`` heading and its entries.

    Only that new section is open; older released sections stay guarded.
    """
    diff = _diff(8, 10, 11)
    assert _load().misplaced(CHANGELOG, diff) == []
    older_section = "## [0.3.12] — 2026-08-11\n- **Older** (#0)\n\n"
    older = CHANGELOG.replace("[0.3.13]: https", older_section + "[0.3.13]: https")
    assert _load().misplaced(older, _diff(8, 14)) == [(14, "- **Older** (#0)")]


def test_blank_lines_are_ignored() -> None:
    assert _load().misplaced(CHANGELOG, _diff(12)) == []


def test_removals_only_pass() -> None:
    """Moving an entry *out* of a released section (#703) is the fix, not the bug."""
    assert _load().misplaced(CHANGELOG, "@@ -11 +10,0 @@\n-- **Old fix** (#1)\n") == []


def test_no_released_section_means_nothing_to_guard() -> None:
    assert _load().misplaced("# Changelog\n\n## [Unreleased]\n- a\n", _diff(4)) == []

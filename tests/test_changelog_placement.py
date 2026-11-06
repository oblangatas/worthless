"""A CHANGELOG entry added by a PR must land under ``[Unreleased]`` (WOR-957).

If a release is cut while a PR is open, merging ``main`` back in can leave the
PR's entry under the heading that just became a released version. Nothing
noticed: the next release notes miss the change and the old version's notes
claim it. That happened twice in one week (#696, #703).
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_CHECKER = _ROOT / ".github" / "scripts" / "check_changelog_placement.py"
_WORKFLOW = _ROOT / ".github" / "workflows" / "changelog-placement.yml"


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


SHIPPED = {"0.3.13"}  # versions whose ``v`` tag exists


def _diff(*added_lines: int) -> str:
    """A ``git diff -U0`` naming one added line per hunk."""
    return "".join(f"@@ -0,0 +{n} @@\n+x\n" for n in added_lines)


def test_entry_under_unreleased_passes() -> None:
    assert _load().misplaced(CHANGELOG, _diff(6), SHIPPED) == []


def test_entry_under_a_released_version_is_caught() -> None:
    assert _load().misplaced(CHANGELOG, _diff(11), SHIPPED) == [(11, "- **Old fix** (#1)")]


def test_hunk_spanning_several_lines_reports_each_line() -> None:
    diff = "@@ -0,0 +10,2 @@\n+a\n+b\n"
    assert [n for n, _ in _load().misplaced(CHANGELOG, diff, SHIPPED)] == [10, 11]


def test_release_heading_and_link_lines_are_allowed() -> None:
    """A release PR renames ``[Unreleased]`` and appends a compare link."""
    assert _load().misplaced(CHANGELOG, _diff(8, 13), SHIPPED) == []


def test_release_pr_may_fill_the_section_it_creates() -> None:
    """A release PR adds the newest ``## [x.y.z]`` heading and its entries.

    That version has no tag yet, so its section is open; tagged sections stay guarded.
    """
    diff = _diff(8, 10, 11)
    assert _load().misplaced(CHANGELOG, diff, set()) == []
    older_section = "## [0.3.12] — 2026-08-11\n- **Older** (#0)\n\n"
    older = CHANGELOG.replace("[0.3.13]: https", older_section + "[0.3.13]: https")
    assert _load().misplaced(older, _diff(8, 14), {"0.3.12"}) == [(14, "- **Older** (#0)")]


def test_blank_lines_are_ignored() -> None:
    assert _load().misplaced(CHANGELOG, _diff(12), SHIPPED) == []


def test_removals_only_pass() -> None:
    """Moving an entry *out* of a released section (#703) is the fix, not the bug."""
    assert _load().misplaced(CHANGELOG, "@@ -11 +10,0 @@\n-- **Old fix** (#1)\n", SHIPPED) == []


def test_no_released_section_means_nothing_to_guard() -> None:
    assert _load().misplaced("# Changelog\n\n## [Unreleased]\n- a\n", _diff(4), SHIPPED) == []


def test_a_merged_but_untagged_release_section_stays_open() -> None:
    """Between the release PR merging and the tag, fixes that land on main ship in
    that tag, so their notes belong in its section (#714, #732, #733 for 0.3.16).

    Only a version whose tag exists is shipped.
    """
    two = CHANGELOG.replace(
        "## [0.3.13]", "## [0.3.14] — 2026-10-13\n- **Merged, not tagged** (#3)\n\n## [0.3.13]"
    )
    assert _load().misplaced(two, _diff(9), {"0.3.13"}) == []
    assert _load().misplaced(two, _diff(9), {"0.3.13", "0.3.14"}) == [
        (9, "- **Merged, not tagged** (#3)")
    ]


def test_no_tags_visible_fails_closed(monkeypatch, capsys) -> None:
    """A checkout without tags must not read as 'nothing has shipped'."""
    mod = _load()
    monkeypatch.setattr(mod, "_shipped", lambda: set())
    monkeypatch.setattr("sys.stdin", io.StringIO(_diff(11)))
    changelog = Path(mod.__file__).parents[2] / "CHANGELOG.md"
    assert mod.main(["check", str(changelog)]) == 1
    assert "no release tags" in capsys.readouterr().out


def _git(repo: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def test_a_tag_on_the_commit_under_test_is_not_shipped_yet(tmp_path, monkeypatch) -> None:
    """Re-running on the release commit after tagging must not flag its own lines."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "one")
    _git(tmp_path, "tag", "v0.1.0")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "release")
    _git(tmp_path, "tag", "v0.2.0")
    monkeypatch.chdir(tmp_path)
    shipped = _load()._shipped()
    assert "0.1.0" in shipped
    assert "0.2.0" not in shipped


def test_a_four_part_tag_closes_its_section(tmp_path, monkeypatch) -> None:
    """0.3.8 shipped as ``v0.3.8.0``; without this its section never closes."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "one")
    _git(tmp_path, "tag", "v0.3.8.0")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "two")
    monkeypatch.chdir(tmp_path)
    assert "0.3.8" in _load()._shipped()


def test_workflow_can_see_tags_and_fails_on_a_git_error() -> None:
    """A shallow checkout fetches no tags (``fetch-tags`` only drops ``--no-tags``), so
    the check would fail on every run. Without bash's pipefail a failed ``git diff``
    hands the checker an empty diff, which passes."""
    steps = yaml.safe_load(_WORKFLOW.read_text())["jobs"]["placement"]["steps"]
    checkout = next(s for s in steps if "actions/checkout" in s.get("uses", ""))
    assert checkout["with"]["fetch-depth"] == 0
    check = next(s for s in steps if "check_changelog_placement.py" in s.get("run", ""))
    assert check["shell"] == "bash"


def test_the_label_overrides_on_both_pull_request_and_push() -> None:
    workflow = yaml.safe_load(_WORKFLOW.read_text())
    job = workflow["jobs"]["placement"]
    assert "changelog-released-edit" in job["if"]
    lookup = next(s for s in job["steps"] if s.get("id") == "label")
    assert "changelog-released-edit" in lookup["run"]
    check = next(s for s in job["steps"] if "check_changelog_placement.py" in s.get("run", ""))
    assert check["if"] == "steps.label.outputs.skip != 'true'"


def test_main_is_rechecked_after_merge() -> None:
    """``on`` parses as YAML's True: a release can land after a PR's last push."""
    workflow = yaml.safe_load(_WORKFLOW.read_text())
    assert workflow[True]["push"]["branches"] == ["main"]

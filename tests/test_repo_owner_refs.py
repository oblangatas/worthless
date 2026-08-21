"""Regression guard: every reference to *our own* repo, image, or gist must
name the current GitHub owner.

The account was renamed ``shacharm2`` -> ``oblangatas`` in Aug 2026. The rename
was applied to some files and stopped (#528), leaving 146 stale references
across 54 files that nobody noticed for a month. What that cost:

  * ``ghcr.io/shacharm2/worthless-proxy`` returned **403** — GHCR does not
    redirect a renamed account's package path, so every documented
    ``docker pull`` was broken, including the ``cosign verify`` command whose
    entire job is to establish trust.
  * The wless.io news feed fetched a gist under the old username and **404**'d
    in production.
  * ``scripts/bump-version.sh`` fell through to a hardcoded ``shacharm2/worthless``
    fallback and would have written wrong CHANGELOG release links.

Plain ``github.com`` links survive a rename via 301, which is exactly why this
rotted quietly: the loudest surfaces (GHCR, gists) fail hard while the most
common one (repo links) keeps working.

Design note — the canonical owner is parsed from ``pyproject.toml``'s
``[project.urls] Repository`` rather than hardcoded here. Hardcoding the new
name would reproduce this very bug on the next rename: one file would be
updated and this guard would happily bless the rest. There is exactly one
source of truth; everything else must agree with it.

Only references to OUR repo/image/gist are checked. Third-party links
(``github.com/anchore/grype``, ``github.com/sigstore/...``) are untouched.

Pure stdlib + file reads, so it runs in the default pytest pass with no extra
setup — same shape as ``test_docs_install_badges.py``.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

# Read the URL with a regex rather than tomllib: the project floor is Python
# 3.10, where tomllib does not exist. Same approach check_docs_versions.py
# already uses to read install.sh's version pin — no new dependency for one line.
_REPO_URL_RE = re.compile(r'^Repository\s*=\s*"([^"]+)"', re.MULTILINE)

# The one gist the website reads its news feed from (website/news-feed.js).
_NEWS_FEED_GIST_ID = "7f6e2293b540004c4a733258a2461800"

# NOT allowlisted, because the patterns below only match URL-shaped references
# and these mention an owner as a bare word, so they are never flagged:
#
#   * sonar-project.properties -- `sonar.organization=shacharm2` /
#     `sonar.projectKey=shacharm2_worthless`. SonarCloud project keys are NOT
#     GitHub-owner-derived and did not move with the rename, so this file is
#     probably right. It is NOT verified-correct: the live badge API returns
#     HTTP 200 for BOTH keys, and only the response BODY distinguishes them --
#     `shacharm2_worthless` returns a real measure, `oblangatas_worthless`
#     returns an error marker. README.md references the latter, but only inside
#     a commented-out block ("held until the existing issues are triaged"), so
#     nothing is visibly broken today -- it would break on re-enable. Tracked
#     separately; do not "fix" this file by find-and-replace in the meantime.
#     (A status-code-only check calls both healthy. That is the same false
#     green as commit 338da36f -- check the body, not the code.)
#   * .github/workflows/tests.yml -- gates a job on
#     `github.repository == '<owner>/worthless'`, a bare comparison rather than
#     a URL. test_workflow_repository_guards_match_canonical below covers it,
#     because on a rename that condition silently evaluates false and the job
#     skips GREEN rather than failing.
#
# Paths that keep a non-canonical owner ON PURPOSE. Every entry needs a reason:
# a bare exclusion here is how the next rename hides again.
_ALLOWLIST: dict[str, str] = {
    "CHANGELOG.md": (
        "Archival PR/release links from shipped versions. GitHub 301-redirects them, "
        "and rewriting released history is noise, not a fix."
    ),
    "docs/install-docker.md": (
        "Deliberately names the dead ghcr.io/shacharm2 path in the troubleshooting "
        "section, so a user hitting the 403 can search the error and find the fix."
    ),
    "tests/test_repo_owner_refs.py": (
        "This guard. It must name the old owner to document what it is guarding against."
    ),
}

# Prefixes whose contents are a point-in-time record, not live references.
_ALLOWLIST_PREFIXES: dict[str, str] = {
    "engineering/": (
        "Review handoffs, research specs and product journeys are dated artifacts. "
        "Rewriting them falsifies the record of what was true when they were written."
    ),
}

# References to OUR things, each capturing the owner segment.
_OWNED_REF_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # github.com/<owner>/worthless — repo links, raw content, edit links, clones.
    ("repo", re.compile(r"github(?:usercontent)?\.com/([A-Za-z0-9-]+)/worthless\b")),
    # ghcr.io/<owner>/worthless-proxy — the container image. Hard-fails on rename.
    ("image", re.compile(r"ghcr\.io/([A-Za-z0-9-]+)/worthless-proxy\b")),
    # The news-feed gist. Hard-fails on rename.
    (
        "gist",
        re.compile(rf"gist\.github(?:usercontent)?\.com/([A-Za-z0-9-]+)/{_NEWS_FEED_GIST_ID}"),
    ),
)


def _canonical_owner() -> str:
    """The single source of truth: pyproject.toml's [project.urls] Repository."""
    pyproject = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    url_match = _REPO_URL_RE.search(pyproject)
    assert url_match, "pyproject.toml has no [project.urls] Repository entry to read"
    repo_url = url_match.group(1)
    m = re.fullmatch(r"https://github\.com/([A-Za-z0-9-]+)/worthless/?", repo_url)
    assert m, (
        f"pyproject.toml [project.urls] Repository is {repo_url!r}, which this guard "
        "cannot parse an owner from. That URL is the canonical owner for the whole "
        "repo — fix it there, not here."
    )
    return m.group(1)


def _tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 — git is on PATH in every dev/CI env
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def _is_allowlisted(path: str) -> bool:
    return path in _ALLOWLIST or any(path.startswith(p) for p in _ALLOWLIST_PREFIXES)


def test_canonical_owner_is_parseable() -> None:
    """The source of truth must itself be well-formed, or the guard is vacuous."""
    assert _canonical_owner()


def test_no_tracked_file_references_a_stale_owner() -> None:
    canonical = _canonical_owner()
    violations: list[str] = []

    for rel in _tracked_text_files():
        if _is_allowlisted(rel):
            continue
        try:
            text = (_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or symlink — no URLs to check

        for lineno, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in _OWNED_REF_PATTERNS:
                for owner in pattern.findall(line):
                    if owner != canonical:
                        violations.append(
                            f"{rel}:{lineno}: {kind} reference names owner "
                            f"{owner!r}, expected {canonical!r}"
                        )

    assert not violations, (
        f"{len(violations)} reference(s) to our own repo/image/gist name an owner "
        f"other than {canonical!r} (from pyproject.toml [project.urls] Repository).\n\n"
        + "\n".join(violations)
        + "\n\nGHCR and gist paths do NOT redirect after an account rename — those "
        "break outright. If a reference is stale on purpose, add it to _ALLOWLIST "
        "with a reason."
    )


def test_allowlist_entries_still_exist_and_still_need_the_exemption() -> None:
    """An allowlist that outlives its reason silently widens over time."""
    canonical = _canonical_owner()
    stale: list[str] = []

    for rel, reason in _ALLOWLIST.items():
        path = _ROOT / rel
        if not path.exists():
            stale.append(f"{rel}: allowlisted but no longer exists — drop the entry")
            continue
        assert reason.strip(), f"{rel}: allowlist entry has no reason"

        text = path.read_text(encoding="utf-8")
        if not any(
            owner != canonical
            for _, pattern in _OWNED_REF_PATTERNS
            for owner in pattern.findall(text)
        ):
            stale.append(
                f"{rel}: allowlisted, but no longer contains a non-{canonical!r} "
                "reference — drop the entry so the file is guarded again"
            )

    assert not stale, "Allowlist has drifted:\n" + "\n".join(stale)


@pytest.mark.parametrize("kind", [k for k, _ in _OWNED_REF_PATTERNS])
def test_guard_actually_catches_a_stale_owner(kind: str) -> None:
    """Prove each pattern fires — a guard that matches nothing passes vacuously."""
    samples = {
        "repo": "see https://github.com/shacharm2/worthless/blob/main/SECURITY.md",
        "image": "docker pull ghcr.io/shacharm2/worthless-proxy:0.3.12",
        "gist": f"https://gist.githubusercontent.com/shacharm2/{_NEWS_FEED_GIST_ID}/raw/news-feed.json",
    }
    canonical = _canonical_owner()
    pattern = dict(_OWNED_REF_PATTERNS)[kind]

    # The pattern extracts whatever owner is present; the guard is the
    # comparison against canonical. Assert both halves of that.
    assert pattern.findall(samples[kind]) == ["shacharm2"], (
        f"{kind} pattern failed to extract the stale owner"
    )
    assert pattern.findall(samples[kind].replace("shacharm2", canonical)) == [canonical], (
        f"{kind} pattern failed to extract the canonical owner"
    )


def test_third_party_github_links_are_not_flagged() -> None:
    """The guard must not touch links to other people's repos."""
    for benign in (
        "https://github.com/anchore/grype",
        "https://github.com/sigstore/cosign-installer",
        "https://github.com/pypi/warehouse/issues/11096",
    ):
        for _, pattern in _OWNED_REF_PATTERNS:
            assert not pattern.findall(benign), f"guard wrongly flagged {benign}"


def test_shell_owner_fallbacks_match_canonical() -> None:
    """The hardcoded fallback owner in release scripts must be current.

    scripts/bump-version.sh keeps a literal `owner_repo="<owner>/worthless"` for
    when origin can't be parsed. It is written bare -- no `github.com/` around
    it -- so none of the URL patterns above see it, and it is exactly the kind
    of string that rotted last time: it silently produced CHANGELOG links for
    the wrong owner while looking like it had been derived (worthless-c478).

    Targeted rather than a broad `<x>/worthless` regex on purpose: that form
    also matches filesystem paths like `src/worthless` and produced a false
    positive on tests/test_archive_reachability.py.
    """
    canonical = _canonical_owner()
    assignment = re.compile(r"""owner_repo=["']([A-Za-z0-9-]+)/worthless["']""")
    offenders: list[str] = []

    shell_scripts = [p for p in _tracked_text_files() if p.endswith((".sh", ".bash"))]
    assert shell_scripts, "no shell scripts found — the glob or the layout moved"

    checked = 0
    for rel in shell_scripts:
        for lineno, line in enumerate((_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            for owner in assignment.findall(line):
                checked += 1
                if owner != canonical:
                    offenders.append(f"{rel}:{lineno}: fallback owner {owner!r} != {canonical!r}")

    assert checked, (
        "no owner_repo= fallback found in any shell script. If the fallback was "
        "removed, delete this test; if it was renamed, update the pattern -- do "
        "not leave it passing vacuously."
    )
    assert not offenders, "Stale hardcoded owner in a release script:\n" + "\n".join(offenders)


def test_workflow_repository_guards_match_canonical() -> None:
    """`if: github.repository == '<owner>/worthless'` must name the current owner.

    Not URL-shaped, so the patterns above never see it. This form is worse than
    a stale link: on a rename the condition quietly evaluates false, the job is
    SKIPPED, and GitHub reports the workflow green. A guard that disappears
    without failing is the exact silent-success shape worthless-c478 is about.
    """
    canonical = _canonical_owner()
    pattern = re.compile(r"""github\.repository\s*==\s*['"]([A-Za-z0-9-]+)/worthless['"]""")
    offenders: list[str] = []
    checked = 0

    for rel in _tracked_text_files():
        if not rel.startswith(".github/workflows/"):
            continue
        for lineno, line in enumerate((_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            for owner in pattern.findall(line):
                checked += 1
                if owner != canonical:
                    offenders.append(
                        f"{rel}:{lineno}: job gated on owner {owner!r} != {canonical!r}"
                    )

    assert checked, (
        "no `github.repository == '<owner>/worthless'` comparison found in any "
        "workflow. If the pattern moved, update it -- do not leave this passing "
        "vacuously."
    )
    assert not offenders, (
        "Workflow job gated on a stale owner (it will SKIP GREEN, not fail):\n"
        + "\n".join(offenders)
    )

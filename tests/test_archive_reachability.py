"""Guard the reachability argument that three .grype.yaml suppressions rest on.

WOR-852. The image carries three CPython ``tarfile`` CVEs — CVE-2026-11940,
CVE-2026-11972 and CVE-2026-4360 — and all three are suppressed on one claim:
nothing in ``src/worthless`` ever hands an archive to the stdlib. The proxy
forwards JSON; it does not open tarballs.

That claim was true when it was measured and written down. Nothing stopped it
from quietly becoming false. A suppression's expiry date cannot catch this —
a date fires on the calendar, not on the commit that adds ``import tarfile``,
so the argument could die months before anyone re-read it.

This test is what actually catches it. Add archive extraction to the package
and this goes red in the same commit, pointing at the suppressions that just
became unsound.

If you are here because this test failed: the fix is NOT to add an allowlist
entry. It is to re-open .grype.yaml and decide whether those three CVEs are
still safe to suppress now that the code reaches the vulnerable module.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "worthless"

# Stdlib modules whose CVEs the .grype.yaml tarfile block waives. `zipfile` is
# in here because the written argument covers it too, not because a zipfile CVE
# is currently suppressed — the argument is "no archive handling at all".
_ARCHIVE_MODULES = {"tarfile", "zipfile"}

# shutil is imported all over for ordinary file work, so the module name alone
# proves nothing. Only the call that UNPACKS one matters: all three waived CVEs
# are extraction bugs needing an attacker-supplied archive, so `make_archive` is
# deliberately absent — writing a tarball cannot reach any of them, and flagging
# it would fail a build while citing three CVEs it has nothing to do with.
_ARCHIVE_CALLS = {"unpack_archive"}


def _violations(source: str, label: str) -> list[str]:
    """Return one message per archive-handling construct in `source`.

    Takes source text rather than a path so the caller owns file reading and
    naming — that keeps this function trivially exercisable from a literal.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover — a syntax error is another test's problem
        return []

    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _ARCHIVE_MODULES:
                    found.append(f"{label}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _ARCHIVE_MODULES:
                found.append(f"{label}:{node.lineno}: from {node.module} import ...")
            # `from shutil import unpack_archive` — the module is innocent, the name isn't.
            for alias in node.names:
                if alias.name in _ARCHIVE_CALLS:
                    found.append(f"{label}:{node.lineno}: from {node.module} import {alias.name}")
        elif isinstance(node, ast.Attribute) and node.attr in _ARCHIVE_CALLS:
            # `shutil.unpack_archive(...)` — caught as an attribute so the import
            # of shutil itself stays allowed.
            found.append(f"{label}:{node.lineno}: .{node.attr}(...)")
    return found


def test_src_worthless_never_touches_archives() -> None:
    """No archive handling anywhere under src/worthless.

    Three .grype.yaml suppressions cite this file's result as their evidence.
    """
    scanned = sorted(_SRC_ROOT.rglob("*.py"))

    # "Found no archive imports" and "found no files" produce the identical
    # green here, so the empty scan has to be ruled out explicitly. A package
    # move, an src-layout change, or running against an installed wheel would
    # otherwise turn this guard into one that always passes.
    assert scanned, (
        f"scanned 0 files under {_SRC_ROOT} — this guard is not pointed at the "
        f"package any more and would pass no matter what the code does. Fix the "
        f"path before trusting a green result from it."
    )

    repo = _SRC_ROOT.parent.parent
    offenders = [v for f in scanned for v in _violations(f.read_text(), str(f.relative_to(repo)))]

    assert not offenders, (
        "src/worthless now handles archives:\n  "
        + "\n  ".join(offenders)
        + "\n\nThis breaks the reachability argument in .grype.yaml that waives "
        "CVE-2026-11940, CVE-2026-11972 and CVE-2026-4360. Re-argue those "
        "suppressions before making this test pass."
    )


def test_guard_actually_detects_archive_use() -> None:
    """The guard above is only worth having if it can fail. Prove it can.

    The empty-scan assertion is what stops a mis-pointed guard passing; this is
    the other half — proof the detector still matches every construct that
    assertion assumes it matches.
    """
    found = _violations(
        "import tarfile\n"
        "import zipfile\n"
        "from tarfile import open as topen\n"
        "import shutil\n"
        "from shutil import unpack_archive\n"
        "shutil.unpack_archive('x')\n",
        "sample.py",
    )

    assert any("import tarfile" in v for v in found)
    assert any("import zipfile" in v for v in found)
    assert any("from tarfile import" in v for v in found)
    assert sum("unpack_archive" in v for v in found) == 2  # from-import AND attribute call


def test_creating_an_archive_is_not_flagged() -> None:
    """`make_archive` must NOT trip the guard.

    All three waived CVEs are extraction bugs requiring an attacker-supplied
    archive. Writing one cannot reach them, so flagging it would fail a build
    while naming three CVEs the commit has nothing to do with.
    """
    assert _violations("import shutil\nshutil.make_archive('x', 'gztar')\n", "s.py") == []

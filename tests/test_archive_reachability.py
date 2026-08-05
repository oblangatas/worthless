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
# proves nothing. These are the two shutil calls that unpack or build archives.
_ARCHIVE_CALLS = {"unpack_archive", "make_archive"}


def _violations(py_file: Path) -> list[str]:
    """Return one message per archive-handling construct found in the file."""
    try:
        tree = ast.parse(py_file.read_text())
    except SyntaxError:  # pragma: no cover — a syntax error is another test's problem
        return []

    try:
        rel: Path | str = py_file.relative_to(_SRC_ROOT.parent.parent)
    except ValueError:
        rel = py_file  # a file outside the repo — only happens in this module's own test
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _ARCHIVE_MODULES:
                    found.append(f"{rel}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _ARCHIVE_MODULES:
                found.append(f"{rel}:{node.lineno}: from {node.module} import ...")
            # `from shutil import unpack_archive` — the module is innocent, the name isn't.
            for alias in node.names:
                if alias.name in _ARCHIVE_CALLS:
                    found.append(f"{rel}:{node.lineno}: from {node.module} import {alias.name}")
        elif isinstance(node, ast.Attribute) and node.attr in _ARCHIVE_CALLS:
            # `shutil.unpack_archive(...)` — caught as an attribute so the import
            # of shutil itself stays allowed.
            found.append(f"{rel}:{node.lineno}: .{node.attr}(...)")
    return found


def test_src_worthless_never_touches_archives() -> None:
    """No archive handling anywhere under src/worthless.

    Three .grype.yaml suppressions cite this file's result as their evidence.
    """
    offenders = [v for f in sorted(_SRC_ROOT.rglob("*.py")) for v in _violations(f)]

    assert not offenders, (
        "src/worthless now handles archives:\n  "
        + "\n  ".join(offenders)
        + "\n\nThis breaks the reachability argument in .grype.yaml that waives "
        "CVE-2026-11940, CVE-2026-11972 and CVE-2026-4360. Re-argue those "
        "suppressions before making this test pass."
    )


def test_guard_actually_detects_archive_use(tmp_path: Path) -> None:
    """The guard above is only worth having if it can fail. Prove it can.

    A green all-clear from a scanner that cannot detect anything is worse than
    no scanner, so exercise every construct the real test relies on.
    """
    sample = tmp_path / "offender.py"
    sample.write_text(
        "import tarfile\n"
        "import zipfile\n"
        "import shutil\n"
        "from shutil import unpack_archive\n"
        "shutil.make_archive('x', 'gztar')\n"
    )

    found = _violations(sample)

    assert any("import tarfile" in v for v in found)
    assert any("import zipfile" in v for v in found)
    assert any("unpack_archive" in v for v in found)
    assert any("make_archive" in v for v in found)

"""Pin the unmapped-findings gate (WOR-852, worthless-77zv).

The container gate runs `only-fixed: true`, which silently drops every finding
grype cannot map to a fixed version — at any severity. Measured 2026-08-10 on
the shipped image, three CRITICALS sat in that blind spot behind a green build.

These tests pin the policy so it cannot drift back:
  - unmapped High/Critical must FAIL
  - `wont-fix` must NOT fail (47 Medium + 16 High of Debian noise lives there)
  - a dated .grype.yaml argument must silence a finding, and nothing else may

Hermetic: every case is a synthetic grype report. No image, no network.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = (
    Path(__file__).resolve().parent.parent
    / "scripts"
    / "hooks"
    / "check_grype_unmapped_findings.py"
)


def _match(cve: str, severity: str, state: str, package: str = "libfake1") -> dict:
    return {
        "vulnerability": {"id": cve, "severity": severity, "fix": {"state": state, "versions": []}},
        "artifact": {"name": package, "type": "deb"},
    }


def _run(tmp_path: Path, matches: list[dict]) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"matches": matches}))
    return subprocess.run(
        [sys.executable, str(HOOK), str(report)], capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize(
    ("severity", "state"),
    [
        ("Critical", "unknown"),
        ("Critical", "not-fixed"),
        ("Critical", ""),
        ("High", "unknown"),
        ("High", "not-fixed"),
    ],
)
def test_unmapped_high_and_critical_fail(tmp_path: Path, severity: str, state: str) -> None:
    """The blind spot the gate exists to close."""
    result = _run(tmp_path, [_match("CVE-2099-00001", severity, state)])
    assert result.returncode == 1
    assert "CVE-2099-00001" in result.stderr


@pytest.mark.parametrize("severity", ["Critical", "High", "Medium", "Low"])
def test_wont_fix_never_gates(tmp_path: Path, severity: str) -> None:
    """`wont-fix` is a vendor decision, not a gap.

    The image carries 47 Medium and 16 High of these. Gating on them would
    make the build permanently red and train people to rubber-stamp
    suppressions, which is worse than the hole this hook closes.
    """
    assert _run(tmp_path, [_match("CVE-2099-00002", severity, "wont-fix")]).returncode == 0


@pytest.mark.parametrize("severity", ["Medium", "Low", "Negligible", "Unknown"])
def test_below_high_does_not_gate(tmp_path: Path, severity: str) -> None:
    """Deliberate scope limit — stated so it is a choice, not an oversight."""
    assert _run(tmp_path, [_match("CVE-2099-00003", severity, "unknown")]).returncode == 0


def test_fixed_findings_do_not_gate(tmp_path: Path) -> None:
    """Those are the ordinary gating scan's job, not this hook's."""
    assert _run(tmp_path, [_match("CVE-2099-00004", "Critical", "fixed")]).returncode == 0


def test_argued_cve_is_silenced(tmp_path: Path) -> None:
    """A CVE with a dated .grype.yaml entry must not gate.

    Uses a real entry from the repo's own config, so this breaks if the perl
    arguments are ever deleted without also fixing the finding.
    """
    result = _run(tmp_path, [_match("CVE-2026-12087", "Critical", "not-fixed", "perl-base")])
    assert result.returncode == 0


def test_the_gate_can_actually_fail(tmp_path: Path) -> None:
    """A gate that cannot fail is worse than no gate.

    Pins that a clean report and a dirty one give DIFFERENT answers — without
    this, every other test here would still pass if the hook always exited 0.
    """
    clean = _run(tmp_path, [_match("CVE-2099-00005", "Critical", "wont-fix")])
    dirty = _run(tmp_path, [_match("CVE-2099-00006", "Critical", "unknown")])
    assert clean.returncode == 0
    assert dirty.returncode == 1


def test_empty_report_does_not_crash(tmp_path: Path) -> None:
    assert _run(tmp_path, []).returncode == 0


def test_duplicate_matches_reported_once(tmp_path: Path) -> None:
    """Grype emits one match per artifact; the same CVE on one package is one finding."""
    dupes = [_match("CVE-2099-00007", "Critical", "unknown") for _ in range(3)]
    result = _run(tmp_path, dupes)
    assert result.returncode == 1
    assert result.stderr.count("CVE-2099-00007") == 1


def test_empty_path_is_a_clear_error_not_a_traceback() -> None:
    """A skipped scan step yields "", and Path("") is "." — a directory.

    This shipped: the arm64 gate ran on PRs where its scan was skipped and
    died with IsADirectoryError. CI caught it; review did not.
    """
    result = subprocess.run(
        [sys.executable, str(HOOK), ""], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2
    assert "no grype report path" in result.stderr
    assert "Traceback" not in result.stderr


def test_directory_argument_is_rejected() -> None:
    """Belt and braces: an actual directory must not be parsed as a report."""
    result = subprocess.run(
        [sys.executable, str(HOOK), "."], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2
    assert "not a file" in result.stderr

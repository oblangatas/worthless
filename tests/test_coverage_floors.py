"""Unit tests for scripts/check-coverage-floors.py (Wave 3, worthless-ky71)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check-coverage-floors.py"


def test_coverage_floors_passes_minimal_fixture(tmp_path: Path) -> None:
    xml = tmp_path / "coverage.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.85" version="7">
  <packages>
    <package name="worthless.crypto" line-rate="0.96"/>
    <package name="worthless.proxy" line-rate="0.86"/>
    <package name="worthless.storage" line-rate="0.87"/>
    <package name="worthless.cli.commands" line-rate="0.90"/>
  </packages>
  <classes>
    <class filename="src/worthless/cli/commands/lock.py" line-rate="0.82"/>
  </classes>
</coverage>
""",
        encoding="utf-8",
    )
    # Script reads cwd/coverage.xml — run from tmp_path
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "worthless.storage" in result.stdout
    assert "lock.py" in result.stdout


def test_coverage_floors_fails_when_storage_below_floor(tmp_path: Path) -> None:
    xml = tmp_path / "coverage.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.85" version="7">
  <packages>
    <package name="worthless.crypto" line-rate="0.96"/>
    <package name="worthless.proxy" line-rate="0.86"/>
    <package name="worthless.storage" line-rate="0.70"/>
  </packages>
  <classes>
    <class filename="src/worthless/cli/commands/lock.py" line-rate="0.82"/>
  </classes>
</coverage>
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "worthless.storage" in result.stdout
    assert "FAIL" in result.stdout

#!/usr/bin/env python3
"""Check per-module coverage floors from coverage.xml.

Floors (enforced on PR ``coverage-gate`` job):
  - overall: 80%
  - worthless.crypto: 95%
  - worthless.proxy: 85%
  - worthless.storage: 85%
  - src/worthless/cli/commands/lock.py: 80%
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PACKAGE_FLOORS = {
    "worthless.crypto": 95.0,
    "worthless.proxy": 85.0,
    "worthless.storage": 85.0,
}

# Single-file modules (coverage.xml <class filename="...">), not separate packages.
FILE_FLOORS = {
    "src/worthless/cli/commands/lock.py": 80.0,
}

OVERALL_FLOOR = 80.0


def main() -> int:
    coverage_path = Path("coverage.xml")
    if not coverage_path.exists():
        print(f"ERROR: {coverage_path} not found. Run pytest --cov first.")
        return 1

    try:
        tree = ET.parse(coverage_path)  # noqa: S314 — trusted coverage XML we generated
    except ET.ParseError as exc:
        print(f"ERROR: failed to parse {coverage_path}: {exc}")
        return 1

    root = tree.getroot()

    # Check overall
    overall = float(root.get("line-rate", 0)) * 100
    failed = False
    if overall < OVERALL_FLOOR:
        print(f"FAIL: overall coverage {overall:.1f}% < {OVERALL_FLOOR}%")
        failed = True
    else:
        print(f"OK: overall coverage {overall:.1f}% >= {OVERALL_FLOOR}%")

    # Check per-package floors
    seen_packages: set[str] = set()
    for pkg in root.findall(".//package"):
        name = pkg.get("name", "").replace("/", ".").removeprefix("src.")
        rate = float(pkg.get("line-rate", 0)) * 100
        for module, floor in PACKAGE_FLOORS.items():
            if name == module or name.startswith(module + "."):
                seen_packages.add(module)
                if rate < floor:
                    print(f"FAIL: {name} coverage {rate:.1f}% < {floor}%")
                    failed = True
                else:
                    print(f"OK: {name} coverage {rate:.1f}% >= {floor}%")

    missing_packages = set(PACKAGE_FLOORS) - seen_packages
    if missing_packages:
        for module in sorted(missing_packages):
            print(f"FAIL: floor package {module!r} not found in coverage data")
        failed = True

    # Check single-file module floors
    seen_files: set[str] = set()
    for cls in root.findall(".//class"):
        filename = cls.get("filename", "")
        if filename not in FILE_FLOORS:
            continue
        seen_files.add(filename)
        rate = float(cls.get("line-rate", 0)) * 100
        floor = FILE_FLOORS[filename]
        if rate < floor:
            print(f"FAIL: {filename} coverage {rate:.1f}% < {floor}%")
            failed = True
        else:
            print(f"OK: {filename} coverage {rate:.1f}% >= {floor}%")

    missing_files = set(FILE_FLOORS) - seen_files
    if missing_files:
        for filename in sorted(missing_files):
            print(f"FAIL: floor file {filename!r} not found in coverage data")
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

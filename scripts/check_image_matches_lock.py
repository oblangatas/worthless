#!/usr/bin/env python3
"""Fail unless a built image holds exactly uv.lock's runtime set (WOR-1077).

dependency-audit.yml audits uv.lock, so this is what makes that audit true of
the image: every distribution in it is a locked package at its locked version,
under the image's own platform markers, apart from pip (from the Python base
image) and worthless itself (built from src/).

`scan` runs it on every PR because that check is required and docker-e2e is
not. test_docker_e2e.py runs it too, which is how publish-docker.yml checks the
image users pull.

    python scripts/check_image_matches_lock.py <image>

Host side is stdlib only. Markers are evaluated inside the image, with pip's
vendored `packaging`.

Exit 0 = the image matches the lock. Exit 1 = it doesn't, and the difference is
printed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Runs inside the image. stdin: `uv export` lines. stdout: the locked set that
# applies to this platform, and what is installed.
_PROBE = """
import importlib.metadata, json, sys
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name

locked, unpinned = {}, []
for line in sys.stdin:
    if line.strip():
        req = Requirement(line)
        pins = [s.version for s in req.specifier if s.operator == "=="]
        if req.url or len(pins) != 1:
            unpinned.append(line.strip())
        elif req.marker is None or req.marker.evaluate():
            locked[canonicalize_name(req.name)] = pins[0]
installed = {
    canonicalize_name(d.metadata["Name"]): d.version
    for d in importlib.metadata.distributions()
}
print(json.dumps({"locked": locked, "unpinned": unpinned, "installed": installed}))
"""


def main(image: str) -> int:
    export = subprocess.run(
        [  # noqa: S607 — `uv` from PATH, as the CI jobs and tests run it
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
            "--no-header",
            "--no-annotate",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    probe = subprocess.run(
        ["docker", "run", "--rm", "-i", "--entrypoint", "python", image, "-c", _PROBE],  # noqa: S607
        input=export,
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        print(f"probe failed in {image}:\n{probe.stderr}", file=sys.stderr)
        return 1
    report = json.loads(probe.stdout)
    locked, installed = report["locked"], report["installed"]

    # A lock entry pointing at a URL exports as `name @ url` with whatever hash
    # the lock carries, and pip-audit skips it. Only `name==version` lines are
    # PyPI releases the audit checked.
    if report["unpinned"]:
        print("uv.lock exports entries that aren't PyPI releases:", file=sys.stderr)
        for line in report["unpinned"]:
            print(f"  {line}", file=sys.stderr)
        return 1
    if installed.pop("worthless", None) is None:
        print(f"worthless is not installed in {image}", file=sys.stderr)
        return 1
    installed.pop("pip", None)
    if installed == locked:
        print(f"{image}: all {len(locked)} packages match uv.lock")
        return 0
    for name in sorted(set(locked) | set(installed)):
        if locked.get(name) != installed.get(name):
            print(f"  {name}: uv.lock {locked.get(name)}, image {installed.get(name)}")
    print(f"{image} doesn't hold uv.lock's runtime set (WOR-1077)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <image>")
    sys.exit(main(sys.argv[1]))

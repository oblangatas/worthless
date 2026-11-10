#!/usr/bin/env python3
"""Fail unless a built image holds exactly uv.lock's runtime set (WOR-1077).

dependency-audit.yml audits uv.lock, so this is what makes that audit true of
the image: every distribution in it is a locked package at its locked version,
under the image's own platform markers, apart from pip (from the Python base
image) and worthless itself (built from src/). Each locked version must also be
the one the audit's own export pins, and each package installed only once.

`scan` runs it on every PR because that check is required and docker-e2e is
not. publish-docker.yml runs it on the amd64 image before pushing, and again,
through test_docker_e2e.py, on the image users pull.

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

# Runs inside the image. stdin: JSON of the two `uv export`s. stdout: the pins
# from each that apply to this platform, and what is installed.
_PROBE = """
import importlib.metadata, json, sys
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name

def applicable(export):
    pins, unpinned = {}, []
    for line in export.splitlines():
        if line.strip():
            req = Requirement(line)
            versions = [s.version for s in req.specifier if s.operator == "=="]
            if req.url or len(versions) != 1:
                unpinned.append(line.strip())
            elif req.marker is None or req.marker.evaluate():
                pins[canonicalize_name(req.name)] = versions[0]
    return pins, unpinned

exports = json.load(sys.stdin)
locked, unpinned = applicable(exports["runtime"])
audited, _ = applicable(exports["audited"])
installed, duplicates = {}, set()
for dist in importlib.metadata.distributions():
    name = canonicalize_name(dist.metadata["Name"])
    if name in installed:
        duplicates.add(name)
    installed[name] = dist.version
print(json.dumps({
    "locked": locked, "unpinned": unpinned, "audited": audited,
    "installed": installed, "duplicates": sorted(duplicates),
}))
"""


def _export(*flags: str) -> str:
    return subprocess.run(
        [  # noqa: S607 — `uv` from PATH, as the CI jobs and tests run it
            "uv",
            "export",
            "--frozen",
            *flags,
            "--no-emit-project",
            "--no-hashes",
            "--no-header",
            "--no-annotate",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout


def main(image: str) -> int:
    """Exit status for *image*: 0 if it holds exactly uv.lock's runtime set, else 1."""
    # The image installs the export without the dev group; dependency-audit.yml
    # audits the one with it. A dev-group conflict can resolve a package to a
    # different version in each, so both are read and compared below.
    exports = {"runtime": _export("--no-dev"), "audited": _export()}
    probe = subprocess.run(
        # No network: the probe only reads stdin, and in publish-docker.yml it
        # runs inside the job that holds the signing token.
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--entrypoint",
            "python",
            image,
            "-c",
            _PROBE,
        ],
        input=json.dumps(exports),
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
    unaudited = sorted(f"{n}=={v}" for n, v in locked.items() if report["audited"].get(n) != v)
    if unaudited:
        print(
            "uv.lock's runtime set has versions the audit doesn't check: " + ", ".join(unaudited),
            file=sys.stderr,
        )
        return 1
    if report["duplicates"]:
        # e.g. `pip install --ignore-installed` leaves the old record behind, and
        # only one of them can describe the files on disk.
        print(
            f"{image} has more than one install record: " + ", ".join(report["duplicates"]),
            file=sys.stderr,
        )
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
            print(
                f"  {name}: uv.lock {locked.get(name)}, image {installed.get(name)}",
                file=sys.stderr,
            )
    print(f"{image} doesn't hold uv.lock's runtime set (WOR-1077)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <image>")
    sys.exit(main(sys.argv[1]))

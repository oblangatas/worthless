#!/usr/bin/env python3
"""Fail if any pinned ``worthless-proxy:X.Y.Z`` image tag in ``docs/`` lags the
released version.

This is the docs-side guard for the drift class that bit us twice:
WOR-734 (``docs/install-docker.md`` stuck at ``0.3.1``) and WOR-733
(``docs/install/docker.md`` stuck at ``0.3.3``) — both shipped while the
released image was newer, pointing readers at images missing recent hardening.

Source of truth for "the released version":
  * ``argv[1]`` if given (release-sync-check passes the network-resolved latest), else
  * ``WORTHLESS_VERSION_PIN`` in ``install.sh`` — which release-sync-check's A1
    already asserts equals PyPI == the latest signed tag, so it is a safe
    in-repo, no-network canonical for PR-time use.

Only FULLY pinned semver tags (``worthless-proxy:1.2.3``) are checked. These
are ignored on purpose:
  * ``:latest`` / ``:0.3`` (partial) — intentional floating pins.
  * historical prose like "pre v0.3.1" — not an image tag, never matches.

If a doc ever needs a deliberately-old pinned tag (e.g. an upgrade example),
add it to ``ALLOWLIST`` below with a reason.
"""

from __future__ import annotations

import pathlib
import re
import sys

DOCS = pathlib.Path("docs")
INSTALL_SH = pathlib.Path("install.sh")
TAG_RE = re.compile(r"worthless-proxy:(\d+\.\d+\.\d+)")
PIN_RE = re.compile(r'^WORTHLESS_VERSION_PIN="([^"]+)"', re.MULTILINE)

# (path, found_version) pairs that are intentionally NOT the current release.
ALLOWLIST: set[tuple[str, str]] = set()


def expected_version() -> str:
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    m = PIN_RE.search(INSTALL_SH.read_text(encoding="utf-8"))
    if not m:
        sys.exit("check_docs_versions: could not read WORTHLESS_VERSION_PIN from install.sh")
    return m.group(1)


def main() -> int:
    expected = expected_version()
    if not DOCS.is_dir():
        sys.exit(f"check_docs_versions: no {DOCS}/ directory at CWD {pathlib.Path.cwd()}")

    bad: list[tuple[pathlib.Path, int, str, str]] = []
    checked = 0
    for doc in sorted([*DOCS.rglob("*.md"), *DOCS.rglob("*.mdx")]):
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for match in TAG_RE.finditer(line):
                checked += 1
                found = match.group(1)
                if found == expected:
                    continue
                if (str(doc), found) in ALLOWLIST:
                    continue
                bad.append((doc, lineno, found, line.strip()))

    if bad:
        print(
            f"::error title=Stale docs image tag::docs/ pins worthless-proxy "
            f"tags that are not the released version {expected}"
        )
        for doc, lineno, found, line in bad:
            print(f"  {doc}:{lineno}  found :{found}  (expected :{expected})")
            print(f"      | {line}")
        print(
            f"\nFix: bump these to :{expected} (or use :latest / a partial :MAJOR.MINOR "
            "pin). If an old tag is intentional, add it to ALLOWLIST in "
            "scripts/check_docs_versions.py with a reason."
        )
        return 1

    print(f"OK: all {checked} pinned worthless-proxy:X.Y.Z tag(s) in docs/ == {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

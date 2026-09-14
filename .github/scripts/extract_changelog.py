#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one version, read from stdin.

Usage:  git show "<tag>:CHANGELOG.md" | extract_changelog.py <version>

The tag's CHANGELOG is piped in as *data* (never executed) so the release
workflow can run this trusted, default-branch script against untrusted tag
content safely. Finds the `## [<version>]` heading and prints everything up to
the next `## [` heading. Exit 0 with the section on stdout when found; exit 3
(empty) when not — the workflow then falls back to `--generate-notes`. WOR-846.
"""

from __future__ import annotations

import sys


def extract(text: str, version: str) -> str | None:
    """Return the changelog body under `## [<version>]`, or None if absent.

    Heading form: `## [0.3.10] — 2026-07-21` (bracketed version, any suffix).
    """
    version = version.lstrip("v")
    out: list[str] = []
    capturing = False
    for line in text.splitlines():
        if line.startswith("## ["):
            if capturing:
                break  # reached the next section
            ver = line[len("## [") :].split("]", 1)[0]
            if ver == version:
                capturing = True
            continue
        if capturing:
            out.append(line)
    body = "\n".join(out).strip()
    return body or None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: extract_changelog.py <version>", file=sys.stderr)
        return 2
    body = extract(sys.stdin.read(), argv[1])
    if body is None:
        return 3
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

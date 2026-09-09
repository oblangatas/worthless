#!/usr/bin/env python
"""Gate `npm audit` on the Worker tree, with time-boxed exceptions.

``npm audit`` is all-or-nothing: it has no ignore file, so a single
unfixable transitive advisory turns every PR red with no way to say
"known, accepted, revisit by this date".

This wraps it. Advisories named in ``npm-audit-allow.json`` pass; anything
else fails, and an entry past its expiry fails too — so an exception cannot
outlive the argument that justified it.

Deliberately NOT `npm audit --omit=dev`. That shortcut was rejected for this
job before, correctly: at the time `npm audit fix` cleared everything with
package.json unchanged, so dev-only was hiding a fix that existed. An
allowlist forces each acceptance to be argued and dated instead of hiding a
whole tree.

Usage:  python scripts/hooks/check_npm_audit.py [worker_dir]
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess  # nosec B404 — fixed argv, no shell
import sys
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "workers" / "worthless-sh"
ALLOW_FILE = "npm-audit-allow.json"
# Warn this far ahead so an expiry is renewed or removed deliberately, not in
# a panic on the morning it breaks the build.
WARN_DAYS = 14


def _advisory_ids(vuln: dict) -> set[str]:
    """GHSA ids reported for one package, from npm audit's `via` chain."""
    ids = set()
    for via in vuln.get("via", []):
        if isinstance(via, dict) and (url := via.get("url", "")):
            ids.add(url.rsplit("/", 1)[-1])
    return ids


def main(argv: list[str]) -> int:
    worker_dir = Path(argv[1]) if len(argv) > 1 else DEFAULT_DIR
    allow_path = worker_dir / ALLOW_FILE

    # Resolve npm up front rather than letting PATH answer at call time — a
    # supply-chain gate that can be shadowed by an earlier PATH entry is not a
    # gate. Also gives a clear error when npm simply is not installed.
    npm = shutil.which("npm")
    if npm is None:
        print("npm not found on PATH — cannot audit the Worker tree.", file=sys.stderr)
        return 1

    proc = subprocess.run(  # nosec B603 — fixed argv, resolved binary, no shell
        [npm, "audit", "--json"],
        cwd=worker_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if not proc.stdout.strip():
        print(f"npm audit produced no output (exit {proc.returncode}).", file=sys.stderr)
        print(proc.stderr.strip()[:2000], file=sys.stderr)
        return 1

    report = json.loads(proc.stdout)
    vulns = report.get("vulnerabilities", {})

    allow: dict[str, dict] = {}
    problems: list[str] = []
    warnings: list[str] = []
    today = dt.date.today()

    if allow_path.is_file():
        for entry in json.loads(allow_path.read_text()).get("allow", []):
            vid = entry.get("id")
            if not vid:
                problems.append(f"{ALLOW_FILE}: an entry has no `id` — name the advisory.")
                continue
            raw = entry.get("expiry")
            if not raw:
                problems.append(f"{vid}: no `expiry`. Every exception must be time-boxed.")
                continue
            try:
                expiry = dt.date.fromisoformat(str(raw).strip())
            except ValueError:
                problems.append(f"{vid}: expiry {raw!r} is not an ISO date (YYYY-MM-DD).")
                continue
            if expiry < today:
                problems.append(
                    f"{vid}: exception EXPIRED on {expiry}. Re-verify whether a fix "
                    f"exists now — do not extend the date without checking."
                )
                continue
            if (expiry - today).days <= WARN_DAYS:
                warnings.append(f"{vid}: exception expires {expiry}.")
            allow[vid] = entry

    unallowed: list[str] = []
    for name, vuln in vulns.items():
        severity = vuln.get("severity", "unknown")
        if severity in ("info", "low"):
            continue
        ids = _advisory_ids(vuln)
        # A package with no direct advisory id is reporting its dependency's;
        # it clears once the root advisory is allowed or fixed.
        if not ids:
            continue
        if ids - allow.keys():
            unallowed.append(f"  {severity:8} {name:32} {','.join(sorted(ids - allow.keys()))}")

    for w in warnings:
        print(f"WARNING  {w}", file=sys.stderr)

    if problems:
        print("\nnpm audit allowlist is not valid:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if unallowed:
        print("\nUnallowed npm advisories in the Worker tree:\n", file=sys.stderr)
        for u in unallowed:
            print(u, file=sys.stderr)
        print(
            f"\nFix them, or add an argued, dated entry to {worker_dir.name}/{ALLOW_FILE}.",
            file=sys.stderr,
        )
        return 1

    allowed_note = f" ({len(allow)} allowed, time-boxed)" if allow else ""
    print(f"npm audit: no unallowed advisories{allowed_note}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

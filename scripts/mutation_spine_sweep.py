#!/usr/bin/env python3
"""Scoped mutation sweep over the WOR-650 honesty / bind-confirmation spine.

For each canonical mutation (operator / string flip) on a load-bearing line,
apply it, run the fast honesty/bind suite, and record whether the suite CATCHES
it (a test fails = KILLED) or not (SURVIVED = a real coverage hole). Restores
each file via ``git checkout`` after every case.

This is hand-scoped mutation testing — reliable where mutmut 3.x won't run
against this repo's pytest addopts (``-n auto`` + strict markers break its
stats phase). ``[tool.mutmut].source_paths`` already lists these files, so a
full mutmut sweep can replace this once that integration is reconciled.

Run:  ``uv run python scripts/mutation_spine_sweep.py``  (from the repo root).
Exit 0 iff every mutation is killed. SAFETY: refuses to run if any target file
has uncommitted changes (the restore is ``git checkout``, which would discard
them).
"""

# ruff: noqa: S607 — trusted local dev tool; fixed git/uv argv, no shell, no user input.

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = "src/worthless/cli/commands/lock.py"
APP = "src/worthless/proxy/app.py"
SENT = "src/worthless/cli/sentinel.py"

FAST = [
    "tests/openclaw/test_lock_bind_confirmation.py",
    "tests/openclaw/test_trust_fix.py",
    "tests/openclaw/test_bind_confirmation_chaos.py",
    "tests/test_wrap_warn_degraded.py",
    "tests/test_proxy_bind_probe.py",
    "tests/cli/test_cli_status.py",
]

# (file, old, new, label). Each `old` must be UNIQUE in its file (asserted).
MUTATIONS = [
    (
        LOCK,
        "_coerce_counter(after_aliases.get(a)) <= _coerce_counter(before_aliases.get(a))",
        "_coerce_counter(after_aliases.get(a)) < _coerce_counter(before_aliases.get(a))",
        "classifier: not_routing  <=  ->  <",
    ),
    (
        LOCK,
        "    if delta < 0:\n        # Proxy bounced between the before/after reads",
        "    if delta > 0:\n        # Proxy bounced between the before/after reads",
        "classifier: restart guard  < 0  ->  > 0",
    ),
    (
        LOCK,
        "if len(not_routing) == len(aliases):",
        "if len(not_routing) != len(aliases):",
        "classifier: all-stale  ==  ->  !=",
    ),
    (
        LOCK,
        'reason == "unrecognized_not_adopted"',
        'reason != "unrecognized_not_adopted"',
        "finaliser: adoption_skipped  ==  ->  !=",
    ),
    (
        LOCK,
        'bind_failed = bind_confirmation["status"] == "fail"',
        'bind_failed = bind_confirmation["status"] != "fail"',
        "finaliser: bind_failed  ==  ->  !=",
    ),
    (
        LOCK,
        "degraded = bind_failed or adoption_skipped",
        "degraded = bind_failed and adoption_skipped",
        "finaliser: degraded  or  ->  and",
    ),
    (
        SENT,
        'sentinel.get("status") == "partial" and sentinel.get("openclaw") == "failed"',
        'sentinel.get("status") == "partial" or sentinel.get("openclaw") == "failed"',
        "is_partial:  and  ->  or",
    ),
    (
        APP,
        "if alias in per_alias or len(per_alias) < 256:",
        "if alias in per_alias or len(per_alias) <= 256:",
        "proxy cap:  < 256  ->  <= 256",
    ),
]


def _dirty(rel: str) -> bool:
    return subprocess.run(["git", "diff", "--quiet", "--", rel], cwd=ROOT).returncode != 0


def _run_fast() -> int:
    return subprocess.run(
        [
            "uv",
            "run",
            "pytest",
            *FAST,
            "-x",
            "-q",
            "-p",
            "no:benchmark",
            "-m",
            "not docker and not playwright",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    ).returncode


def main() -> int:
    dirty = sorted({rel for rel, *_ in MUTATIONS if _dirty(rel)})
    if dirty:
        print(f"ABORT: uncommitted changes in {dirty}; commit or stash first.")
        return 2

    results = []
    for rel, old, new, label in MUTATIONS:
        path = ROOT / rel
        src = path.read_text()
        if src.count(old) != 1:
            results.append((label, f"BAD-ANCHOR({src.count(old)})"))
            print(f"BAD-ANCHOR({src.count(old)}) {label}")
            continue
        path.write_text(src.replace(old, new, 1))
        try:
            rc = _run_fast()
        finally:
            subprocess.run(["git", "checkout", "--", rel], cwd=ROOT, check=True)
        status = "KILLED" if rc != 0 else "SURVIVED"
        results.append((label, status))
        print(f"{status:9} {label}")

    bad = [lbl for lbl, s in results if s != "KILLED"]
    print(f"\n=== {len(results) - len(bad)}/{len(results)} mutations KILLED ===")
    if bad:
        print("NOT killed / issues:", bad)
        return 1
    print("0 survivors on the honesty/bind spine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

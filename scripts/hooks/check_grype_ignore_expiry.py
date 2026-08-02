#!/usr/bin/env python3
"""Enforce the expiry contract on .grype.yaml ignore rules.

Grype does NOT support an `expiry` field. Its IgnoreRule schema silently drops
unknown keys, so an entry written as

    - vulnerability: CVE-2026-11940
      expiry: "2020-01-01"        # five years ago

still suppresses the finding. Measured 2026-08-01 against grype 0.114.0: an
expiry five years in the past changed nothing, exit stayed 0.

That makes every "time-boxed" ignore permanent and silent, which is the
opposite of what .grype.yaml's own header promises. This hook is the mechanism
that makes the promise real: it fails once an ignore is past its date, so the
suppression has to be re-argued rather than quietly inherited.

Exit 0 = every ignore is dated and current. Exit 1 = something needs re-checking.
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]

# Every repo-root config grype auto-discovers. Verified with `grype config
# locations` (grype 0.114.0): it reads BOTH of these, in this order, and
# anchore/scan-action passes no explicit --config, so both are live in CI.
# Checking only .grype.yaml left .grype/config.yaml as a silent hiding place
# for undated suppressions.
CONFIGS = (REPO / ".grype.yaml", REPO / ".grype" / "config.yaml")


def check(config: Path, today: dt.date) -> list[str]:
    """Return one problem string per bad ignore rule. Empty list = all good."""
    if not config.exists():
        return [f"{config.name} is missing — the scan has no ignore policy to enforce."]

    data = yaml.safe_load(config.read_text()) or {}
    rules = data.get("ignore") or []
    if not rules:
        return []

    where = config.name if config.parent == REPO else f"{config.parent.name}/{config.name}"
    problems: list[str] = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            problems.append(f"{where}: ignore entry {i} is {type(rule).__name__}, not a mapping.")
            continue

        vuln = rule.get("vulnerability")
        if not vuln:
            # No CVE id means the rule matches on package/type alone, silencing
            # a whole class of findings. An expiry date cannot make that safe.
            problems.append(
                f"{where}: ignore entry {i} has no `vulnerability` id — it would "
                f"suppress by package match alone ({rule!r}). Name the CVE."
            )
            continue
        vuln = f"{where}: {vuln}"
        raw = rule.get("expiry")

        if raw is None:
            problems.append(
                f"{vuln}: no `expiry`. Every ignore must be time-boxed — an "
                f"undated suppression never gets revisited."
            )
            continue

        # yaml may hand back a date already, or a quoted string.
        if isinstance(raw, dt.datetime):
            expiry = raw.date()
        elif isinstance(raw, dt.date):
            expiry = raw
        else:
            try:
                expiry = dt.date.fromisoformat(str(raw).strip())
            except ValueError:
                problems.append(f"{vuln}: expiry {raw!r} is not an ISO date (YYYY-MM-DD).")
                continue

        if expiry < today:
            days = (today - expiry).days
            problems.append(
                f"{vuln}: expired {days} day(s) ago on {expiry.isoformat()}. "
                f"Re-measure the upstream fix status, then either drop the ignore "
                f"or extend it with a fresh reason — do not extend it blind."
            )

    return problems


def check_all(configs: tuple[Path, ...], today: dt.date) -> list[str]:
    """Check every grype config that exists. At least one must.

    A missing secondary config is fine — a missing primary one is not, and is
    reported by check() itself.
    """
    present = [c for c in configs if c.exists()]
    if not present:
        return [f"none of {[c.name for c in configs]} exist — no ignore policy to enforce."]
    return [p for c in present for p in check(c, today)]


def main() -> int:
    problems = check_all(CONFIGS, dt.date.today())
    if not problems:
        return 0

    print("Grype ignore rules need attention:\n", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        "\nNote: grype itself does not honour `expiry` — it drops unknown keys. "
        "This hook is the only thing enforcing it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

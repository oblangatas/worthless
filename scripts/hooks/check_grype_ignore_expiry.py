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


# How long before expiry to start warning. The window has to be long enough to
# re-measure an upstream fix without panic, short enough that the warning still
# means something when it appears.
WARN_DAYS = 14

# grype matches `package.name` as a LITERAL string — until the name contains a
# regex metacharacter, at which point the whole name becomes a full-match
# regex and every `.` in it turns into a wildcard. Measured on grype 0.114.0:
# a bare `urllib.` does NOT match `urllib3`, but `urllib.|zzzz` DOES.
#
# `.` is deliberately absent from this set. Dotted package names are ordinary
# (`backports.tarfile`, `gopkg.in/yaml.v2`) and inert on their own; flagging
# them would be noise. It is the OTHER metacharacters that arm the dots.
REGEX_ACTIVATORS = frozenset("*?+[](){}^$|\\")


def check(config: Path, today: dt.date, warnings: list[str] | None = None) -> list[str]:
    """Return one problem string per bad ignore rule. Empty list = all good.

    Caller guarantees the file exists — check_all() filters first.

    ponytail: warnings ride an optional out-param rather than a second return
    value, so every existing caller and test keeps working unchanged. A
    warning is never a problem — it must not affect the exit code.
    """
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

        # A package name that is secretly a regex suppresses more than it says.
        pkg = rule.get("package")
        name = (pkg or {}).get("name") if isinstance(pkg, dict) else None
        if name:
            armed = sorted(set(str(name)) & REGEX_ACTIVATORS)
            if armed:
                problems.append(
                    f"{vuln}: package name {name!r} contains {''.join(armed)!r}, which makes "
                    f"grype treat the whole name as a full-match regex — every `.` in it "
                    f"becomes a wildcard and the ignore silences packages it never named. "
                    f"Use a literal name, or split into one entry per package."
                )

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
        elif warnings is not None and (expiry - today).days <= WARN_DAYS:
            left = (expiry - today).days
            when = "expires today" if left == 0 else f"expires in {left} day(s)"
            warnings.append(
                f"{vuln}: {when}, on {expiry.isoformat()}. Re-measure NOW, while this "
                f"is still a notice. Once it lapses it blocks every commit in the repo, "
                f"and the cheapest way out of that is a blind date bump."
            )

    return problems


def check_all(
    configs: tuple[Path, ...], today: dt.date, warnings: list[str] | None = None
) -> list[str]:
    """Check every grype config that exists. At least one must.

    Either location alone is legitimate — grype reads both, so a repo that
    keeps all its ignores in .grype/config.yaml is fine. What is NOT fine is
    neither existing, which would mean the scan has no ignore policy at all
    and this gate has nothing to enforce.
    """
    present = [c for c in configs if c.exists()]
    if not present:
        return [f"none of {[c.name for c in configs]} exist — no ignore policy to enforce."]
    return [p for c in present for p in check(c, today, warnings)]


def main() -> int:
    warnings: list[str] = []
    problems = check_all(CONFIGS, dt.date.today(), warnings)

    # Warnings print FIRST so a real failure stays the last thing on screen —
    # that is the line people actually read.
    if warnings:
        print(
            f"NOTICE: {len(warnings)} grype ignore(s) expire within {WARN_DAYS} days. "
            f"Not a failure — this commit proceeds.\n",
            file=sys.stderr,
        )
        for w in warnings:
            print(f"  ~ {w}", file=sys.stderr)
        print("", file=sys.stderr)

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

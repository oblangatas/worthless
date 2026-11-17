#!/usr/bin/env python3
"""Run `npm audit` and let through only argued, dated, still-unfixable advisories.

Both npm audit jobs were bare `npm audit`, with no way to suppress anything.
That held until GHSA-fc5q-39xc-vjpf (picomatch ReDoS) was widened on
2026-11-17 to every published version, with no fixed release to take, which
turned the required "npm audit (worker)" check red on every PR (WOR-1156).

A waiver in .npm-audit-waivers.json covers ONE advisory on ONE package in the
named scopes, and stops covering it the moment any of these is true:

  - the date passes (the `expires` day itself still counts);
  - the package publishes any version after `last_release_seen`, which is
    the direct test for "a fix shipped". The audit's own signals miss it:
    GitHub can leave the advisory range as `<=4.0.7` after 4.0.8 ships, and
    npm's `fixAvailable` reports only a breaking downgrade whenever an older
    copy (the docs tree's picomatch 2.x) can't move. That is exactly how an
    earlier allowlist hid the sharp fix (beads worthless-kzfq);
  - npm offers a non-breaking fix on the package's own record;
  - the advisory's range, severity or package no longer match the waiver.

It also fails closed on anything it can't fully read: an npm error, a report
version other than 2, totals that disagree, or an affected package that doesn't
trace back to a waived advisory. And it fails on a waiver that matches nothing,
so the PR that takes the fix also removes the waiver.

Exit 0 = every advisory is waived and every waiver is live and used.
Exit 1 = something needs a person.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WAIVERS = REPO / ".npm-audit-waivers.json"

SCOPES = ("worker", "docs")

# Same warning window as check_grype_ignore_expiry.py.
WARN_DAYS = 14
# Not a grype convention: a cap of our own, so a renewal is a fresh decision
# (a council cycle) rather than one long date.
MAX_DAYS = 45

FIELDS = (
    "advisory",
    "package",
    "range",
    "severity",
    "scopes",
    "expires",
    "last_release_seen",
    "ticket",
    "reason",
)

ADVISORY_URL = re.compile(r"^https://github\.com/advisories/(GHSA(?:-[0-9a-z]{4}){3})$")
# GitHub's "no patched version exists" form, exactly as npm prints it. A `<X`
# range already encodes a fix, which is the kzfq shape: never waivable.
NO_FIX_RANGE = re.compile(r"^<=\d+\.\d+\.\d+$")


class AuditError(Exception):
    """npm's output can't be trusted as an audit report."""


@dataclass
class Result:
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    waived: list[dict] = field(default_factory=list)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    if dupes:
        raise ValueError(f"duplicate key(s) {dupes}")
    return dict(pairs)


def load_waivers(path: Path) -> list[dict]:
    data = json.loads(path.read_text(), object_pairs_hook=_reject_duplicates)
    if (
        not isinstance(data, dict)
        or set(data) != {"waivers"}
        or not isinstance(data["waivers"], list)
    ):
        raise ValueError(f'{path.name} must be {{"waivers": [...]}} and nothing else')
    return data["waivers"]


def _date(raw: object) -> dt.date | None:
    if not isinstance(raw, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        return None


def _instant(raw: object) -> dt.datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def waiver_shape_problems(w: object) -> list[str]:
    """Problems with a waiver on its own, before any date or report."""
    if not isinstance(w, dict):
        return [f"waiver {w!r} is not an object"]
    name = w.get("advisory", "<no advisory>")
    problems = [f"{name}: missing field '{f}'" for f in FIELDS if f not in w]
    problems += [f"{name}: unknown field '{f}'" for f in sorted(set(w) - set(FIELDS))]
    if problems:
        return problems
    for f in ("advisory", "package", "range", "severity", "ticket", "reason"):
        if not isinstance(w[f], str) or not w[f].strip():
            problems.append(f"{name}: '{f}' must be a non-empty string")
    if problems:
        return problems
    if not re.fullmatch(r"GHSA(?:-[0-9a-z]{4}){3}", w["advisory"]):
        problems.append(f"{name}: 'advisory' must be a GHSA id")
    if not NO_FIX_RANGE.match(w["range"]):
        problems.append(
            f"{name}: range {w['range']!r} is not of the form '<=X.Y.Z' (copy it from "
            "`npm audit --json`). A '<X' range means a fixed version exists: take it"
        )
    scopes = w["scopes"]
    if not isinstance(scopes, list) or not scopes or any(s not in SCOPES for s in scopes):
        problems.append(f"{name}: 'scopes' must be a non-empty list drawn from {list(SCOPES)}")
    if _date(w["expires"]) is None:
        problems.append(f"{name}: 'expires' must be a YYYY-MM-DD date")
    if _instant(w["last_release_seen"]) is None:
        problems.append(f"{name}: 'last_release_seen' must be an ISO timestamp with a timezone")
    return problems


def parse_report(text: str) -> dict:
    try:
        report = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(f"npm audit printed something that is not JSON: {text[:200]!r}") from exc
    return report


def _report_problems(report: object) -> list[str]:
    if not isinstance(report, dict):
        return ["npm audit output is not a JSON object"]
    if "error" in report:
        return [f"npm audit reported an error: {report['error']!r} (registry outage? rerun)"]
    if report.get("auditReportVersion") != 2:
        return [
            f"unsupported auditReportVersion {report.get('auditReportVersion')!r}; "
            "this gate reads 2"
        ]
    vulns = report.get("vulnerabilities")
    total = (report.get("metadata") or {}).get("vulnerabilities", {}).get("total")
    if not isinstance(vulns, dict) or not isinstance(total, int):
        return ["npm audit output lacks 'vulnerabilities' or 'metadata.vulnerabilities.total'"]
    if total != len(vulns):
        return [f"metadata counts {total} vulnerable packages but the report lists {len(vulns)}"]
    return []


def _covers(w: dict, adv: dict, scope: str) -> bool:
    return (
        scope in w["scopes"]
        and adv["id"] == w["advisory"]
        and adv["name"] == w["package"]
        and adv["range"] == w["range"]
        and adv["severity"] == w["severity"]
    )


def evaluate(
    report: object, waivers: list, *, scope: str, today: dt.date, releases: dict
) -> Result:
    """Decide the audit. `releases` maps package -> npm's `time` object."""
    result = Result()
    problems = result.problems

    live: list[dict] = []
    for w in waivers:
        shape = waiver_shape_problems(w)
        if shape:
            problems.extend(shape)
            continue
        if scope not in w["scopes"]:
            continue
        expires = _date(w["expires"])
        if expires is None:  # unreachable: waiver_shape_problems checked it
            continue
        days = (expires - today).days
        if days < 0:
            problems.append(
                f"{w['advisory']}: waiver expired on {w['expires']}. "
                "Re-argue it with the council or take the fix"
            )
            continue
        if days > MAX_DAYS:
            problems.append(
                f"{w['advisory']}: expires in {days} days; waivers are capped at {MAX_DAYS} days"
            )
            continue
        if days <= WARN_DAYS:
            result.warnings.append(
                f"{w['advisory']}: waiver expires {w['expires']} ({days} days left)"
            )
        problems.extend(_release_problems(w, releases.get(w["package"])))
        live.append(w)

    report_problems = _report_problems(report)
    if report_problems or not isinstance(report, dict):
        return Result(problems=problems + report_problems, warnings=result.warnings)
    vulns = report["vulnerabilities"]

    used: set[int] = set()
    rooted: set[str] = set()
    flagged: set[str] = set()

    def flag(pkg: str, problem: str) -> None:
        problems.append(problem)
        flagged.add(pkg)

    for pkg, rec in vulns.items():
        via = rec.get("via") if isinstance(rec, dict) else None
        if not isinstance(via, list) or not via:
            flag(pkg, f"{pkg}: report entry has no 'via' causes")
            continue
        for item in via:
            if isinstance(item, str):
                if item not in vulns:
                    flag(pkg, f"{pkg}: caused by {item!r}, which the report does not list")
                continue
            if not isinstance(item, dict):
                flag(pkg, f"{pkg}: unreadable cause {item!r}")
                continue
            match = ADVISORY_URL.match(str(item.get("url", "")))
            if not match:
                flag(pkg, f"{pkg}: advisory without a GitHub advisory id: {item.get('url')!r}")
                continue
            adv = {
                "id": match.group(1),
                "name": item.get("name"),
                "range": item.get("range"),
                "severity": item.get("severity"),
            }
            hit = next((i for i, w in enumerate(live) if _covers(w, adv, scope)), None)
            if hit is None:
                flag(
                    pkg,
                    f"{adv['id']} on {adv['name']} (range {adv['range']}, {adv['severity']}) "
                    f"has no live waiver for scope '{scope}'",
                )
                continue
            fix = (vulns.get(adv["name"]) or {}).get("fixAvailable")
            if fix is True or (isinstance(fix, dict) and fix.get("isSemVerMajor") is False):
                flag(
                    pkg,
                    f"{adv['id']}: npm offers a non-breaking fix ({fix!r}). "
                    "Take it and drop the waiver",
                )
                continue
            used.add(hit)
            rooted.add(pkg)

    # Every affected package must trace back to a waived advisory. Effects
    # carry only package-name causes; their own `fixAvailable` is ignored,
    # because npm marks vite `true` although picomatch is its only cause.
    changed = True
    while changed:
        changed = False
        for pkg, rec in vulns.items():
            if pkg in rooted or not isinstance(rec, dict):
                continue
            if any(isinstance(v, str) and v in rooted for v in rec.get("via") or []):
                rooted.add(pkg)
                changed = True
    for pkg in vulns:
        if pkg not in rooted and pkg not in flagged:
            problems.append(f"{pkg}: does not trace back to any waived advisory")

    for i, w in enumerate(live):
        if i not in used:
            problems.append(
                f"{w['advisory']}: waiver matches nothing in the '{scope}' audit. "
                "Remove it (or drop this scope) in the PR that took the fix"
            )
        else:
            result.waived.append(w)
    return result


def _release_problems(w: dict, times: object) -> list[str]:
    """`last_release_seen` must be exactly the package's newest release.

    Any later release ends the waiver ("a fix shipped"). Requiring an exact
    match, not just "nothing later", stops a renewal from parking the value in
    the future, which would switch this check off.
    """
    if not isinstance(times, dict) or not times:
        return [f"{w['advisory']}: could not read {w['package']}'s release history from npm"]
    seen = _instant(w["last_release_seen"])
    problems = []
    published: list[tuple[dt.datetime, str]] = []
    for version, raw in sorted(times.items()):
        if version in ("created", "modified"):
            continue
        when = _instant(raw)
        if when is None:
            problems.append(f"{w['advisory']}: {w['package']} {version} has no readable date")
            continue
        published.append((when, version))
        if seen is not None and when > seen:
            problems.append(
                f"{w['advisory']}: {w['package']} {version} was published {raw}, after the "
                "waiver's last_release_seen. Check whether it fixes the advisory, then take it "
                "or re-argue"
            )
    if not published:
        return problems + [f"{w['advisory']}: {w['package']} has no releases on npm"]
    newest, version = max(published)
    if seen != newest:
        problems.append(
            f"{w['advisory']}: last_release_seen {w['last_release_seen']} is not the newest "
            f"{w['package']} release ({version}, {newest.isoformat()})"
        )
    return problems


def _npm_env() -> dict:
    # An inherited NPM_CONFIG_OMIT=dev would shrink the worker audit to its one
    # prod package and pass. Nothing from the environment shapes this audit.
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("NPM_CONFIG_")}


def run_npm_audit(tree: Path) -> dict:
    cmd = ["npm", "audit", "--json", "--include=dev", "--include=optional", "--include=peer"]
    try:
        proc = subprocess.run(
            cmd, cwd=tree, env=_npm_env(), capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        raise AuditError("npm is not installed") from exc
    if proc.returncode not in (0, 1):
        raise AuditError(f"npm audit exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    report = parse_report(proc.stdout)
    vulns = report.get("vulnerabilities") if isinstance(report, dict) else None
    # An error report is judged (and failed) by evaluate(); otherwise npm's
    # exit code and its findings must agree.
    if isinstance(vulns, dict) and "error" not in report and (proc.returncode == 1) != bool(vulns):
        raise AuditError(
            f"npm audit exited {proc.returncode} but listed {len(vulns)} vulnerable packages"
        )
    return report


def npm_release_times(package: str) -> dict:
    try:
        proc = subprocess.run(
            ["npm", "view", package, "time", "--json"],  # noqa: S607 — npm from PATH, set up by CI
            env=_npm_env(),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AuditError("npm is not installed") from exc
    if proc.returncode != 0:
        raise AuditError(f"npm view {package} time failed: {proc.stderr.strip()[:300]}")
    times = json.loads(proc.stdout)
    if not isinstance(times, dict):
        raise AuditError(f"npm view {package} time returned {type(times).__name__}")
    return times


def _today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="npm audit, with dated self-ending waivers")
    parser.add_argument("--scope", required=True, choices=SCOPES)
    parser.add_argument(
        "--dir", required=True, type=Path, help="the npm tree to audit, relative to the repo root"
    )
    args = parser.parse_args(argv)

    try:
        waivers = load_waivers(WAIVERS)
        packages = {
            w["package"]
            for w in waivers
            if isinstance(w, dict) and args.scope in (w.get("scopes") or [])
        }
        releases = {p: npm_release_times(p) for p in sorted(packages)}
        report = run_npm_audit(REPO / args.dir)
    except (AuditError, ValueError, OSError) as exc:
        print(f"npm audit gate: {exc}", file=sys.stderr)
        return 1

    result = evaluate(
        report,
        waivers,
        scope=args.scope,
        today=_today(),
        releases=releases,
    )
    for w in result.waived:
        print(
            f"waived {w['advisory']} on {w['package']} until {w['expires']} "
            f"({w['ticket']}): {w['reason']}"
        )
    for warning in result.warnings:
        # `::warning::` lifts it into the PR's check summary; a green job's log
        # is never read.
        print(f"::warning::{warning}")
    if result.problems:
        print(f"npm audit ({args.scope}) FAILED:", file=sys.stderr)
        for p in result.problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    total = report["metadata"]["vulnerabilities"]["total"]
    print(
        f"npm audit ({args.scope}): {total} vulnerable package(s), all traced to live waivers"
        if total
        else f"npm audit ({args.scope}): clean"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

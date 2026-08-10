#!/usr/bin/env python3
"""Fail on High/Critical findings grype cannot map to a fixed version.

The container gate runs with ``only-fixed: true``, which keeps only findings
whose ``fix.state`` is ``fixed``. Everything else is dropped — including
``unknown``, which is what a record with no version data looks like.

That is not a severity filter, and it is not bounded. Measured 2026-08-10 on
the shipped image: THREE CRITICALS sit in that blind spot right now
(CVE-2026-12087, CVE-2026-13221, CVE-2026-57433, all perl-base) and the gate
exits 0. CVE-2026-4360 evades it too, despite having a released upstream fix,
because its record carries ``versionConstraint: "none (unknown)"``.

So ``only-fixed: true`` is really an ignore rule with no CVE id, no reason, no
ticket and no expiry, hiding in workflow YAML where
check_grype_ignore_expiry.py cannot see it. That file rejects exactly this
shape when it appears in .grype.yaml — an ignore with no ``vulnerability`` id,
because it "would suppress by package match alone". This hook closes the same
hole on the other side.

WHY NOT JUST DROP only-fixed: the image carries 47 Medium and 16 High
``wont-fix`` findings from Debian. ``wont-fix`` is a DIFFERENT state from
``unknown``/``not-fixed`` — the vendor looked and declined. Gating on the
latter two catches the real blind spot without dragging in that noise.

Exit 0 = nothing unmapped above the bar, or everything that is has a dated
argument. Exit 1 = something needs arguing or fixing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]

# Both locations grype auto-discovers, same as check_grype_ignore_expiry.py.
CONFIGS = (REPO / ".grype.yaml", REPO / ".grype" / "config.yaml")

# Severities that gate. Medium/Low unmapped findings are deliberately NOT
# gated: the Debian base carries too many for that to be actionable, and
# treating them as blocking would train people to rubber-stamp suppressions.
GATING_SEVERITIES = {"Critical", "High"}

# Fix states that mean "grype has no fixed version for this".
#   unknown / ""  -> no version data at all (the CVE-2026-4360 shape)
#   not-fixed     -> upstream has not fixed it
#   wont-fix      -> the vendor looked and declined. NOT gated: that is a
#                    considered decision by someone closer to the package.
UNMAPPED_STATES = {"unknown", "not-fixed", ""}


def argued_cves(configs: tuple[Path, ...]) -> set[str]:
    """CVE ids that already carry a dated argument in a grype config.

    Only the id is read here. Whether the date is still valid is
    check_grype_ignore_expiry.py's job — duplicating it would mean two places
    to fix when the contract changes.
    """
    argued: set[str] = set()
    for config in configs:
        if not config.exists():
            continue
        data = yaml.safe_load(config.read_text()) or {}
        for rule in data.get("ignore") or []:
            if isinstance(rule, dict) and rule.get("vulnerability"):
                argued.add(str(rule["vulnerability"]))
    return argued


def unmapped_findings(report: dict, argued: set[str]) -> list[tuple[str, str, str, str]]:
    """Return (severity, cve, package, state) for each gating finding.

    Deduplicated by (cve, package): grype reports one match per matching
    artifact, so a single CVE against a source package plus its binaries would
    otherwise be reported several times over.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str, str, str]] = []
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        severity = vuln.get("severity") or "Unknown"
        if severity not in GATING_SEVERITIES:
            continue

        state = (vuln.get("fix") or {}).get("state") or ""
        if state not in UNMAPPED_STATES:
            continue

        cve = vuln.get("id") or "?"
        if cve in argued:
            continue

        package = (match.get("artifact") or {}).get("name") or "?"
        if (cve, package) in seen:
            continue
        seen.add((cve, package))
        out.append((severity, cve, package, state or "unknown"))

    # Critical before High, then stable by id so output does not churn.
    out.sort(key=lambda row: (row[0] != "Critical", row[1]))
    return out


def summary(report: dict) -> str:
    """One line per (severity, fix state) — what the image is carrying.

    Replaces the raw table this step used to print. The table listed every
    match, which for this image is ~181 rows; nobody reads that on a green
    job. The shape is what tells you whether something changed.
    """
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}
    counts: dict[tuple[str, str], int] = {}
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        key = (vuln.get("severity") or "Unknown", (vuln.get("fix") or {}).get("state") or "unknown")
        counts[key] = counts.get(key, 0) + 1

    lines = ["Container findings by severity and fix status:"]
    for (severity, state), count in sorted(
        counts.items(), key=lambda kv: (rank.get(kv[0][0], 9), kv[0][1])
    ):
        lines.append(f"  {severity:<11} {state:<10} {count:>4}")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_grype_unmapped_findings.py <grype-report.json>", file=sys.stderr)
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"grype report not found: {report_path}", file=sys.stderr)
        return 2

    report = json.loads(report_path.read_text())

    # Print the carry summary either way. This step replaced a raw table that
    # nothing gated on; losing the visibility to gain the gate would be a bad
    # trade, and 181 rows nobody reads is worse than a shape anyone can scan.
    print(summary(report))

    findings = unmapped_findings(report, argued_cves(CONFIGS))

    if not findings:
        print("\nNo unmapped High/Critical findings. Every one is fixed, wont-fix, or argued.")
        return 0

    print(
        f"\n{len(findings)} High/Critical finding(s) that the fixed-only gate cannot see:\n",
        file=sys.stderr,
    )
    for severity, cve, package, state in findings:
        print(f"  {severity:<9} {cve:<18} {package:<16} fix={state}", file=sys.stderr)
    print(
        "\nGrype has no fixed version for these, so `only-fixed: true` drops them and\n"
        "the build would otherwise pass. Either bump the package, or add a dated\n"
        "entry to .grype.yaml explaining why it is not reachable here.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

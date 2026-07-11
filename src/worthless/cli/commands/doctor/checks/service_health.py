"""WOR-726: service_health — service-specific breakage the other checks miss.

Synthesized from a reliability + security premortem on the launchd/systemd
proxy service. Plain ``status`` proves the proxy answers ``/healthz``; it does
NOT prove the *right* binary is running, on the *right* port, for a home that
still exists, without a stale legacy label, and (on Linux) with linger enabled
so it survives logout. Each of those is a way the service silently degrades
weeks after install with nobody watching.

Read-only: no ``--fix``. Every finding names its own remediation because the
correct repair (re-install, stop a foreign process, enable linger) depends on
the user's intent.

Scope — what this does NOT do (be honest, do not oversell). This is a
hygiene + naive-tamper *detector*, not a defense against a hostile service:

* It only inspects worthless's own unit (``sh.worthless.proxy`` + the legacy
  label). An attacker who can write to the LaunchAgents / systemd-user dir can
  install a service under *any other* label and this check is blind to it.
* The binary check compares the launch-binary *path*, not its hash — a trojaned
  binary swapped in at the expected path is not detected here.
* It is passive: it only helps if the user runs ``worthless doctor``. It does
  not prevent tampering, only surfaces the shapes it recognizes.

Closing the remaining execution vectors (launchd ``Program`` key, systemd
``ExecStartPre``/``LD_PRELOAD``/``DYLD_INSERT_LIBRARIES``) is tracked as a
follow-up; even then the label-scope limit above stands.
"""

from __future__ import annotations

import re
from pathlib import Path

from worthless.cli.commands.service import launchd, systemd
from worthless.cli.commands.service._common import (
    _worthless_home_paths_in_unit,
    current_platform_backend_name,
    resolve_worthless_binary,
)
from worthless.cli.commands.service.templates import LEGACY_LAUNCHD_LABEL
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.errors import WorthlessError

check_id = "service_health"

_LAUNCHD_BINARY_RE = re.compile(
    r"<key>ProgramArguments</key>\s*<array>\s*<string>([^<]+)</string>",
    re.DOTALL,
)
_SYSTEMD_BINARY_RE = re.compile(r"ExecStart=(\S+)")


def _binary_in_unit(content: str, backend_name: str) -> str | None:
    pattern = _LAUNCHD_BINARY_RE if backend_name == "launchd" else _SYSTEMD_BINARY_RE
    match = pattern.search(content)
    return match.group(1) if match else None


# --- pure sub-checks (each returns a finding dict or None) --------------------


def _binary_mismatch(content: str, backend_name: str, expected: Path) -> dict | None:
    raw = _binary_in_unit(content, backend_name)
    if raw is None:
        # Our own units ALWAYS carry ExecStart / ProgramArguments. If we can't
        # find the launch-binary field, the unit is tampered or an unrecognized
        # shape — fail CLOSED with a finding, never a silent OK. (Security
        # review: a regex-evading unit must not read as healthy.)
        return {
            "kind": "unverifiable_unit",
            "remediation": "The service unit is in a shape worthless can't verify "
            "(the launch-binary field is missing or malformed). Re-run "
            "`worthless service install`, or inspect the unit by hand.",
        }
    try:
        installed = Path(raw).resolve()
        want = expected.resolve()
    except OSError:
        return None
    if installed == want:
        return None
    return {
        "kind": "binary_mismatch",
        "installed_binary": str(installed),
        "expected_binary": str(want),
        "remediation": "Re-run `worthless service install` to point the service at "
        "the current binary. If you didn't install this unit, treat it as hostile.",
    }


def _orphan_home_findings(content: str) -> list[dict]:
    findings: list[dict] = []
    for raw in _worthless_home_paths_in_unit(content):
        if not Path(raw).exists():
            findings.append(
                {
                    "kind": "orphan_home",
                    "worthless_home": raw,
                    "remediation": "The service points at a WORTHLESS_HOME that no "
                    "longer exists — it may still serve stale key material. Run "
                    "`worthless service uninstall` to tear it down.",
                }
            )
    return findings


def _legacy_label_finding(legacy_plist: Path) -> dict | None:
    if not legacy_plist.is_file():
        return None
    return {
        "kind": "legacy_label",
        "legacy_plist": str(legacy_plist),
        "remediation": "A pre-rename `dev.worthless.proxy` LaunchAgent is still "
        "present. Re-run `worthless service install` to migrate it, or remove it "
        "manually.",
    }


def _linger_finding(linger_enabled: bool) -> dict | None:
    if linger_enabled:
        return None
    return {
        "kind": "linger_off",
        "remediation": "systemd linger is off — the proxy will stop when you log "
        "out. Run `loginctl enable-linger $USER`, or re-run "
        "`worthless service install`.",
    }


# --- thin platform wiring (patchable in tests) --------------------------------


def _installed_unit_path(backend_name: str) -> Path:
    if backend_name == "launchd":
        return launchd.plist_path()
    return systemd.unit_path()


def _linger_ok_if_systemd(backend_name: str) -> bool:
    if backend_name != "systemd":
        return True  # not applicable on launchd
    return systemd._linger_enabled()


def _skip(reason: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status="ok",
        findings=[],
        summary=reason,
        fixable=False,
        fixed=[],
        skipped_reason=reason,
    )


def run(ctx: CheckContext) -> CheckResult:
    try:
        backend_name = current_platform_backend_name()
    except WorthlessError:
        return _skip("`worthless service` is not supported on this platform.")

    unit_path = _installed_unit_path(backend_name)
    if not unit_path.is_file():
        return _skip("No worthless service is installed.")

    try:
        content = unit_path.read_text()
    except OSError:
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[{"kind": "unit_unreadable", "unit_path": str(unit_path)}],
            summary=f"Cannot read the service unit at {unit_path}.",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    findings: list[dict] = []

    try:
        expected_binary = resolve_worthless_binary()
        binary_finding = _binary_mismatch(content, backend_name, expected_binary)
        if binary_finding:
            findings.append(binary_finding)
    except WorthlessError:
        pass  # can't resolve our own binary — a different check owns that

    findings.extend(_orphan_home_findings(content))

    if backend_name == "launchd":
        legacy_plist = unit_path.parent / f"{LEGACY_LAUNCHD_LABEL}.plist"
        legacy_finding = _legacy_label_finding(legacy_plist)
        if legacy_finding:
            findings.append(legacy_finding)

    linger_finding = _linger_finding(_linger_ok_if_systemd(backend_name))
    if linger_finding:
        findings.append(linger_finding)

    status = "warn" if findings else "ok"
    summary = "Service healthy." if not findings else f"{len(findings)} service issue(s) found."
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )

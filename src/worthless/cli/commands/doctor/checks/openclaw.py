"""WOR-464 / WOR-515: OpenClaw integration drift check + secrets audit gate.

JSON-mode reporter for:
- Integration drift (skill install, provider enrollment) — WOR-464
- Audit gate state: plaintext keys (exit-73 state) and binary failures
  (exit-87 state) — WOR-515 AC 10. Surfaces exactly what ``worthless lock``
  would reject, so users can remediate before attempting to lock.

``--fix`` is not yet wired here — repair requires a TTY
(``openclaw secrets configure`` prompts interactively per M0 findings).
"""

from __future__ import annotations

import asyncio
from typing import Literal

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.process import resolve_port
from worthless.openclaw import audit as _oc_audit
from worthless.openclaw import integration as _oc_integration

check_id = "openclaw"


def _audit_gate_findings() -> list[dict]:
    """Run the secrets audit gate and return doctor findings.

    Returns a list of finding dicts describing any exit-73 (plaintext) or
    exit-87 (subprocess failure) conditions that would block ``worthless lock``.
    Returns an empty list when the gate would pass.
    """
    try:
        openclaw_bin = _oc_audit.resolve_openclaw_bin()
    except _oc_audit.AuditGateError as exc:
        return [
            {
                "issue": (
                    f"openclaw binary unavailable (worthless lock would exit 87): {exc.reason}"
                ),
                "exit_code": 87,
                "remediation": (
                    "set WORTHLESS_OPENCLAW_BIN to the absolute path of the openclaw binary"
                ),
            }
        ]

    try:
        _, classification = _oc_audit.run_and_classify(openclaw_bin)
    except _oc_audit.AuditGateError as exc:
        return [
            {
                "issue": (
                    f"openclaw secrets audit failed (worthless lock would exit 87): {exc.reason}"
                ),
                "exit_code": 87,
                "remediation": "check that the openclaw daemon is running and retry",
            }
        ]

    findings: list[dict] = []

    for code in classification.unknown_codes:
        findings.append(
            {
                "issue": (
                    f"openclaw audit returned unknown finding code {code!r}"
                    f" (worthless lock would exit 87)"
                ),
                "exit_code": 87,
                "remediation": ("update worthless to a version that understands this finding code"),
            }
        )

    for blocking in classification.blocking:
        file_safe = _oc_audit.sanitise_for_message(blocking.file)
        path_safe = _oc_audit.sanitise_for_message(blocking.json_path)
        findings.append(
            {
                "issue": (
                    f"plaintext API key detected (worthless lock would exit 73): {path_safe}"
                ),
                "exit_code": 73,
                "file": file_safe,
                "json_path": path_safe,
                "remediation": ("run `openclaw secrets configure` to migrate keys to SecretRefs"),
            }
        )

    return findings


def run(ctx: CheckContext) -> CheckResult:
    from worthless.cli.commands.doctor import (
        _check_providers,
        _check_skill,
        is_orphan,
    )

    state = _oc_integration.detect()
    if not state.present:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="OpenClaw not installed.",
            fixable=True,
            fixed=[],
            skipped_reason="openclaw not present",
        )

    # Read-only here: ``--fix`` repair path is exclusively the text
    # runner's responsibility for v0.4.
    skill_issues, _fixed_items = _check_skill(state, fix=False, dry_run=ctx.dry_run)

    try:
        enrollments = asyncio.run(ctx.repo.list_enrollments())
    except Exception:  # noqa: BLE001
        enrollments = []
        skill_issues.append("could not read enrollment DB — provider check skipped")

    healthy = [e for e in enrollments if not is_orphan(e)]
    port = resolve_port(None)
    provider_issues = _check_providers(state, healthy, port=port)

    audit_findings = _audit_gate_findings()

    all_issues = skill_issues + provider_issues
    # Promote plain-string integration issues to the same structured shape as
    # audit_findings so all entries in findings[] have consistent keys.
    findings: list[dict] = [{"issue": s, "exit_code": None} for s in all_issues] + audit_findings

    has_error = any(f.get("exit_code") == 87 for f in audit_findings)
    status: Literal["ok", "warn", "error"]
    if has_error:
        status = "error"
    elif findings:
        status = "warn"
    else:
        status = "ok"

    # WOR-516: always surface the OpenClaw .bak recovery path so operators
    # know where to look if openclaw.json is damaged after a failed lock.
    # The note is low-signal when everything is healthy (status=ok) but
    # critical when a write-failed event appears in the findings list.
    recovery_note = {
        "issue": (
            "Recovery: if openclaw.json is damaged, restore from "
            "~/.openclaw/openclaw.json.bak "
            "(written by the openclaw daemon on each config change)"
        ),
        "exit_code": None,
    }

    summary = (
        "OpenClaw integration healthy."
        if not findings
        else f"{len(findings)} OpenClaw issue{'s' if len(findings) != 1 else ''}"
    )
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings + [recovery_note],
        summary=summary,
        fixable=True,
        fixed=[],
        skipped_reason=None,
    )

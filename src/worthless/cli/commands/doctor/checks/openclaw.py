"""WOR-464: OpenClaw integration drift check adapter.

JSON-mode reporter for the same drift the legacy ``_check_openclaw_section``
surfaces. JSON ``--fix`` is not yet wired here — the skill-reinstall path
stays exclusively in the text mode for v0.4 (it requires a workspace dir
that may not exist; ``--json`` mode should report the drift, not silently
repair it).
"""

from __future__ import annotations

import asyncio

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.process import resolve_port
from worthless.openclaw import integration as _oc_integration

check_id = "openclaw"


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

    all_issues = skill_issues + provider_issues
    findings = [{"issue": s} for s in all_issues]
    status = "ok" if not all_issues else "warn"
    summary = (
        "OpenClaw integration healthy."
        if not all_issues
        else f"{len(all_issues)} OpenClaw integration issue{'s' if len(all_issues) != 1 else ''}"
    )
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        fixable=True,
        fixed=[],
        skipped_reason=None,
    )

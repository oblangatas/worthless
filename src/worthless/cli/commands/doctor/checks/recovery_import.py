"""WOR-464: recovery-file import check (darwin-only).

Always runs (even without ``--fix``) because recovery is a one-way
idempotent operation: importing a ``<account>.recover`` file into the
local-scope keychain heals a sibling Mac. The check both detects AND
imports — there is no ``--fix``-gated mode.
"""

from __future__ import annotations

import sys

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult

check_id = "recovery_import"


def run(ctx: CheckContext) -> CheckResult:
    from worthless.cli.commands.doctor import (
        _import_recovery_files,
        _list_recovery_files,
    )

    if sys.platform != "darwin":
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="Recovery-file import is macOS-only.",
            fixable=False,
            fixed=[],
            skipped_reason="non-darwin platform",
        )

    files = _list_recovery_files(ctx.home)
    if not files:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="No recovery files awaiting import.",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    findings = [{"recovery_file": str(p)} for p in files]
    # Import is unconditional (not gated on --fix) — recovery is safe
    # and idempotent. JSON consumers see ``fixed`` populated even when
    # ``fix=False`` because the import already happened.
    imported = _import_recovery_files(files)
    fixed = [{"recovery_file": str(p)} for p in files[:imported]]
    return CheckResult(
        check_id=check_id,
        status="ok" if imported == len(files) else "warn",
        findings=findings,
        summary=f"Recovered {imported} key(s) from a sibling Mac.",
        fixable=False,
        fixed=fixed,
        skipped_reason=None,
    )

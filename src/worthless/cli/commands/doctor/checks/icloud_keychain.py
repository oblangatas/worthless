"""WOR-464: iCloud-synced keychain entry check (darwin-only).

Delegates to the legacy ``_list_synced_keychain_entries`` so the
platform/backend probe stays in one place. Non-darwin emits
``skipped_reason``.
"""

from __future__ import annotations

import sys

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult

check_id = "icloud_keychain"


def run(ctx: CheckContext) -> CheckResult:
    from worthless.cli.commands.doctor import _list_synced_keychain_entries

    if sys.platform != "darwin":
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="iCloud Keychain check is macOS-only.",
            fixable=True,
            fixed=[],
            skipped_reason="non-darwin platform",
        )

    synced = _list_synced_keychain_entries()
    findings = [{"keychain_account": u} for u in synced]
    status = "ok" if not synced else "warn"
    n = len(synced)
    summary = (
        "No iCloud-synced keychain entries."
        if n == 0
        else f"{n} Worthless key{'s' if n != 1 else ''} stored in iCloud Keychain"
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

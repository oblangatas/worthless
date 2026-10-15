"""WOR-958: keys a cut-off lock left in plain text.

``lock`` commits the DB, then rewrites ``.env``. A ``kill -9`` between the
two leaves the DB saying "locked" over the real key. Report only: ``lock``
re-locks it onto the stored shard. A purge here would drop sibling
enrollments, and a fresh split would break every other copy of shard A.
"""

from __future__ import annotations

import asyncio

from worthless.cli.commands.doctor.checks._helpers import load_enrollments
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.orphans import UNLOCKED_FIX_PHRASE, find_unlocked

check_id = "unlocked_keys"


def run(ctx: CheckContext) -> CheckResult:
    enrollments, err = load_enrollments(ctx, check_id)
    if err is not None:
        return err
    try:
        unlocked = asyncio.run(find_unlocked(ctx.repo, enrollments))
    except Exception as exc:  # noqa: BLE001 - SR-04 scrub
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary=f"unlocked-key check failed: {type(exc).__name__}",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    findings = [
        {
            "key_alias": e.key_alias,
            "var_name": e.var_name,
            "env_path": e.env_path,
            "remediation": f"run `{UNLOCKED_FIX_PHRASE} --env {e.env_path}`",
        }
        for e in unlocked
    ]
    n = len(findings)
    return CheckResult(
        check_id=check_id,
        status="warn" if findings else "ok",
        findings=findings,
        summary=(
            f"{n} key{'s' if n != 1 else ''} still in plain text (a lock was cut off); "
            f"run `{UNLOCKED_FIX_PHRASE}` on each .env."
            if findings
            else "No keys left in plain text by a cut-off lock."
        ),
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )

"""WOR-464: orphan-DB check adapter.

Delegates to the legacy ``_list_orphans`` helper in
``worthless.cli.commands.doctor`` so the discovery logic stays in one
place. Read-only here; the legacy ``_doctor_apply`` handles repair in
text mode. JSON ``--json --fix`` repair is wired in ``runner.py`` so
both modes share the same purge path.
"""

from __future__ import annotations

import asyncio
import itertools

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult

check_id = "orphan_db"


def _repair_orphans(ctx: CheckContext, orphans: list) -> list[dict]:
    from worthless.cli.commands.doctor import _purge_all

    purged = asyncio.run(_purge_all(orphans, ctx.repo, ctx.home.shard_a_dir))
    return [
        {"key_alias": e.key_alias, "env_path": e.env_path}
        for e in itertools.islice(orphans, purged)
    ]


def run(ctx: CheckContext) -> CheckResult:
    # Late import to avoid the package's __init__.py loading the registry
    # before legacy symbols (_list_orphans, etc.) are defined.
    from worthless.cli.commands.doctor import _list_orphans

    try:
        orphans = asyncio.run(_list_orphans(ctx.repo))
    except Exception as exc:  # noqa: BLE001 - SR-04 scrub
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary=f"orphan DB read failed: {type(exc).__name__}",
            fixable=True,
            fixed=[],
            skipped_reason=None,
        )

    n = len(orphans)
    findings = [
        {
            "key_alias": e.key_alias,
            "var_name": e.var_name,
            "env_path": e.env_path,
        }
        for e in orphans
    ]
    fixed: list[dict] = []
    status = "ok" if not orphans else "warn"

    if ctx.fix and orphans and not ctx.dry_run:
        try:
            fixed = _repair_orphans(ctx, orphans)
            if len(fixed) == n:
                status = "ok"
        except Exception as exc:  # noqa: BLE001
            return CheckResult(
                check_id=check_id,
                status="error",
                findings=findings,
                summary=f"orphan purge failed: {type(exc).__name__}",
                fixable=True,
                fixed=fixed,
                skipped_reason=None,
            )

    summary = (
        "No orphan enrollments found."
        if n == 0
        else f"{n} broken record{'s' if n != 1 else ''} (.env line deleted)"
    )
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )

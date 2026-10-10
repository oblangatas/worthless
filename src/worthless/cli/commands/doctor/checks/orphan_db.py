"""WOR-464: orphan-DB check adapter.

Delegates to the legacy ``_list_orphans`` helper in
``worthless.cli.commands.doctor`` so the discovery logic stays in one
place. Read-only here; the legacy ``_doctor_apply`` handles repair in
text mode. JSON ``--json --fix`` repair is wired in ``runner.py`` so
both modes share the same purge path.
"""

from __future__ import annotations

import asyncio

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.orphans import env_file_missing

check_id = "orphan_db"

# Per-finding advice for a key whose .env is missing. Set on the finding so
# the runner's generic orphan playbook ("This key is gone") never reaches it:
# that advice is false for a moved project, and following it destroys the key.
MOVED_REMEDIATION = (
    "This key is safe — only its `.env` is missing from where it was locked, "
    "usually because the project moved. Put the project back at that path, then "
    "run `worthless unlock`. `worthless doctor --fix` leaves it alone. If the "
    "project is gone for good, `worthless uninstall --force` removes Worthless "
    "and deletes this key with it."
)


def _repair_orphans(ctx: CheckContext, orphans: list) -> list[dict]:
    """Purge, then report exactly the records that are gone.

    Not a positional slice of the input: ``_purge_all`` skips moved ``.env``
    files (WOR-935) and state drift, so "the first N" would name keys that
    were deliberately kept — and an agent would act on that.
    """
    from worthless.cli.commands.doctor import _purge_all

    async def _purge_then_survivors() -> set[tuple[str, str | None]]:
        await _purge_all(orphans, ctx.repo, ctx.home.shard_a_dir)
        return {(e.key_alias, e.env_path) for e in await ctx.repo.list_enrollments()}

    survivors = asyncio.run(_purge_then_survivors())
    return [
        {"key_alias": e.key_alias, "env_path": e.env_path}
        for e in orphans
        if (e.key_alias, e.env_path) not in survivors
    ]


def run(ctx: CheckContext) -> CheckResult:
    # Late import to avoid the package's __init__.py loading the registry
    # before legacy symbols (_list_orphans, etc.) are defined.
    from worthless.cli.commands.doctor import _list_orphans

    try:
        _all, orphans = asyncio.run(_list_orphans(ctx.repo))
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
            "reason": "env_file_missing" if env_file_missing(e) else "env_line_missing",
            **({"remediation": MOVED_REMEDIATION} if env_file_missing(e) else {}),
        }
        for e in orphans
    ]
    moved = sum(1 for f in findings if f["reason"] == "env_file_missing")
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

    if n == 0:
        summary = "No orphan enrollments found."
    else:
        plural = "s" if n != 1 else ""
        dead = n - moved
        parts = [f"{n} broken record{plural} (.env line or file missing)."]
        if dead:
            parts.append(
                f"{dead} with the .env line deleted: run 'worthless doctor --fix' to purge, "
                "or 'worthless uninstall --force' for a clean removal."
            )
        if moved:
            parts.append(
                f"{moved} whose .env was not found {'is' if moved == 1 else 'are'} kept, "
                "never purged: if the project moved, put it back and run "
                "'worthless unlock'; if it is gone for good, 'worthless uninstall --force' "
                "removes Worthless and deletes these keys."
            )
        summary = " ".join(parts)
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        # Nothing for --fix to do when every orphan is a moved key it must keep.
        fixable=n == 0 or moved < n,
        fixed=fixed,
        skipped_reason=None,
    )

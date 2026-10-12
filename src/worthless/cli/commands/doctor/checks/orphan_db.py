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
from worthless.cli.orphans import (
    DELETED_FIX_PHRASE,
    MOVED_FIX_PHRASE,
    SHARED_KEY_PHRASE,
    env_file_missing,
)

check_id = "orphan_db"


def _missing_env_remediation(alias: str, live_copy: str | None) -> str:
    """Per-finding advice for a key whose .env is missing.

    Set on the finding so the runner's generic orphan playbook ("This key is
    gone") never reaches it: that is wrong for a moved project, and following
    it can destroy a recoverable key. ``live_copy`` is another ``.env`` that
    still holds the same key: then revoke would delete a working key, so it is
    never offered.
    """
    removed = (
        SHARED_KEY_PHRASE.format(other=live_copy)
        if live_copy
        else DELETED_FIX_PHRASE.format(alias=alias)
    )
    return (
        "This key may still be recoverable: its `.env` is missing from where it "
        f"was locked, and `worthless doctor --fix` leaves it alone. {MOVED_FIX_PHRASE}. "
        f"{removed}."
    )


def _repair_orphans(ctx: CheckContext, orphans: list) -> list[dict]:
    """Purge, then report exactly the records that are gone.

    Not a positional slice of the input: ``_purge_all`` skips moved ``.env``
    files (WOR-935) and state drift, so "the first N" would name keys that
    were deliberately kept — and an agent would act on that.
    """
    from worthless.cli.commands.doctor import _purge_all

    purged = asyncio.run(_purge_all(orphans, ctx.repo, ctx.home.shard_a_dir))
    return [
        {"key_alias": e.key_alias, "env_path": e.env_path}
        for e in orphans
        if (e.key_alias, e.env_path) in purged
    ]


def _live_copies(all_enrollments: list, orphans: list) -> dict[str, str]:
    """alias -> one ``.env`` that still holds that key (not an orphan)."""
    dead = {(o.key_alias, o.env_path) for o in orphans}
    return {
        e.key_alias: e.env_path
        for e in all_enrollments
        if e.env_path and (e.key_alias, e.env_path) not in dead
    }


def _finding(e, live: dict[str, str]) -> dict:
    """One orphan as an agent sees it. Checks the filesystem once."""
    moved = env_file_missing(e)
    finding = {
        "key_alias": e.key_alias,
        "var_name": e.var_name,
        "env_path": e.env_path,
        "reason": "env_file_missing" if moved else "env_line_missing",
    }
    if moved:
        finding["remediation"] = _missing_env_remediation(e.key_alias, live.get(e.key_alias))
    return finding


def _build_summary(n: int, moved: int) -> str:
    if n == 0:
        return "No orphan enrollments found."
    dead = n - moved
    parts = [f"{n} broken record{'s' if n != 1 else ''} (.env line or file missing)."]
    if dead:
        parts.append(
            f"{dead} with the .env line deleted: run 'worthless doctor --fix' to purge, "
            "or 'worthless uninstall --force' for a clean removal."
        )
    if moved:
        parts.append(
            f"{moved} whose .env was not found {'is' if moved == 1 else 'are'} kept, "
            "never purged: if the project moved, put it back and run "
            "'worthless unlock'; if it was deleted, 'worthless revoke --alias <alias>' "
            "removes that key. To remove Worthless entirely, 'worthless uninstall "
            "--force' — it also deletes every key it can't restore."
        )
    return " ".join(parts)


def run(ctx: CheckContext) -> CheckResult:
    # Late import to avoid the package's __init__.py loading the registry
    # before legacy symbols (_list_orphans, etc.) are defined.
    from worthless.cli.commands.doctor import _list_orphans

    try:
        all_enrollments, orphans = asyncio.run(_list_orphans(ctx.repo))
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
    live = _live_copies(all_enrollments, orphans)
    findings = [_finding(e, live) for e in orphans]
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

    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=_build_summary(n, moved),
        # Nothing for --fix to do when every orphan is a moved key it must keep.
        fixable=n == 0 or moved < n,
        fixed=fixed,
        skipped_reason=None,
    )

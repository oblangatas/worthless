"""WOR-464: stranded shard-A files.

A file in ``~/.worthless/shard_a/`` named ``<key_alias>`` with no
corresponding enrollment row in the DB. Common cause: a crash mid-revoke
that deleted the DB row before unlinking shard_a, or a manual DB edit.

Repair: unlink the stranded file. Safe — shard_a alone is unusable
without the matching shard_b row in the DB.
"""

from __future__ import annotations

import logging

from worthless.cli.commands.doctor.checks._helpers import load_enrollments, maybe_fix
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult

logger = logging.getLogger(__name__)
check_id = "stranded_shards"


def _repair_stranded(ctx: CheckContext, stranded: list, on_disk: dict) -> list[dict]:
    fixed: list[dict] = []
    for name in stranded:
        try:
            on_disk[name].unlink(missing_ok=True)
            fixed.append({"shard_path": str(on_disk[name])})
        except OSError as exc:
            logger.warning(
                "Failed to unlink stranded shard %s: %s",
                name,
                type(exc).__name__,
            )
    return fixed


def _list_shard_a_files(ctx: CheckContext) -> tuple[dict | None, CheckResult | None]:
    """Return (on_disk_map, None) or (None, early_result) on I/O error."""
    shard_a_dir = ctx.home.shard_a_dir
    try:
        on_disk = {p.name: p for p in shard_a_dir.iterdir() if p.is_file()}
        return on_disk, None
    except OSError as exc:
        if not shard_a_dir.exists():
            return None, CheckResult(
                check_id=check_id,
                status="ok",
                findings=[],
                summary="No shard_a directory; nothing to scan.",
                fixable=True,
                fixed=[],
                skipped_reason=None,
            )
        return None, CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary=f"Could not list shard_a directory: {type(exc).__name__}",
            fixable=True,
            fixed=[],
            skipped_reason=None,
        )


def _build_summary(n: int) -> str:
    if n == 0:
        return "No stranded shard files."
    return f"{n} stranded shard file{'s' if n != 1 else ''} with no DB enrollment"


def run(ctx: CheckContext) -> CheckResult:
    on_disk, early = _list_shard_a_files(ctx)
    if early is not None:
        return early
    if on_disk is None:  # pragma: no cover — unreachable: _list_shard_a_files always pairs
        raise RuntimeError("_list_shard_a_files returned (None, None) — programming error")

    enrollments, err = load_enrollments(ctx, check_id)
    if err is not None:
        return err
    if enrollments is None:  # pragma: no cover — unreachable: load_enrollments always pairs
        raise RuntimeError("load_enrollments returned (None, None) — programming error")

    known_aliases = {e.key_alias for e in enrollments}
    stranded = sorted(name for name in on_disk if name not in known_aliases)

    findings = [{"shard_path": str(on_disk[name])} for name in stranded]
    status = "ok" if not stranded else "warn"
    fixed, status = maybe_fix(
        ctx, stranded, lambda items: _repair_stranded(ctx, items, on_disk), status
    )

    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=_build_summary(len(stranded)),
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )

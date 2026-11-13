"""WOR-464: stranded shard-A files.

A file in ``~/.worthless/shard_a/`` named ``<key_alias>`` with no
corresponding enrollment row in the DB. Common cause: a crash mid-revoke
that deleted the DB row before unlinking shard_a, or a manual DB edit.

Repair: unlink the file only when its key has no shard row left either, so
the file can never be used again.

A file whose key still has its shard row is NOT stranded: it is half of a
recoverable key. The v0.3.7–v0.3.14 doctor bug deleted enrollment rows of
healthy keys, and on an old-format key the next ``--fix`` then deleted this
file, the last copy of its first half (WOR-959). Such files are reported and
kept. If the shard rows can't be read, nothing is deleted.
"""

from __future__ import annotations

import asyncio
import logging

from worthless.cli.commands.doctor.checks._helpers import load_enrollments, maybe_fix
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult

logger = logging.getLogger(__name__)
check_id = "stranded_shards"

# No destructive command in here: agents run whatever a remediation names.
KEPT_REMEDIATION = (
    "This key is probably still recoverable: its link was removed, but both halves "
    "are still on this machine. Keep this file and don't uninstall Worthless. An "
    'upcoming release re-links it; search "WRTLS-102" in the Worthless GitHub issues.'
)


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


def _build_summary(n: int, kept: int) -> str:
    if n == 0 and kept == 0:
        return "No stranded shard files."
    parts = []
    if n:
        parts.append(f"{n} stranded shard file{'s' if n != 1 else ''} with no key left")
    if kept:
        parts.append(f"{kept} kept: the key is probably still recoverable")
    return "; ".join(parts)


def _unreadable(exc: Exception) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status="error",
        findings=[],
        summary=f"Could not read shard rows, so nothing was deleted: {type(exc).__name__}",
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )


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

    try:
        with_shard_row = set(asyncio.run(ctx.repo.list_keys()))
    except Exception as exc:  # noqa: BLE001 - a failed read must never turn into a delete
        return _unreadable(exc)

    known_aliases = {e.key_alias for e in enrollments}
    unlinked = sorted(name for name in on_disk if name not in known_aliases)
    stranded = [name for name in unlinked if name not in with_shard_row]
    kept = [name for name in unlinked if name in with_shard_row]

    findings = [{"shard_path": str(on_disk[n]), "reason": "no_key_left"} for n in stranded]
    findings += [
        {
            "shard_path": str(on_disk[n]),
            "reason": "key_still_recoverable",
            "remediation": KEPT_REMEDIATION,
        }
        for n in kept
    ]
    status = "ok" if not unlinked else "warn"
    fixed, status = maybe_fix(
        ctx, stranded, lambda items: _repair_stranded(ctx, items, on_disk), status
    )
    if kept:
        status = "warn"

    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=_build_summary(len(stranded), len(kept)),
        # Nothing for --fix to do when every finding is a key it must keep.
        fixable=bool(stranded) or not kept,
        fixed=fixed,
        skipped_reason=None,
    )

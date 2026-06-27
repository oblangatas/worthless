"""Shared helpers for doctor check modules."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from worthless.cli.commands.doctor.registry import CheckContext, CheckResult


async def _init_and_list(repo) -> list:  # type: ignore[type-arg]
    await repo.initialize()
    return await repo.list_enrollments()


def load_enrollments(
    ctx: CheckContext, check_id: str
) -> tuple[list, None] | tuple[None, CheckResult]:
    """Initialize the repo and return enrollments, or an error CheckResult.

    Returns a 2-tuple:
      - ``(enrollments, None)`` on success
      - ``(None, CheckResult)`` on failure

    Usage::

        enrollments, err = load_enrollments(ctx, check_id)
        if err is not None:
            return err
    """
    from worthless.cli.commands.doctor.registry import CheckResult

    try:
        enrollments = asyncio.run(_init_and_list(ctx.repo))
        return enrollments, None
    except Exception as exc:  # noqa: BLE001
        return None, CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary=f"Could not read enrollment DB: {type(exc).__name__}",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )


def maybe_fix(
    ctx: CheckContext,
    items: list,
    repair_fn: Callable[[list], list[dict]],
    status: Literal["ok", "warn", "error"],
) -> tuple[list[dict], Literal["ok", "warn", "error"]]:
    """Run repair_fn on items when ctx.fix is set and dry_run is off.

    Returns (fixed, updated_status). Status flips to "ok" only when
    every item was successfully repaired.
    """
    fixed: list[dict] = []
    if ctx.fix and items and not ctx.dry_run:
        fixed = repair_fn(items)
        if len(fixed) == len(items):
            status = "ok"
    return fixed, status

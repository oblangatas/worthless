"""WOR-464: Check protocol + CheckResult contract + ALL_CHECKS registry.

A Check is a callable returning a :class:`CheckResult`. Checks are pure
read-only diagnostics by default; if ``fix=True`` is passed AND the check
declares ``fixable=True``, the check may mutate state and record what it
did in the ``fixed`` field.

Why a registry: ``--json`` mode must enumerate ALL checks (including
those with no findings) so consumers see a complete picture. The text
runner can also iterate the same list and stay byte-identical to the
existing output by keeping the per-check rendering in the legacy
``_doctor_run`` path — registry-driven JSON is additive, not a rewrite.
"""

from __future__ import annotations

from typing import Literal, Protocol, TypedDict

from worthless.cli.bootstrap import WorthlessHome
from worthless.storage.repository import ShardRepository


class CheckContext:
    """Bundle of resources shared across checks within one doctor run.

    Held as a regular class (not a dataclass) so checks can stash
    intermediate state (e.g. ``enrollments``) on it without forcing
    every check to take a long argument list.
    """

    def __init__(
        self,
        *,
        home: WorthlessHome,
        repo: ShardRepository,
        fix: bool,
        dry_run: bool,
    ) -> None:
        self.home = home
        self.repo = repo
        self.fix = fix
        self.dry_run = dry_run


class CheckResult(TypedDict, total=False):
    """Stable per-check output shape for ``--json``.

    Fields:
        check_id: stable identifier (snake_case). Never renamed without
            bumping SCHEMA_VERSION.
        status: ``ok`` (no findings), ``warn`` (findings, recoverable),
            or ``error`` (findings, cannot auto-repair OR check itself
            crashed).
        findings: list of dicts describing each individual issue. Shape
            is per-check; keep keys snake_case.
        summary: 1-line human-readable summary, used by JSON consumers
            and (optionally) by the text runner.
        fixable: True iff the check supports ``--fix``. ``fernet_drift``
            is hardcoded False — drift is dangerous and only the user
            can decide which side is canonical.
        fixed: list of dicts describing repairs actually performed in
            this run. Empty when ``fix=False`` or no repairs were needed.
        skipped_reason: present when the check could not run at all
            (e.g. platform mismatch); status is ``ok`` in that case.
    """

    check_id: str
    status: Literal["ok", "warn", "error"]
    findings: list[dict]
    summary: str
    fixable: bool
    fixed: list[dict]
    skipped_reason: str | None


class Check(Protocol):
    """A doctor check: name + run callable.

    A new check is added by:
      1. writing the module under ``checks/``
      2. exposing a ``run(ctx: CheckContext) -> CheckResult`` callable
      3. appending it to :data:`ALL_CHECKS`
    """

    check_id: str

    def run(self, ctx: CheckContext) -> CheckResult: ...


def _build_all_checks() -> list:
    """Return the ordered list of registered checks.

    Order matches the existing text runner's diagnostic sequence so
    JSON consumers see findings in the same order a human would scan
    them on the console. New checks (orphan_keychain, stranded_shards,
    fernet_drift, broken_status) are appended after the legacy four
    so existing JSON consumers don't see a reordering when a new check
    lands.
    """
    from worthless.cli.commands.doctor.checks import (
        broken_status,
        fernet_drift,
        icloud_keychain,
        openclaw as openclaw_check,
        orphan_db,
        orphan_keychain,
        recovery_import,
        stranded_shards,
    )

    return [
        recovery_import,
        orphan_db,
        openclaw_check,
        icloud_keychain,
        orphan_keychain,
        stranded_shards,
        fernet_drift,
        broken_status,
    ]


# Lazily built to avoid circular imports between doctor/__init__.py and
# the checks/ modules (the checks may import helpers from __init__.py).
ALL_CHECKS: list = []


def ensure_registered() -> list:
    """Populate :data:`ALL_CHECKS` on first call; return it."""
    global ALL_CHECKS
    if not ALL_CHECKS:
        ALL_CHECKS = _build_all_checks()
    return ALL_CHECKS

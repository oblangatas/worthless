"""Stable error codes and event objects for the OpenClaw integration.

The string values of :class:`OpenclawErrorCode` are wire-format: they
appear in ``worthless lock --json`` / ``worthless doctor --json`` output
and are consumed by Pi (the JSON parser referenced in spec AC6). Renaming
a value is a breaking change for downstream agents — extend, don't rename.

The :class:`OpenclawIntegrationEvent` dataclass is frozen so events
appended to a sink in lock-core can't be mutated by later stages before
``--json`` renders them.

Spec: ``.claude/plans/graceful-dreaming-reef.md`` §"Public API contracts
for Phase 2.a" and the failure-mode tables F01–F47.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OpenclawErrorCode(str, Enum):
    """Wire-stable identifiers for OpenClaw integration events.

    Subclasses :class:`str` so JSON serialization yields the dotted string
    directly without needing a custom encoder.
    """

    CONFIG_UNREADABLE = "openclaw.config_unreadable"
    CONFIG_RECREATED = "openclaw.config_recreated"
    CONFIG_UPDATED = "openclaw.config_updated"
    CONFIG_MISSING = "openclaw.config_missing"
    PROVIDER_CONFLICT = "openclaw.provider_conflict"
    PROVIDER_ADOPTED_UNRECOGNIZED = "openclaw.provider_adopted_unrecognized"
    PROVIDER_ADOPTION_SKIPPED = "openclaw.provider_adoption_skipped"
    PROVIDER_RECOGNITION_UNAVAILABLE = "openclaw.provider_recognition_unavailable"
    SYMLINK_REFUSED = "openclaw.symlink_refused"
    WRITE_FAILED = "openclaw.write_failed"
    LOCK_TIMEOUT = "openclaw.lock_timeout"
    SKILL_FOREIGN_OWNER = "openclaw.skill_foreign_owner"
    SKILL_INSTALL_FAILED = "openclaw.skill_install_failed"
    HOME_MISMATCH = "openclaw.home_mismatch"


@dataclass(frozen=True)
class OpenclawIntegrationEvent:
    """One structured event emitted by the OpenClaw integration layer.

    Frozen so a downstream stage can't flip ``level`` before the JSON
    renderer reads it.
    """

    code: OpenclawErrorCode
    level: str  # "info" | "warn" | "error"
    detail: str
    extra: dict[str, str] | None = field(default=None)

    def to_dict(self) -> dict[str, str]:
        """Wire-stable serialization for sentinel + ``--json`` output.

        Single-source the {code, level, detail} shape so downstream
        consumers (sentinel writer, ``--json`` renderer, doctor) all
        agree. Replaces a pair of byte-identical ``_event_to_dict``
        helpers that lived in ``cli/commands/lock.py`` and
        ``cli/commands/unlock.py``.

        ``extra`` is intentionally omitted from the wire shape — it's a
        debug-side-channel for human readers, not part of the JSON
        contract Pi consumes.
        """
        return {
            "code": self.code.value,
            "level": self.level,
            "detail": self.detail,
        }


class OpenclawIntegrationError(Exception):
    """Hard refusal raised by :mod:`worthless.openclaw.skill` operations.

    Caught by ``integration.apply_lock()`` (Phase 2.b) and converted to an
    :class:`OpenclawIntegrationEvent` — never propagates into lock-core
    per locked decision L1.
    """

    def __init__(self, code: OpenclawErrorCode, detail: str) -> None:
        self.code = code
        super().__init__(detail)


class OpenclawConfigUnreadableError(Exception):
    """Raised by ``apply_lock`` when openclaw.json exists but is owned by a
    different UID (Docker two-UID topology) or ``WORTHLESS_OPENCLAW_CONFIG_SHARED``
    is set.

    WOR-516 case (c) fix: abort before any writes rather than silently
    overwriting with a blank-slate config (which was the bug Ido hit).

    Exit code 87 (env fault) — the user must fix their deployment topology
    before re-running ``worthless lock``.
    """


@dataclass(frozen=True)
class OpenclawIntegrationReport:
    """Wire-stable JSON shape for ``worthless --json lock|unlock`` output.

    Spec AC6: parseable by Pi (the JSON consumer agent). Wire format
    mirrored to the on-disk sentinel at
    ``$WORTHLESS_HOME/last-lock-status.json`` so doctor + status can read
    the same shape without re-deriving it.

    Frozen — once emitted, downstream consumers must see a stable payload.
    Spec said "Pydantic" originally; this codebase doesn't have pydantic
    as a dep, so we use a frozen dataclass + ``dataclasses.asdict`` for
    JSON serialization. Wire shape is the only contract that matters.

    Fields:
        ts: ISO 8601 UTC timestamp of the operation.
        status: ``"ok"`` (everything succeeded) or ``"partial"`` (lock-core
            succeeded but the OpenClaw stage hit a detected+failed condition).
            ``"partial"`` triggers the trust-fix exit-non-zero path.
        openclaw: ``"ok"`` | ``"failed"`` | ``"absent"`` — the OpenClaw stage
            outcome. ``"absent"`` means OpenClaw was not detected on this host.
        alias_count: number of aliases the operation touched (lock: wired;
            unlock: removed).
        events: structured event list, one entry per
            :class:`OpenclawIntegrationEvent` surfaced during the operation.
    """

    ts: str
    status: str  # "ok" | "partial"
    openclaw: str  # "ok" | "failed" | "absent"
    alias_count: int
    events: tuple[dict[str, str], ...] = field(default_factory=tuple)

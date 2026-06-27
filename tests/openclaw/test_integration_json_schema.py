"""Phase 2.e — AC6: ``OpenclawIntegrationReport`` round-trip / schema tests.

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` §"AC6" —
the JSON shape produced by ``worthless lock --json`` and
``worthless unlock --json`` must be parseable by Pi (the downstream JSON
consumer agent). These tests prove the wire contract is stable and
round-trips through ``dataclasses.asdict`` + ``json.dumps`` without
losing any field.

``OpenclawIntegrationReport`` lives in ``worthless.openclaw.errors`` because
it is shared between lock, unlock, and doctor. It is a frozen dataclass
(not Pydantic — the project does not carry Pydantic as a dep), so the
tests validate the field-level contract by name + type.

WOR-477 gap 2: these tests were missing from the original Phase 2.e
deliverable. Adding them to satisfy AC6.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone

import pytest

from worthless.openclaw.errors import (
    OpenclawErrorCode,
    OpenclawIntegrationEvent,
    OpenclawIntegrationReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_report(
    *,
    status: str = "ok",
    openclaw: str = "ok",
    alias_count: int = 1,
    events: tuple[dict[str, str], ...] = (),
) -> OpenclawIntegrationReport:
    return OpenclawIntegrationReport(
        ts=_now_ts(),
        status=status,
        openclaw=openclaw,
        alias_count=alias_count,
        events=events,
    )


def _make_event(
    code: OpenclawErrorCode = OpenclawErrorCode.CONFIG_UPDATED,
    level: str = "info",
    detail: str = "test event",
) -> OpenclawIntegrationEvent:
    return OpenclawIntegrationEvent(code=code, level=level, detail=detail)


# ---------------------------------------------------------------------------
# AC6-01: required fields present with correct types
# ---------------------------------------------------------------------------


class TestAc6RequiredFields:
    """AC6-01: every required field is present with the right Python type."""

    def test_ts_is_str(self) -> None:
        r = _make_report()
        assert isinstance(r.ts, str) and r.ts

    def test_status_is_str(self) -> None:
        r = _make_report()
        assert isinstance(r.status, str)

    def test_openclaw_is_str(self) -> None:
        r = _make_report()
        assert isinstance(r.openclaw, str)

    def test_alias_count_is_int(self) -> None:
        r = _make_report()
        assert isinstance(r.alias_count, int)

    def test_events_is_tuple(self) -> None:
        r = _make_report()
        assert isinstance(r.events, tuple)


# ---------------------------------------------------------------------------
# AC6-02: dataclasses.asdict round-trip
# ---------------------------------------------------------------------------


class TestAc6AsDict:
    """AC6-02: ``dataclasses.asdict`` produces the wire dict Pi parses."""

    def test_empty_report_asdict_has_all_keys(self) -> None:
        r = _make_report()
        d = dataclasses.asdict(r)
        assert set(d) == {"ts", "status", "openclaw", "alias_count", "events"}

    def test_events_empty_tuple_serializes_as_empty_list(self) -> None:
        r = _make_report(events=())
        d = dataclasses.asdict(r)
        assert d["events"] == ()  # asdict preserves tuple

    def test_events_with_entries_serializes_correctly(self) -> None:
        ev = _make_event(
            code=OpenclawErrorCode.CONFIG_UPDATED,
            level="info",
            detail="wrote worthless-openai",
        )
        r = _make_report(events=(ev.to_dict(),))
        d = dataclasses.asdict(r)
        assert len(d["events"]) == 1
        entry = d["events"][0]
        assert entry["code"] == "openclaw.config_updated"
        assert entry["level"] == "info"
        assert entry["detail"] == "wrote worthless-openai"

    def test_json_roundtrip_preserves_all_fields(self) -> None:
        """Full JSON serialization round-trip — what Pi actually does."""
        ev = _make_event(
            code=OpenclawErrorCode.WRITE_FAILED,
            level="error",
            detail="EACCES on replace",
        )
        r = _make_report(
            status="partial",
            openclaw="failed",
            alias_count=2,
            events=(ev.to_dict(),),
        )
        wire = json.dumps(dataclasses.asdict(r))
        parsed = json.loads(wire)

        assert parsed["status"] == "partial"
        assert parsed["openclaw"] == "failed"
        assert parsed["alias_count"] == 2
        assert len(parsed["events"]) == 1
        assert parsed["events"][0]["code"] == "openclaw.write_failed"


# ---------------------------------------------------------------------------
# AC6-03: wire-stable error code values
# ---------------------------------------------------------------------------


class TestAc6WireStableErrorCodes:
    """AC6-03: OpenclawErrorCode string values are wire-stable.

    These are the exact strings Pi (and any downstream consumer) parses.
    Renaming any value is a BREAKING CHANGE. This test pins them so a
    rename trips CI before it can ship.
    """

    @pytest.mark.parametrize(
        "code, expected_value",
        [
            (OpenclawErrorCode.CONFIG_UNREADABLE, "openclaw.config_unreadable"),
            (OpenclawErrorCode.CONFIG_RECREATED, "openclaw.config_recreated"),
            (OpenclawErrorCode.CONFIG_UPDATED, "openclaw.config_updated"),
            (OpenclawErrorCode.CONFIG_MISSING, "openclaw.config_missing"),
            (OpenclawErrorCode.PROVIDER_CONFLICT, "openclaw.provider_conflict"),
            (OpenclawErrorCode.SYMLINK_REFUSED, "openclaw.symlink_refused"),
            (OpenclawErrorCode.WRITE_FAILED, "openclaw.write_failed"),
            (OpenclawErrorCode.LOCK_TIMEOUT, "openclaw.lock_timeout"),
            (OpenclawErrorCode.SKILL_FOREIGN_OWNER, "openclaw.skill_foreign_owner"),
            (OpenclawErrorCode.SKILL_INSTALL_FAILED, "openclaw.skill_install_failed"),
            (OpenclawErrorCode.HOME_MISMATCH, "openclaw.home_mismatch"),
        ],
    )
    def test_error_code_wire_value(self, code: OpenclawErrorCode, expected_value: str) -> None:
        assert code.value == expected_value, (
            f"Wire value for {code.name!r} changed — breaking change for Pi consumers"
        )


# ---------------------------------------------------------------------------
# AC6-04: report is frozen (immutable after construction)
# ---------------------------------------------------------------------------


class TestAc6Frozen:
    """AC6-04: ``OpenclawIntegrationReport`` is frozen — Pi sees a stable snapshot."""

    def test_cannot_mutate_ts(self) -> None:
        r = _make_report()
        with pytest.raises((AttributeError, TypeError)):
            r.ts = "mutated"  # type: ignore[misc]

    def test_cannot_mutate_events(self) -> None:
        r = _make_report()
        with pytest.raises((AttributeError, TypeError)):
            r.events = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AC6-05: event.to_dict() wire shape
# ---------------------------------------------------------------------------


class TestAc6EventToDict:
    """AC6-05: ``OpenclawIntegrationEvent.to_dict()`` wire shape is exact."""

    def test_to_dict_has_exactly_three_keys(self) -> None:
        ev = _make_event()
        d = ev.to_dict()
        assert set(d) == {"code", "level", "detail"}, (
            "extra field leaked into wire shape — breaks Pi schema"
        )

    def test_extra_field_not_in_wire_dict(self) -> None:
        """``extra`` is a debug side-channel, never on the wire."""
        ev = OpenclawIntegrationEvent(
            code=OpenclawErrorCode.WRITE_FAILED,
            level="error",
            detail="ENOSPC",
            extra={"path": "/home/user/.openclaw/openclaw.json", "nlink": "2"},
        )
        d = ev.to_dict()
        assert "extra" not in d

    def test_code_value_is_string_not_enum(self) -> None:
        """Pi JSON-parses a raw string, not a Python enum object."""
        ev = _make_event(code=OpenclawErrorCode.CONFIG_UPDATED)
        d = ev.to_dict()
        assert d["code"] == "openclaw.config_updated"
        assert isinstance(d["code"], str)


# ---------------------------------------------------------------------------
# AC6-06: status / openclaw accepted values
# ---------------------------------------------------------------------------


class TestAc6StatusValues:
    """AC6-06: ``status`` and ``openclaw`` accept the documented values."""

    @pytest.mark.parametrize("status", ["ok", "partial"])
    def test_status_accepted_values(self, status: str) -> None:
        r = _make_report(status=status)
        assert r.status == status

    @pytest.mark.parametrize("openclaw_val", ["ok", "failed", "absent"])
    def test_openclaw_accepted_values(self, openclaw_val: str) -> None:
        r = _make_report(openclaw=openclaw_val)
        assert r.openclaw == openclaw_val

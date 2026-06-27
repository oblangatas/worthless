"""Phase 2.a errors module — enum stability + dataclass shape.

Spec: graceful-dreaming-reef.md §"Public API contracts for Phase 2.a" /
``worthless.openclaw.errors``. Enum values are wire-format for the
``--json`` event stream; renaming them is a breaking change for the Pi
parser referenced in AC6.
"""

from __future__ import annotations

import dataclasses

import pytest


def test_error_code_values_are_stable_strings() -> None:
    """Phase 2.a contract: every OpenclawErrorCode member maps to a
    fixed dotted-string value. Renames break the Pi --json consumer.
    """
    from worthless.openclaw.errors import OpenclawErrorCode

    expected = {
        "CONFIG_UNREADABLE": "openclaw.config_unreadable",
        "CONFIG_RECREATED": "openclaw.config_recreated",
        "CONFIG_UPDATED": "openclaw.config_updated",
        "PROVIDER_CONFLICT": "openclaw.provider_conflict",
        "SYMLINK_REFUSED": "openclaw.symlink_refused",
        "WRITE_FAILED": "openclaw.write_failed",
        "LOCK_TIMEOUT": "openclaw.lock_timeout",
        "SKILL_FOREIGN_OWNER": "openclaw.skill_foreign_owner",
        "SKILL_INSTALL_FAILED": "openclaw.skill_install_failed",
        "HOME_MISMATCH": "openclaw.home_mismatch",
    }
    for name, wire in expected.items():
        member = getattr(OpenclawErrorCode, name)
        assert member.value == wire, f"{name} drifted: {member.value!r}"


def test_error_code_is_str_enum() -> None:
    """OpenclawErrorCode must subclass str so JSON serialization yields
    the wire string directly without needing a custom encoder.
    """
    from worthless.openclaw.errors import OpenclawErrorCode

    assert isinstance(OpenclawErrorCode.CONFIG_UNREADABLE, str)
    assert OpenclawErrorCode.CONFIG_UNREADABLE == "openclaw.config_unreadable"


def test_event_dataclass_is_frozen_and_serializable() -> None:
    """OpenclawIntegrationEvent: frozen + dataclasses.asdict round-trips.

    Frozen guarantees event objects passed into the events_sink can't be
    mutated by downstream code before --json renders them.
    """
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationEvent,
    )

    extras = {"path": "/example/openclaw.json"}
    event = OpenclawIntegrationEvent(
        code=OpenclawErrorCode.CONFIG_UNREADABLE,
        level="warn",
        detail="malformed JSON",
        extra=extras,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.level = "error"  # type: ignore[misc]

    payload = dataclasses.asdict(event)
    assert payload["code"] == OpenclawErrorCode.CONFIG_UNREADABLE
    assert payload["level"] == "warn"
    assert payload["detail"] == "malformed JSON"
    assert payload["extra"] == extras


def test_event_extra_defaults_to_none() -> None:
    """OpenclawIntegrationEvent.extra is optional with default=None."""
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationEvent,
    )

    event = OpenclawIntegrationEvent(
        code=OpenclawErrorCode.CONFIG_RECREATED,
        level="info",
        detail="recreated empty config",
    )
    assert event.extra is None


def test_integration_error_carries_error_code() -> None:
    """OpenclawIntegrationError exposes a .code attribute that is an
    OpenclawErrorCode (per F32 SKILL_FOREIGN_OWNER contract).
    """
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationError,
    )

    err = OpenclawIntegrationError(
        OpenclawErrorCode.SKILL_FOREIGN_OWNER,
        "owned by uid=99",
    )
    assert isinstance(err, Exception)
    assert err.code is OpenclawErrorCode.SKILL_FOREIGN_OWNER
    assert "owned by uid=99" in str(err)

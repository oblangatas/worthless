"""WOR-658: doctor check surfaces bind_confirmation state.

The status command shows DEGRADED on bind-fail; this doctor check turns the
same signal into a diagnostic the user can act on. Both share the sentinel
as the source of truth — these tests pin the check's classify-and-remediate
contract directly. Full end-to-end doctor invocation lives in
test_doctor_fix_behavior.py; we only need the unit contract here.
"""

from __future__ import annotations

import pytest

from worthless.cli.commands.doctor.checks import bind_confirmation


def test_classify_fail_returns_error_with_routing_message() -> None:
    """A bind_confirmation.status=fail sentinel → error status + a message
    naming the routing failure and pointing at the remediation."""
    sentinel = {
        "bind_confirmation": {"status": "fail", "delta": 0, "reached": 1},
    }
    status, summary = bind_confirmation._classify(sentinel)
    assert status == "error"
    assert "routing" in summary.lower() or "rout" in summary.lower()
    assert "openclaw" in summary.lower() or "lock" in summary.lower()


def test_classify_skipped_unrecognised_returns_warn_with_squatter_hint() -> None:
    """proxy_unrecognised → warn (not error) + a message pointing at the
    foreign service on the port."""
    sentinel = {
        "bind_confirmation": {"status": "skipped", "reason": "proxy_unrecognised"},
    }
    status, summary = bind_confirmation._classify(sentinel)
    assert status == "warn"
    assert "worthless" in summary.lower() or "port" in summary.lower()


def test_classify_skipped_unhealthy_returns_warn_with_start_proxy_hint() -> None:
    """proxy_unhealthy_* → warn + start-the-proxy hint."""
    for reason in (
        "proxy_unhealthy_before",
        "proxy_unhealthy_after",
        "proxy_check_raised_before",
        "proxy_check_raised_after",
    ):
        sentinel = {"bind_confirmation": {"status": "skipped", "reason": reason}}
        status, summary = bind_confirmation._classify(sentinel)
        assert status == "warn", reason
        assert "worthless up" in summary or "proxy" in summary.lower()


def test_classify_pass_is_silent() -> None:
    """status=pass → None (no finding to surface) + a PASS summary."""
    sentinel = {"bind_confirmation": {"status": "pass", "delta": 1}}
    status, summary = bind_confirmation._classify(sentinel)
    assert status is None
    assert "PASS" in summary


def test_classify_missing_sentinel_is_silent() -> None:
    """No sentinel (lock never ran on this host) → no finding."""
    assert bind_confirmation._classify(None)[0] is None
    assert bind_confirmation._classify({})[0] is None


def test_classify_old_sentinel_without_bind_confirmation_is_silent() -> None:
    """Backward-compat: pre-WOR-658 sentinels lack the field → no finding."""
    status, summary = bind_confirmation._classify(
        {"status": "ok", "openclaw": "ok", "alias_count": 1, "events": []}
    )
    assert status is None
    assert "predates" in summary.lower() or "no bind-confirmation" in summary.lower()


# ---------------------------------------------------------------------------
# Registry: the new check is wired into ALL_CHECKS so doctor actually runs it.
# ---------------------------------------------------------------------------


def test_check_is_registered_in_all_checks() -> None:
    """ALL_CHECKS must include bind_confirmation — otherwise the check
    silently disappears from the doctor run regardless of how good the
    classify function is."""
    from worthless.cli.commands.doctor.registry import ensure_registered

    checks = ensure_registered()
    ids = [c.check_id for c in checks]
    assert "bind_confirmation" in ids, f"bind_confirmation missing from {ids}"


# ---------------------------------------------------------------------------
# Coverage guard: every ``reason`` value lock-side _confirm_bind emits must
# be handled by BOTH the doctor _classify AND the status _bind_confirmation_message.
# This is the structural test the code-reviewer flagged was missing — without
# it, lock can add a new skipped reason and both surfaces silently swallow
# it (exactly the silent-pass class WOR-658 was built to expose).
# ---------------------------------------------------------------------------


# Every skipped reason _confirm_bind can emit (lock.py). Adding a new reason
# to lock REQUIRES adding it here AND to both helpers — the test forces it.
_ALL_SKIPPED_REASONS = (
    "no_aliases",  # the one intentionally-silent reason (precondition, not a problem)
    "proxy_check_raised_before",
    "proxy_unhealthy_before",
    "proxy_unrecognised",
    "proxy_check_raised_after",
    "proxy_unhealthy_after",
    "proxy_unrecognised_after",
    "proxy_restarted",
    "synthetic_unreachable",
)


@pytest.mark.parametrize("reason", _ALL_SKIPPED_REASONS)
def test_doctor_classify_handles_every_skipped_reason(reason: str) -> None:
    """No reason _confirm_bind emits may fall through to the silent
    'Bind-confirmation state is fine.' default. ``no_aliases`` is the one
    exception — it means there was nothing to confirm in the first place.
    """
    status, summary = bind_confirmation._classify(
        {"bind_confirmation": {"status": "skipped", "reason": reason}}
    )
    if reason == "no_aliases":
        assert status is None, f"no_aliases is a precondition, not a finding — got {status!r}"
        return
    assert status == "warn", (
        f"reason={reason!r} fell through to status={status!r} — doctor "
        f"would silently mark this OK and the user would never know "
        f"routing wasn't proven."
    )
    assert "Proof-of-routing" in summary or "inconclusive" in summary.lower(), (
        f"reason={reason!r} got non-routing summary: {summary!r}"
    )


@pytest.mark.parametrize("reason", _ALL_SKIPPED_REASONS)
def test_status_message_handles_every_skipped_reason(reason: str) -> None:
    """Same structural guard for status's _bind_confirmation_message."""
    from worthless.cli.commands.status import _bind_confirmation_message

    msg = _bind_confirmation_message({"bind_confirmation": {"status": "skipped", "reason": reason}})
    if reason == "no_aliases":
        assert msg is None, f"no_aliases is a precondition, not a finding — got {msg!r}"
        return
    assert msg is not None and msg, (
        f"reason={reason!r} produced no status message — user gets a "
        f"silent skipped verdict and never knows routing wasn't proven."
    )

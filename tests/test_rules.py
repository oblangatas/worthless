"""Tests for the rules engine — spend cap, rate limit, and pipeline behavior."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from unittest.mock import patch
from zoneinfo import ZoneInfo

import aiosqlite
import pytest

from worthless.proxy.errors import (
    time_window_error_response,
    token_budget_error_response,
)
from worthless.proxy.rules import (
    RateLimitRule,
    RulesEngine,
    SpendCapRule,
    TimeWindowRule,
    TokenBudgetRule,
)
from worthless.storage.schema import SCHEMA


# ---------------------------------------------------------------------------
# RulesEngine pipeline
# ---------------------------------------------------------------------------


class _PassRule:
    """Stub rule that always passes."""

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> None:
        return None


class _DenyRule:
    """Stub rule that always denies with a 403."""

    def __init__(self) -> None:
        self.called = False

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ):
        self.called = True
        # Return a simple dict to simulate a denial response
        return {"status": 403, "detail": "denied"}


class _BodyCapturingRule:
    """Stub rule that captures the body it receives."""

    def __init__(self) -> None:
        self.received_body: bytes | None = None

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ):
        self.received_body = body
        return None


@pytest.mark.asyncio
async def test_empty_rules_engine_returns_none():
    engine = RulesEngine(rules=[])
    result = await engine.evaluate("test-alias", object(), body=b"")
    assert result.denial is None


@pytest.mark.asyncio
async def test_single_passing_rule_returns_none():
    engine = RulesEngine(rules=[_PassRule()])
    result = await engine.evaluate("test-alias", object(), body=b"")
    assert result.denial is None


@pytest.mark.asyncio
async def test_short_circuits_on_first_denial():
    deny = _DenyRule()
    never_reached = _DenyRule()
    engine = RulesEngine(rules=[deny, never_reached])
    result = await engine.evaluate("test-alias", object(), body=b"")
    assert result is not None
    assert deny.called is True
    assert never_reached.called is False


# ---------------------------------------------------------------------------
# Body parameter passthrough (WOR-182)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rules_engine_passes_body_to_rules():
    """RulesEngine.evaluate() must forward body kwarg to each rule."""
    rule = _BodyCapturingRule()
    engine = RulesEngine(rules=[rule])
    test_body = b'{"model": "gpt-4o"}'
    await engine.evaluate("test-alias", object(), body=test_body)
    assert rule.received_body == test_body


@pytest.mark.asyncio
async def test_rules_engine_body_defaults_to_empty():
    """Body defaults to b'' when not provided."""
    rule = _BodyCapturingRule()
    engine = RulesEngine(rules=[rule])
    await engine.evaluate("test-alias", object())
    assert rule.received_body == b""


@pytest.mark.asyncio
async def test_spend_cap_accepts_body_parameter(tmp_path):
    """SpendCapRule.evaluate() accepts body kwarg without error."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=1000.0, total_tokens=500)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b'{"model": "gpt-4"}')
        assert result.denial is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_rate_limit_accepts_body_parameter():
    """RateLimitRule.evaluate() accepts body kwarg without error."""
    rule = RateLimitRule(default_rps=10.0)
    result = await rule.evaluate("k1", _fake_request("127.0.0.1"), body=b'{"model": "gpt-4"}')
    assert result is None


# ---------------------------------------------------------------------------
# SpendCapRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spend_cap_under_limit(tmp_path):
    """Spend below cap -> None (pass)."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=1000.0, total_tokens=500)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        # Small valid request — 500 spent + tiny estimate fits under cap=1000.
        result = await rule.evaluate("k1", object(), body=b'{"max_tokens": 50}')
        assert result.denial is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_exceeded(tmp_path):
    """Spend at or above cap -> 402 denial."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=100.0, total_tokens=150)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result.denial is not None
        assert result.denial.status_code == 402
        body = json.loads(result.denial.body)
        assert "spend cap" in body["error"]["message"].lower()
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_null_no_cap(tmp_path):
    """NULL spend_cap -> no limit -> None (pass)."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=None, total_tokens=999999)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result.denial is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_no_enrollment_record(tmp_path):
    """Alias with no enrollment_config row -> pass (no cap configured)."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias=None, spend_cap=None, total_tokens=0)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("unknown-alias", object(), body=b"")
        assert result.denial is None
    finally:
        await db_conn.close()


# ---------------------------------------------------------------------------
# TokenBudgetRule (WOR-160)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_budget_all_null_passes(tmp_path):
    """All budget columns NULL → no limit → pass."""

    db_path = str(tmp_path / "tb.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=None, total_tokens=999999)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_under_daily_limit(tmp_path):
    """Tokens below daily budget → pass."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", daily=100000, tokens_today=50000)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_daily_exceeded(tmp_path):
    """Tokens at or above daily budget → 429 with usage stats."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", daily=100000, tokens_today=100000)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 429
        body = json.loads(result.body)
        assert "daily" in body["error"]["message"]
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_weekly_exceeded(tmp_path):
    """Weekly budget exceeded → 429."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", weekly=500000, tokens_this_week=500000)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 429
        body = json.loads(result.body)
        assert "weekly" in body["error"]["message"]
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_monthly_exceeded(tmp_path):
    """Monthly budget exceeded → 429."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", monthly=2000000, tokens_this_month=2000000)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 429
        body = json.loads(result.body)
        assert "monthly" in body["error"]["message"]
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_daily_ok_monthly_exceeded(tmp_path):
    """Daily under limit but monthly exceeded → 429 monthly."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(
        db_path,
        alias="k1",
        daily=100000,
        monthly=500000,
        tokens_today=50000,
        tokens_this_month=500000,
    )

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 429
        body = json.loads(result.body)
        assert "monthly" in body["error"]["message"]
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_old_records_not_counted(tmp_path):
    """Spend records older than the window are not counted."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", daily=100000, tokens_old=999999)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is None  # Old tokens don't count
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_no_enrollment_config(tmp_path):
    """No enrollment_config row → pass (no budget configured)."""

    db_path = str(tmp_path / "tb.db")
    await _setup_spend_db(db_path, alias=None, spend_cap=None, total_tokens=0)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("unknown-alias", object(), body=b"")
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_fail_closed_on_db_error(tmp_path):
    """DB error → fail closed (429)."""

    db_path = str(tmp_path / "tb.db")
    db_conn = await aiosqlite.connect(db_path)
    # Don't create tables — queries will fail
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 429
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_anthropic_error_format(tmp_path):
    """Anthropic provider → Anthropic error format."""

    db_path = str(tmp_path / "tb.db")
    await _setup_token_budget_db(db_path, alias="k1", daily=100, tokens_today=200)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        result = await rule.evaluate("k1", object(), provider="anthropic", body=b"")
        assert result is not None
        assert result.status_code == 429
        body = json.loads(result.body)
        assert body["type"] == "error"
        assert "daily" in body["error"]["message"]
    finally:
        await db_conn.close()


# ---------------------------------------------------------------------------
# TimeWindowRule (WOR-161)
# ---------------------------------------------------------------------------


async def _setup_time_window_db(db_path: str, *, alias: str, time_window: str | None) -> None:
    """Create a test DB with time_window config."""
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, time_window) VALUES (?, ?)",
            (alias, time_window),
        )
        await db.commit()


@pytest.mark.asyncio
async def test_time_window_null_passes(tmp_path):
    """NULL time_window → no restriction → pass."""
    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=None)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_within_window(tmp_path):
    """Current time within configured window → pass."""

    now = datetime.now(ZoneInfo("UTC"))
    # Build a window that includes the current hour
    start_hour = now.hour
    end_hour = (now.hour + 2) % 24
    window = json.dumps(
        {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
            "tz": "UTC",
            "days": [1, 2, 3, 4, 5, 6, 7],
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_outside_hour(tmp_path):
    """Current time outside configured hours → 403."""

    now = datetime.now(ZoneInfo("UTC"))
    # Build a window that excludes the current hour
    start_hour = (now.hour + 3) % 24
    end_hour = (now.hour + 5) % 24
    window = json.dumps(
        {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
            "tz": "UTC",
            "days": [1, 2, 3, 4, 5, 6, 7],
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 403
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_wrong_day(tmp_path):
    """Current day not in allowed days → 403."""

    now = datetime.now(ZoneInfo("UTC"))
    # Exclude today's isoweekday
    allowed_days = [d for d in range(1, 8) if d != now.isoweekday()]
    window = json.dumps(
        {
            "start": "00:00",
            "end": "23:59",
            "tz": "UTC",
            "days": allowed_days,
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 403
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_overnight(tmp_path):
    """Overnight window (end < start, e.g. 22:00-06:00) works correctly."""

    now = datetime.now(ZoneInfo("UTC"))
    # Build an overnight window guaranteed to include current hour:
    # start = current_hour - 2 (wraps around), end = current_hour + 2
    # e.g., if now is 3:00, window is 01:00-05:00 (not overnight)
    # if now is 0:00, window is 22:00-02:00 (overnight)
    # Force overnight: set start after current, end before current, spanning midnight
    end_hour = (now.hour + 1) % 24
    start_hour = (now.hour - 1) % 24
    # Ensure start > end to make it overnight
    if start_hour <= end_hour:
        start_hour = (end_hour + 12) % 24

    window = json.dumps(
        {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
            "tz": "UTC",
            "days": [1, 2, 3, 4, 5, 6, 7],
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        # Should pass — current time is within the overnight window
        assert result is None
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_invalid_timezone(tmp_path):
    """Invalid timezone → fail closed (403)."""
    window = json.dumps(
        {
            "start": "09:00",
            "end": "17:00",
            "tz": "Fake/Nowhere",
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 403
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_malformed_json(tmp_path):
    """Malformed JSON in time_window → fail closed (403)."""
    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window="not valid json{{")

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result is not None
        assert result.status_code == 403
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_time_window_anthropic_format(tmp_path):
    """Anthropic provider → Anthropic error format."""

    now = datetime.now(ZoneInfo("UTC"))
    start_hour = (now.hour + 3) % 24
    end_hour = (now.hour + 5) % 24
    window = json.dumps(
        {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
            "tz": "UTC",
            "days": [1, 2, 3, 4, 5, 6, 7],
        }
    )

    db_path = str(tmp_path / "tw.db")
    await _setup_time_window_db(db_path, alias="k1", time_window=window)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TimeWindowRule(db=db_conn)
        result = await rule.evaluate("k1", object(), provider="anthropic", body=b"")
        assert result is not None
        assert result.status_code == 403
        body = json.loads(result.body)
        assert body["type"] == "error"
    finally:
        await db_conn.close()


# ---------------------------------------------------------------------------
# RateLimitRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_under_threshold():
    rule = RateLimitRule(default_rps=10.0)
    # Single request should pass
    result = await rule.evaluate("k1", _fake_request("127.0.0.1"))
    assert result is None


@pytest.mark.asyncio
async def test_rate_limit_exceeded():
    rule = RateLimitRule(default_rps=2.0)
    req = _fake_request("127.0.0.1")
    # Fire 3 requests rapidly; third should be denied
    await rule.evaluate("k1", req)
    await rule.evaluate("k1", req)
    result = await rule.evaluate("k1", req)
    assert result is not None
    assert result.status_code == 429
    assert "retry-after" in {k.lower() for k in result.headers}


@pytest.mark.asyncio
async def test_rate_limit_uses_sliding_window():
    rule = RateLimitRule(default_rps=2.0)
    req = _fake_request("127.0.0.1")
    await rule.evaluate("k1", req)
    await rule.evaluate("k1", req)
    # Advance time past the 1s window without sleeping
    fake_now = time.monotonic() + 1.1
    with patch("time.monotonic", return_value=fake_now):
        result = await rule.evaluate("k1", req)
    assert result is None  # Should pass after window slides


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeRequest:
    """Minimal request-like object with client info."""

    def __init__(self, ip: str) -> None:
        self.client = type("Client", (), {"host": ip})()


def _fake_request(ip: str = "127.0.0.1") -> _FakeRequest:
    return _FakeRequest(ip)


@pytest.mark.asyncio
async def test_spend_cap_returns_anthropic_error_format(tmp_path):
    """When provider=anthropic, spend cap denial uses Anthropic error format."""

    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=100.0, total_tokens=150)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("k1", object(), provider="anthropic", body=b"")
        assert result.denial is not None
        assert result.denial.status_code == 402
        body = json.loads(result.denial.body)
        # Anthropic format: {"type": "error", "error": {"type": ..., "message": ...}}
        assert body["type"] == "error"
        assert "spend cap" in body["error"]["message"].lower()
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_rate_limit_returns_anthropic_error_format():
    """When provider=anthropic, rate limit denial uses Anthropic error format."""
    rule = RateLimitRule(default_rps=1.0)
    req = _fake_request("127.0.0.1")
    await rule.evaluate("k1", req, provider="anthropic", body=b"")
    result = await rule.evaluate("k1", req, provider="anthropic", body=b"")
    assert result is not None
    assert result.status_code == 429
    body = json.loads(result.body)
    assert body["type"] == "error"
    assert "rate limit" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_per_enrollment_rate_limit(tmp_path):
    """Per-enrollment rate_limit_rps from DB overrides default."""
    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias="k1", spend_cap=None, total_tokens=0, rate_limit_rps=2.0)

    rule = RateLimitRule(default_rps=100.0, db_path=db_path)
    req = _fake_request("127.0.0.1")
    # First two should pass (per-enrollment limit is 2)
    assert await rule.evaluate("k1", req) is None
    assert await rule.evaluate("k1", req) is None
    # Third should be denied
    result = await rule.evaluate("k1", req)
    assert result is not None
    assert result.status_code == 429


@pytest.mark.asyncio
async def test_per_enrollment_rate_limit_falls_back_to_default(tmp_path):
    """Without per-enrollment config, falls back to default_rps."""
    db_path = str(tmp_path / "test.db")
    await _setup_spend_db(db_path, alias=None, spend_cap=None, total_tokens=0)

    rule = RateLimitRule(default_rps=2.0, db_path=db_path)
    req = _fake_request("127.0.0.1")
    await rule.evaluate("unknown", req)
    await rule.evaluate("unknown", req)
    result = await rule.evaluate("unknown", req)
    assert result is not None
    assert result.status_code == 429


async def _setup_spend_db(
    db_path: str,
    *,
    alias: str | None,
    spend_cap: float | None,
    total_tokens: int,
    rate_limit_rps: float | None = None,
) -> None:
    """Create a test DB with spend_log and enrollment_config tables pre-populated."""

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        if alias is not None:
            await db.execute(
                "INSERT INTO enrollment_config"
                " (key_alias, spend_cap, rate_limit_rps)"
                " VALUES (?, ?, ?)",
                (alias, spend_cap, rate_limit_rps if rate_limit_rps is not None else 100.0),
            )
            if total_tokens > 0:
                await db.execute(
                    "INSERT INTO spend_log (key_alias, tokens, model, provider) "
                    "VALUES (?, ?, ?, ?)",
                    (alias, total_tokens, "gpt-4", "openai"),
                )
        await db.commit()


async def _setup_token_budget_db(
    db_path: str,
    *,
    alias: str,
    daily: int | None = None,
    weekly: int | None = None,
    monthly: int | None = None,
    tokens_today: int = 0,
    tokens_this_week: int = 0,
    tokens_this_month: int = 0,
    tokens_old: int = 0,
) -> None:
    """Create a test DB with token budget config and time-stamped spend records."""

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute(
            "INSERT INTO enrollment_config"
            " (key_alias, token_budget_daily, token_budget_weekly,"
            " token_budget_monthly)"
            " VALUES (?, ?, ?, ?)",
            (alias, daily, weekly, monthly),
        )
        # Today's tokens
        if tokens_today > 0:
            await db.execute(
                "INSERT INTO spend_log"
                " (key_alias, tokens, model, provider, created_at)"
                " VALUES (?, ?, ?, ?, datetime('now'))",
                (alias, tokens_today, "gpt-4", "openai"),
            )
        # This week's tokens (3 days ago)
        if tokens_this_week > 0:
            await db.execute(
                "INSERT INTO spend_log"
                " (key_alias, tokens, model, provider, created_at)"
                " VALUES (?, ?, ?, ?, datetime('now', '-3 days'))",
                (alias, tokens_this_week, "gpt-4", "openai"),
            )
        # This month's tokens (15 days ago)
        if tokens_this_month > 0:
            await db.execute(
                "INSERT INTO spend_log"
                " (key_alias, tokens, model, provider, created_at)"
                " VALUES (?, ?, ?, ?, datetime('now', '-15 days'))",
                (alias, tokens_this_month, "gpt-4", "openai"),
            )
        # Old tokens (60 days ago — outside all windows)
        if tokens_old > 0:
            await db.execute(
                "INSERT INTO spend_log"
                " (key_alias, tokens, model, provider, created_at)"
                " VALUES (?, ?, ?, ?, datetime('now', '-60 days'))",
                (alias, tokens_old, "gpt-4", "openai"),
            )
        await db.commit()


async def _seed_aliases(db_path: str, *, count: int, column: str, value: float | int) -> None:
    """Seed enrollment_config with *count* aliases, each with one column set."""
    # `column` is whitelisted; the f-string is not user-influenced.
    assert column in {"spend_cap", "token_budget_daily"}
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        for i in range(count):
            await db.execute(
                f"INSERT INTO enrollment_config (key_alias, {column}) VALUES (?, ?)",  # noqa: S608
                (f"alias-{i}", value),
            )
        await db.commit()


# ---------------------------------------------------------------------------
# SpendCapRule — persistent connection, atomic, fail-closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spend_cap_concurrent_two_connections(tmp_path):
    """Two concurrent requests via separate connections — both over cap get denied."""

    db_path = str(tmp_path / "concurrent.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute("PRAGMA journal_mode=WAL")
        # Cap of 100, already spent 100 — both should be denied
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 100.0),
        )
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            ("k1", 100, "gpt-4", "openai"),
        )
        await db.commit()

    # Two SEPARATE connections to test real concurrency (not serialized on one conn)
    db_conn1 = await aiosqlite.connect(db_path)
    db_conn2 = await aiosqlite.connect(db_path)
    await db_conn1.execute("PRAGMA journal_mode=WAL")
    await db_conn1.execute("PRAGMA busy_timeout=5000")
    await db_conn2.execute("PRAGMA journal_mode=WAL")
    await db_conn2.execute("PRAGMA busy_timeout=5000")
    try:
        rule1 = SpendCapRule(db=db_conn1)
        rule2 = SpendCapRule(db=db_conn2)
        results = await asyncio.gather(
            rule1.evaluate("k1", object()),
            rule2.evaluate("k1", object()),
        )
        # Both should be denied since spend (100) >= cap (100)
        assert all(r.denial is not None and r.denial.status_code == 402 for r in results)
    finally:
        await db_conn1.close()
        await db_conn2.close()


@pytest.mark.asyncio
async def test_spend_cap_concurrent_under_cap_serialized(tmp_path):
    """At 40/100 spent, two small concurrent requests that both fit under the cap
    both pass — the durable holds serialise via the DB write lock (no overrun)."""

    db_path = str(tmp_path / "concurrent2.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 100.0),
        )
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            ("k1", 40, "gpt-4", "openai"),
        )
        await db.commit()

    db_conn1 = await aiosqlite.connect(db_path)
    db_conn2 = await aiosqlite.connect(db_path)
    await db_conn1.execute("PRAGMA journal_mode=WAL")
    await db_conn1.execute("PRAGMA busy_timeout=5000")
    await db_conn2.execute("PRAGMA journal_mode=WAL")
    await db_conn2.execute("PRAGMA busy_timeout=5000")
    try:
        rule1 = SpendCapRule(db=db_conn1)
        rule2 = SpendCapRule(db=db_conn2)
        body = b'{"max_tokens": 20}'  # estimate 20; 40 + 20 + 20 = 80 <= 100
        results = await asyncio.gather(
            rule1.evaluate("k1", object(), body=body),
            rule2.evaluate("k1", object(), body=body),
        )
        # Both fit: 40 + 2*20 = 80 <= 100 cap
        assert all(r.denial is None for r in results)
    finally:
        await db_conn1.close()
        await db_conn2.close()


@pytest.mark.asyncio
async def test_spend_cap_toctou_20_concurrent(tmp_path):
    """TOCTOU regression: 20 concurrent requests on ONE rule instance must
    honour the hard cap. Without the reservation fix all 20 observe
    total_tokens=0 and all return None (pass), overrunning the cap 4x.

    Setup: cap=90, max_tokens=18 per request -> exactly 5 should pass
    (5x18=90 <= cap).  Without the fix passes==20; with the fix passes==5.
    """
    db_path = str(tmp_path / "toctou.db")
    async with aiosqlite.connect(db_path) as setup_db:
        await setup_db.executescript(SCHEMA)
        await setup_db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 90),
        )
        await setup_db.commit()

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        body = json.dumps({"max_tokens": 18}).encode()  # estimate exactly 18

        results = await asyncio.gather(*[rule.evaluate("k1", None, body=body) for _ in range(20)])

        passes = sum(1 for r in results if r.denial is None)
        assert passes == 5, (
            f"Expected exactly 5 passes (cap=90, estimated_cost=18), got {passes}. "
            "TOCTOU not fixed -- concurrent requests bypassed the spend cap."
        )
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_refund_does_not_erase_sibling_hold(tmp_path):
    """WOR-626 dissolved: refunding one in-flight hold must not touch a concurrent
    sibling's hold. The ledger refunds by HANDLE, so the place/release asymmetry
    that let an over-sized release erase a sibling is gone by construction.
    """
    db_path = str(tmp_path / "independent_refund.db")
    async with aiosqlite.connect(db_path) as setup_db:
        await setup_db.executescript(SCHEMA)
        await setup_db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 1000),
        )
        await setup_db.commit()

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        body = json.dumps({"max_tokens": 100}).encode()

        # Two concurrent in-flight requests each place their own durable hold.
        a = await rule.evaluate("k1", None, body=body)
        b = await rule.evaluate("k1", None, body=body)
        assert a.spend_handle is not None and b.spend_handle is not None
        assert a.spend_handle != b.spend_handle

        # Refund B by its OWN handle — A's hold must be untouched.
        await rule.ledger.refund(b.spend_handle)

        # A's hold survived: settling it records A's actual spend; B left nothing.
        await rule.ledger.settle(a.spend_handle, 50)
        async with db_conn.execute(
            "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = 'k1'"
        ) as cur:
            (committed,) = await cur.fetchone()
        assert committed == 50, "A's hold survived B's refund and settled to its actual"
        async with db_conn.execute(
            "SELECT COUNT(*) FROM pending_charges WHERE key_alias = 'k1'"
        ) as cur:
            (pending,) = await cur.fetchone()
        assert pending == 0, "both holds resolved (B refunded, A settled) — none orphaned"
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_counts_input_not_just_max_tokens(tmp_path):
    """WOR-659 Task 4 (RED): a request with a huge prompt but ``max_tokens=1`` must
    be DENIED — the cap reserves the ESTIMATED INPUT cost, not just the declared
    output budget.

    A 200K-char prompt with ``max_tokens=1`` must still be denied under a
    1000-token cap, because the gate reserves the full
    ``estimate_request_tokens`` admission cost (input + declared output).
    This guards against under-counting large-input / tiny-output requests.
    """
    db_path = str(tmp_path / "input_cap.db")
    async with aiosqlite.connect(db_path) as setup_db:
        await setup_db.executescript(SCHEMA)
        await setup_db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 1000),
        )
        await setup_db.commit()

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = SpendCapRule(db=db_conn)
        body = json.dumps(
            {"messages": [{"role": "user", "content": "z" * 200_000}], "max_tokens": 1}
        ).encode()
        gate = await rule.evaluate("k1", None, body=body)
        assert gate.denial is not None, (
            "a 200K-char prompt with max_tokens=1 must be denied under a 1000-token "
            "cap; the gate must reserve the estimated INPUT cost, not just max_tokens"
        )
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_token_budget_reserved_dict_drops_zero_entries(tmp_path):
    """Same bound applies to TokenBudgetRule's _reserved dict — both
    rules share the release_reservation pattern."""
    db_path = str(tmp_path / "bound_budget.db")
    n = 50
    await _seed_aliases(db_path, count=n, column="token_budget_daily", value=10_000)

    db_conn = await aiosqlite.connect(db_path)
    try:
        rule = TokenBudgetRule(db=db_conn)
        body = json.dumps({"max_tokens": 10}).encode()
        for i in range(n):
            alias = f"alias-{i}"
            assert await rule.evaluate(alias, None, body=body) is None
            await rule.release_reservation(alias, 10)

        assert len(rule._reserved) == 0, (
            f"_reserved leaked {len(rule._reserved)} dead entries on TokenBudgetRule"
        )
    finally:
        await db_conn.close()


@pytest.mark.asyncio
async def test_spend_cap_fail_closed_on_db_error(tmp_path):
    """SpendCapRule returns deny (ErrorResponse) when DB raises an exception."""

    db_path = str(tmp_path / "fail.db")
    db_conn = await aiosqlite.connect(db_path)
    # Don't create tables — queries will fail
    try:
        rule = SpendCapRule(db=db_conn)
        result = await rule.evaluate("k1", object(), body=b"")
        assert result.denial is not None
        assert result.denial.status_code == 402
    finally:
        await db_conn.close()


# ---------------------------------------------------------------------------
# RateLimitRule — concurrency (worthless-ks6)
#
# The race condition is between window read (line ~319) and window write
# (line ~335), separated by `await self._load_limit(alias)`.  To expose
# it we MUST provide a db_path so the await actually yields the event
# loop.  Without yielding, asyncio.gather runs each coroutine to
# completion before starting the next — no interleaving, no race.
# ---------------------------------------------------------------------------


async def _setup_rate_limit_db(db_path: str, *, alias: str, rps: float) -> None:
    """Create a DB with enrollment_config for per-key rate limit."""
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, rate_limit_rps) VALUES (?, ?)",
            (alias, rps),
        )
        await db.commit()


@pytest.mark.asyncio
async def test_rate_limit_concurrent_burst_no_overcount(tmp_path):
    """5 concurrent requests at rps=5 all pass; next 5 all denied.

    Validates that the sliding-window read-modify-write is atomic:
    no undercounting (security) and no overcounting (false-positive UX).

    Uses db_path to force an await inside evaluate(), which yields
    to the event loop and exposes the read-modify-write race.
    """
    db_path = str(tmp_path / "rl1.db")
    await _setup_rate_limit_db(db_path, alias="burst-alias", rps=5.0)

    rule = RateLimitRule(default_rps=5.0, db_path=db_path)
    req = _fake_request("10.0.0.99")

    # Fire 5 concurrent calls — all should be allowed
    first_batch = await asyncio.gather(*(rule.evaluate("burst-alias", req) for _ in range(5)))
    allowed = [r for r in first_batch if r is None]
    assert len(allowed) == 5, (
        f"Expected exactly 5 allowed, got {len(allowed)}. "
        f"Race condition: concurrent reads see stale window state."
    )

    # Fire 5 more — all should be denied (429)
    second_batch = await asyncio.gather(*(rule.evaluate("burst-alias", req) for _ in range(5)))
    denied = [r for r in second_batch if r is not None and r.status_code == 429]
    assert len(denied) == 5, (
        f"Expected exactly 5 denied, got {len(denied)}. Window lost updates from concurrent writes."
    )


@pytest.mark.asyncio
async def test_rate_limit_no_false_positive_under_limit(tmp_path):
    """10 concurrent requests at rps=10 all pass — no false denials.

    Without locking, concurrent reads can overcount the window length
    and falsely deny requests that should be within the limit.

    We force every call to hit the `await _load_limit()` path by
    clearing the limits cache before each evaluate, ensuring the
    event loop yields between window read and write every time.
    """
    db_path = str(tmp_path / "rl2.db")
    await _setup_rate_limit_db(db_path, alias="fp-alias", rps=10.0)

    rule = RateLimitRule(default_rps=10.0, db_path=db_path)
    req = _fake_request("10.0.0.100")

    async def _evaluate_uncached(alias: str, request: object, **kwargs):
        """Clear the limit cache so _load_limit always fires (and yields)."""
        rule._limits.pop(alias, None)
        return await RateLimitRule.evaluate(rule, alias, request, **kwargs)

    results = await asyncio.gather(*(_evaluate_uncached("fp-alias", req) for _ in range(10)))

    allowed = [r for r in results if r is None]
    assert len(allowed) == 10, (
        f"Expected all 10 allowed (within limit), got {len(allowed)} allowed. "
        f"False positives from concurrent overcounting."
    )


@pytest.mark.asyncio
async def test_rate_limit_concurrent_exact_boundary(tmp_path):
    """At rps=3, exactly 3 concurrent pass; the 4th is denied.

    Also verifies a mixed gather of 4 concurrent calls yields exactly
    3 allows and 1 denial.
    """
    db_path = str(tmp_path / "rl3.db")
    await _setup_rate_limit_db(db_path, alias="boundary-alias", rps=3.0)
    # Second alias for phase 3
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, rate_limit_rps) VALUES (?, ?)",
            ("boundary-alias-2", 3.0),
        )
        await db.commit()

    rule = RateLimitRule(default_rps=3.0, db_path=db_path)
    req = _fake_request("10.0.0.101")

    # Phase 1: 3 concurrent — all should pass
    batch1 = await asyncio.gather(*(rule.evaluate("boundary-alias", req) for _ in range(3)))
    allowed1 = [r for r in batch1 if r is None]
    assert len(allowed1) == 3, f"Expected 3 allowed, got {len(allowed1)}."

    # Phase 2: 1 more — should be denied
    extra = await rule.evaluate("boundary-alias", req)
    assert extra is not None and extra.status_code == 429, (
        "4th request should be denied after 3 concurrent fills."
    )

    # Phase 3: fresh alias, 4 concurrent — exactly 3 pass, 1 denied
    batch2 = await asyncio.gather(*(rule.evaluate("boundary-alias-2", req) for _ in range(4)))
    allowed2 = [r for r in batch2 if r is None]
    denied2 = [r for r in batch2 if r is not None and r.status_code == 429]
    assert len(allowed2) == 3, f"Expected exactly 3 allowed in mixed gather, got {len(allowed2)}."
    assert len(denied2) == 1, f"Expected exactly 1 denied in mixed gather, got {len(denied2)}."


@pytest.mark.asyncio
async def test_rate_limiter_ttl_cleanup():
    """Rate limiter _windows dict entries older than 2s are cleaned up."""

    rule = RateLimitRule(default_rps=100.0, cleanup_interval=0.0)
    req = _fake_request("10.0.0.1")

    # Add some entries
    await rule.evaluate("k1", req)
    await rule.evaluate("k2", _fake_request("10.0.0.2"))
    assert len(rule._windows) == 2

    # Simulate time passing beyond the 2s TTL
    fake_now = time.monotonic() + 3.0
    with patch("time.monotonic", return_value=fake_now):
        # Trigger cleanup by evaluating again
        await rule.evaluate("k3", _fake_request("10.0.0.3"))

    # k1 and k2 entries should be cleaned up, only k3 remains
    assert ("k1", "10.0.0.1") not in rule._windows
    assert ("k2", "10.0.0.2") not in rule._windows
    assert ("k3", "10.0.0.3") in rule._windows
    # Locks should be cleaned alongside windows
    assert ("k1", "10.0.0.1") not in rule._locks
    assert ("k2", "10.0.0.2") not in rule._locks


@pytest.mark.asyncio
async def test_rate_limiter_expired_keys_removed():
    """After cleanup, expired (alias, ip) keys are completely removed from _windows."""

    rule = RateLimitRule(default_rps=100.0, cleanup_interval=0.0)
    req = _fake_request("10.0.0.1")

    # Add entries for multiple keys
    for i in range(5):
        await rule.evaluate(f"alias-{i}", req)

    assert len(rule._windows) == 5

    # Move time forward past TTL
    fake_now = time.monotonic() + 3.0
    with patch("time.monotonic", return_value=fake_now):
        await rule.evaluate("fresh-alias", req)

    # All old entries should be removed
    for i in range(5):
        assert (f"alias-{i}", "10.0.0.1") not in rule._windows
        assert (f"alias-{i}", "10.0.0.1") not in rule._locks
    assert ("fresh-alias", "10.0.0.1") in rule._windows


# ---------------------------------------------------------------------------
# WOR-183: Structured error factories
# ---------------------------------------------------------------------------


def test_token_budget_error_openai():
    """token_budget_error_response returns 429 with period, used, and limit."""
    resp = token_budget_error_response(period="daily", used=85000, limit=100000, provider="openai")
    assert resp.status_code == 429
    body = json.loads(resp.body)
    assert "daily" in body["error"]["message"]
    assert "85,000" in body["error"]["message"] or "85000" in body["error"]["message"]
    assert "100,000" in body["error"]["message"] or "100000" in body["error"]["message"]


def test_token_budget_error_anthropic():
    resp = token_budget_error_response(
        period="weekly", used=500000, limit=500000, provider="anthropic"
    )
    assert resp.status_code == 429
    body = json.loads(resp.body)
    assert body["type"] == "error"
    assert "weekly" in body["error"]["message"]


def test_time_window_error_openai():
    """time_window_error_response returns 403 with current time and window."""
    resp = time_window_error_response(
        current_time="22:15 UTC", window="09:00-17:00", provider="openai"
    )
    assert resp.status_code == 403
    body = json.loads(resp.body)
    assert "22:15" in body["error"]["message"]
    assert "09:00-17:00" in body["error"]["message"]


def test_time_window_error_anthropic():
    resp = time_window_error_response(
        current_time="03:00 EST", window="09:00-17:00", provider="anthropic"
    )
    assert resp.status_code == 403
    body = json.loads(resp.body)
    assert body["type"] == "error"

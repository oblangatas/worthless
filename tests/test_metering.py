"""Tests for metering — token extraction from OpenAI and Anthropic responses."""

from __future__ import annotations

import json

import pytest

from worthless.proxy.metering import (
    extract_usage_anthropic,
    extract_usage_openai,
    record_spend,
)


# ---------------------------------------------------------------------------
# OpenAI token extraction
# ---------------------------------------------------------------------------


def test_extract_usage_openai_json():
    """Standard JSON response with usage.total_tokens and model."""
    data = json.dumps(
        {
            "id": "chatcmpl-abc",
            "model": "gpt-4",
            "choices": [{"message": {"content": "Hello"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }
    ).encode()
    result = extract_usage_openai(data)
    assert result is not None
    assert result.total_tokens == 30
    assert result.model == "gpt-4"


def test_extract_usage_openai_sse():
    """SSE stream with final chunk containing usage field."""
    chunks = (
        b"data: "
        + json.dumps({"choices": [{"delta": {"content": "Hi"}}], "model": "gpt-4o"}).encode()
        + b"\n\n"
        b"data: "
        + json.dumps(
            {
                "choices": [{"delta": {}}],
                "model": "gpt-4o",
                "usage": {"prompt_tokens": 5, "completion_tokens": 15, "total_tokens": 20},
            }
        ).encode()
        + b"\n\n"
        b"data: [DONE]\n\n"
    )
    result = extract_usage_openai(chunks)
    assert result is not None
    assert result.total_tokens == 20
    assert result.model == "gpt-4o"


def test_extract_usage_openai_missing():
    """No usage field -> return None."""
    data = json.dumps({"id": "chatcmpl-abc", "choices": []}).encode()
    assert extract_usage_openai(data) is None


def test_extract_usage_openai_empty():
    """Empty bytes -> return None."""
    assert extract_usage_openai(b"") is None


def test_extract_usage_openai_malformed():
    """Malformed JSON -> return None (no crash)."""
    assert extract_usage_openai(b"{not valid json") is None


# ---------------------------------------------------------------------------
# Anthropic token extraction
# ---------------------------------------------------------------------------


def test_extract_usage_anthropic_message_delta():
    """SSE with message_start + message_delta: total = input + output."""
    sse_data = (
        b"event: message_start\n"
        b"data: "
        + json.dumps(
            {
                "type": "message_start",
                "message": {
                    "model": "claude-3-5-sonnet-20241022",
                    "usage": {"input_tokens": 15},
                },
            }
        ).encode()
        + b"\n\n"
        b"event: content_block_delta\n"
        b'data: {"type": "content_block_delta", "delta": {"text": "Hi"}}\n\n'
        b"event: message_delta\n"
        b"data: "
        + json.dumps(
            {
                "type": "message_delta",
                "usage": {"output_tokens": 42},
            }
        ).encode()
        + b"\n\n"
    )
    result = extract_usage_anthropic(sse_data)
    assert result is not None
    assert result.total_tokens == 57  # 15 input + 42 output
    assert result.model == "claude-3-5-sonnet-20241022"


def test_extract_usage_anthropic_missing():
    """No message_delta event -> return None."""
    sse_data = (
        b"event: content_block_delta\n"
        b'data: {"type": "content_block_delta", "delta": {"text": "Hi"}}\n\n'
    )
    assert extract_usage_anthropic(sse_data) is None


def test_extract_usage_anthropic_empty():
    """Empty bytes -> return None."""
    assert extract_usage_anthropic(b"") is None


def test_extract_usage_anthropic_malformed():
    """Malformed data -> return None (no crash)."""
    assert extract_usage_anthropic(b"event: message_delta\ndata: broken{json\n\n") is None


def test_extract_usage_anthropic_multi_delta_returns_last():
    """When multiple message_delta events exist, return usage from the last one."""
    delta_1 = json.dumps({"type": "message_delta", "usage": {"output_tokens": 10}}).encode()
    delta_2 = json.dumps({"type": "message_delta", "usage": {"output_tokens": 42}}).encode()
    sse_data = (
        b"event: message_start\n"
        b"data: "
        + json.dumps(
            {
                "type": "message_start",
                "message": {"model": "claude-3-haiku-20240307", "usage": {"input_tokens": 8}},
            }
        ).encode()
        + b"\n\n"
        b"event: message_delta\n"
        b"data: " + delta_1 + b"\n\n"
        b"event: content_block_delta\n"
        b'data: {"type": "content_block_delta", "delta": {"text": "more"}}\n\n'
        b"event: message_delta\n"
        b"data: " + delta_2 + b"\n\n"
    )
    result = extract_usage_anthropic(sse_data)
    assert result is not None
    assert result.total_tokens == 50  # 8 input + 42 output (last delta)
    assert result.model == "claude-3-haiku-20240307"


def test_extract_usage_anthropic_delta_only_no_start():
    """message_delta without message_start: output tokens only, no model."""
    sse_data = (
        b"event: message_delta\n"
        b"data: "
        + json.dumps({"type": "message_delta", "usage": {"output_tokens": 25}}).encode()
        + b"\n\n"
    )
    result = extract_usage_anthropic(sse_data)
    assert result is not None
    assert result.total_tokens == 25
    assert result.model is None


def test_extract_usage_openai_sse_no_usage_in_any_chunk():
    """SSE stream where no chunk contains a usage field → None."""
    chunks = (
        b"data: "
        + json.dumps({"choices": [{"delta": {"content": "Hi"}}], "model": "gpt-4o"}).encode()
        + b"\n\n"
        b"data: " + json.dumps({"choices": [{"delta": {}}], "model": "gpt-4o"}).encode() + b"\n\n"
        b"data: [DONE]\n\n"
    )
    assert extract_usage_openai(chunks) is None


def test_extract_usage_openai_json_no_model():
    """OpenAI JSON without model field: tokens extracted, model is None."""
    data = json.dumps(
        {
            "id": "chatcmpl-abc",
            "choices": [],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }
    ).encode()
    result = extract_usage_openai(data)
    assert result is not None
    assert result.total_tokens == 30
    assert result.model is None


# ---------------------------------------------------------------------------
# record_spend
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_spend(tmp_path):
    """record_spend inserts a row into spend_log."""
    import aiosqlite

    from worthless.storage.schema import SCHEMA

    db_path = str(tmp_path / "test.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await record_spend(db_path, alias="k1", tokens=100, model="gpt-4", provider="openai")

    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT tokens, model, provider FROM spend_log WHERE key_alias = ?",
            ("k1",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == 100
    assert row[1] == "gpt-4"
    assert row[2] == "openai"


@pytest.mark.asyncio
async def test_record_spend_accepts_any_token_count(tmp_path):
    """record_spend inserts whatever token count the caller provides.

    The caller (_do_record_spend / _record_metering in proxy/app.py) is
    responsible for choosing the right amount — when usage extraction fails,
    the caller MUST pass _spend_reservation (fail-closed), NOT 0.
    This test verifies the DB layer accepts any non-negative value.
    """
    import aiosqlite

    from worthless.storage.schema import SCHEMA

    db_path = str(tmp_path / "test.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    # Caller provides reservation amount (fail-closed), not 0
    await record_spend(db_path, alias="k1", tokens=500, model=None, provider="openai")

    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT tokens, model FROM spend_log WHERE key_alias = ?",
            ("k1",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == 500, "Caller must pass reservation amount (fail-closed), not zero"
    assert row[1] is None


def test_extraction_failure_is_distinguishable_from_zero_usage():
    """None (extraction failed) is distinct from UsageInfo(total_tokens=0) (legit zero)."""
    # Extraction failure
    assert extract_usage_openai(b"garbage") is None

    # Legitimate zero usage (usage block present but tokens=0)
    data = json.dumps(
        {"usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}, "model": "gpt-4"}
    ).encode()
    result = extract_usage_openai(data)
    assert result is not None
    assert result.total_tokens == 0
    assert result.model == "gpt-4"


# ---------------------------------------------------------------------------
# Phase 1c: fail-closed streaming usage (worthless-dupf.4)
# ---------------------------------------------------------------------------


def test_fake_zero_usage_injected_after_real_usage_ignored():
    """Injected zero usage at stream end does not override real usage.

    Attack: malicious upstream sends the real usage chunk first, then appends
    {"usage": {"total_tokens": 0}} at the very end just before [DONE].
    reversed() finds the injected zero first and returns 0 — wrong.
    Forward iteration with last-wins also returns 0 — still wrong.

    The correct defence: use StreamingUsageCollector (incremental) for the
    streaming path, which already processes chunks as they arrive and takes
    the last seen value. For the buffered extract_usage_openai path, the
    known-good approach is to require the usage block to appear in the FINAL
    non-DONE data chunk (OpenAI canonical position). This test documents the
    expected behavior after the fix: real usage (60) must be returned, not 0.
    """
    stream = (
        # Real usage in the canonical final chunk before [DONE]
        b"data: "
        + json.dumps(
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "model": "gpt-4o",
                "usage": {"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60},
            }
        ).encode()
        + b"\n\n"
        # Attacker appends a fake zero usage chunk after the real one
        b"data: " + json.dumps({"usage": {"total_tokens": 0}, "model": "gpt-4o"}).encode() + b"\n\n"
        b"data: [DONE]\n\n"
    )
    result = extract_usage_openai(stream)
    assert result is not None
    assert result.total_tokens == 60, (
        "Real usage must be returned even when a zero-usage chunk is appended after it. "
        "This requires first-wins (not last-wins) when usage is found."
    )


def test_multiple_usage_blocks_uses_first():
    """When multiple usage blocks appear in SSE, the FIRST one wins.

    First-wins defends against end-of-stream injection: an attacker who appends
    a fake zero-usage block after the real usage block is ignored because the
    real block was already found first.
    """
    stream = (
        b"data: "
        + json.dumps({"usage": {"total_tokens": 100}, "model": "gpt-4o"}).encode()
        + b"\n\n"
        # Attacker-injected zero after the real usage
        b"data: " + json.dumps({"usage": {"total_tokens": 0}, "model": "gpt-4o"}).encode() + b"\n\n"
        b"data: [DONE]\n\n"
    )
    result = extract_usage_openai(stream)
    assert result is not None
    assert result.total_tokens == 100, (
        "First-wins: real usage (100) found first; injected zero (0) at end is ignored"
    )


def test_missing_usage_in_stream_returns_none():
    """SSE stream with no usage block at all returns None."""
    stream = (
        b"data: "
        + json.dumps({"choices": [{"delta": {"content": "Hi"}}], "model": "gpt-4o"}).encode()
        + b"\n\n"
        b"data: [DONE]\n\n"
    )
    assert extract_usage_openai(stream) is None


def test_interrupted_stream_returns_none():
    """Truncated SSE (no [DONE], no usage block) returns None."""
    stream = (
        b"data: "
        + json.dumps({"choices": [{"delta": {"content": "He"}}], "model": "gpt-4o"}).encode()
        + b"\n\n"
        # Stream ends abruptly — no usage, no [DONE]
    )
    assert extract_usage_openai(stream) is None


def test_anthropic_missing_usage_returns_none():
    """Anthropic SSE with no message_delta returns None."""
    stream = (
        b"event: message_start\n"
        b"data: "
        + json.dumps(
            {"message": {"model": "claude-3-5-sonnet-20241022", "usage": {"input_tokens": 10}}}
        ).encode()
        + b"\n\n"
        # No message_delta — stream truncated
    )
    assert extract_usage_anthropic(stream) is None


def test_anthropic_interrupted_stream_returns_none():
    """Anthropic truncated SSE (no message_delta) returns None."""
    stream = b"event: content_block_delta\ndata: {}\n\n"
    assert extract_usage_anthropic(stream) is None

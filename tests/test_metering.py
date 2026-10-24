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
# WOR-980: a "usage" that isn't an object means no usage, never a crash
# ---------------------------------------------------------------------------


def _sse(*events: tuple[str, object]) -> bytes:
    """Build an Anthropic-style SSE body from (event name, data payload) pairs."""
    return b"".join(
        f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode() for name, payload in events
    )


@pytest.mark.parametrize("usage", ["x", None, ["total_tokens"], 5], ids=repr)
@pytest.mark.parametrize(
    "extract", [extract_usage_openai, extract_usage_anthropic], ids=["openai", "anthropic"]
)
def test_json_non_dict_usage_is_no_usage(extract, usage):
    body = json.dumps({"model": "m", "choices": [], "usage": usage}).encode()
    assert extract(body) is None


@pytest.mark.parametrize(
    "delta",
    [{"type": "message_delta", "usage": "x"}, {"usage": None}, "usage", ["usage"]],
    ids=repr,
)
def test_extract_usage_anthropic_sse_non_dict_delta_is_no_usage(delta):
    assert extract_usage_anthropic(_sse(("message_delta", delta))) is None


@pytest.mark.parametrize(
    "start",
    [["x"], {"message": "x"}, {"message": {"model": "m", "usage": "x"}}],
    ids=repr,
)
def test_extract_usage_anthropic_sse_non_dict_start_counts_output_only(start):
    body = _sse(("message_start", start), ("message_delta", {"usage": {"output_tokens": 7}}))
    result = extract_usage_anthropic(body)
    assert result is not None
    assert result.total_tokens == 7


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
async def test_record_spend_zero_token_audit_row(tmp_path):
    """When extraction returns None, record_spend still inserts a 0-token audit row."""
    import aiosqlite

    from worthless.storage.schema import SCHEMA

    db_path = str(tmp_path / "test.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    # Simulate what _do_record_spend does when extraction fails
    usage = extract_usage_openai(b"not valid json at all")
    assert usage is None

    tokens = usage.total_tokens if usage else 0
    model = usage.model if usage else None
    await record_spend(db_path, alias="k1", tokens=tokens, model=model, provider="openai")

    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT tokens, model FROM spend_log WHERE key_alias = ?",
            ("k1",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == 0, "Failed extraction should record 0 tokens for audit"
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

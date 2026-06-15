"""Unit tests for the response-model extractor (WOR-696).

Tests the pure parser directly, pinning BOTH provider SSE wire shapes:

- OpenAI Chat Completions: ``data: {"model":"gpt-...","choices":...}`` per chunk
- Anthropic Messages: ``data: {"type":"message_start","message":{"model":"claude-...","..."}}``

The integration test in test_ceiling_floor_and_stream_kills.py covers the
end-to-end OpenAI path through the FastAPI app. This file fills the gap
the spec-vs-implementation review (Jenny) flagged: the Anthropic branch
of ``extract_response_model`` was implemented but never exercised by a
test.
"""

from __future__ import annotations

from worthless.proxy.response_model_audit import bounded_increment, extract_response_model


# ---------------------------------------------------------------------------
# extract_response_model — OpenAI shape
# ---------------------------------------------------------------------------


def test_extract_openai_per_chunk_model() -> None:
    """OpenAI emits the model at top level of every streamed chunk."""
    chunk = b'data: {"model":"gpt-4o-mini","choices":[{"delta":{"role":"assistant"}}]}\n\n'
    assert extract_response_model(chunk) == "gpt-4o-mini"


def test_extract_openai_picks_first_data_event_when_chunk_carries_many() -> None:
    """Multiple SSE events in one chunk → FIRST ``model`` field wins.

    Distinct models per event so a regression that picks the second
    (or last, or random) event fails this test loudly.
    """
    chunk = (
        b'data: {"model":"gpt-4o-mini","choices":[{"delta":{"role":"assistant"}}]}\n\n'
        b'data: {"model":"gpt-5","choices":[{"delta":{"content":"hi"}}]}\n\n'
    )
    assert extract_response_model(chunk) == "gpt-4o-mini"


# ---------------------------------------------------------------------------
# extract_response_model — Anthropic shape
# ---------------------------------------------------------------------------


def test_extract_anthropic_message_start_nested_model() -> None:
    """Anthropic carries ``model`` one level deeper, under ``message``."""
    chunk = (
        b'data: {"type":"message_start","message":'
        b'{"id":"msg_01","model":"claude-opus-4-5","role":"assistant"}}\n\n'
    )
    assert extract_response_model(chunk) == "claude-opus-4-5"


def test_extract_anthropic_message_delta_then_message_start() -> None:
    """Anthropic streams a few non-model events first; extractor must skip
    forward to the ``message_start`` event."""
    chunk = (
        b'data: {"type":"ping"}\n\n'
        b'data: {"type":"message_start","message":{"id":"msg_99","model":"claude-haiku-4-5"}}\n\n'
    )
    assert extract_response_model(chunk) == "claude-haiku-4-5"


# ---------------------------------------------------------------------------
# extract_response_model — robustness contract
# ---------------------------------------------------------------------------


def test_extract_returns_none_on_done_sentinel() -> None:
    """[DONE] is the OpenAI terminal marker; no model, no panic."""
    assert extract_response_model(b"data: [DONE]\n\n") is None


def test_extract_returns_none_on_empty_chunk() -> None:
    assert extract_response_model(b"") is None


def test_extract_returns_none_on_malformed_json() -> None:
    """Junk in a data line must not raise — passthrough invariant."""
    chunk = b"data: {not really json\n\n"
    assert extract_response_model(chunk) is None


def test_extract_returns_none_on_non_utf8_bytes() -> None:
    """Random binary noise (e.g. compressed framing artifacts) → None, no raise.

    The contract is None on non-extractable input. Empty-string would
    be a parser regression (model values must be non-empty strings).
    """
    chunk = b"\xff\xfe\x00\x01data: {\xc3\x28"
    assert extract_response_model(chunk) is None


def test_extract_returns_none_when_model_is_not_a_string() -> None:
    """Defensive: a malformed upstream could send ``model: null`` or ``model: 123``."""
    chunk = b'data: {"model":null,"choices":[]}\n\n'
    assert extract_response_model(chunk) is None
    chunk = b'data: {"model":42,"choices":[]}\n\n'
    assert extract_response_model(chunk) is None


def test_extract_returns_none_when_data_is_a_json_array_not_object() -> None:
    """Hypothetical upstream that wraps events in an array → extractor refuses."""
    chunk = b'data: [{"model":"x"}]\n\n'
    assert extract_response_model(chunk) is None


# ---------------------------------------------------------------------------
# bounded_increment — cardinality cap (worthless-cchq)
# ---------------------------------------------------------------------------


def test_bounded_increment_caps_cardinality_at_1024() -> None:
    """Counter must not grow unboundedly even under hostile input.

    Attacker controls upstream model strings (e.g. via a malicious
    OpenRouter-compatible custom URL that returns a unique ``"model":"x-<uuid>"``
    per response). Without a cap, the dict grows ~100 bytes per pair × millions
    of pairs = OOM the proxy. brutus on commit 5e84e9a (worthless-cchq) flagged
    this; the cap is the fix.
    """
    counter: dict[tuple[str, str], int] = {}
    for i in range(2000):
        bounded_increment(counter, (f"req-{i}", f"resp-{i}"))
    # Exactly 1024: the first 1024 keys land, the remaining 976 are
    # dropped at the cap. == catches both unbounded growth AND the
    # silent-stop-early regression that <= would hide.
    assert len(counter) == 1024, (
        f"counter has {len(counter)} entries, expected exactly 1024 "
        f"(first 1024 land, 976 dropped at cap) — either unbounded "
        f"growth (OOM vector, worthless-cchq) or implementation stops "
        f"growing before reaching the cap (silent loss of legit signal)"
    )


def test_bounded_increment_still_counts_existing_keys_when_at_cap() -> None:
    """At the cap, existing keys MUST still increment.

    Dropping is for NEW keys (cardinality bound); existing keys are the
    legitimate observation signal and must keep counting.
    """
    counter: dict[tuple[str, str], int] = {}
    # Fill to the cap with distinct pairs.
    for i in range(1024):
        bounded_increment(counter, (f"req-{i}", f"resp-{i}"))
    assert len(counter) == 1024

    # Existing key — count goes up.
    bounded_increment(counter, ("req-0", "resp-0"))
    assert counter[("req-0", "resp-0")] == 2

    # New key at cap — silently dropped, NOT raised, NOT OOM.
    bounded_increment(counter, ("req-novel", "resp-novel"))
    assert ("req-novel", "resp-novel") not in counter
    assert len(counter) == 1024


def test_bounded_increment_below_cap_is_plain_increment() -> None:
    """The cap path is only active above the threshold. Below it,
    bounded_increment must behave identically to a normal dict increment."""
    counter: dict[tuple[str, str], int] = {}
    bounded_increment(counter, ("gpt-4o-mini", "gpt-5"))
    bounded_increment(counter, ("gpt-4o-mini", "gpt-5"))
    bounded_increment(counter, ("gpt-4o-mini", "gpt-5"))
    assert counter == {("gpt-4o-mini", "gpt-5"): 3}

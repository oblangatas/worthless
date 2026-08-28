"""Tests for the request-cost estimator (WOR-659 Task 3).

The estimate is the spend cap's denominator: estimate = input + n*max_tokens.
Input is a conservative char count over messages + system + tools; non-text
content blocks (images) floor high; an unparsable body fails high, never 0.
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from worthless.proxy.estimation import estimate_request_tokens


def _body(payload: dict) -> bytes:
    return json.dumps(payload).encode()


def test_input_is_counted_not_just_output() -> None:
    """A bigger prompt yields a bigger estimate (input is charged)."""
    small = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    big = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "x" * 4000}], "max_tokens": 10}),
    )
    assert big > small


def test_huge_prompt_tiny_max_tokens_is_not_cheap() -> None:
    """The headline attack: a 200K-char prompt with max_tokens=1 must NOT
    estimate ~1 — the input must dominate."""
    est = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "z" * 200_000}], "max_tokens": 1}),
    )
    assert est > 10_000  # input counted; nowhere near the max_tokens=1 lie


def test_counts_system_and_tools() -> None:
    """Anthropic `system` and the `tools` schema are charged, not ignored."""
    base = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    with_system = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": "hi"}],
                "system": "S" * 2000,
                "max_tokens": 10,
            }
        ),
    )
    with_tools = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": "hi"}],
                "tools": [{"name": "f", "description": "D" * 2000, "parameters": {}}],
                "max_tokens": 10,
            }
        ),
    )
    assert with_system > base
    assert with_tools > base


def test_non_text_block_floors_high() -> None:
    """An image (non-text) content block costs a high constant, not ~0 chars."""
    est = estimate_request_tokens(
        _body(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "image", "source": {"url": "x"}},
                            {"type": "text", "text": "hi"},
                        ],
                    }
                ],
                "max_tokens": 10,
            }
        ),
    )
    text_only = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    assert est > text_only + 500  # the image block added a real, high cost


def test_huge_declared_max_tokens_is_honored_not_clamped() -> None:
    """A huge DECLARED max_tokens is honored as written — we never invent a
    model output bound to clamp it (would under-count exactly the big requests
    that the cap needs to catch). Denial is the cap's job, not the estimator's.
    """
    est = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10**6}),
    )
    assert est >= 10**6  # honored as declared, no invented ceiling


def test_scales_output_by_n() -> None:
    """n completions multiply the output estimate."""
    one = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 1000, "n": 1}),
    )
    four = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 1000, "n": 4}),
    )
    assert four > one * 3  # ~4x the output term


def test_missing_max_tokens_reserves_zero_for_output() -> None:
    """No declared max_tokens → reserve nothing for the unknown output. The user
    is never blocked merely for omitting an output limit (Worthless is a
    passthrough; provider/model defaults are not ours to invent). Actual output
    is billed on settle.
    """
    est = estimate_request_tokens(_body({"messages": [{"role": "user", "content": "hi" * 10}]}))
    # ~20 input chars → ~10 input tokens; output term reserves 0. No inflated bound.
    assert est < 50


def test_malformed_body_fails_high_never_zero() -> None:
    """An unparsable / non-dict body returns a high floor, never 0."""
    assert estimate_request_tokens(b"not json") > 0
    assert estimate_request_tokens(b"[]") > 0
    assert estimate_request_tokens(b"") > 0


def test_tool_call_args_are_counted() -> None:
    """OpenAI tool_calls args ride beside content (often content=null) — charged."""
    base = estimate_request_tokens(
        _body({"messages": [{"role": "assistant", "content": None}], "max_tokens": 10}),
    )
    with_calls = estimate_request_tokens(
        _body(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {"id": "c1", "function": {"name": "f", "arguments": "A" * 2000}}
                        ],
                    }
                ],
                "max_tokens": 10,
            }
        ),
    )
    assert with_calls > base + 500


def test_tool_result_text_counted_not_flat() -> None:
    """A large tool_result block is counted by length, not a flat floor."""
    est = estimate_request_tokens(
        _body(
            {
                "messages": [
                    {"role": "user", "content": [{"type": "tool_result", "content": "R" * 8000}]}
                ],
                "max_tokens": 10,
            }
        ),
    )
    assert est > 3000  # 8000 chars / 2 ≈ 4000, far above a flat 1024 floor


def test_functions_key_charged_like_tools() -> None:
    """The legacy OpenAI `functions` field is charged, not a free bypass."""
    base = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    with_functions = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": "hi"}],
                "functions": [{"name": "f", "description": "D" * 2000}],
                "max_tokens": 10,
            }
        ),
    )
    assert with_functions > base + 500


def test_system_as_block_list_charged() -> None:
    """Anthropic `system` as a list of text blocks is charged."""
    base = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    est = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": "hi"}],
                "system": [{"type": "text", "text": "S" * 2000}],
                "max_tokens": 10,
            }
        ),
    )
    assert est > base + 500


def test_content_list_of_plain_strings_charged() -> None:
    """Content as a list of bare strings is charged, not skipped."""
    est = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": ["A" * 2000]}], "max_tokens": 10}),
    )
    assert est > 500


def test_non_dict_message_does_not_crash() -> None:
    """A non-dict message (raw string / number / None) is skipped, no crash."""
    assert estimate_request_tokens(_body({"messages": ["raw", 42, None], "max_tokens": 10})) > 0


def test_negative_and_non_int_n_treated_as_one() -> None:
    """n must be a positive int; anything else falls back to 1 (no free output)."""
    one = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 1000, "n": 1}),
    )
    for bad_n in (-5, 0, "4", 2.0):
        got = estimate_request_tokens(
            _body(
                {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 1000, "n": bad_n}
            ),
        )
        assert got == one


def test_invalid_max_tokens_reserves_zero_for_output() -> None:
    """An invalid max_tokens (negative / string / float) is treated as absent —
    we count only what's literally declared, and reserve 0 for the output.
    """
    for bad in (-1, "100", 2.0):
        est = estimate_request_tokens(
            _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": bad}),
        )
        # ~1 input token; output reserves 0 because max_tokens was not a valid int.
        assert est < 50


@settings(max_examples=60, deadline=None)
@given(
    text=st.text(max_size=300),
    n=st.integers(min_value=0, max_value=8),
    mt=st.integers(min_value=0, max_value=20000),
)
def test_property_estimate_nonneg_and_monotonic_in_input(text: str, n: int, mt: int) -> None:
    """Fuzzed: the estimate is non-negative and never decreases as input grows."""

    def est(content: str) -> int:
        return estimate_request_tokens(
            _body({"messages": [{"role": "user", "content": content}], "n": n, "max_tokens": mt}),
        )

    base = est(text)
    assert base >= 0
    assert est(text + "x" * 100) >= base  # more input never lowers the estimate


def test_max_completion_tokens_honored_for_modern_openai() -> None:
    """Modern OpenAI sends max_completion_tokens, not max_tokens — honor it
    rather than over-reserving to the ceiling."""
    est = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_completion_tokens": 50}),
    )
    assert est < 500  # honored (~50), not fallen back to the ceiling (4096)


def test_image_block_floors_exactly() -> None:
    """An image block adds exactly the image floor over the same text content."""
    img = estimate_request_tokens(
        _body(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "image", "source": {"url": "x"}},
                            {"type": "text", "text": "hi"},
                        ],
                    }
                ],
                "max_tokens": 10,
            }
        ),
    )
    txt = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
                "max_tokens": 10,
            }
        ),
    )
    assert img - txt == 1600


def test_dict_shaped_content_is_counted() -> None:
    """A single content block sent as an OBJECT (not a list) must be counted —
    the headline attack's sibling shape that both providers accept."""
    est = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": {"type": "text", "text": "R" * 200_000}}],
                "max_tokens": 1,
            }
        ),
    )
    assert est > 10_000  # not the ~1 the dict-content bluff used to return


def test_unknown_and_nonstring_text_blocks_counted_by_length() -> None:
    """A text block with a NON-string `text`, and unknown block types, fall to the
    serialised-length catch-all — never silently dropped. (A text block's string
    `text` is the only field a provider bills, so sibling keys are intentionally
    not counted; the provider ignores them upstream too.)"""
    nonstr = estimate_request_tokens(
        _body(
            {
                "messages": [{"role": "user", "content": [{"type": "text", "text": ["A" * 8000]}]}],
                "max_tokens": 1,
            }
        ),
    )
    unknown = estimate_request_tokens(
        _body(
            {
                "messages": [
                    {"role": "user", "content": [{"type": "input_audio", "data": "A" * 8000}]}
                ],
                "max_tokens": 1,
            }
        ),
    )
    assert nonstr > 3000  # ~8000 serialised chars / 2, not dropped to ~0
    assert unknown > 3000


def test_unexpected_scalar_content_counted_not_dropped() -> None:
    """A message `content` that is an unexpected scalar (int/bool) is serialised and
    counted (fail-high), not silently dropped to 0 — CodeRabbit on #277."""
    # content is a bare scalar (not str/list/dict) — exercises the fail-high path
    est = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": 10**18}], "max_tokens": 0}),
    )
    assert est >= 5  # ~19 serialised chars / 2, well above the never-0 floor


def test_empty_valid_request_never_zero() -> None:
    """A valid but empty request (no content, max_tokens=0) still estimates >=1 — the
    'never 0' invariant holds for valid payloads too, not just malformed ones."""
    assert estimate_request_tokens(_body({"messages": [], "max_tokens": 0})) == 1


def test_absent_fields_do_not_inflate() -> None:
    """Genuinely absent system/prompt/input stay at 0 chars — the fail-high serialise
    path must not count a missing field as the string 'null'."""
    bare = estimate_request_tokens(
        _body({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}),
    )
    assert bare < 20  # ~1 input token + 1 output token, no phantom 'null' chars


def test_top_level_prompt_and_input_counted() -> None:
    """Legacy `prompt` / Responses-API `input` at the top level are charged."""
    for key in ("prompt", "input"):
        est = estimate_request_tokens(_body({key: "R" * 200_000, "max_tokens": 1}))
        assert est > 10_000

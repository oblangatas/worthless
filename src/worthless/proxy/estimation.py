"""Request-cost estimator for the spend cap (WOR-659 Task 3).

``estimate = input + n * min(max_tokens, ceiling)``. Input char-counts messages
(content + tool-call args) + system + tools + top-level prompt. A text block
counts its ``text`` (the only field a provider bills there); unknown block types
count their full serialised length; images floor high. An unparseable body fails
high, never 0. An *admission* estimate — the ledger settles to the provider's
actual usage afterwards.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["estimate_request_tokens"]

# Conservative char→token ratio. Dense text (CJK / code / base64) runs ~1 token
# per char, so we stay well below 4; the ledger settles to the actual usage.
_CHARS_PER_TOKEN = 2
_IMAGE_BLOCK_TYPES = frozenset({"image", "image_url", "input_image"})
_IMAGE_BLOCK_TOKENS = 1600  # cover Anthropic (~1600) / OpenAI high-detail tiling
_MALFORMED_FLOOR_TOKENS = 4096  # unparseable body → fail high, never 0


def _walk_content(value: Any) -> tuple[int, int]:
    """Return (text_chars, image_block_count) for a message/system content."""
    if isinstance(value, str):
        return len(value), 0
    if isinstance(value, dict):
        value = [value]  # a single content block sent as an object, not a list
    if value is None:
        return 0, 0  # genuinely absent field
    if not isinstance(value, list):
        return len(json.dumps(value)), 0  # unexpected scalar → fail high, count serialised
    chars = images = 0
    for block in value:
        if isinstance(block, str):
            chars += len(block)
        elif isinstance(block, dict):
            btype = block.get("type")
            if btype == "text" and isinstance(block.get("text"), str):
                # a provider bills only `text` here; sibling keys are ignored upstream too
                chars += len(block["text"])
            elif btype in _IMAGE_BLOCK_TYPES:
                images += 1
            else:
                # non-str text / tool_use / tool_result / unknown → full serialised length
                chars += len(json.dumps(block))
    return chars, images


def _count_chars_and_images(payload: dict[str, Any]) -> tuple[int, int]:
    """Sum input chars + image blocks across messages, system, tools, and the
    top-level prompt — every field that bills as input."""
    chars = images = 0
    for msg in payload.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        c, b = _walk_content(msg.get("content"))
        chars += c
        images += b
        # OpenAI tool-call args ride alongside content (often content=null).
        for key in ("tool_calls", "function_call"):
            v = msg.get(key)
            if v is not None:
                chars += len(json.dumps(v))
    c, b = _walk_content(payload.get("system"))
    chars += c
    images += b
    tools = payload.get("tools") or payload.get("functions")
    if tools is not None:
        chars += len(json.dumps(tools))
    # Legacy completions / Responses API carry the prompt at the top level.
    for key in ("prompt", "input"):
        c, b = _walk_content(payload.get(key))
        chars += c
        images += b
    return chars, images


def _resolve_output_units(payload: dict[str, Any], max_output_ceiling: int) -> tuple[int, int]:
    """(n, capped_max_tokens) — both validated; invalid/absent values assume the worst."""
    n = payload.get("n", 1)
    if not isinstance(n, int) or n < 1:
        n = 1
    max_tokens = payload.get("max_tokens")
    if not isinstance(max_tokens, int) or max_tokens < 0:
        max_tokens = payload.get("max_completion_tokens")  # modern OpenAI o-series
    if not isinstance(max_tokens, int) or max_tokens < 0:
        max_tokens = max_output_ceiling  # absent/invalid → assume the worst
    return n, min(max_tokens, max_output_ceiling)


def estimate_request_tokens(body: bytes, *, max_output_ceiling: int) -> int:
    """Estimate a request's token cost for the spend cap. Fails high, never 0."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return _MALFORMED_FLOOR_TOKENS
    if not isinstance(payload, dict):
        return _MALFORMED_FLOOR_TOKENS

    chars, images = _count_chars_and_images(payload)
    input_tokens = math.ceil(chars / _CHARS_PER_TOKEN) + images * _IMAGE_BLOCK_TOKENS
    n, max_tokens = _resolve_output_units(payload, max_output_ceiling)
    return max(input_tokens + n * max_tokens, 1)  # never 0, even for an empty valid request

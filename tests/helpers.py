"""Shared test helpers for the worthless test suite."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Scanner-safe fake key generators
# ---------------------------------------------------------------------------
# Generate deterministic high-entropy keys at runtime so literal API-key
# patterns never appear in source — avoids tripping ``worthless scan``,
# GitHub secret scanning, or any other regex-based secret detector.
# ---------------------------------------------------------------------------


def fake_key(prefix: str, seed: str = "test-fixture-seed") -> str:
    """Generate a deterministic high-entropy fake key at runtime."""
    raw = hashlib.sha256(seed.encode()).digest()
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")[:48]
    return prefix + body


def fake_openai_key() -> str:
    return fake_key("sk-" + "proj-")


def fake_anthropic_key() -> str:
    return fake_key("sk-" + "ant-" + "api03-", seed="anthropic-fixture-seed")


class MockAsyncByteStream(httpx.AsyncByteStream):
    """Mock async byte stream that yields chunks one at a time."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def verify_upstream_response_openai(data: dict) -> None:
    """Assert 200/429 from an OpenAI-protocol upstream and 'choices' on 200."""
    status = data["status"]
    body = data.get("body", {})
    assert status in (200, 429), (
        f"Expected 200 or 429 from OpenAI-protocol upstream, got {status}. body: {body}"
    )
    if status == 200:
        assert "choices" in body, f"Missing 'choices' in 200 response: {body}"


def verify_upstream_response_anthropic(data: dict) -> None:
    """Assert 200/429/529 from an Anthropic-protocol upstream and 'content' on 200."""
    status = data["status"]
    body = data.get("body", {})
    assert status in (200, 429, 529), (
        f"Expected 200/429/529 from Anthropic upstream, got {status}. body: {body}"
    )
    if status == 200:
        assert "content" in body, f"Missing 'content' in 200 response: {body}"


def make_streaming_response(
    chunks: list[bytes],
    status_code: int = 200,
    headers: dict[str, Any] | None = None,
) -> httpx.Response:
    """Create a mock httpx.Response that streams SSE chunks."""
    _headers = {"content-type": "text/event-stream"}
    if headers:
        _headers.update(headers)
    stream = MockAsyncByteStream(chunks)
    return httpx.Response(
        status_code=status_code,
        headers=_headers,
        stream=stream,
    )

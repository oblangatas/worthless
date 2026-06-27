"""Adapter contracts for provider request/response transformation."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Protocol

import httpx

INTERNAL_HEADER_PREFIX = "x-worthless-"

# RFC 2616 hop-by-hop headers that must not be forwarded by proxies.
_HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "connection",
        "transfer-encoding",
        "te",
        "upgrade",
        "proxy-authorization",
        "host",
        "keep-alive",
        "trailer",
        "proxy-connection",
    }
)

SSE_RESPONSE_HEADERS: dict[str, str] = {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


_SENSITIVE_HEADER_KEYS: frozenset[str] = frozenset({"authorization", "x-api-key"})


@dataclass(frozen=True)
class AdapterRequest:
    """Upstream request prepared by a provider adapter."""

    url: str
    headers: dict[str, str]
    body: bytes

    def __repr__(self) -> str:
        redacted: dict[str, str] = {}
        for k, v in self.headers.items():
            if k.lower() in _SENSITIVE_HEADER_KEYS:
                redacted[k] = "REDACTED"
            else:
                redacted[k] = v
        return (
            f"AdapterRequest(url={self.url!r}, headers={redacted!r}, body=<{len(self.body)} bytes>)"
        )


@dataclass(frozen=True)
class AdapterResponse:
    """Upstream response relayed by a provider adapter."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    is_streaming: bool = False
    stream: AsyncIterator[bytes] | None = field(default=None, compare=False)

    def __repr__(self) -> str:
        return (
            f"AdapterResponse(status_code={self.status_code}, "
            f"headers=<{len(self.headers)} entries>, "
            f"body=<{len(self.body)} bytes>, "
            f"is_streaming={self.is_streaming})"
        )


class ProviderAdapter(Protocol):
    """Protocol that all provider adapters must satisfy."""

    def prepare_request(
        self,
        *,
        body: bytes,
        headers: dict[str, str],
        api_key: bytearray,
        base_url: str,
    ) -> AdapterRequest: ...

    async def relay_response(self, response: httpx.Response) -> AdapterResponse: ...


def strip_internal_headers(headers: dict[str, str]) -> dict[str, str]:
    """Copy headers, dropping x-worthless-*, hop-by-hop headers, and lowercasing keys."""
    return {
        low: v
        for k, v in headers.items()
        if not (low := k.lower()).startswith(INTERNAL_HEADER_PREFIX)
        and low not in _HOP_BY_HOP_HEADERS
    }


# Headers that describe the encoding/framing of THIS specific transfer.
# Once httpx auto-decompresses upstream body via aread()/aiter_bytes(),
# the original Content-Encoding no longer matches the forwarded bytes;
# Content-Length is wrong for the same reason. Strip both so the SDK
# client doesn't try to gunzip plain JSON (M2 / Blocker #3 / 8rqs PR #127).
# worthless-yo9o (P2 follow-up) deepens this to true raw passthrough.
_BODY_ENCODING_HEADERS = frozenset({"content-encoding", "content-length"})


def _filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop body-encoding headers that no longer match the (decompressed) body."""
    return {k: v for k, v in headers.items() if k.lower() not in _BODY_ENCODING_HEADERS}


async def relay_response(response: httpx.Response) -> AdapterResponse:
    """Shared relay logic for all adapters — handles streaming and non-streaming.

    Supports responses sent with stream=True: for non-SSE responses, reads the
    body with aread() before accessing content.
    """
    content_type = response.headers.get("content-type", "")
    ct_main = content_type.split(";")[0].strip().lower()
    if ct_main == "text/event-stream":
        return AdapterResponse(
            status_code=response.status_code,
            headers=dict(SSE_RESPONSE_HEADERS),
            body=b"",
            is_streaming=True,
            stream=response.aiter_bytes(),
        )
    # For non-streaming: read body if sent with stream=True
    if not hasattr(response, "_content"):
        await response.aread()
    return AdapterResponse(
        status_code=response.status_code,
        headers=_filter_response_headers(dict(response.headers)),
        body=response.content,
        is_streaming=False,
    )

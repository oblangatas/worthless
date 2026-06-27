"""OpenAI provider adapter — stateless request/response transformer."""

from __future__ import annotations

import json

import httpx

from worthless.adapters.types import (
    AdapterRequest,
    AdapterResponse,
    relay_response,
    strip_internal_headers,
)


def _inject_include_usage(body: bytes) -> bytes:
    """Ensure streaming requests receive a final usage chunk for metering.

    OpenAI only emits token counts in the SSE stream when
    ``stream_options.include_usage`` is ``true`` (WOR-240).

    Skipped when the request carries ``tools``: modifying the body of a
    tool-call request causes OpenAI to return 400. Streaming tool-call
    metering is a known gap tracked in WOR-500.

    Returns the original ``body`` bytes unchanged when no injection is needed
    so callers can detect the no-op via byte identity and skip Content-Length
    removal.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body

    if not isinstance(payload, dict) or not payload.get("stream"):
        return body

    # Don't touch tool-call requests — body modification causes OpenAI 400.
    if payload.get("tools"):
        return body

    # Already set — return original bytes unchanged.
    if payload.get("stream_options", {}).get("include_usage"):
        return body

    payload.setdefault("stream_options", {})["include_usage"] = True
    return json.dumps(payload).encode()


class OpenAIAdapter:
    """Transforms requests for the OpenAI chat completions API."""

    def prepare_request(
        self,
        *,
        body: bytes,
        headers: dict[str, str],
        api_key: bytearray,
        base_url: str,
    ) -> AdapterRequest:
        out_headers = strip_internal_headers(headers)
        out_headers["authorization"] = f"Bearer {api_key.decode()}"
        new_body = _inject_include_usage(body)
        if new_body is not body:
            # Body was modified: stale Content-Length must be removed so
            # httpx recalculates it from the actual byte count.
            out_headers.pop("content-length", None)
        url = f"{base_url.rstrip('/')}/chat/completions"
        return AdapterRequest(url=url, headers=out_headers, body=new_body)

    async def relay_response(self, response: httpx.Response) -> AdapterResponse:
        return await relay_response(response)

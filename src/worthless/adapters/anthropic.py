"""Anthropic provider adapter — stateless request/response transformer."""

from __future__ import annotations

import httpx

from worthless.adapters.types import (
    AdapterRequest,
    AdapterResponse,
    relay_response,
    strip_internal_headers,
)

DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter:
    """Transforms requests for the Anthropic messages API."""

    def prepare_request(
        self,
        *,
        body: bytes,
        headers: dict[str, str],
        api_key: bytearray,
        base_url: str,
    ) -> AdapterRequest:
        out_headers = strip_internal_headers(headers)
        out_headers["x-api-key"] = api_key.decode()

        if "anthropic-version" not in out_headers:
            out_headers["anthropic-version"] = DEFAULT_ANTHROPIC_VERSION

        url = f"{base_url.rstrip('/')}/messages"
        return AdapterRequest(url=url, headers=out_headers, body=body)

    async def relay_response(self, response: httpx.Response) -> AdapterResponse:
        return await relay_response(response)

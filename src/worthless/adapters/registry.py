"""Path-based adapter lookup."""

from __future__ import annotations

from worthless.adapters.anthropic import AnthropicAdapter
from worthless.adapters.openai import OpenAIAdapter
from worthless.adapters.types import ProviderAdapter

_ADAPTERS: dict[str, ProviderAdapter] = {
    "/v1/chat/completions": OpenAIAdapter(),
    "/v1/messages": AnthropicAdapter(),
}


def get_adapter(path: str) -> ProviderAdapter | None:
    """Return the adapter for the given request path, or None if unrecognized."""
    return _ADAPTERS.get(path)

"""Tests for adapter bytearray migration — api_key: str -> bytearray (SR-01)."""

from __future__ import annotations

from worthless.adapters.anthropic import AnthropicAdapter
from worthless.adapters.openai import OpenAIAdapter


class TestOpenAIAdapterBytearray:
    """OpenAI adapter accepts bytearray api_key and produces correct headers."""

    def test_prepare_request_with_bytearray_key(self):
        adapter = OpenAIAdapter()
        key = bytearray(b"sk-test-key-12345")
        result = adapter.prepare_request(
            body=b'{"model": "gpt-4"}',
            headers={"content-type": "application/json"},
            api_key=key,
            base_url="https://api.openai.com/v1",
        )
        assert result.headers["authorization"] == "Bearer sk-test-key-12345"

    def test_prepare_request_bytearray_not_mutated(self):
        """The adapter should not zero or mutate the key — caller owns lifecycle."""
        adapter = OpenAIAdapter()
        key = bytearray(b"sk-test-key-12345")
        original = bytes(key)
        adapter.prepare_request(
            body=b'{"model": "gpt-4"}',
            headers={},
            api_key=key,
            base_url="https://api.openai.com/v1",
        )
        assert bytes(key) == original


class TestAnthropicAdapterBytearray:
    """Anthropic adapter accepts bytearray api_key and produces correct headers."""

    def test_prepare_request_with_bytearray_key(self):
        adapter = AnthropicAdapter()
        key = bytearray(b"sk-ant-test-key-12345")
        result = adapter.prepare_request(
            body=b'{"model": "claude-3-5-sonnet"}',
            headers={"content-type": "application/json"},
            api_key=key,
            base_url="https://api.anthropic.com/v1",
        )
        assert result.headers["x-api-key"] == "sk-ant-test-key-12345"

    def test_prepare_request_bytearray_not_mutated(self):
        adapter = AnthropicAdapter()
        key = bytearray(b"sk-ant-test-key-12345")
        original = bytes(key)
        adapter.prepare_request(
            body=b'{"model": "claude-3-5-sonnet"}',
            headers={},
            api_key=key,
            base_url="https://api.anthropic.com/v1",
        )
        assert bytes(key) == original

    def test_anthropic_version_header_preserved(self):
        adapter = AnthropicAdapter()
        key = bytearray(b"sk-ant-test")
        result = adapter.prepare_request(
            body=b"{}",
            headers={},
            api_key=key,
            base_url="https://api.anthropic.com/v1",
        )
        assert "anthropic-version" in result.headers

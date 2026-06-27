"""Tests for provider adapters — PROX-01 and PROX-02."""

from __future__ import annotations

import json

import httpx
import pytest

from worthless.adapters.openai import OpenAIAdapter, _inject_include_usage
from worthless.adapters.anthropic import AnthropicAdapter
from worthless.adapters.registry import get_adapter
from worthless.adapters.types import AdapterRequest, AdapterResponse


# ---------------------------------------------------------------------------
# _inject_include_usage unit tests
# ---------------------------------------------------------------------------


class TestInjectIncludeUsage:
    """Unit tests for the stream_options.include_usage injection helper."""

    def _body(self, **kwargs) -> bytes:
        return json.dumps(kwargs).encode()

    def test_non_streaming_unchanged(self):
        """Non-streaming requests must pass through byte-identical."""
        body = self._body(model="gpt-4o", stream=False, messages=[])
        assert _inject_include_usage(body) is body

    def test_streaming_no_tools_injects(self):
        """Plain streaming without tools gets include_usage injected."""
        body = self._body(model="gpt-4o", stream=True, messages=[])
        result = _inject_include_usage(body)
        assert result is not body
        parsed = json.loads(result)
        assert parsed["stream_options"]["include_usage"] is True

    def test_streaming_with_tools_unchanged(self):
        """Streaming with tools must NOT be modified — OpenAI returns 400 otherwise."""
        tools = [{"type": "function", "function": {"name": "read", "parameters": {}}}]
        body = self._body(model="gpt-4o", stream=True, messages=[], tools=tools)
        assert _inject_include_usage(body) is body, (
            "body was modified for a tool-call request — this causes OpenAI 400"
        )

    def test_streaming_with_tools_body_not_re_serialised(self):
        """No re-serialisation on tool-call requests — bytes are identical to input."""
        tools = [{"type": "function", "function": {"name": "exec"}}]
        body = self._body(model="gpt-4o-mini", stream=True, messages=[], tools=tools)
        result = _inject_include_usage(body)
        assert result == body

    def test_already_has_include_usage_unchanged(self):
        """Idempotent: if client already set include_usage, bytes are unchanged."""
        body = self._body(
            model="gpt-4o",
            stream=True,
            messages=[],
            stream_options={"include_usage": True},
        )
        assert _inject_include_usage(body) is body

    def test_invalid_json_unchanged(self):
        """Malformed body passes through untouched."""
        body = b"not json"
        assert _inject_include_usage(body) is body

    def test_empty_body_unchanged(self):
        assert _inject_include_usage(b"") == b""

    def test_injected_body_is_valid_json(self):
        """Injected body round-trips cleanly."""
        body = self._body(model="gpt-4o", stream=True, messages=[{"role": "user", "content": "hi"}])
        result = _inject_include_usage(body)
        parsed = json.loads(result)
        assert parsed["stream_options"]["include_usage"] is True
        assert parsed["model"] == "gpt-4o"

    def test_streaming_with_empty_tools_list_injects(self):
        """Empty tools list is falsy — injection proceeds, not skipped.

        ``tools=[]`` is not a tool-call request; it carries no schemas that
        OpenAI might reject after re-serialisation. The bypass guard
        (``if payload.get("tools")``) correctly treats an empty list as
        "no tools" and allows include_usage injection.
        """
        body = self._body(model="gpt-4o", stream=True, messages=[], tools=[])
        result = _inject_include_usage(body)
        assert result is not body
        assert json.loads(result)["stream_options"]["include_usage"] is True

    def test_existing_stream_options_preserved(self):
        """Other stream_options fields survive the injection."""
        body = self._body(
            model="gpt-4o",
            stream=True,
            messages=[],
            stream_options={"other_option": True},
        )
        result = _inject_include_usage(body)
        parsed = json.loads(result)
        assert parsed["stream_options"]["include_usage"] is True
        assert parsed["stream_options"]["other_option"] is True


# ---------------------------------------------------------------------------
# OpenAI adapter
# ---------------------------------------------------------------------------


class TestOpenAIRequestTransform:
    def test_openai_request_transform(
        self, sample_openai_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={"content-type": "application/json"},
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        assert isinstance(req, AdapterRequest)
        assert req.url == "https://api.openai.com/v1/chat/completions"
        assert req.headers["authorization"] == f"Bearer {sample_api_key.decode()}"
        assert req.body == sample_openai_body

    def _tool_call_body(self) -> bytes:
        """Minimal OpenAI streaming request with tools — the exact shape that
        caused the OpenAI 400 regression (WOR-501)."""
        return json.dumps(
            {
                "model": "gpt-4o-mini",
                "stream": True,
                "messages": [{"role": "user", "content": "hello"}],
                "tools": [
                    {"type": "function", "function": {"name": "read_file", "parameters": {}}}
                ],
            }
        ).encode()

    def test_tool_call_body_passes_through_byte_identical(self):
        """Streaming tool-call requests must reach OpenAI byte-for-byte unchanged.

        Root cause of WOR-501: ``_inject_include_usage`` re-serialised the
        full request body (including 28 tools and 115 KB of schema) to add
        ``stream_options.include_usage``. OpenAI accepted the semantically
        identical JSON but returned 400 — the re-serialisation changed
        key ordering in a way OpenAI's parser rejected.

        Fix: skip injection entirely when ``tools`` is present.
        """
        adapter = OpenAIAdapter()
        body = self._tool_call_body()
        req = adapter.prepare_request(
            body=body,
            headers={"content-type": "application/json"},
            api_key=bytearray(b"sk-test"),
            base_url="https://api.openai.com/v1",
        )
        assert req.body is body, "tool-call request body was re-serialised — this causes OpenAI 400"

    def test_tool_call_request_preserves_content_length(self):
        """Content-Length header must NOT be removed for unmodified tool-call bodies.

        When the body is not modified, the original Content-Length is still
        correct. Removing it forces httpx to recalculate — harmless but
        unnecessary, and it masks whether the body was actually touched.
        """
        adapter = OpenAIAdapter()
        body = self._tool_call_body()
        req = adapter.prepare_request(
            body=body,
            headers={
                "content-type": "application/json",
                "content-length": str(len(body)),
            },
            api_key=bytearray(b"sk-test"),
            base_url="https://api.openai.com/v1",
        )
        # Body unchanged → Content-Length should survive (httpx will use it).
        assert "content-length" in req.headers

    def test_plain_streaming_removes_content_length_after_injection(self):
        """When include_usage is injected, the old Content-Length is wrong.

        The adapter must drop it so httpx recalculates from the actual
        (longer) body.
        """
        adapter = OpenAIAdapter()
        body = json.dumps(
            {
                "model": "gpt-4o",
                "stream": True,
                "messages": [{"role": "user", "content": "hi"}],
            }
        ).encode()
        req = adapter.prepare_request(
            body=body,
            headers={
                "content-type": "application/json",
                "content-length": str(len(body)),
            },
            api_key=bytearray(b"sk-test"),
            base_url="https://api.openai.com/v1",
        )
        # Body was modified (include_usage injected) → stale Content-Length removed.
        assert "content-length" not in req.headers

    def test_plain_streaming_injects_include_usage_at_adapter_level(self):
        """End-to-end: plain streaming through prepare_request gets include_usage."""
        adapter = OpenAIAdapter()
        body = json.dumps(
            {
                "model": "gpt-4o",
                "stream": True,
                "messages": [],
            }
        ).encode()
        req = adapter.prepare_request(
            body=body,
            headers={"content-type": "application/json"},
            api_key=bytearray(b"sk-test"),
            base_url="https://api.openai.com/v1",
        )
        parsed = json.loads(req.body)
        assert parsed.get("stream_options", {}).get("include_usage") is True


class TestOpenAIResponseRelay:
    @pytest.mark.asyncio
    async def test_openai_response_relay(self) -> None:
        body = b'{"id":"chatcmpl-1","choices":[]}'
        upstream = httpx.Response(
            status_code=200,
            content=body,
            headers={"content-type": "application/json"},
        )
        adapter = OpenAIAdapter()
        resp = await adapter.relay_response(upstream)
        assert isinstance(resp, AdapterResponse)
        assert resp.status_code == 200
        assert resp.body == body
        assert resp.is_streaming is False

    @pytest.mark.asyncio
    async def test_openai_error_relay(self) -> None:
        error_body = b'{"error":{"message":"rate limited","type":"rate_limit"}}'
        upstream = httpx.Response(
            status_code=429,
            content=error_body,
            headers={"content-type": "application/json"},
        )
        adapter = OpenAIAdapter()
        resp = await adapter.relay_response(upstream)
        assert resp.status_code == 429
        assert resp.body == error_body


# ---------------------------------------------------------------------------
# Anthropic adapter
# ---------------------------------------------------------------------------


class TestAnthropicRequestTransform:
    def test_anthropic_request_transform(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={"content-type": "application/json"},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert isinstance(req, AdapterRequest)
        assert req.url == "https://api.anthropic.com/v1/messages"
        assert req.headers["x-api-key"] == sample_api_key.decode()
        assert req.body == sample_anthropic_body

    def test_anthropic_version_header_default(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        """Default anthropic-version header is added when client omits it."""
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={"content-type": "application/json"},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert req.headers["anthropic-version"] == "2023-06-01"

    def test_anthropic_version_header_preserved(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        """Client-provided anthropic-version header is preserved."""
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={
                "content-type": "application/json",
                "anthropic-version": "2024-01-01",
            },
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert req.headers["anthropic-version"] == "2024-01-01"


class TestAnthropicResponseRelay:
    @pytest.mark.asyncio
    async def test_anthropic_response_relay(self) -> None:
        body = b'{"id":"msg_01","content":[{"type":"text","text":"Hello"}]}'
        upstream = httpx.Response(
            status_code=200,
            content=body,
            headers={"content-type": "application/json"},
        )
        adapter = AnthropicAdapter()
        resp = await adapter.relay_response(upstream)
        assert isinstance(resp, AdapterResponse)
        assert resp.status_code == 200
        assert resp.body == body
        assert resp.is_streaming is False

    @pytest.mark.asyncio
    async def test_anthropic_error_relay(self) -> None:
        error_body = b'{"type":"error","error":{"type":"invalid_request_error"}}'
        upstream = httpx.Response(
            status_code=400,
            content=error_body,
            headers={"content-type": "application/json"},
        )
        adapter = AnthropicAdapter()
        resp = await adapter.relay_response(upstream)
        assert resp.status_code == 400
        assert resp.body == error_body


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_get_adapter_openai(self) -> None:
        adapter = get_adapter("/v1/chat/completions")
        assert isinstance(adapter, OpenAIAdapter)

    def test_get_adapter_anthropic(self) -> None:
        adapter = get_adapter("/v1/messages")
        assert isinstance(adapter, AnthropicAdapter)

    def test_get_adapter_unknown(self) -> None:
        adapter = get_adapter("/v1/unknown")
        assert adapter is None

    def test_get_adapter_empty_path(self) -> None:
        adapter = get_adapter("")
        assert adapter is None

    def test_get_adapter_returns_singletons(self) -> None:
        """Registry returns the same adapter instance on repeated calls."""
        a1 = get_adapter("/v1/chat/completions")
        a2 = get_adapter("/v1/chat/completions")
        assert a1 is a2

    def test_get_adapter_partial_path_no_match(self) -> None:
        assert get_adapter("/v1/chat") is None
        assert get_adapter("/v1/messages/extra") is None


# ---------------------------------------------------------------------------
# Header stripping (hop-by-hop at adapter level)
# ---------------------------------------------------------------------------


class TestHopByHopStrippingAdapterLevel:
    def test_openai_strips_hop_by_hop(
        self, sample_openai_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={
                "content-type": "application/json",
                "host": "attacker.example.com",
                "transfer-encoding": "chunked",
                "connection": "close",
            },
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        for key in req.headers:
            assert key not in ("host", "transfer-encoding", "connection")

    def test_anthropic_strips_hop_by_hop(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={
                "content-type": "application/json",
                "host": "attacker.example.com",
                "proxy-authorization": "Basic evil",
            },
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        for key in req.headers:
            assert key not in ("host", "proxy-authorization")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_openai_empty_body(self, sample_api_key: bytearray) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=b"", headers={}, api_key=sample_api_key, base_url="https://api.openai.com/v1"
        )
        assert req.body == b""
        assert req.url == "https://api.openai.com/v1/chat/completions"

    def test_anthropic_empty_body(self, sample_api_key: bytearray) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=b"",
            headers={},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert req.body == b""
        assert req.url == "https://api.anthropic.com/v1/messages"

    def test_openai_unicode_body(self, sample_api_key: bytearray) -> None:
        body = '{"messages":[{"role":"user","content":"Hello \U0001f600"}]}'.encode()
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=body, headers={}, api_key=sample_api_key, base_url="https://api.openai.com/v1"
        )
        assert req.body == body

    def test_anthropic_preserves_extra_headers(self, sample_api_key: bytearray) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=b"{}",
            headers={"content-type": "application/json", "x-custom": "val"},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert req.headers["x-custom"] == "val"

    def test_openai_preserves_extra_headers(self, sample_api_key: bytearray) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=b"{}",
            headers={"content-type": "application/json", "x-custom": "val"},
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        assert req.headers["x-custom"] == "val"

    def test_openai_api_key_overrides_existing_auth(self, sample_api_key: bytearray) -> None:
        """If incoming headers contain authorization, it gets replaced."""
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=b"{}",
            headers={"authorization": "Bearer old-key"},
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        assert req.headers["authorization"] == f"Bearer {sample_api_key.decode()}"

    def test_anthropic_api_key_overrides_existing(self, sample_api_key: bytearray) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=b"{}",
            headers={"x-api-key": "old-key"},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert req.headers["x-api-key"] == sample_api_key.decode()


# ---------------------------------------------------------------------------
# Header stripping
# ---------------------------------------------------------------------------


class TestHeaderStripping:
    def test_openai_header_stripping(
        self, sample_openai_body: bytes, sample_api_key: bytearray
    ) -> None:
        """Headers matching x-worthless-* are stripped before forwarding."""
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={
                "content-type": "application/json",
                "x-worthless-trace-id": "abc123",
                "x-worthless-session": "xyz",
            },
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        for key in req.headers:
            assert not key.lower().startswith("x-worthless-")

    def test_anthropic_header_stripping(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        """Anthropic adapter also strips x-worthless-* headers."""
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={
                "content-type": "application/json",
                "x-worthless-trace-id": "abc123",
                "x-worthless-session": "xyz",
            },
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        for key in req.headers:
            assert not key.lower().startswith("x-worthless-")


# ---------------------------------------------------------------------------
# worthless-8rqs Phase 5: per-enrollment base_url
# ---------------------------------------------------------------------------


class TestPerEnrollmentBaseURL:
    """Adapters take ``base_url`` per request — the env var WORTHLESS_UPSTREAM_*
    is gone. Every prepare_request call must specify the upstream explicitly,
    and the resulting URL appends the protocol-specific path."""

    def test_openai_uses_passed_base_url(
        self, sample_openai_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={},
            api_key=sample_api_key,
            base_url="https://openrouter.ai/api/v1",
        )
        assert req.url == "https://openrouter.ai/api/v1/chat/completions"

    def test_anthropic_uses_passed_base_url(
        self, sample_anthropic_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={},
            api_key=sample_api_key,
            base_url="https://my.anthropic.example/v1",
        )
        assert req.url == "https://my.anthropic.example/v1/messages"

    def test_base_url_trailing_slash_normalized(
        self, sample_openai_body: bytes, sample_api_key: bytearray
    ) -> None:
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={},
            api_key=sample_api_key,
            base_url="https://x.example/v1/",  # trailing slash
        )
        assert req.url == "https://x.example/v1/chat/completions"

    def test_base_url_required(self, sample_openai_body: bytes, sample_api_key: bytearray) -> None:
        """Missing ``base_url`` raises TypeError — there's no default."""
        adapter = OpenAIAdapter()
        with pytest.raises(TypeError):
            adapter.prepare_request(  # type: ignore[call-arg]
                body=sample_openai_body,
                headers={},
                api_key=sample_api_key,
            )

    def test_env_var_has_no_effect_on_openai(
        self,
        sample_openai_body: bytes,
        sample_api_key: bytearray,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Anti-regression: setting the legacy env var must NOT influence the URL.
        After 8rqs the adapter does not read os.environ at all."""
        monkeypatch.setenv("WORTHLESS_UPSTREAM_OPENAI_URL", "https://attacker.example/v1")
        adapter = OpenAIAdapter()
        req = adapter.prepare_request(
            body=sample_openai_body,
            headers={},
            api_key=sample_api_key,
            base_url="https://api.openai.com/v1",
        )
        assert "attacker" not in req.url, (
            f"env var leaked into URL: {req.url} — adapter is reading os.environ"
        )
        assert req.url == "https://api.openai.com/v1/chat/completions"

    def test_env_var_has_no_effect_on_anthropic(
        self,
        sample_anthropic_body: bytes,
        sample_api_key: bytearray,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("WORTHLESS_UPSTREAM_ANTHROPIC_URL", "https://attacker.example/v1")
        adapter = AnthropicAdapter()
        req = adapter.prepare_request(
            body=sample_anthropic_body,
            headers={},
            api_key=sample_api_key,
            base_url="https://api.anthropic.com/v1",
        )
        assert "attacker" not in req.url
        assert req.url == "https://api.anthropic.com/v1/messages"

"""Tests for WOR-80 security hardening fixes.

Covers:
- worthless-1mb: Error responses metered
- worthless-9dz: /readyz no longer leaks enrollment state
- worthless-dx1: Anthropic non-streaming JSON metering
- worthless-64x: Malformed header values rejected
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import aiosqlite
import httpx
import pytest
import respx

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.metering import extract_usage_anthropic
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard

from tests._fakes import pin_shard_b


# ------------------------------------------------------------------
# Fixtures & helpers
# ------------------------------------------------------------------

PROXY_BODY = b'{"model": "gpt-4", "messages": []}'
OPENAI_COMPLETIONS = "https://api.openai.com/v1/chat/completions"


def _proxy_headers(alias: str, shard_a_utf8: str) -> dict[str, str]:
    return {
        "authorization": f"Bearer {shard_a_utf8}",
        "content-type": "application/json",
    }


def _proxy_url(alias: str, path: str = "/v1/chat/completions") -> str:
    return f"/{alias}{path}"


@pytest.fixture()
def proxy_settings(tmp_db_path: str, fernet_key: bytes, tmp_path) -> ProxySettings:
    return ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )


@pytest.fixture()
async def proxy_app(proxy_settings: ProxySettings, repo):
    app = create_app(proxy_settings)
    db = await aiosqlite.connect(proxy_settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[
            SpendCapRule(db=db),
            RateLimitRule(
                default_rps=proxy_settings.default_rate_limit_rps,
                db_path=proxy_settings.db_path,
            ),
        ]
    )
    yield app
    await app.state.httpx_client.aclose()
    await db.close()


@pytest.fixture()
async def enrolled_alias(repo, proxy_settings: ProxySettings, proxy_app):
    """Enroll a test key and return (alias, shard_a_utf8, raw_api_key).

    WOR-309: pins the per-alias plaintext shard-B onto the FakeIPCSupervisor
    attached to ``proxy_app.state.ipc_supervisor`` so the proxy's IPC-based
    decrypt round-trips to the real shard-B (the fake otherwise returns a
    DEFAULT plaintext that fails reconstruction → 401).
    """
    alias = "test-key"
    api_key = "sk-test-key-1234567890abcdef"
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")

    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.store(
        alias, shard, prefix=sr.prefix, charset=sr.charset, base_url="https://api.openai.com/v1"
    )

    pin_shard_b(proxy_app, alias, sr.shard_b)

    shard_a_utf8 = sr.shard_a.decode("utf-8")
    return alias, shard_a_utf8, api_key.encode()


@pytest.fixture()
async def proxy_client(proxy_app):
    transport = httpx.ASGITransport(app=proxy_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _make_bare_app(
    proxy_settings: ProxySettings,
    tmp_db_path: str,
    fernet_key: bytes,
    *,
    close_db: bool = False,
) -> tuple:
    """Create a minimal app with an empty repo. Returns (app, db)."""
    app = create_app(proxy_settings)
    empty_repo = ShardRepository(tmp_db_path, fernet_key)
    await empty_repo.initialize()
    db = await aiosqlite.connect(proxy_settings.db_path)
    app.state.db = db
    app.state.repo = empty_repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(rules=[])
    if close_db:
        await db.close()
    return app, db


async def _get_readyz(app) -> httpx.Response:
    """GET /readyz via ASGI transport."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/readyz")


# ------------------------------------------------------------------
# worthless-1mb: Error responses (4xx/5xx) must be metered
# ------------------------------------------------------------------


class TestErrorResponseMetering:
    """Error responses should still record spend --- upstream consumed tokens."""

    @respx.mock
    async def test_4xx_records_spend(
        self, proxy_client: httpx.AsyncClient, enrolled_alias, proxy_settings
    ):
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(
                400,
                text=json.dumps(
                    {
                        "error": {
                            "message": "invalid model",
                            "type": "invalid_request_error",
                            "param": "model",
                            "code": None,
                        },
                        "usage": {"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10},
                    }
                ),
            )
        )

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 400
        mock_record.assert_called_once()

    @respx.mock
    async def test_5xx_records_spend(
        self, proxy_client: httpx.AsyncClient, enrolled_alias, proxy_settings
    ):
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(
                500,
                json={"error": {"message": "internal error", "type": "server_error"}},
            )
        )

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 500
        mock_record.assert_called_once()

    @respx.mock
    async def test_connect_error_does_not_meter(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """502 from connection failure should NOT meter --- no tokens consumed."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(side_effect=httpx.ConnectError("Connection refused"))

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 502
        mock_record.assert_not_called()

    @respx.mock
    async def test_error_passes_correct_token_count(
        self, proxy_client: httpx.AsyncClient, enrolled_alias, proxy_settings
    ):
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(
                400,
                text=json.dumps(
                    {
                        "error": {
                            "message": "context length exceeded",
                            "type": "invalid_request_error",
                            "param": None,
                            "code": "context_length_exceeded",
                        },
                        "usage": {"prompt_tokens": 42, "completion_tokens": 0, "total_tokens": 42},
                    }
                ),
            )
        )

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 400
        mock_record.assert_called_once()
        tokens_arg = mock_record.call_args[0][2]
        assert tokens_arg == 42

    @respx.mock
    async def test_empty_body_records_zero_tokens(
        self, proxy_client: httpx.AsyncClient, enrolled_alias, proxy_settings
    ):
        """Error with empty body should still call record_spend with 0 tokens (audit trail)."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(return_value=httpx.Response(500, text=""))

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 500
        mock_record.assert_called_once()
        tokens_arg = mock_record.call_args[0][2]
        assert tokens_arg == 0

    @respx.mock
    async def test_timeout_does_not_meter(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """504 from timeout should NOT meter --- no tokens consumed."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(side_effect=httpx.ReadTimeout("Read timed out"))

        with patch("worthless.proxy.app.record_spend", new_callable=AsyncMock) as mock_record:
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 504
        mock_record.assert_not_called()

    @respx.mock
    async def test_record_spend_failure_does_not_crash_request(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """If record_spend raises, the response must still return 200 (spend silently untracked)."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 5}})
        )

        with patch(
            "worthless.proxy.app.record_spend",
            new_callable=AsyncMock,
            side_effect=Exception("DB locked"),
        ):
            resp = await proxy_client.post(
                _proxy_url(alias),
                headers=_proxy_headers(alias, shard_a_utf8),
                content=PROXY_BODY,
            )

        assert resp.status_code == 200


# ------------------------------------------------------------------
# worthless-9dz: /readyz must not leak enrollment state
# ------------------------------------------------------------------

FORBIDDEN_READYZ_WORDS = ["key", "enroll", "shard", "alias", "secret", "token"]


class TestReadyzOracle:
    """/readyz must not reveal whether keys are enrolled."""

    async def test_readyz_returns_200(self, proxy_settings: ProxySettings, tmp_db_path, fernet_key):
        app, db = await _make_bare_app(proxy_settings, tmp_db_path, fernet_key)
        resp = await _get_readyz(app)

        assert resp.status_code == 200
        body_lower = resp.text.lower()
        assert "keys" not in body_lower
        assert "enrolled" not in body_lower

        await app.state.httpx_client.aclose()
        await db.close()

    async def test_response_identical_with_or_without_keys(
        self,
        proxy_client: httpx.AsyncClient,
        enrolled_alias,
        proxy_settings: ProxySettings,
        tmp_db_path,
        fernet_key,
    ):
        resp_with = await proxy_client.get("/readyz")

        app, db = await _make_bare_app(proxy_settings, tmp_db_path, fernet_key)
        resp_without = await _get_readyz(app)
        await app.state.httpx_client.aclose()
        await db.close()

        assert resp_with.status_code == resp_without.status_code == 200
        assert resp_with.content == resp_without.content, (
            "readyz body must be byte-identical regardless of enrollment state"
        )

    async def test_body_never_leaks_enrollment_state(
        self,
        proxy_client: httpx.AsyncClient,
        enrolled_alias,
        proxy_settings: ProxySettings,
        tmp_db_path,
        fernet_key,
    ):
        resp_with = await proxy_client.get("/readyz")

        app, db = await _make_bare_app(proxy_settings, tmp_db_path, fernet_key)
        resp_without = await _get_readyz(app)
        await app.state.httpx_client.aclose()
        await db.close()

        for resp in (resp_with, resp_without):
            body_lower = resp.text.lower()
            for word in FORBIDDEN_READYZ_WORDS:
                assert word not in body_lower, f"readyz body leaks '{word}': {resp.text}"

    async def test_503_body_does_not_leak_internals(
        self, proxy_settings: ProxySettings, tmp_db_path, fernet_key
    ):
        """503 must not expose DB paths, exception traces, or internals."""
        app, _db = await _make_bare_app(proxy_settings, tmp_db_path, fernet_key, close_db=True)

        resp = await _get_readyz(app)

        assert resp.status_code == 503
        assert resp.json() == {"status": "unavailable"}
        forbidden = [
            "traceback",
            "exception",
            ".db",
            "sqlite",
            "path",
            "shard",
            "key",
            "enroll",
        ]
        body_lower = resp.text.lower()
        for word in forbidden:
            assert word not in body_lower, f"503 body leaks '{word}': {resp.text}"

        await app.state.httpx_client.aclose()

    async def test_returns_503_when_db_broken(
        self, proxy_settings: ProxySettings, tmp_db_path, fernet_key
    ):
        app, _db = await _make_bare_app(proxy_settings, tmp_db_path, fernet_key, close_db=True)

        resp = await _get_readyz(app)

        assert resp.status_code == 503
        assert resp.json()["status"] == "unavailable"

        await app.state.httpx_client.aclose()


# ------------------------------------------------------------------
# worthless-dx1: Anthropic non-streaming JSON must be metered
# ------------------------------------------------------------------


def _anthropic_json(
    *,
    usage: dict | None = None,
    model: str | None = "claude-3-5-sonnet-20241022",
    msg_type: str = "message",
    extra: dict | None = None,
) -> bytes:
    """Build an Anthropic response body for testing."""
    body: dict = {"type": msg_type}
    if model is not None:
        body["model"] = model
    if usage is not None:
        body["usage"] = usage
    if extra:
        body.update(extra)
    return json.dumps(body).encode()


class TestAnthropicNonStreamingMetering:
    """Anthropic non-streaming (JSON) responses must extract usage correctly."""

    def test_extract_input_and_output(self):
        data = _anthropic_json(usage={"input_tokens": 10, "output_tokens": 25})
        result = extract_usage_anthropic(data)
        assert result is not None
        assert result.total_tokens == 35
        assert result.model == "claude-3-5-sonnet-20241022"

    def test_no_usage_returns_none(self):
        data = _anthropic_json(
            extra={"id": "msg_123", "content": [{"type": "text", "text": "Hello"}]},
        )
        # Remove usage key entirely
        parsed = json.loads(data)
        parsed.pop("usage", None)
        result = extract_usage_anthropic(json.dumps(parsed).encode())
        assert result is None

    def test_error_json_returns_none(self):
        data = json.dumps(
            {
                "type": "error",
                "error": {"type": "invalid_request_error", "message": "bad request"},
            }
        ).encode()
        result = extract_usage_anthropic(data)
        assert result is None

    def test_only_input_tokens(self):
        data = _anthropic_json(usage={"input_tokens": 42})
        result = extract_usage_anthropic(data)
        assert result is not None
        assert result.total_tokens == 42

    def test_only_output_tokens(self):
        data = _anthropic_json(usage={"output_tokens": 17})
        result = extract_usage_anthropic(data)
        assert result is not None
        assert result.total_tokens == 17

    def test_zero_tokens(self):
        data = _anthropic_json(usage={"input_tokens": 0, "output_tokens": 0})
        result = extract_usage_anthropic(data)
        assert result is not None, "Zero-token usage must return UsageInfo, not None"
        assert result.total_tokens == 0

    def test_no_model_field(self):
        data = _anthropic_json(usage={"input_tokens": 5, "output_tokens": 10}, model=None)
        result = extract_usage_anthropic(data)
        assert result is not None
        assert result.total_tokens == 15
        assert result.model is None

    def test_sse_still_parses(self):
        """SSE responses that start with valid JSON still parse correctly."""
        sse_data = (
            b"event: message_start\n"
            b"data: "
            + json.dumps(
                {
                    "type": "message_start",
                    "message": {
                        "model": "claude-3-5-sonnet-20241022",
                        "usage": {"input_tokens": 10},
                    },
                }
            ).encode()
            + b"\n\n"
            b"event: message_delta\n"
            b"data: "
            + json.dumps({"type": "message_delta", "usage": {"output_tokens": 20}}).encode()
            + b"\n\n"
        )
        result = extract_usage_anthropic(sse_data)
        assert result is not None
        assert result.total_tokens == 30


# ------------------------------------------------------------------
# worthless-64x: Malformed header values (null/CR/LF) rejected
# ------------------------------------------------------------------


def _make_asgi_scope(
    headers: list[tuple[bytes, bytes]], path: str = "/test-key/v1/chat/completions"
) -> dict:
    """Build a raw ASGI scope for POST /<alias>/v1/chat/completions."""
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "query_string": b"",
        "headers": headers,
        "scheme": "http",
        "root_path": "",
    }


async def _invoke_asgi(app, scope: dict) -> int:
    """Invoke the ASGI app and return the HTTP status code."""
    status_code = None

    async def receive():
        return {"type": "http.request", "body": PROXY_BODY, "more_body": False}

    async def send(message):
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = message["status"]

    await app(scope, receive, send)
    assert status_code is not None, "ASGI app did not send http.response.start"
    return status_code


def _asgi_headers(alias: str, shard_a_utf8: str, extra: list[tuple[bytes, bytes]] | None = None):
    """Build ASGI header list with Authorization: Bearer and optional extras."""
    headers = [
        (b"authorization", f"Bearer {shard_a_utf8}".encode()),
        (b"content-type", b"application/json"),
    ]
    if extra:
        headers.extend(extra)
    return headers


class TestMalformedHeaderValues:
    """Header values containing null bytes or CRLF should be rejected."""

    @pytest.mark.parametrize(
        "bad_value",
        ["test\x00value", "test\rvalue", "test\nvalue"],
        ids=["null", "cr", "lf"],
    )
    async def test_malformed_value_rejected(self, proxy_app, enrolled_alias, bad_value):
        """Uses raw ASGI scope to bypass httpx client-side header validation."""
        alias, shard_a_utf8, _ = enrolled_alias
        scope = _make_asgi_scope(
            _asgi_headers(alias, shard_a_utf8, [(b"x-custom", bad_value.encode("latin-1"))]),
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 401

    async def test_null_in_authorization_rejected(self, proxy_app, enrolled_alias):
        alias, shard_a_utf8, _ = enrolled_alias
        scope = _make_asgi_scope(
            [
                (b"authorization", f"Bearer {shard_a_utf8}\x00".encode("latin-1")),
                (b"content-type", b"application/json"),
            ],
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 401

    async def test_crlf_injection_rejected(self, proxy_app, enrolled_alias):
        alias, shard_a_utf8, _ = enrolled_alias
        scope = _make_asgi_scope(
            _asgi_headers(alias, shard_a_utf8, [(b"x-custom", b"inject\r\nX-Evil: true")]),
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 401

    async def test_bare_null_byte_rejected(self, proxy_app, enrolled_alias):
        alias, shard_a_utf8, _ = enrolled_alias
        scope = _make_asgi_scope(
            _asgi_headers(alias, shard_a_utf8, [(b"x-custom", b"\x00")]),
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 401

    @respx.mock
    async def test_empty_value_passes(self, proxy_app, enrolled_alias):
        """Empty string header value is valid and must not be rejected."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 5}})
        )
        scope = _make_asgi_scope(
            _asgi_headers(alias, shard_a_utf8, [(b"x-custom", b"")]),
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 200

    @respx.mock
    async def test_tab_value_passes(self, proxy_app, enrolled_alias):
        """Tab character in header value is valid per RFC 7230."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 5}})
        )
        scope = _make_asgi_scope(
            _asgi_headers(alias, shard_a_utf8, [(b"x-custom", b"value\twith\ttabs")]),
            path=f"/{alias}/v1/chat/completions",
        )
        assert await _invoke_asgi(proxy_app, scope) == 200

    @respx.mock
    async def test_normal_values_pass(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Legitimate header values must not be rejected (false-positive check)."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post(OPENAI_COMPLETIONS).mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 5}})
        )
        headers = _proxy_headers(alias, shard_a_utf8)
        headers.update(
            {
                "x-custom": "perfectly-normal-value",
                "x-another": "value with spaces and symbols !@#$%",
            }
        )
        resp = await proxy_client.post(
            _proxy_url(alias),
            headers=headers,
            content=PROXY_BODY,
        )
        assert resp.status_code == 200

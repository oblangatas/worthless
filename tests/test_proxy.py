"""Integration tests for the Worthless proxy — gate-before-reconstruct pipeline.

Tests prove the three architectural invariants:
1. Gate-before-reconstruct (CRYP-05): rules engine runs BEFORE reconstruct_key
2. Transparent routing (PROX-04): correct upstream URL/headers per provider
3. Server-side reconstruction (PROX-05): key never in response
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import aiosqlite
import httpx
import pytest
import respx

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.errors import ErrorResponse
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import StoredShard

from tests._fakes import pin_shard_b


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def proxy_settings(tmp_db_path: str, fernet_key: bytes, tmp_path) -> ProxySettings:
    """ProxySettings pointing at a temp DB with insecure mode on (no TLS needed)."""
    return ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )


@pytest.fixture()
async def enrolled_alias(repo, proxy_settings: ProxySettings, proxy_app):
    """Enroll a test key and return (alias, shard_a_utf8, raw_api_key).

    Also pins the alias's plaintext shard-B onto the autouse FakeIPCSupervisor
    attached to ``proxy_app.state.ipc_supervisor``. Without this pin the fake
    returns its default plaintext, reconstruction yields the wrong API key,
    and every routing test that depends on real reconstruction returns 401.
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
async def proxy_app(proxy_settings: ProxySettings, repo):
    """A proxy app with state pre-initialized (ASGITransport skips lifespan)."""
    app = create_app(proxy_settings)
    # Manually set up state since ASGITransport doesn't run lifespan
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
async def proxy_client(proxy_app):
    """httpx.AsyncClient wired to the proxy app via ASGITransport."""
    transport = httpx.ASGITransport(app=proxy_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ------------------------------------------------------------------
# Health endpoints (no auth required)
# ------------------------------------------------------------------


class TestExtractAliasAndPath:
    """Unit tests for _extract_alias_and_path — URL path parsing (SR-09)."""

    def test_valid_alias_and_path(self):
        from worthless.proxy.app import _extract_alias_and_path

        result = _extract_alias_and_path("/my-alias/v1/chat/completions")
        assert result == ("my-alias", "/v1/chat/completions")

    def test_alias_with_underscores_and_digits(self):
        from worthless.proxy.app import _extract_alias_and_path

        result = _extract_alias_and_path("/openai_key-12ab/v1/models")
        assert result == ("openai_key-12ab", "/v1/models")

    def test_no_path_after_alias_returns_none(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("/onlyone") is None

    def test_empty_path_returns_none(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("/") is None

    def test_bare_empty_returns_none(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("") is None

    def test_invalid_alias_chars_returns_none(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("/bad..alias/v1/foo") is None

    def test_path_traversal_rejected(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("/../etc/passwd") is None

    def test_leading_trailing_slashes_stripped(self):
        from worthless.proxy.app import _extract_alias_and_path

        result = _extract_alias_and_path("///alias///v1/foo")
        # After strip("/") and split("/", 1): first segment is empty string
        # because "///alias///v1/foo".strip("/") = "alias///v1/foo"
        assert result is not None
        assert result[0] == "alias"

    def test_special_chars_in_alias_rejected(self):
        from worthless.proxy.app import _extract_alias_and_path

        assert _extract_alias_and_path("/al!as/v1/foo") is None
        assert _extract_alias_and_path("/al@as/v1/foo") is None
        assert _extract_alias_and_path("/al as/v1/foo") is None


class TestHealthEndpoints:
    async def test_root_returns_ok(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.get("/")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_healthz_returns_ok(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    async def test_healthz_includes_requests_proxied(self, proxy_client: httpx.AsyncClient):
        """GET /healthz must return an integer requests_proxied field."""
        resp = await proxy_client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert "requests_proxied" in data
        assert isinstance(data["requests_proxied"], int)
        assert data["requests_proxied"] >= 0

    async def test_healthz_count_increments_after_spend_log(
        self, proxy_app, proxy_client: httpx.AsyncClient
    ):
        """After inserting a spend_log row, /healthz count should reflect it."""
        # Insert a spend_log row directly
        db = proxy_app.state.db
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            ("test-key", 100, "gpt-4", "openai"),
        )
        await db.commit()

        resp = await proxy_client.get("/healthz")
        data = resp.json()
        assert data["requests_proxied"] >= 1

    async def test_readyz_returns_200_when_no_keys(
        self, proxy_settings: ProxySettings, tmp_db_path, fernet_key
    ):
        """readyz returns 200 even with no keys — must not leak enrollment state."""
        from worthless.proxy.rules import RulesEngine
        from worthless.storage.repository import ShardRepository

        app = create_app(proxy_settings)
        empty_repo = ShardRepository(tmp_db_path, fernet_key)
        await empty_repo.initialize()
        db = await aiosqlite.connect(proxy_settings.db_path)
        app.state.db = db
        app.state.repo = empty_repo
        app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
        app.state.rules_engine = RulesEngine(rules=[])

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/readyz")
            assert resp.status_code == 200
        await app.state.httpx_client.aclose()
        await db.close()

    async def test_readyz_returns_200_with_keys(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        resp = await proxy_client.get("/readyz")
        assert resp.status_code == 200


# ------------------------------------------------------------------
# Auth — uniform 401 (anti-enumeration)
# ------------------------------------------------------------------


class TestUniformAuth:
    async def test_missing_alias_returns_401(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.post("/v1/chat/completions", content=b"{}")
        assert resp.status_code == 401

    async def test_unknown_alias_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        resp = await proxy_client.post(
            "/nonexistent/v1/chat/completions",
            headers={"authorization": "Bearer fake-shard-a"},
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_missing_bearer_returns_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        alias, _, _ = enrolled_alias
        # Request with alias in URL but no Authorization header
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_all_401_bodies_identical(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """All auth failure modes must return the same body (anti-enumeration)."""
        # Missing alias
        r1 = await proxy_client.post("/v1/chat/completions", content=b"{}")
        # Unknown alias
        r2 = await proxy_client.post(
            "/nonexistent/v1/chat/completions",
            headers={"authorization": "Bearer fake-shard-a"},
            content=b"{}",
        )
        assert r1.status_code == r2.status_code == 401
        assert r1.content == r2.content

    async def test_alias_path_traversal_rejected(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.post(
            "/..%2F..%2Fetc%2Fpasswd/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )
        assert resp.status_code == 401


# ------------------------------------------------------------------
# Gate-before-reconstruct (CRYP-05)
# ------------------------------------------------------------------


class TestGateBeforeReconstruct:
    @pytest.mark.parametrize(
        "status_code, error_body, extra_headers",
        [
            (402, b'{"error": "spend cap exceeded"}', {}),
            (429, b'{"error": "rate limit exceeded"}', {"Retry-After": "1"}),
        ],
        ids=["spend-cap", "rate-limit"],
    )
    @respx.mock
    async def test_denial_skips_reconstruct(
        self, proxy_app, enrolled_alias, status_code, error_body, extra_headers
    ):
        """When rules engine denies, reconstruct_key is never called."""
        alias, shard_a_utf8, _ = enrolled_alias

        with patch("worthless.proxy.app.reconstruct_key_fp", wraps=None) as mock_reconstruct:
            proxy_app.state.rules_engine = type(
                "MockEngine",
                (),
                {
                    "evaluate": AsyncMock(
                        return_value=ErrorResponse(
                            status_code=status_code,
                            body=error_body,
                            headers={"content-type": "application/json", **extra_headers},
                        )
                    ),
                    "release_spend_reservation": AsyncMock(return_value=None),
                },
            )()

            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={"authorization": f"Bearer {shard_a_utf8}"},
                    content=b'{"model": "gpt-4", "messages": []}',
                )
            assert resp.status_code == status_code
            mock_reconstruct.assert_not_called()

    @respx.mock
    async def test_rules_pass_then_reconstruct_called(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """When rules engine passes, key IS reconstructed and upstream called."""
        alias, shard_a_utf8, _ = enrolled_alias

        # Mock upstream to return a response
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "hi"}}], "usage": {"total_tokens": 10}},
            )
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200


# ------------------------------------------------------------------
# Transparent routing (PROX-04)
# ------------------------------------------------------------------


class TestTransparentRouting:
    @respx.mock
    async def test_openai_path_routes_to_openai(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        alias, shard_a_utf8, _ = enrolled_alias

        route = respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert route.called

    @respx.mock
    async def test_anthropic_path_routes_to_anthropic(
        self, repo, proxy_settings: ProxySettings, proxy_app
    ):
        """Enroll an Anthropic key and verify routing."""
        api_key = "sk-ant-test-key-12345678901234"
        sr = split_key_fp(api_key, prefix="sk-ant-", provider="anthropic")

        shard = StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider="anthropic",
        )
        await repo.store(
            "ant-key",
            shard,
            prefix=sr.prefix,
            charset=sr.charset,
            base_url="https://api.anthropic.com/v1",
        )

        pin_shard_b(proxy_app, "ant-key", sr.shard_b)

        shard_a_utf8 = sr.shard_a.decode("utf-8")

        route = respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(
                200,
                json={"content": [], "usage": {"output_tokens": 5}},
            )
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                "/ant-key/v1/messages",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "claude-3-5-sonnet-20241022", "max_tokens": 10}',
            )
        assert route.called

    async def test_unknown_path_returns_401_anti_enumeration(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Unknown paths return uniform 401, not 404 (H-2/M-3 anti-enumeration)."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/unknown",
            headers={"authorization": f"Bearer {shard_a_utf8}"},
            content=b"{}",
        )
        assert resp.status_code == 401


# ------------------------------------------------------------------
# Server-side reconstruction (PROX-05) — key never in response
# ------------------------------------------------------------------


class TestKeyNotInResponse:
    @respx.mock
    async def test_key_not_in_response_headers(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        alias, shard_a_utf8, raw_key = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )

        key_str = raw_key.decode()
        # Key must not appear in any response header
        for name, value in resp.headers.items():
            assert key_str not in value, f"Key found in header {name}"
        # Key must not appear in body
        assert key_str.encode() not in resp.content

    @respx.mock
    async def test_worthless_headers_stripped_from_response(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                headers={"x-worthless-internal": "leak", "x-request-id": "abc"},
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )

        for name in resp.headers:
            assert not name.lower().startswith("x-worthless-"), f"Leaked internal header: {name}"


# ------------------------------------------------------------------
# Security
# ------------------------------------------------------------------


class TestSecurity:
    async def test_tls_enforcement_when_not_insecure(
        self, tmp_db_path, fernet_key, repo, enrolled_alias, proxy_settings
    ):
        """Without allow_insecure, non-TLS requests are rejected."""
        from worthless.proxy.rules import RulesEngine

        settings = ProxySettings(
            db_path=tmp_db_path,
            fernet_key=bytearray(fernet_key),
            allow_insecure=False,
        )
        app = create_app(settings)
        # Manually set state
        app.state.repo = repo
        app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
        app.state.rules_engine = RulesEngine(rules=[])

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            alias, shard_a_utf8, _ = enrolled_alias
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={"authorization": f"Bearer {shard_a_utf8}"},
                content=b"{}",
            )
            # Should get uniform 401 (no info leak about TLS requirement)
            assert resp.status_code == 401
        await app.state.httpx_client.aclose()

    async def test_query_params_stripped_for_adapter_lookup(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Query params should not affect adapter resolution (returns 401 for unknown)."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/unknown?foo=bar",
            headers={"authorization": f"Bearer {shard_a_utf8}"},
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_no_openapi_docs(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.get("/docs")
        assert resp.status_code != 200

    async def test_no_redoc(self, proxy_client: httpx.AsyncClient):
        resp = await proxy_client.get("/redoc")
        assert resp.status_code != 200


# ------------------------------------------------------------------
# Settings validation (L-8)
# ------------------------------------------------------------------


class TestSettingsValidation:
    def test_create_app_accepts_empty_fernet_key(self, tmp_path):
        """WOR-309: ``create_app()`` MUST accept an empty Fernet key.

        The proxy no longer decrypts anything itself — the sidecar holds
        the key. Pre-WOR-309 ``create_app`` raised ``ValueError`` on an
        empty key; post-WOR-309 it builds the app cleanly.
        """
        settings = ProxySettings(
            db_path=str(tmp_path / "test.db"),
            fernet_key=bytearray(),
            allow_insecure=True,
        )
        # MUST NOT raise — proxy never reconstructs in-process.
        app = create_app(settings)
        assert app is not None


# ------------------------------------------------------------------
# Transparent proxy — alias inference from request path
# ------------------------------------------------------------------


@pytest.fixture()
async def openai_enrolled_proxy(proxy_settings: ProxySettings, repo):
    """Proxy app with an openai key enrolled using the provider-hash alias format."""
    alias = "openai-abcd1234"
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

    app = create_app(proxy_settings)
    pin_shard_b(app, alias, sr.shard_b)

    db = await aiosqlite.connect(proxy_settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[
            SpendCapRule(db=db),
            RateLimitRule(default_rps=100.0, db_path=proxy_settings.db_path),
        ]
    )
    yield app, alias, sr.shard_a
    await app.state.httpx_client.aclose()
    await db.close()


# ------------------------------------------------------------------
# Upstream errors — 502/504 (WOR-75)
# ------------------------------------------------------------------


class TestUpstreamErrors:
    """WOR-75: Proxy returns sanitized errors when upstream fails."""

    @pytest.mark.parametrize(
        "side_effect, expected_status, leaked_text",
        [
            (httpx.ConnectError("Connection refused"), 502, "Connection refused"),
            (httpx.ReadTimeout("Read timed out"), 504, "Read timed out"),
            (httpx.HTTPError("Something broke"), 502, "Something broke"),
        ],
        ids=["connect-error-502", "timeout-504", "generic-502"],
    )
    @respx.mock
    async def test_upstream_error_returns_sanitized_response(
        self,
        proxy_client: httpx.AsyncClient,
        enrolled_alias,
        side_effect: httpx.HTTPError,
        expected_status: int,
        leaked_text: str,
    ):
        """Upstream errors are mapped to correct status and internal details are not leaked."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(side_effect=side_effect)

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == expected_status
        assert "error" in resp.json()
        assert leaked_text not in resp.text


class TestTransparentProxy:
    """Proxy extracts alias from URL path (SR-09)."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_alias_in_url_routes_correctly(self, openai_enrolled_proxy):
        """Request to /<alias>/v1/chat/completions with Bearer shard-A should succeed."""
        app, alias, shard_a = openai_enrolled_proxy

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
        )

        shard_a_utf8 = bytes(shard_a).decode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            resp = await client.post(
                f"http://testserver/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"authorization": f"Bearer {shard_a_utf8}"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_unknown_path_without_alias_returns_401(self, openai_enrolled_proxy):
        """Unknown path without alias prefix should 401."""
        app, _, _ = openai_enrolled_proxy

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            resp = await client.get("http://testserver/v1/unknown/endpoint")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_bearer_returns_401(self, openai_enrolled_proxy):
        """Request with alias in URL but no Bearer token should 401."""
        app, alias, _ = openai_enrolled_proxy

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            resp = await client.post(
                f"http://testserver/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
        assert resp.status_code == 401

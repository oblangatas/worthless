"""End-to-end proxy integration tests — full lifecycle, shard isolation,
wrong shard-A, cross-alias attacks, and URL path edge cases.

Proves the real pipeline works: enroll -> split -> send HTTP request with
Bearer shard-A -> proxy reconstructs original key -> upstream receives it.
"""

from __future__ import annotations

import dataclasses
import json

import aiosqlite
import httpx
import pytest
import respx

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard

from tests._fakes import pin_shard_b


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def proxy_settings(tmp_db_path: str, fernet_key: bytes) -> ProxySettings:
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
            RateLimitRule(default_rps=proxy_settings.default_rate_limit_rps),
        ]
    )
    yield app
    await app.state.httpx_client.aclose()
    await db.close()


@pytest.fixture()
async def proxy_client(proxy_app):
    transport = httpx.ASGITransport(app=proxy_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _enroll(
    repo: ShardRepository,
    alias: str,
    api_key: str,
    prefix: str,
    provider: str,
    proxy_app=None,
):
    """Enroll a key and return (alias, shard_a_utf8, raw_api_key).

    If ``proxy_app`` is supplied, also pins the alias's plaintext shard-B
    onto the autouse FakeIPCSupervisor at ``proxy_app.state.ipc_supervisor``.
    Without this pin the fake returns its default plaintext, reconstruction
    yields the wrong API key, and reconstruct-dependent tests return 401.
    """
    sr = split_key_fp(api_key, prefix=prefix, provider=provider)
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider=provider,
    )
    await repo.store(
        alias, shard, prefix=sr.prefix, charset=sr.charset, base_url="https://api.openai.com/v1"
    )
    if proxy_app is not None:
        pin_shard_b(proxy_app, alias, sr.shard_b)
    shard_a_utf8 = sr.shard_a.decode("utf-8")
    return alias, shard_a_utf8, api_key


@pytest.fixture()
async def enrolled_alias(repo, proxy_app):
    return await _enroll(
        repo,
        "test-key",
        "sk-test-key-1234567890abcdef",
        "sk-",
        "openai",
        proxy_app=proxy_app,
    )


# ------------------------------------------------------------------
# 1. Full request lifecycle — upstream receives RECONSTRUCTED key
# ------------------------------------------------------------------


class TestFullRequestLifecycle:
    """Prove the complete pipeline: enroll -> split -> HTTP request ->
    proxy reconstructs -> upstream receives the ORIGINAL key."""

    @respx.mock
    async def test_upstream_receives_reconstructed_key(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """The upstream provider must receive the original unsplit API key."""
        alias, shard_a_utf8, original_key = enrolled_alias
        captured_headers: dict[str, str] = {}

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )

        respx.post("https://api.openai.com/v1/chat/completions").mock(side_effect=capture_request)

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )

        assert resp.status_code == 200
        # The upstream must receive the ORIGINAL key, not shard-A
        upstream_auth = captured_headers.get("authorization", "")
        assert upstream_auth == f"Bearer {original_key}", (
            f"Upstream received '{upstream_auth}' but expected 'Bearer {original_key}'"
        )
        # Shard-A must NOT be what the upstream sees
        assert shard_a_utf8 not in upstream_auth

    @respx.mock
    async def test_upstream_receives_correct_body(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """The request body must be forwarded to the upstream unchanged."""
        alias, shard_a_utf8, _ = enrolled_alias
        captured_body: list[bytes] = []

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_body.append(request.content)
            return httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )

        respx.post("https://api.openai.com/v1/chat/completions").mock(side_effect=capture_request)

        body = b'{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=body,
        )

        assert resp.status_code == 200
        assert len(captured_body) == 1
        sent = json.loads(captured_body[0])
        assert sent["model"] == "gpt-4"
        assert sent["messages"][0]["content"] == "hello"

    @respx.mock
    async def test_response_body_relayed_to_client(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """The upstream response must be relayed back to the client."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "world"}}],
                    "usage": {"total_tokens": 42},
                },
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
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "world"


# ------------------------------------------------------------------
# 2. Shard-A isolation — proxy has NO shard_a_dir
# ------------------------------------------------------------------


class TestShardAIsolation:
    """ProxySettings must not have any shard_a_dir attribute.
    The proxy process has zero access to shard-A file paths."""

    def test_proxy_settings_has_no_shard_a_dir(self, proxy_settings: ProxySettings):
        with pytest.raises(AttributeError):
            _ = proxy_settings.shard_a_dir

    def test_proxy_settings_has_no_shard_a_path(self, proxy_settings: ProxySettings):
        with pytest.raises(AttributeError):
            _ = proxy_settings.shard_a_path

    def test_proxy_settings_fields_do_not_mention_shard_a(self):
        """No field name in ProxySettings should reference shard_a."""
        field_names = [f.name for f in dataclasses.fields(ProxySettings)]
        for name in field_names:
            assert "shard_a" not in name.lower(), f"ProxySettings has shard_a field: {name}"


# ------------------------------------------------------------------
# 3. Wrong shard-A — HMAC verification must fail with 401
# ------------------------------------------------------------------


class TestWrongShardA:
    """Sending a valid-looking but incorrect shard-A must 401."""

    async def test_wrong_shard_a_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        alias, correct_shard_a, _ = enrolled_alias
        # Flip characters to create a wrong shard-A of the same format
        wrong_shard_a = correct_shard_a[:-4] + "ZZZZ"

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {wrong_shard_a}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_empty_bearer_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        alias, _, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": "Bearer ",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_random_token_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        alias, _, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": "Bearer sk-completelyfaketoken123456",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_wrong_shard_a_body_matches_uniform_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Wrong shard-A must return the same body as unknown alias (anti-enumeration)."""
        alias, correct_shard_a, _ = enrolled_alias
        wrong_shard_a = correct_shard_a[:-4] + "ZZZZ"

        # Wrong shard-A on valid alias
        r1 = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={"authorization": f"Bearer {wrong_shard_a}"},
            content=b"{}",
        )
        # Unknown alias entirely
        r2 = await proxy_client.post(
            "/nonexistent/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )
        assert r1.status_code == r2.status_code == 401
        assert r1.content == r2.content, "401 bodies must be identical (anti-enumeration)"


# ------------------------------------------------------------------
# 4. Cross-alias attack — alias-A's shard-A on alias-B's URL
# ------------------------------------------------------------------


class TestCrossAliasAttack:
    """Sending one alias's shard-A to a different alias's endpoint must fail."""

    @pytest.fixture()
    async def two_aliases(self, repo, proxy_app):
        """Enroll two different keys under different aliases."""
        a = await _enroll(
            repo, "alias-a", "sk-keyAAAAAAAAAAAAAAAA", "sk-", "openai", proxy_app=proxy_app
        )
        b = await _enroll(
            repo, "alias-b", "sk-keyBBBBBBBBBBBBBBBB", "sk-", "openai", proxy_app=proxy_app
        )
        return a, b

    async def test_cross_alias_shard_a_rejected(self, proxy_client: httpx.AsyncClient, two_aliases):
        """Alias-A's shard-A sent to alias-B's URL must fail reconstruction."""
        (alias_a, shard_a_of_a, _), (alias_b, shard_a_of_b, _) = two_aliases

        # Send alias-A's shard-A to alias-B's URL
        resp = await proxy_client.post(
            f"/{alias_b}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_of_a}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_reverse_cross_alias_also_rejected(
        self, proxy_client: httpx.AsyncClient, two_aliases
    ):
        """Alias-B's shard-A sent to alias-A's URL must also fail."""
        (alias_a, shard_a_of_a, _), (alias_b, shard_a_of_b, _) = two_aliases

        resp = await proxy_client.post(
            f"/{alias_a}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_of_b}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    @respx.mock
    async def test_correct_alias_still_works(self, proxy_client: httpx.AsyncClient, two_aliases):
        """Each alias's own shard-A must still work correctly."""
        (alias_a, shard_a_of_a, key_a), (alias_b, shard_a_of_b, key_b) = two_aliases

        captured_keys: list[str] = []

        def capture(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            captured_keys.append(auth.replace("Bearer ", ""))
            return httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 1}})

        respx.post("https://api.openai.com/v1/chat/completions").mock(side_effect=capture)

        # Alias A with its own shard-A
        resp_a = await proxy_client.post(
            f"/{alias_a}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_of_a}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp_a.status_code == 200
        assert captured_keys[-1] == key_a

        # Alias B with its own shard-A
        resp_b = await proxy_client.post(
            f"/{alias_b}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_of_b}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp_b.status_code == 200
        assert captured_keys[-1] == key_b


# ------------------------------------------------------------------
# 5. URL path edge cases
# ------------------------------------------------------------------


class TestURLPathEdgeCases:
    """Test alias extraction and routing for tricky URL paths."""

    async def test_trailing_slash_works(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """/<alias>/v1/chat/completions/ (trailing slash) should still route."""
        alias, shard_a_utf8, _ = enrolled_alias
        # Trailing slash changes the path — the adapter may or may not match.
        # The important thing is it does NOT crash or leak info.
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions/",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        # Either 200 (if adapter matches) or 401 (unknown path, anti-enum) — never 500
        assert resp.status_code in (200, 401)
        assert resp.status_code != 500

    async def test_case_sensitive_alias(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Alias matching is case-sensitive: uppercase alias should not match."""
        alias, shard_a_utf8, _ = enrolled_alias
        upper_alias = alias.upper()
        # Only matches if alias == upper_alias (which it won't for 'test-key')
        if upper_alias != alias:
            resp = await proxy_client.post(
                f"/{upper_alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )
            # Unknown alias -> 401
            assert resp.status_code == 401

    async def test_path_traversal_dot_dot_rejected(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Path traversal via /<alias>/../<other>/v1/... must not reach another alias."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/../other-alias/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        # The path is either normalized by ASGI (dropping the alias) or rejected
        assert resp.status_code == 401

    async def test_encoded_path_traversal_rejected(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """URL-encoded traversal /%2e%2e/ must be rejected."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/%2e%2e/other-alias/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_double_slash_in_path(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Double slashes should not bypass alias extraction."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"//{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        # Either routes correctly or 401 — never 500
        assert resp.status_code in (200, 401)

    async def test_alias_with_special_chars_rejected(self, proxy_client: httpx.AsyncClient):
        """Aliases with characters outside [a-zA-Z0-9_-] must be rejected."""
        for bad_alias in ["test key", "test/key", "test;key", "test&key", "test=key"]:
            resp = await proxy_client.post(
                f"/{bad_alias}/v1/chat/completions",
                headers={"authorization": "Bearer fake"},
                content=b"{}",
            )
            assert resp.status_code == 401, f"Alias '{bad_alias}' was not rejected"

    async def test_empty_alias_rejected(self, proxy_client: httpx.AsyncClient):
        """An empty alias segment (just /v1/chat/completions) must 401."""
        resp = await proxy_client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_very_long_alias_rejected(self, proxy_client: httpx.AsyncClient):
        """Extremely long alias should not cause issues."""
        long_alias = "a" * 10000
        resp = await proxy_client.post(
            f"/{long_alias}/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )
        # Should get 401 (not enrolled), not crash
        assert resp.status_code == 401

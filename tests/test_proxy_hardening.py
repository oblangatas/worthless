"""Proxy hardening tests — repr redaction, dead code removal, SSE streaming,
gate ordering, zeroing, error handling.

Tests for Phase 3.1:
- Plan 01: AdapterRequest/Response repr redaction, dead code removal, bytearray compliance
- Plan 02: SSE streaming, gate-before-decrypt, zeroing, async I/O, error handling,
  upstream sanitization, anti-enumeration, metering resilience
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

import aiosqlite

from worthless.adapters import registry
from worthless.adapters.types import AdapterRequest, AdapterResponse
from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import _ALIAS_RE, _BAD_HEADER_CHARS, _extract_alias_and_path, create_app
from worthless.proxy.config import DeployMode, ProxySettings
from worthless.proxy.errors import ErrorResponse, gateway_error_response
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import EncryptedShard, StoredShard


# ------------------------------------------------------------------
# Fixtures (Plan 02)
# ------------------------------------------------------------------


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
async def enrolled_alias(repo, proxy_settings: ProxySettings):
    """Enroll a test key and return (alias, shard_a_utf8, raw_api_key)."""
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

    shard_a_utf8 = sr.shard_a.decode("utf-8")
    return alias, shard_a_utf8, api_key.encode()


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


# ==================================================================
# Plan 01 tests (repr redaction, dead code removal, bytearray)
# ==================================================================


# ------------------------------------------------------------------
# AdapterRequest repr redaction (SR-04)
# ------------------------------------------------------------------


class TestAdapterRequestRepr:
    """AdapterRequest.__repr__ must not expose body content."""

    def test_body_redacted_in_repr(self) -> None:
        req = AdapterRequest(
            url="https://api.openai.com/v1/chat/completions",
            headers={"content-type": "application/json"},
            body=b'{"model":"gpt-4","messages":[{"role":"user","content":"secret prompt"}]}',
        )
        r = repr(req)
        assert "secret prompt" not in r
        assert "<" in r and "bytes>" in r

    def test_body_length_shown(self) -> None:
        body = b"x" * 42
        req = AdapterRequest(url="https://example.com", headers={}, body=body)
        assert "<42 bytes>" in repr(req)

    def test_sensitive_headers_still_redacted(self) -> None:
        req = AdapterRequest(
            url="https://example.com",
            headers={"authorization": "Bearer sk-secret-key"},
            body=b"{}",
        )
        r = repr(req)
        assert "sk-secret-key" not in r
        assert "REDACTED" in r


# ------------------------------------------------------------------
# AdapterResponse repr redaction (SR-04)
# ------------------------------------------------------------------


class TestAdapterResponseRepr:
    """AdapterResponse.__repr__ must not expose body or header values."""

    def test_body_redacted_in_repr(self) -> None:
        resp = AdapterResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"choices":[{"message":{"content":"secret response"}}]}',
        )
        r = repr(resp)
        assert "secret response" not in r
        assert "<" in r and "bytes>" in r

    def test_headers_redacted_in_repr(self) -> None:
        resp = AdapterResponse(
            status_code=200,
            headers={"x-request-id": "abc123", "content-type": "application/json"},
            body=b"{}",
        )
        r = repr(resp)
        assert "abc123" not in r
        assert "<2 entries>" in r

    def test_body_length_shown(self) -> None:
        resp = AdapterResponse(status_code=200, headers={}, body=b"y" * 99)
        assert "<99 bytes>" in repr(resp)


# ------------------------------------------------------------------
# Dead code removal
# ------------------------------------------------------------------


class TestDeadCodeRemoval:
    def test_dependencies_module_removed(self) -> None:
        dep_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "worthless"
            / "proxy"
            / "dependencies.py"
        )
        assert not dep_path.exists()

    def test_dependencies_module_not_importable(self) -> None:
        with pytest.raises(ImportError):
            import worthless.proxy.dependencies  # noqa: F401


# ------------------------------------------------------------------
# Bytearray compliance (SR-01)
# ------------------------------------------------------------------


class TestBytearrayCompliance:
    def test_stored_shard_bytearray_fields(self) -> None:
        shard = StoredShard(
            shard_b=bytearray(b"shard-b-data"),
            commitment=bytearray(b"commitment-data"),
            nonce=bytearray(b"nonce-data"),
            provider="openai",
        )
        assert isinstance(shard.shard_b, bytearray)
        assert isinstance(shard.commitment, bytearray)
        assert isinstance(shard.nonce, bytearray)


class TestStoredShardRepr:
    """StoredShard.__repr__ must not expose shard material (SR-04)."""

    def test_shard_b_not_in_repr(self) -> None:
        shard = StoredShard(
            shard_b=bytearray(b"secret-shard-b"),
            commitment=bytearray(b"secret-commitment"),
            nonce=bytearray(b"secret-nonce"),
            provider="openai",
        )
        r = repr(shard)
        assert b"secret-shard-b".decode() not in r
        assert b"secret-commitment".decode() not in r
        assert b"secret-nonce".decode() not in r
        assert "<14 bytes>" in r
        assert "provider='openai'" in r

    def test_encrypted_shard_repr_redacted(self) -> None:
        enc = EncryptedShard(
            shard_b_enc=b"encrypted-data-here",
            commitment=b"commit-bytes",
            nonce=b"nonce-bytes",
            provider="anthropic",
        )
        r = repr(enc)
        assert b"encrypted-data-here".decode() not in r
        assert "<19 bytes>" in r
        assert "provider='anthropic'" in r


# ==================================================================
# Plan 02 tests (SSE streaming, gate ordering, zeroing, errors, etc.)
# ==================================================================


# ------------------------------------------------------------------
# B-1: SSE Streaming
# ------------------------------------------------------------------


class TestSSEStreaming:
    @respx.mock
    async def test_stream_true_passed_to_httpx_send(self, proxy_app, enrolled_alias):
        """Verify httpx.send() is called with stream=True for all requests."""
        alias, shard_a_utf8, _ = enrolled_alias
        send_kwargs: dict = {}

        async def capturing_send(req, **kwargs):
            send_kwargs.update(kwargs)
            # Return a non-streaming response to keep things simple
            return httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
                request=req,
            )

        proxy_app.state.httpx_client.send = capturing_send

        respx.post("https://api.openai.com/v1/chat/completions").pass_through()

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        assert send_kwargs.get("stream") is True, "httpx.send() must be called with stream=True"

    @respx.mock
    async def test_streaming_response_uses_streaming_path(self, proxy_app, enrolled_alias):
        """When adapter returns is_streaming=True, proxy uses StreamingResponse."""
        alias, shard_a_utf8, _ = enrolled_alias
        sse_body = b'data: {"id":"1","choices":[{"delta":{"content":"Hello"}}]}\n\ndata: [DONE]\n\n'

        async def sse_stream():
            for chunk in sse_body.split(b"\n\n"):
                if chunk:
                    yield chunk + b"\n\n"

        # Mock the adapter to return a streaming response
        async def mock_relay(upstream_resp):
            return AdapterResponse(
                status_code=200,
                headers={"content-type": "text/event-stream"},
                body=b"",
                is_streaming=True,
                stream=sse_stream(),
            )

        # Mock httpx send to return a streaming-like response
        async def mock_send(req, **kwargs):
            resp = httpx.Response(200, headers={"content-type": "text/event-stream"}, request=req)
            return resp

        proxy_app.state.httpx_client.send = mock_send

        # Patch the adapter's relay_response
        adapter = registry.get_adapter("/v1/chat/completions")
        orig_relay = adapter.relay_response
        adapter.relay_response = mock_relay

        try:
            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": [], "stream": true}',
                )
            assert resp.status_code == 200
            assert b"Hello" in resp.content
        finally:
            if orig_relay:
                adapter.relay_response = orig_relay

    @respx.mock
    async def test_non_streaming_response_properly_handled(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Non-streaming responses are read and returned normally."""
        alias, shard_a_utf8, _ = enrolled_alias

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
        assert b"hi" in resp.content


# ------------------------------------------------------------------
# B-2: Gate-before-decrypt ordering
# ------------------------------------------------------------------


class TestGateBeforeDecrypt:
    @respx.mock
    async def test_fetch_encrypted_before_rules_decrypt_after(self, proxy_app, enrolled_alias):
        """fetch_encrypted called BEFORE rules_engine.evaluate, decrypt_shard AFTER."""
        alias, shard_a_utf8, _ = enrolled_alias
        call_order: list[str] = []

        orig_fetch = proxy_app.state.repo.fetch_encrypted
        orig_decrypt = proxy_app.state.repo.decrypt_shard

        async def mock_fetch(a):
            call_order.append("fetch_encrypted")
            return await orig_fetch(a)

        def mock_decrypt(enc):
            call_order.append("decrypt_shard")
            return orig_decrypt(enc)

        async def mock_evaluate(_self, a, r, **kwargs):
            call_order.append("evaluate")
            return None

        proxy_app.state.repo.fetch_encrypted = mock_fetch
        proxy_app.state.repo.decrypt_shard = mock_decrypt

        async def mock_release(_self, alias, amount):
            pass

        proxy_app.state.rules_engine = type(
            "MockEngine", (), {"evaluate": mock_evaluate, "release_spend_reservation": mock_release}
        )()

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        assert call_order == ["fetch_encrypted", "evaluate", "decrypt_shard"]

    @respx.mock
    async def test_denial_skips_decrypt(self, proxy_app, enrolled_alias):
        """When rules engine denies, decrypt_shard is never called."""
        alias, shard_a_utf8, _ = enrolled_alias
        decrypt_called = False

        orig_decrypt = proxy_app.state.repo.decrypt_shard

        def mock_decrypt(enc):
            nonlocal decrypt_called
            decrypt_called = True
            return orig_decrypt(enc)

        proxy_app.state.repo.decrypt_shard = mock_decrypt
        proxy_app.state.rules_engine = type(
            "MockEngine",
            (),
            {
                "evaluate": AsyncMock(
                    return_value=ErrorResponse(
                        status_code=402,
                        body=b'{"error": "spend cap exceeded"}',
                        headers={"content-type": "application/json"},
                    )
                ),
                "release_spend_reservation": AsyncMock(return_value=None),
            },
        )()

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )
        assert resp.status_code == 402
        assert not decrypt_called

    @respx.mock
    async def test_proxy_response_pipe_is_consistent_with_gzip_upstream(
        self, proxy_app, enrolled_alias
    ):
        """M2 (Blocker #3 / true-pipe minimum): when upstream returns a gzipped
        body with Content-Encoding: gzip, the proxy's forwarded response must be
        internally consistent — either the body is decompressed AND
        Content-Encoding is removed, OR the body stays gzipped AND
        Content-Encoding is preserved.

        Failure mode pre-fix: proxy auto-decompresses upstream gzip via httpx's
        aread()/aiter_bytes(), but forwards the original Content-Encoding: gzip
        header back to the SDK. SDK tries to gunzip plain JSON → DecodingError.
        Live smoke during PR #127 review required Accept-Encoding: identity to
        bypass — which means default SDK calls (which advertise gzip) don't work.

        worthless-yo9o (P2 follow-up) will deepen this to a true byte-transparent
        pipe with aiter_raw — no decompression at all. M2 is the minimum to
        unblock real SDKs today: header gets stripped after decompression.
        """
        import gzip
        import json as _json

        alias, shard_a_utf8, _ = enrolled_alias
        expected_payload = {
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "OK"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
        }
        body_bytes = _json.dumps(expected_payload).encode()
        gzipped_body = gzip.compress(body_bytes)

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=gzipped_body,
                headers={
                    "content-encoding": "gzip",
                    "content-type": "application/json",
                    "content-length": str(len(gzipped_body)),
                },
            )
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=(
                    b'{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}'
                ),
            )

        # Status forwards through.
        assert resp.status_code == 200, f"got {resp.status_code}: {resp.text[:200]!r}"

        # Critical: the proxy's response must be consistent.
        # Either Content-Encoding is gone (because we already decompressed)
        # OR the body is still gzipped (true raw pipe).
        ce = resp.headers.get("content-encoding", "").lower()
        body_raw = resp.content  # this is what's on the wire to the SDK

        if ce == "gzip":
            # Raw pipe: body must still be gzipped — gunzip should yield JSON.
            try:
                ungz = gzip.decompress(body_raw)
            except OSError as exc:
                pytest.fail(
                    f"proxy returned Content-Encoding: gzip but body is NOT gzipped — "
                    f"SDK clients will error decompressing. {exc}. "
                    f"First 32 bytes: {body_raw[:32]!r}"
                )
            data = _json.loads(ungz)
        else:
            # Header stripped: body must be decompressed JSON directly.
            data = resp.json()

        # In both consistent states, the JSON payload must round-trip.
        assert data["usage"]["total_tokens"] == 4
        assert data["choices"][0]["message"]["content"] == "OK"

    @respx.mock
    async def test_null_base_url_refused_before_reconstruction(
        self, proxy_app, enrolled_alias, caplog
    ):
        """SR-03 + anti-enumeration: a row with NULL base_url (legacy /
        pre-8rqs enrollment) must be refused BEFORE any key reconstruction
        AND BEFORE rules-engine evaluation, AND with the same uniform 401
        an unknown alias would get — no content-shape oracle.

        Three contracts pinned here:

        1. SR-03 (gate before reconstruct). Reconstruction must not fire.
           Original 8rqs Phase 6 placed the NULL check AFTER reconstruction;
           M1 hoists it above. Rules engine must not fire either —
           ``rules_engine.evaluate`` runs BETWEEN the row fetch and the
           reconstruction, so any leak there would also count as
           pre-reconstruction key-material exposure once worthless-rzi1
           lands per-request DB re-validation inside the rules path.

        2. Anti-enumeration. The original M1 fix returned a distinctive
           503 with a relock hint. That let an attacker probe the DB by
           content-shape (random alias → 401, real legacy alias → 503).
           Same oracle class as worthless-bi7h's timing oracle. M5 changes
           the response to ``_uniform_401()`` — byte-identical to the
           unknown-alias path.

        3. Operator signal preserved. The relock hint moved from the wire
           to the server log. Without a server-side log line, the
           legacy-row condition would be silent to operators. caplog
           assertion below pins that.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        # Inject a row that fetch_encrypted returns with base_url=None.
        # EncryptedShard is a NamedTuple — use _replace to clone with NULL base_url.
        orig_fetch = proxy_app.state.repo.fetch_encrypted

        async def fetch_with_null_base_url(a):
            row = await orig_fetch(a)
            return row._replace(base_url=None) if row is not None else None

        proxy_app.state.repo.fetch_encrypted = fetch_with_null_base_url

        # Track every gate that must NOT fire on the NULL base_url denial
        # path: reconstruction (SR-03 strict) + rules-engine evaluate.
        with (
            patch("worthless.proxy.app.reconstruct_key") as mock_reconstruct,
            patch("worthless.proxy.app.reconstruct_key_fp") as mock_reconstruct_fp,
            patch.object(
                proxy_app.state.rules_engine,
                "evaluate",
                wraps=proxy_app.state.rules_engine.evaluate,
            ) as mock_evaluate,
            caplog.at_level(logging.WARNING, logger="worthless.proxy.app"),
        ):
            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": []}',
                )

                # Anti-enumeration: capture an unknown-alias response from the
                # SAME proxy and assert byte-equality. If they differ, the
                # legacy-row path is leaking existence.
                unknown_resp = await client.post(
                    "/this-alias-never-existed/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": []}',
                )

        # Assertion order: gate-bypass call_counts FIRST so a regression in
        # any one gate surfaces at the precise contract it broke, instead
        # of being masked by a later status-code mismatch.

        # SR-03 contract: NEITHER reconstruction function called.
        assert mock_reconstruct.call_count == 0, (
            f"reconstruct_key called {mock_reconstruct.call_count} times — "
            "SR-03 violated: NULL base_url should refuse BEFORE reconstruction"
        )
        assert mock_reconstruct_fp.call_count == 0, (
            f"reconstruct_key_fp called {mock_reconstruct_fp.call_count} times — "
            "SR-03 violated: NULL base_url should refuse BEFORE reconstruction"
        )

        # Rules-engine must also be skipped on this denial path.
        assert mock_evaluate.call_count == 0, (
            f"rules_engine.evaluate called {mock_evaluate.call_count} times — "
            "the SR-03 docstring promises gating BEFORE rules evaluation, "
            "but rules ran anyway"
        )

        # Anti-enumeration: legacy-row response is byte-identical to the
        # unknown-alias response. No content-shape oracle.
        assert resp.status_code == 401, (
            f"expected uniform 401 (anti-enumeration), got {resp.status_code}: {resp.text}"
        )
        assert resp.status_code == unknown_resp.status_code, (
            f"legacy-row response status {resp.status_code} != unknown-alias "
            f"status {unknown_resp.status_code} — content-shape oracle leaks "
            "DB membership"
        )
        assert resp.content == unknown_resp.content, (
            "legacy-row response body differs from unknown-alias body — "
            "content-shape oracle leaks DB membership"
        )

        # Operator signal preserved. The relock hint moved from the wire to
        # the server log. Without a logged warning, operators have no way
        # to know a legacy row was hit.
        legacy_warnings = [
            r
            for r in caplog.records
            if "NULL base_url" in r.getMessage() and alias in r.getMessage()
        ]
        assert legacy_warnings, (
            "no operator warning logged for NULL-base_url path — "
            f"legacy-row condition is silent. caplog records: "
            f"{[r.getMessage() for r in caplog.records]}"
        )


# ------------------------------------------------------------------
# B-3: Bytearray zeroing
# ------------------------------------------------------------------


class TestByteArrayZeroing:
    @respx.mock
    async def test_shard_material_zeroed_after_request(self, proxy_app, enrolled_alias):
        """shard_a and stored shard fields are zeroed after request completes."""
        alias, shard_a_utf8, _ = enrolled_alias
        captured_stored: dict = {}

        orig_decrypt = proxy_app.state.repo.decrypt_shard

        def capturing_decrypt(enc):
            result = orig_decrypt(enc)
            captured_stored["shard"] = result
            return result

        proxy_app.state.repo.decrypt_shard = capturing_decrypt

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        shard = captured_stored["shard"]
        assert all(b == 0 for b in shard.shard_b), "shard_b not zeroed"
        assert all(b == 0 for b in shard.commitment), "commitment not zeroed"
        assert all(b == 0 for b in shard.nonce), "nonce not zeroed"


# ------------------------------------------------------------------
# Reconstruct failure zeroing
# ------------------------------------------------------------------


class TestReconstructFailureZeroing:
    @respx.mock
    async def test_shard_material_zeroed_on_reconstruct_failure(self, proxy_app, enrolled_alias):
        """When reconstruct_key raises, all shard material is zeroed and 401 returned."""
        alias, shard_a_utf8, _ = enrolled_alias
        captured_stored: dict = {}

        orig_decrypt = proxy_app.state.repo.decrypt_shard

        def capturing_decrypt(enc):
            result = orig_decrypt(enc)
            captured_stored["shard"] = result
            return result

        proxy_app.state.repo.decrypt_shard = capturing_decrypt

        with patch(
            "worthless.proxy.app.reconstruct_key_fp",
            side_effect=Exception("tampered shard"),
        ):
            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": []}',
                )

        assert resp.status_code == 401
        shard = captured_stored["shard"]
        assert all(b == 0 for b in shard.shard_b), "shard_b not zeroed on failure"
        assert all(b == 0 for b in shard.commitment), "commitment not zeroed on failure"
        assert all(b == 0 for b in shard.nonce), "nonce not zeroed on failure"


# ------------------------------------------------------------------
# H-1: Error handling (502/504)
# ------------------------------------------------------------------


class TestErrorHandling:
    @respx.mock
    async def test_timeout_returns_504(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """httpx.TimeoutException returns 504."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 504

    @respx.mock
    async def test_connect_error_returns_502(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """httpx.ConnectError returns 502."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 502

    @respx.mock
    async def test_generic_http_error_returns_502(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Generic httpx.HTTPError (not Timeout/Connect) returns 502."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            side_effect=httpx.HTTPError("some http error")
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 502


# ------------------------------------------------------------------
# Invalid Bearer token
# ------------------------------------------------------------------


class TestInvalidBearerToken:
    async def test_invalid_bearer_token_returns_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Invalid Bearer token returns uniform 401."""
        alias, _, _ = enrolled_alias

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": "Bearer !!!not-valid-shard!!!",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401


# ------------------------------------------------------------------
# M-4: Upstream error sanitization
# ------------------------------------------------------------------


class TestUpstreamSanitization:
    @respx.mock
    async def test_upstream_error_body_sanitized(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Upstream 4xx/5xx error bodies are sanitized."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                500,
                json={
                    "error": {
                        "message": "Internal server details leaked",
                        "type": "server_error",
                    }
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
        assert b"Internal server details leaked" not in resp.content
        assert resp.status_code == 500

    @respx.mock
    async def test_malformed_upstream_error_uses_fallback(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Malformed upstream error body falls back to generic error."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                500,
                content=b"not valid json at all",
                headers={"content-type": "text/plain"},
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
        assert resp.status_code == 500
        body = json.loads(resp.content)
        assert body["error"]["message"] == "upstream provider error"


class TestUpstreamSanitizationAnthropic:
    @respx.mock
    async def test_anthropic_error_body_sanitized(self, proxy_app, tmp_path, fernet_key):
        """Upstream Anthropic error bodies are sanitized to Anthropic format."""
        # Enroll an Anthropic key
        alias = "anthropic-key"
        api_key = "sk-ant-test-key-12345678901234"
        sr = split_key_fp(api_key, prefix="sk-ant-", provider="anthropic")
        shard = StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider="anthropic",
        )
        await proxy_app.state.repo.store(
            alias,
            shard,
            prefix=sr.prefix,
            charset=sr.charset,
            base_url="https://api.anthropic.com/v1",
        )
        shard_a_utf8 = sr.shard_a.decode("utf-8")

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(
                500,
                json={
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": "Internal server secret details leaked here",
                    },
                },
            )
        )

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/messages",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "claude-3-5-sonnet-20241022",'
                b' "max_tokens": 10, "messages": []}',
            )

        body = json.loads(resp.content)
        assert resp.status_code == 500
        assert b"Internal server secret details leaked here" not in resp.content
        assert body["type"] == "error"
        assert body["error"]["type"] == "api_error"
        assert body["error"]["message"] == "upstream provider error"


# ------------------------------------------------------------------
# H-2/M-3: Anti-enumeration
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Path normalization
# ------------------------------------------------------------------


class TestPathNormalization:
    """Verify path cleaning handles edge cases without breaking routing."""

    @respx.mock
    async def test_path_with_query_params_stripped(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Query params are stripped — /<alias>/v1/chat/completions?foo=bar routes correctly."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 1}},
            )
        )
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions?foo=bar",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200

    @respx.mock
    async def test_path_with_multiple_query_separators(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Multiple ? in path — only first segment used."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 1}},
            )
        )
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions?a=1?b=2",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200

    async def test_unknown_path_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Unrecognized path returns uniform 401 (not 404)."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v2/something/else",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
            },
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_empty_path_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Root path / returns uniform 401 (no adapter matches)."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            "/",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
            },
            content=b"{}",
        )
        assert resp.status_code == 401


class TestAntiEnumeration:
    async def test_unknown_endpoint_returns_401_not_404(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Unknown endpoint returns 401 format, not 404."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/unknown",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
            },
            content=b"{}",
        )
        assert resp.status_code == 401

    async def test_all_failure_responses_identical_format(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """404 (unknown endpoint) and 401 (no alias) return same body."""
        alias, shard_a_utf8, _ = enrolled_alias
        r1 = await proxy_client.post("/v1/chat/completions", content=b"{}")
        r2 = await proxy_client.post(
            f"/{alias}/v1/unknown",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
            },
            content=b"{}",
        )
        assert r1.status_code == r2.status_code == 401
        assert r1.content == r2.content

    async def test_all_failure_modes_return_byte_identical_401(
        self,
        proxy_client: httpx.AsyncClient,
        enrolled_alias,
        proxy_settings: ProxySettings,
    ):
        """All _uniform_401() code paths return byte-identical responses.

        Exercises 7 failure modes. The 8th (malformed header keys with
        null/CR/LF bytes) cannot be triggered through httpx -- it validates
        header names client-side. That path requires raw ASGI scope injection.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        responses: list[tuple[str, httpx.Response]] = []

        # 1. Missing alias (bare path, no alias prefix)
        r = await proxy_client.post("/v1/chat/completions", content=b"{}")
        responses.append(("missing_alias", r))

        # 2. Path traversal alias
        r = await proxy_client.post(
            "/..%2F..%2Fetc%2Fpasswd/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )
        responses.append(("path_traversal", r))

        # 3. Unknown alias (not in DB)
        r = await proxy_client.post(
            "/nonexistent-alias/v1/chat/completions",
            headers={"authorization": "Bearer fake-shard-a"},
            content=b"{}",
        )
        responses.append(("unknown_alias", r))

        # 4. Invalid Bearer token
        r = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={"authorization": "Bearer !!!not-valid-shard!!!"},
            content=b"{}",
        )
        responses.append(("invalid_bearer_token", r))

        # 5. Missing Bearer header
        r = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            content=b"{}",
        )
        responses.append(("missing_bearer", r))

        # 6. Unknown endpoint (no adapter match)
        r = await proxy_client.post(
            f"/{alias}/v1/totally-unknown-endpoint",
            headers={"authorization": f"Bearer {shard_a_utf8}"},
            content=b"{}",
        )
        responses.append(("unknown_endpoint", r))

        # 7. Reconstruction failure (mock reconstruct_key_fp to raise)
        with patch("worthless.proxy.app.reconstruct_key_fp", side_effect=ValueError("tampered")):
            r = await proxy_client.post(
                f"/{alias}/v1/chat/completions",
                headers={"authorization": f"Bearer {shard_a_utf8}"},
                content=b"{}",
            )
        responses.append(("reconstruct_failure", r))

        # Assert ALL return 401 with byte-identical bodies
        reference_label, reference = responses[0]
        for label, resp in responses:
            assert resp.status_code == 401, f"{label}: expected 401, got {resp.status_code}"
            assert resp.content == reference.content, f"{label} body differs from {reference_label}"

    async def test_tls_enforcement_returns_identical_401(
        self, proxy_settings: ProxySettings, repo, enrolled_alias
    ):
        """TLS enforcement failure returns the same 401 as other failure modes."""
        tls_settings = replace(
            proxy_settings,
            allow_insecure=False,
            deploy_mode=DeployMode.PUBLIC,
            host="0.0.0.0",  # noqa: S104 — testing public-mode bind/TLS contract
            trusted_proxies=("10.0.0.0/8",),
        )
        app = create_app(tls_settings)
        db = await aiosqlite.connect(proxy_settings.db_path)
        try:
            app.state.db = db
            app.state.repo = repo
            app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
            app.state.rules_engine = RulesEngine(rules=[])

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                alias, shard_a_utf8, _ = enrolled_alias

                # TLS failure: ASGI transport defaults scheme to "http"
                r_tls = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                    },
                    content=b"{}",
                )
                # Reference: missing alias (known uniform 401)
                r_ref = await client.post("/v1/chat/completions", content=b"{}")

            assert r_tls.status_code == 401
            assert r_tls.content == r_ref.content
        finally:
            await app.state.httpx_client.aclose()
            await db.close()


# ------------------------------------------------------------------
# M-9/M-10: Metering resilience
# ------------------------------------------------------------------


class TestMeteringResilience:
    @respx.mock
    async def test_record_spend_failure_does_not_break_response(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """record_spend failure logs warning but does not break response."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 10}},
            )
        )

        with patch("worthless.proxy.app.record_spend", side_effect=Exception("db error")):
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
# Gateway error response structure
# ------------------------------------------------------------------


class TestGatewayErrorResponse:
    def test_gateway_error_response_structure(self):
        """gateway_error_response produces correct JSON structure."""
        err = gateway_error_response(502, "bad gateway")
        assert err.status_code == 502
        assert b"bad gateway" in err.body
        assert err.headers["content-type"] == "application/json"


# ==================================================================
# Plan 03 tests (body size limit, CORS denial)
# ==================================================================


# ------------------------------------------------------------------
# ------------------------------------------------------------------
# M-11: CORS Denial
# ------------------------------------------------------------------


class TestCORSDenial:
    """CORS is explicitly denied — no Access-Control-Allow-Origin in responses."""

    @pytest.fixture()
    async def cors_client(self, proxy_settings: ProxySettings, repo):
        """Client for CORS testing."""
        import aiosqlite

        from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule

        app = create_app(proxy_settings)
        db = await aiosqlite.connect(proxy_settings.db_path)
        app.state.db = db
        app.state.repo = repo
        app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
        app.state.rules_engine = RulesEngine(
            rules=[
                SpendCapRule(db=db),
                RateLimitRule(default_rps=100.0),
            ]
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
        await app.state.httpx_client.aclose()
        await db.close()

    async def test_cors_preflight_denied(self, cors_client):
        """CORS preflight (OPTIONS with Origin) gets no Access-Control-Allow-Origin."""
        resp = await cors_client.options(
            "/v1/chat/completions",
            headers={
                "origin": "https://evil.com",
                "access-control-request-method": "POST",
            },
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_regular_request_no_cors_header(self, cors_client):
        """Regular request has no Access-Control-Allow-Origin header."""
        resp = await cors_client.post(
            "/healthz",
            headers={"origin": "https://evil.com"},
        )
        assert "access-control-allow-origin" not in resp.headers


# ==================================================================
# Auth collapse: TLS header trust
# ==================================================================


@pytest.fixture()
async def attack_scenario(
    tmp_db_path: str,
    fernet_key: bytes,
    tmp_path,
):
    """Enrolled key in DB, secure defaults (TLS required)."""
    from worthless.crypto.splitter import split_key_fp
    from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
    from worthless.storage.repository import ShardRepository, StoredShard

    alias = "openai-abcd1234"
    api_key = "sk-test-key-1234567890abcdef"
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")

    settings = ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        allow_insecure=False,
    )

    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()

    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.store(
        alias, shard, prefix=sr.prefix, charset=sr.charset, base_url="https://api.openai.com/v1"
    )

    app = create_app(settings)
    db = await aiosqlite.connect(tmp_db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[
            SpendCapRule(db=db),
            RateLimitRule(default_rps=100.0, db_path=tmp_db_path),
        ]
    )

    shard_a_utf8 = sr.shard_a.decode("utf-8")
    yield app, alias, shard_a_utf8, settings
    await app.state.httpx_client.aclose()
    await db.close()


class TestAuthCollapse:
    """Verify that TLS header trust cannot be exploited to reconstruct
    API keys without credentials."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_unauthenticated_request_cannot_reconstruct_key(self, attack_scenario):
        """Bare request with no auth must not reach upstream."""
        app, alias, shard_a_utf8, settings = attack_scenario

        upstream = respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": "pwned"}}]})
        )

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

        assert resp.status_code == 401, (
            f"Attack succeeded! Got {resp.status_code} -- "
            "unauthenticated request reconstructed an API key."
        )
        assert not upstream.called, "Upstream was called -- key was reconstructed without auth"

    @pytest.mark.asyncio
    async def test_spoofed_xfp_does_not_bypass_tls(self, attack_scenario):
        """X-Forwarded-Proto: https over plain HTTP must be rejected."""
        app, alias, shard_a_utf8, settings = attack_scenario

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "x-forwarded-proto": "https",
                },
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

        assert resp.status_code == 401, (
            f"Spoofed X-Forwarded-Proto bypassed TLS! Got {resp.status_code}."
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_real_tls_connection_accepted(self, attack_scenario):
        """Request over real HTTPS (scope scheme=https) passes TLS check."""
        app, alias, shard_a_utf8, settings = attack_scenario

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": []})
        )

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                },
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_no_auth_headers_rejected(self, attack_scenario):
        """Bare request with no Authorization header is rejected."""
        app, alias, shard_a_utf8, settings = attack_scenario

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

        assert resp.status_code == 401


# ==================================================================
# SR-09 enforcement: _extract_alias_and_path unit tests
# ==================================================================


class TestExtractAliasAndPath:
    """Direct unit tests for _extract_alias_and_path — SR-09 alias extraction."""

    def test_standard_path(self) -> None:
        result = _extract_alias_and_path("/myalias/v1/chat/completions")
        assert result == ("myalias", "/v1/chat/completions")

    def test_root_path_returns_none(self) -> None:
        assert _extract_alias_and_path("/") is None

    def test_alias_only_no_subpath_returns_none(self) -> None:
        assert _extract_alias_and_path("/myalias") is None

    def test_double_slash_strips_to_valid(self) -> None:
        # strip("/") collapses leading slashes, so //v1/... becomes v1/...
        # which parses as alias="v1", path="/chat/completions"
        result = _extract_alias_and_path("//v1/chat/completions")
        assert result == ("v1", "/chat/completions")

    def test_alias_with_hyphens_underscores_digits(self) -> None:
        result = _extract_alias_and_path("/my-alias_01/v1/messages")
        assert result == ("my-alias_01", "/v1/messages")

    def test_path_traversal_returns_none(self) -> None:
        assert _extract_alias_and_path("/../../etc/passwd") is None

    def test_alias_with_spaces_returns_none(self) -> None:
        assert _extract_alias_and_path("/alias with spaces/v1/") is None

    def test_alias_with_trailing_slash_only_returns_none(self) -> None:
        # /valid-alias/ strip("/") -> "valid-alias" -> split gives 1 part -> None
        assert _extract_alias_and_path("/valid-alias/") is None


# ==================================================================
# SR-09 enforcement: Bearer token edge cases
# ==================================================================


class TestBearerTokenEdgeCases:
    """Edge cases for Authorization header parsing."""

    async def test_empty_bearer_token_returns_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Authorization: Bearer (empty token after space) returns 401."""
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

    async def test_non_bearer_scheme_returns_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Authorization: Token xyz (non-Bearer scheme) returns 401."""
        alias, _, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": "Token xyz",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    @respx.mock
    async def test_lowercase_bearer_accepted(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Authorization: bearer <token> (lowercase) should work."""
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 1}},
            )
        )

        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200

    async def test_no_authorization_header_returns_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """No Authorization header at all returns 401."""
        alias, _, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_no_scheme_returns_401(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Authorization: <token> (no scheme prefix) returns 401."""
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": shard_a_utf8,
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    @respx.mock
    async def test_x_api_key_header_accepted(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Anthropic x-api-key header should be accepted as shard-A source."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 1}}),
        )
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "x-api-key": shard_a_utf8,
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200, f"x-api-key should be accepted, got {resp.status_code}"

    @respx.mock
    async def test_bearer_takes_precedence_over_x_api_key(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """When both Authorization: Bearer and x-api-key are present, Bearer wins."""
        alias, shard_a_utf8, _ = enrolled_alias
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 1}}),
        )
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "x-api-key": "wrong-shard-a-value",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 200, f"Bearer should take precedence, got {resp.status_code}"


# ==================================================================
# SR-09 enforcement: ProxySettings structural guard
# ==================================================================


class TestProxySettingsStructuralGuard:
    """ProxySettings must not reference shard-A material."""

    def test_proxy_settings_has_no_shard_a_fields(self):
        """SR-09: ProxySettings must not reference shard-A files."""
        assert not hasattr(ProxySettings, "shard_a_dir")
        assert not hasattr(ProxySettings, "allow_alias_inference")


# ==================================================================
# Adversarial security tests — WOR-196 release hardening
# ==================================================================


# ------------------------------------------------------------------
# ATK-1: Shard-A extraction attacks via Authorization header
# ------------------------------------------------------------------


class TestShardAExtractionAttacks:
    """Adversarial tests targeting shard-A extraction from Authorization header."""

    async def test_header_injection_crlf_in_bearer_token(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Bearer token with CRLF injection attempt must be rejected.

        Attack: Authorization: Bearer <shard-A>\\r\\nX-Injected: evil
        Goal: Inject additional headers via the bearer token value.
        httpx ASGITransport does NOT reject CR/LF in header values, so they
        reach our _BAD_HEADER_CHARS check which must return 401.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        poisoned_token = f"{shard_a_utf8}\r\nX-Injected: evil"
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {poisoned_token}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401, (
            f"CRLF injection in bearer token was not rejected! Got {resp.status_code}"
        )

    async def test_header_injection_null_byte_in_bearer_token(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Bearer token containing null bytes must be rejected.

        Attack: Authorization: Bearer <shard-A>\\x00<garbage>
        Goal: Truncation or confusion in downstream processing.
        httpx ASGITransport does NOT reject null bytes in headers, so they
        reach our _BAD_HEADER_CHARS check which must return 401.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        poisoned_token = f"{shard_a_utf8}\x00garbage-after-null"
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {poisoned_token}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401, (
            f"Null byte injection in bearer token was not rejected! Got {resp.status_code}"
        )

    async def test_crlf_in_bearer_rejected_at_app_level(self, proxy_app, enrolled_alias):
        """Direct ASGI scope injection: null/CR/LF in header value triggers 401.

        Bypasses httpx header validation by constructing raw ASGI scope.
        This exercises the _BAD_HEADER_CHARS check in the proxy handler.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        poisoned_token = f"Bearer {shard_a_utf8}\r\nX-Injected: evil"

        # Build a raw ASGI scope with the poisoned header
        scope = {
            "type": "http",
            "method": "POST",
            "path": f"/{alias}/v1/chat/completions",
            "query_string": b"",
            "headers": [
                (b"authorization", poisoned_token.encode("utf-8", errors="surrogateescape")),
                (b"content-type", b"application/json"),
            ],
            "scheme": "http",
            "root_path": "",
            "asgi": {"version": "3.0"},
            "server": ("test", 80),
        }

        response_started = {}
        response_body = bytearray()

        async def receive():
            return {"type": "http.request", "body": b'{"model": "gpt-4", "messages": []}'}

        async def send(message):
            if message["type"] == "http.response.start":
                response_started["status"] = message["status"]
                response_started["headers"] = message.get("headers", [])
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))

        await proxy_app(scope, receive, send)
        assert response_started["status"] == 401, (
            f"CRLF injection in bearer token was not rejected! Got {response_started['status']}"
        )

    async def test_null_byte_in_bearer_rejected_at_app_level(self, proxy_app, enrolled_alias):
        """Direct ASGI scope injection: null byte in Authorization header triggers 401."""
        alias, shard_a_utf8, _ = enrolled_alias
        poisoned_token = f"Bearer {shard_a_utf8}\x00garbage"

        scope = {
            "type": "http",
            "method": "POST",
            "path": f"/{alias}/v1/chat/completions",
            "query_string": b"",
            "headers": [
                (b"authorization", poisoned_token.encode("utf-8", errors="surrogateescape")),
                (b"content-type", b"application/json"),
            ],
            "scheme": "http",
            "root_path": "",
            "asgi": {"version": "3.0"},
            "server": ("test", 80),
        }

        response_started = {}

        async def receive():
            return {"type": "http.request", "body": b'{"model": "gpt-4", "messages": []}'}

        async def send(message):
            if message["type"] == "http.response.start":
                response_started["status"] = message["status"]

        await proxy_app(scope, receive, send)
        assert response_started["status"] == 401, (
            f"Null byte injection not rejected! Got {response_started['status']}"
        )

    async def test_oversized_bearer_token_rejected(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Bearer token of 256KB+ must not cause memory exhaustion or crash.

        Attack: Authorization: Bearer <256KB of data>
        Goal: OOM or slow processing via oversized header.
        """
        alias, _, _ = enrolled_alias
        huge_token = "A" * (256 * 1024)  # 256KB
        resp = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {huge_token}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        # Must reject — either 401 (reconstruct fails) or 431 (headers too large)
        assert resp.status_code in (401, 431), (
            f"Oversized bearer token not rejected! Got {resp.status_code}"
        )

    async def test_wrong_alias_shard_a_rejected(self, proxy_app, repo, enrolled_alias):
        """Shard-A for alias-X used against alias-Y must fail reconstruction.

        Attack: Steal shard-A from one alias, use it to reconstruct another alias's key.
        """
        alias_a, shard_a_for_alias_a, _ = enrolled_alias

        # Enroll a second alias with a different key
        alias_b = "other-key"
        api_key_b = "sk-other-key-9876543210fedcba"
        sr_b = split_key_fp(api_key_b, prefix="sk-", provider="openai")
        shard_b = StoredShard(
            shard_b=bytearray(sr_b.shard_b),
            commitment=bytearray(sr_b.commitment),
            nonce=bytearray(sr_b.nonce),
            provider="openai",
        )
        await repo.store(
            alias_b,
            shard_b,
            prefix=sr_b.prefix,
            charset=sr_b.charset,
            base_url="https://api.openai.com/v1",
        )

        # Use shard-A from alias_a against alias_b
        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias_b}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_for_alias_a}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        assert resp.status_code == 401, (
            f"Cross-alias shard-A attack succeeded! Got {resp.status_code}"
        )


# ------------------------------------------------------------------
# ATK-2: Alias extraction attacks via URL path
# ------------------------------------------------------------------


class TestAliasExtractionAttacks:
    """Adversarial tests targeting alias extraction from URL path."""

    async def test_path_traversal_cross_alias(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Path traversal: /<alias>/../<other>/v1/chat/completions.

        Attack: Use .. segments to escape the alias prefix and steal another alias.
        Result: alias is extracted as first segment, but the api_path contains ../
                which won't match any adapter -> 401.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/../other-alias/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401, (
            f"Path traversal to other alias was not rejected! Got {resp.status_code}"
        )

    async def test_filesystem_traversal(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Path traversal: /<alias>/../../etc/passwd.

        Attack: Attempt filesystem traversal through the proxy path.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}/../../etc/passwd",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401
        assert b"passwd" not in resp.content

    async def test_url_encoded_traversal(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """URL-encoded traversal: /%2e%2e/admin/v1/chat/completions.

        Attack: Use percent-encoded dots to bypass regex alias validation.
        _ALIAS_RE rejects '%' so this fails at alias validation.
        """
        resp = await proxy_client.post(
            "/%2e%2e/admin/v1/chat/completions",
            headers={
                "authorization": "Bearer fake-token",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_double_encoded_traversal(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Double-encoded traversal: /%252e%252e/v1/chat/completions.

        Attack: Double percent-encoding to bypass single-decode filters.
        """
        resp = await proxy_client.post(
            "/%252e%252e/v1/chat/completions",
            headers={
                "authorization": "Bearer fake-token",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    async def test_null_byte_in_alias(self, proxy_client: httpx.AsyncClient, enrolled_alias):
        """Null byte in alias: /<alias>%00evil/v1/chat/completions.

        Attack: Null byte truncation to mutate the alias lookup.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        resp = await proxy_client.post(
            f"/{alias}%00evil/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4", "messages": []}',
        )
        assert resp.status_code == 401

    def test_alias_regex_rejects_special_chars(self):
        """The alias regex must reject dots, slashes, percent, null, and unicode."""
        attack_aliases = [
            "..",
            "../",
            "..%2f",
            "alias%00",
            "alias\x00",
            "alias/sub",
            "alias.evil",
            "alias;drop",
            "alias&cmd",
            "alias<script>",
            "alias\uff0e\uff0e",  # fullwidth dots
        ]
        for attack in attack_aliases:
            result = _extract_alias_and_path(f"/{attack}/v1/chat/completions")
            if result is not None:
                extracted_alias, _ = result
                # If we got a result, the alias must NOT be the full attack string
                # (it should have been truncated or rejected by regex)
                assert extracted_alias != attack or _ALIAS_RE.fullmatch(attack), (
                    f"Dangerous alias accepted: {attack!r}"
                )

    async def test_traversal_responses_identical_to_normal_401(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Path traversal 401s must be byte-identical to normal 401s (anti-enumeration)."""
        # Reference: normal unknown alias
        ref = await proxy_client.post(
            "/nonexistent/v1/chat/completions",
            headers={"authorization": "Bearer fake"},
            content=b"{}",
        )

        traversal_paths = [
            "/%2e%2e/admin/v1/chat/completions",
            "/..%2f..%2fetc%2fpasswd",
            "/valid/../other/v1/chat/completions",
        ]
        for path in traversal_paths:
            resp = await proxy_client.post(
                path,
                headers={"authorization": "Bearer fake"},
                content=b"{}",
            )
            assert resp.status_code == 401
            assert resp.content == ref.content, (
                f"Traversal path {path} produces different 401 body (information leak)"
            )


# ------------------------------------------------------------------
# ATK-3: Timing attacks — constant-time rejection
# ------------------------------------------------------------------


class TestTimingAttacks:
    """Timing side-channel tests for authentication rejection paths.

    These verify that all rejection paths return the same pre-computed response
    object, making timing differences negligible. We do not measure wall-clock
    time (too flaky in CI) — instead we verify the structural property that
    guarantees constant-time behavior: all paths use _uniform_401().
    """

    async def test_valid_alias_wrong_shard_vs_invalid_alias_same_body(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Valid alias + wrong shard-A vs invalid alias: same response body.

        If they differ, an attacker can enumerate valid aliases.
        """
        alias, _, _ = enrolled_alias

        # Valid alias, wrong shard
        r1 = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={"authorization": "Bearer wrong-shard-aaaa"},
            content=b'{"model": "gpt-4", "messages": []}',
        )

        # Invalid alias
        r2 = await proxy_client.post(
            "/nonexistent-alias-xyz/v1/chat/completions",
            headers={"authorization": "Bearer wrong-shard-aaaa"},
            content=b'{"model": "gpt-4", "messages": []}',
        )

        assert r1.status_code == r2.status_code == 401
        assert r1.content == r2.content, (
            "Valid alias + wrong shard produces different 401 than invalid alias — "
            "enables alias enumeration via response body"
        )

    async def test_valid_alias_wrong_shard_vs_no_auth_same_body(
        self, proxy_client: httpx.AsyncClient, enrolled_alias
    ):
        """Valid alias + wrong shard vs no auth header at all: same response."""
        alias, _, _ = enrolled_alias

        r1 = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={"authorization": "Bearer wrong-shard"},
            content=b'{"model": "gpt-4", "messages": []}',
        )

        r2 = await proxy_client.post(
            f"/{alias}/v1/chat/completions",
            content=b'{"model": "gpt-4", "messages": []}',
        )

        assert r1.status_code == r2.status_code == 401
        assert r1.content == r2.content

    @respx.mock
    async def test_rules_denial_vs_auth_failure_different_status(self, proxy_app, enrolled_alias):
        """Rules denial (402/429) uses a DIFFERENT status code than auth failure (401).

        This is intentional — budget exceeded is a legitimate business response,
        not an enumeration vector. But the 401 bodies must all be identical.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        # Set up rules engine to deny
        proxy_app.state.rules_engine = type(
            "MockEngine",
            (),
            {
                "evaluate": AsyncMock(
                    return_value=ErrorResponse(
                        status_code=402,
                        body=b'{"error": "spend cap exceeded"}',
                        headers={"content-type": "application/json"},
                    )
                ),
                "release_spend_reservation": AsyncMock(return_value=None),
            },
        )()

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        # 402 is correct — rules denial is a different status code
        assert resp.status_code == 402
        # Verify this is NOT a 401 body (different error category)
        body = json.loads(resp.content)
        assert "spend cap" in body["error"]


# ------------------------------------------------------------------
# ATK-4: SR-09 deep enforcement — no shard-A at rest
# ------------------------------------------------------------------


class TestSR09DeepEnforcement:
    """Verify the proxy has absolutely no path to shard-A material on disk, env, or config."""

    def test_proxy_settings_no_filesystem_path_for_shards(self):
        """ProxySettings must not contain any path-like attribute for shard material."""
        forbidden_attrs = [
            "shard_a_dir",
            "shard_a_path",
            "shard_a_file",
            "shard_dir",
            "shard_path",
            "shards_dir",
            "key_dir",
            "key_path",
            "key_file",
            "allow_alias_inference",
            "scan_dir",
            "shard_a_env",
            "shard_a_var",
        ]
        for attr in forbidden_attrs:
            assert not hasattr(ProxySettings, attr), (
                f"SR-09 violation: ProxySettings has forbidden attribute '{attr}'"
            )

    def test_proxy_settings_fields_are_safe(self):
        """All ProxySettings fields are safe — none reference shard-A material."""
        import dataclasses

        fields = {f.name for f in dataclasses.fields(ProxySettings)}
        dangerous_keywords = {"shard_a", "key_dir", "key_path", "shard_dir"}
        for field_name in fields:
            for keyword in dangerous_keywords:
                assert keyword not in field_name.lower(), (
                    f"SR-09 violation: ProxySettings field '{field_name}' "
                    f"contains dangerous keyword '{keyword}'"
                )

    def test_proxy_app_module_no_shard_a_disk_access(self):
        """The proxy app module must not import os.scandir, glob, or pathlib for shard scanning."""
        import inspect

        from worthless.proxy import app as proxy_module

        source = inspect.getsource(proxy_module)
        forbidden_patterns = [
            "WORTHLESS_SHARD_A_DIR",
            "shard_a_dir",
            "scandir",
            "shard_a_path",
            "read_shard_a",
            "load_shard_a",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, f"SR-09 violation: proxy app module contains '{pattern}'"

    def test_proxy_config_module_no_shard_a_references(self):
        """The proxy config module must not reference shard-A storage."""
        import inspect

        from worthless.proxy import config as config_module

        source = inspect.getsource(config_module)
        forbidden_patterns = [
            "WORTHLESS_SHARD_A",
            "shard_a_dir",
            "shard_a_path",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"SR-09 violation: proxy config module contains '{pattern}'"
            )

    def test_extract_alias_from_path_not_disk(self):
        """Alias extraction uses URL path parsing, not filesystem enumeration."""
        # The function must work without any filesystem access
        result = _extract_alias_and_path("/my-alias/v1/chat/completions")
        assert result == ("my-alias", "/v1/chat/completions")
        # It must NOT access the filesystem — verify by checking it works
        # even with a nonexistent alias (no disk lookup)
        result = _extract_alias_and_path("/totally-fake-alias/v1/messages")
        assert result == ("totally-fake-alias", "/v1/messages")


# ------------------------------------------------------------------
# ATK-5: _BAD_HEADER_CHARS completeness
# ------------------------------------------------------------------


class TestBadHeaderCharsCompleteness:
    """Verify _BAD_HEADER_CHARS covers all dangerous control characters."""

    def test_bad_header_chars_includes_null(self):
        assert "\x00" in _BAD_HEADER_CHARS

    def test_bad_header_chars_includes_cr(self):
        assert "\r" in _BAD_HEADER_CHARS

    def test_bad_header_chars_includes_lf(self):
        assert "\n" in _BAD_HEADER_CHARS

    def test_alias_regex_is_strict_allowlist(self):
        """_ALIAS_RE must use fullmatch and reject anything outside [a-zA-Z0-9_-]."""

        # Verify the pattern is a strict character class
        assert _ALIAS_RE.pattern == "[a-zA-Z0-9_-]+"
        # Verify it rejects dangerous characters
        for char in "/.%\x00\r\n;&#<>|$(){}[]!'\"\\@^~`":
            assert not _ALIAS_RE.fullmatch(f"alias{char}evil"), (
                f"_ALIAS_RE accepts dangerous character: {char!r}"
            )


# ==================================================================
# Phase 1c: fail-closed streaming accounting (worthless-dupf.4)
# ==================================================================


class TestFailClosedSpendAccounting:
    """When usage extraction fails (truncated/malformed response), charge the
    spend reservation rather than releasing free (worthless-dupf.4).

    An attacker who truncates the upstream response to dodge the spend cap
    must be charged the conservative max_tokens estimate instead of 0.
    """

    @pytest.fixture()
    async def accounting_client(self, proxy_settings: ProxySettings, repo):
        """Proxy client wired with a real SpendCapRule for accounting tests."""
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
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
        await app.state.httpx_client.aclose()
        await db.close()

    @respx.mock
    async def test_non_streaming_no_usage_charges_reservation(
        self, accounting_client, enrolled_alias
    ):
        """Non-streaming response with no usage field charges _spend_reservation, not 0.

        The request body has max_tokens=50; upstream returns JSON with no usage field.
        record_spend must be called with 50 tokens (the reservation), not 0.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        # Upstream returns success but no usage field — extraction returns None
        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},  # no "usage" key
            )
        )

        recorded: list[tuple] = []

        async def capture_spend(db_path, alias, tokens, model, provider):
            recorded.append((alias, tokens, model, provider))

        with patch("worthless.proxy.app.record_spend", side_effect=capture_spend):
            resp = await accounting_client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 50}',
            )

        assert resp.status_code == 200
        assert len(recorded) == 1, "record_spend must be called exactly once"
        _, tokens, _, _ = recorded[0]
        assert tokens == 50, (
            f"Fail-closed: should charge reservation (50), got {tokens}. "
            "Charging 0 allows attackers to avoid the spend cap."
        )

    @respx.mock
    async def test_streaming_truncated_charges_reservation(self, accounting_client, enrolled_alias):
        """Streaming response with no usage in SSE charges _spend_reservation, not 0.

        The request body has max_tokens=75; upstream streams content but never
        sends a usage chunk. record_spend must be called with 75 tokens.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        # SSE stream with NO usage chunk — truncated/truncated stream
        sse_no_usage = (
            b"data: "
            + json.dumps({"choices": [{"delta": {"content": "Hi"}}], "model": "gpt-4o"}).encode()
            + b"\n\n"
            b"data: [DONE]\n\n"
        )

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=sse_no_usage,
                headers={"content-type": "text/event-stream"},
            )
        )

        recorded: list[tuple] = []

        async def capture_spend(db_path, alias, tokens, model, provider):
            recorded.append((alias, tokens, model, provider))

        with patch("worthless.proxy.app.record_spend", side_effect=capture_spend):
            resp = await accounting_client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 75}',
            )
            # Drain stream
            _ = resp.content

        assert resp.status_code == 200
        assert len(recorded) == 1, "record_spend must be called exactly once"
        _, tokens, _, _ = recorded[0]
        assert tokens == 75, (
            f"Fail-closed: should charge reservation (75), got {tokens}. "
            "Charging 0 on truncated stream lets attackers bypass the spend cap."
        )


class TestRequestBodyLimit:
    """Request body size enforcement before rules evaluation (worthless-dupf.3).

    A request body exceeding WORTHLESS_MAX_REQUEST_BYTES must be rejected with
    413 before RulesEngine.evaluate() runs — preventing memory exhaustion from
    an authenticated attacker who sends huge prompt payloads across all enrolled
    keys simultaneously.
    """

    @pytest.fixture()
    async def limited_proxy_app(self, proxy_settings: ProxySettings, repo):
        """Proxy app with a tiny 1 KB body limit for fast tests."""
        small_settings = replace(proxy_settings, max_request_bytes=1024)
        app = create_app(small_settings)
        db = await aiosqlite.connect(small_settings.db_path)
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
    async def limited_proxy_client(self, limited_proxy_app):
        transport = httpx.ASGITransport(app=limited_proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    async def test_oversized_request_body_rejected_with_413(
        self, limited_proxy_client, enrolled_alias
    ):
        """Body > max_request_bytes → 413 before rules_engine.evaluate()."""
        alias, shard_a_utf8, _ = enrolled_alias
        oversized_body = b"x" * 1025  # 1 byte over 1 KB limit

        resp = await limited_proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=oversized_body,
        )

        assert resp.status_code == 413, (
            f"Expected 413 for body exceeding limit, got {resp.status_code}. "
            "Oversized bodies must be rejected before rules evaluation."
        )

    async def test_rules_not_called_when_body_exceeds_limit(
        self, limited_proxy_app, limited_proxy_client, enrolled_alias
    ):
        """rules_engine.evaluate() must NOT be called when the body is too large.

        The 413 must fire BEFORE the rules gate — otherwise the DoS still hits
        the expensive rules path before being rejected.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        oversized_body = b"x" * 1025

        evaluate_called = False
        original_evaluate = limited_proxy_app.state.rules_engine.evaluate

        async def tracking_evaluate(*args, **kwargs):
            nonlocal evaluate_called
            evaluate_called = True
            return await original_evaluate(*args, **kwargs)

        limited_proxy_app.state.rules_engine.evaluate = tracking_evaluate

        resp = await limited_proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=oversized_body,
        )

        assert resp.status_code == 413
        assert not evaluate_called, (
            "rules_engine.evaluate must NOT be called when body exceeds size limit. "
            "The size guard must fire before the rules gate."
        )

    @respx.mock
    async def test_body_at_exact_limit_passes(self, limited_proxy_client, enrolled_alias):
        """Body exactly at max_request_bytes → request proceeds (not rejected)."""
        alias, shard_a_utf8, _ = enrolled_alias

        # Build a body exactly 1024 bytes
        base = b'{"model":"gpt-4o","messages":[],"max_tokens":1}'
        at_limit = base + b" " * (1024 - len(base))
        assert len(at_limit) == 1024

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 1}},
            )
        )

        resp = await limited_proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=at_limit,
        )

        assert resp.status_code == 200, (
            f"Body exactly at limit should pass; got {resp.status_code}. "
            "Limit is exclusive-upper-bound: > limit rejects, == limit passes."
        )

    def test_default_limit_is_4mb(self, proxy_settings: ProxySettings):
        """Default max_request_bytes is 4 MB when no env override is set."""
        assert proxy_settings.max_request_bytes == 4 * 1024 * 1024, (
            f"Default body limit should be 4 MB, got {proxy_settings.max_request_bytes}. "
            "A reasonable default prevents memory exhaustion without blocking real requests."
        )

    def test_limit_configurable_via_env(self, monkeypatch, tmp_db_path: str, fernet_key: bytes):
        """WORTHLESS_MAX_REQUEST_BYTES env var overrides the default limit."""
        monkeypatch.setenv("WORTHLESS_MAX_REQUEST_BYTES", "2048")
        settings = ProxySettings(
            db_path=tmp_db_path,
            fernet_key=bytearray(fernet_key),
            allow_insecure=True,
        )
        assert settings.max_request_bytes == 2048, (
            f"Expected limit=2048 from env, got {settings.max_request_bytes}. "
            "WORTHLESS_MAX_REQUEST_BYTES must set the body size limit."
        )

    async def test_chunked_body_over_limit_rejected(self, limited_proxy_client, enrolled_alias):
        """Chunked transfer (no Content-Length) over limit → 413.

        The guard must count actual bytes read from request.stream(), NOT trust
        the Content-Length header, which is absent for chunked requests.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        # Send content via an async iterator — httpx omits Content-Length for generators
        async def chunked_payload():
            yield b"x" * 600  # chunk 1
            yield b"x" * 600  # chunk 2 — total 1200 > 1024 limit

        resp = await limited_proxy_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=chunked_payload(),
        )

        assert resp.status_code == 413, (
            f"Chunked body over limit should return 413, got {resp.status_code}. "
            "Guard must count stream bytes, not trust Content-Length."
        )


class TestResponseBufferCap:
    """Non-SSE upstream response buffering cap (worthless-dupf.5).

    A huge or gzip-bomb upstream response must be rejected with 502 before
    the decompressed body exhausts proxy memory.  The cap applies only to
    non-streaming responses (is_streaming=False); SSE streams are exempt.
    """

    @pytest.fixture()
    async def small_resp_limit_app(self, proxy_settings: ProxySettings, repo):
        """Proxy app with a 512-byte response body limit for fast tests."""
        small_settings = replace(proxy_settings, max_response_bytes=512)
        app = create_app(small_settings)
        db = await aiosqlite.connect(small_settings.db_path)
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
    async def small_resp_limit_client(self, small_resp_limit_app):
        transport = httpx.ASGITransport(app=small_resp_limit_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    @respx.mock
    async def test_non_sse_response_over_limit_rejected_with_502(
        self, small_resp_limit_client, enrolled_alias
    ):
        """Upstream non-SSE body > max_response_bytes → proxy returns 502.

        A large upstream response (real or decompressed from a gzip bomb)
        must be rejected before the proxy forwards it, preventing OOM.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        big_body = b"x" * 513  # 1 byte over 512-byte limit

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=big_body,
                headers={"content-type": "application/json"},
            )
        )

        resp = await small_resp_limit_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 10}',
        )

        assert resp.status_code == 502, (
            f"Expected 502 for oversized upstream response, got {resp.status_code}. "
            "The proxy must not forward or buffer huge upstream responses."
        )

    @respx.mock
    async def test_non_sse_response_content_length_over_limit_rejected(
        self, small_resp_limit_client, enrolled_alias
    ):
        """Content-Length header > max_response_bytes → 502 before body is buffered.

        When the upstream declares a body that would exceed the limit, the
        proxy must reject immediately without calling aread() on the full body.
        """
        alias, shard_a_utf8, _ = enrolled_alias
        declared_big = 513  # > 512 limit

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=b"x" * declared_big,
                headers={
                    "content-type": "application/json",
                    "content-length": str(declared_big),
                },
            )
        )

        resp = await small_resp_limit_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 10}',
        )

        assert resp.status_code == 502, (
            f"Expected 502 when Content-Length exceeds limit, got {resp.status_code}. "
            "Fast rejection without buffering is required."
        )

    @respx.mock
    async def test_non_sse_response_at_limit_passes(self, small_resp_limit_client, enrolled_alias):
        """Non-SSE body exactly at max_response_bytes → forwarded normally (200)."""
        alias, shard_a_utf8, _ = enrolled_alias
        at_limit = b'{"choices":[],"usage":{"total_tokens":1}}' + b" " * (
            512 - len(b'{"choices":[],"usage":{"total_tokens":1}}')
        )
        assert len(at_limit) == 512

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=at_limit,
                headers={"content-type": "application/json"},
            )
        )

        resp = await small_resp_limit_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 10}',
        )

        assert resp.status_code == 200, (
            f"Body exactly at limit should pass, got {resp.status_code}."
        )

    @respx.mock
    async def test_sse_streaming_not_blocked_by_response_cap(
        self, small_resp_limit_client, enrolled_alias
    ):
        """SSE streaming responses are exempt from the non-SSE response cap.

        The cap applies to buffered non-SSE bodies only — streaming responses
        bypass it (they have their own unbounded-but-chunked delivery path).
        """
        alias, shard_a_utf8, _ = enrolled_alias
        # SSE body WAY over 512-byte limit — should still pass for streaming.
        # Pad content chunks to ensure total > 512 bytes.
        content_chunk = json.dumps(
            {"choices": [{"delta": {"content": "x" * 80}}], "model": "gpt-4o"}
        ).encode()
        usage_chunk = json.dumps(
            {"choices": [{"delta": {}}], "usage": {"total_tokens": 5}, "model": "gpt-4o"}
        ).encode()
        sse_chunks = (
            (b"data: " + content_chunk + b"\n\n") * 5
            + b"data: "
            + usage_chunk
            + b"\n\ndata: [DONE]\n\n"
        )
        assert len(sse_chunks) > 512, "SSE payload must exceed limit to test exemption"

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                content=sse_chunks,
                headers={"content-type": "text/event-stream"},
            )
        )

        resp = await small_resp_limit_client.post(
            f"/{alias}/v1/chat/completions",
            headers={
                "authorization": f"Bearer {shard_a_utf8}",
                "content-type": "application/json",
            },
            content=b'{"model": "gpt-4o", "messages": [], "max_tokens": 10}',
        )

        assert resp.status_code == 200, (
            f"SSE streaming must not be blocked by the non-SSE response cap, "
            f"got {resp.status_code}."
        )

    def test_default_response_limit_is_8mb(self, proxy_settings: ProxySettings):
        """Default max_response_bytes is 8 MB."""
        assert proxy_settings.max_response_bytes == 8 * 1024 * 1024, (
            f"Default response limit should be 8 MB, got {proxy_settings.max_response_bytes}."
        )

    def test_response_limit_configurable_via_env(
        self, monkeypatch, tmp_db_path: str, fernet_key: bytes
    ):
        """WORTHLESS_MAX_RESPONSE_BYTES env var overrides the default limit."""
        monkeypatch.setenv("WORTHLESS_MAX_RESPONSE_BYTES", "4096")
        settings = ProxySettings(
            db_path=tmp_db_path,
            fernet_key=bytearray(fernet_key),
            allow_insecure=True,
        )
        assert settings.max_response_bytes == 4096, (
            f"Expected 4096 from env, got {settings.max_response_bytes}."
        )


# ==================================================================
# Phase 1a: Decoy tripwire at proxy ingress (worthless-ld4m)
# ==================================================================


class TestDecoyTripwire:
    """When a decoy shard-A is presented, the proxy MUST:
    1. Return a uniform 401 (same as any other auth failure).
    2. Log a warning containing "decoy_detected" (alert + audit trail).
    3. Never call is_known_decoy on every request (performance guard).
    4. Not alert for non-decoy wrong keys.

    Design: a decoy enrollment stores sha256(shard_a_bytes) as decoy_hash.
    The stored shard_b/commitment is intentionally mismatched so reconstruction
    always fails — a decoy key can never succeed. The proxy computes
    sha256(presented_shard_a_bytes) BEFORE zeroing, then fires a background
    decoy check only at the reconstruction-failure path.
    """

    @pytest.fixture()
    async def decoy_enrolled(self, repo, proxy_settings: ProxySettings, tmp_path):
        """Enroll a decoy alias: valid shard_a, mismatched shard_b/commitment.

        The mismatch guarantees reconstruction always fails, so the proxy
        always returns 401 — making decoy detection fire on the failure path.

        Uses store_enrolled (not store) so an enrollments row is created —
        set_decoy_hash writes to that row.

        Returns (alias, shard_a_utf8, shard_a_bytes).
        """
        alias = "decoy-key"
        # Split two different keys — use shard_a from key1, shard_b/commitment from key2.
        # reconstruct_key_fp will fail the commitment check because the stored
        # shard_b doesn't correspond to the presented shard_a.
        api_key1 = "sk-decoy-key-1234567890abcdef"
        api_key2 = "sk-other-key-9876543210fedcba"
        sr1 = split_key_fp(api_key1, prefix="sk-", provider="openai")
        sr2 = split_key_fp(api_key2, prefix="sk-", provider="openai")

        # Store shard_b/commitment from sr2 but shard_a will be sr1's
        shard = StoredShard(
            shard_b=bytearray(sr2.shard_b),  # mismatched!
            commitment=bytearray(sr2.commitment),  # mismatched!
            nonce=bytearray(sr2.nonce),
            provider="openai",
        )
        # store_enrolled creates both shards and enrollments rows;
        # set_decoy_hash updates the enrollments row.
        env_path = tmp_path / ".env"
        env_path.write_text(f"OPENAI_API_KEY={api_key1}\n")
        await repo.store_enrolled(
            alias,
            shard,
            var_name="OPENAI_API_KEY",
            env_path=str(env_path),
            prefix=sr1.prefix,
            charset=sr1.charset,
            base_url="https://api.openai.com/v1",
        )

        # Mark as decoy: store sha256(shard_a_bytes)
        shard_a_bytes = bytes(sr1.shard_a)
        await repo.set_decoy_hash(alias, str(env_path), shard_a_bytes)

        shard_a_utf8 = sr1.shard_a.decode("utf-8")
        return alias, shard_a_utf8, shard_a_bytes

    async def test_decoy_key_triggers_alert_not_just_401(
        self,
        proxy_app,
        decoy_enrolled,
        caplog,
    ):
        """Presenting a decoy shard-A returns 401 AND logs 'decoy_detected'.

        The attacker gets no extra information (same 401), but the operator
        sees the alert in the audit log.
        """
        alias, shard_a_utf8, _ = decoy_enrolled

        import logging

        with caplog.at_level(logging.WARNING, logger="worthless.proxy.app"):
            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {shard_a_utf8}",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": []}',
                )

        # Still returns uniform 401 — no information leak to attacker
        assert resp.status_code == 401, (
            f"Decoy presentation must return 401, got {resp.status_code}"
        )
        # Background decoy check must have logged "decoy_detected"
        # Allow a brief moment for the background task to complete
        import asyncio

        await asyncio.sleep(0.05)
        decoy_logs = [r for r in caplog.records if "decoy_detected" in r.getMessage()]
        assert decoy_logs, (
            "Decoy presentation did not trigger 'decoy_detected' warning. "
            f"Log records: {[r.getMessage() for r in caplog.records]}"
        )

    async def test_decoy_detection_uses_shard_a_hash_not_original_key(
        self,
        repo,
        decoy_enrolled,
    ):
        """is_known_decoy is keyed on sha256(shard_a_bytes), not the original API key.

        Presenting the sha256 of the original key (not shard_a) must NOT
        trigger decoy detection. Only sha256(shard_a_bytes) matches.
        """
        import hashlib

        alias, shard_a_utf8, shard_a_bytes = decoy_enrolled

        # sha256 of the shard_a bytes → should match
        shard_a_digest = hashlib.sha256(shard_a_bytes).digest()
        assert await repo.is_known_decoy(shard_a_digest), (
            "is_known_decoy(sha256(shard_a_bytes)) must return True for a decoy"
        )

        # sha256 of the original key string → must NOT match
        original_key = "sk-decoy-key-1234567890abcdef"
        original_key_digest = hashlib.sha256(original_key.encode()).digest()
        assert not await repo.is_known_decoy(original_key_digest), (
            "is_known_decoy must NOT match when given sha256 of the original key "
            "— it must be keyed on sha256(shard_a_bytes) only"
        )

    @respx.mock
    async def test_decoy_detection_does_not_call_is_known_decoy_on_every_request(
        self,
        proxy_app,
        enrolled_alias,
    ):
        """Normal successful requests must never call is_known_decoy (performance guard).

        The decoy check fires ONLY on the reconstruction-failure path,
        never on the happy path — calling it every request would add a
        DB round-trip to every valid request.
        """
        alias, shard_a_utf8, _ = enrolled_alias

        respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [], "usage": {"total_tokens": 5}},
            )
        )

        call_log: list[str] = []

        original_is_known_decoy = proxy_app.state.repo.is_known_decoy

        async def tracking_is_known_decoy(shard_a_sha256):
            call_log.append("called")
            return await original_is_known_decoy(shard_a_sha256)

        proxy_app.state.repo.is_known_decoy = tracking_is_known_decoy

        transport = httpx.ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=b'{"model": "gpt-4", "messages": []}',
            )

        assert resp.status_code == 200
        assert len(call_log) == 0, (
            f"is_known_decoy was called {len(call_log)} time(s) on a normal request — "
            "must only fire on the reconstruction-failure path"
        )

    async def test_non_decoy_wrong_key_does_not_trigger_alert(
        self,
        proxy_app,
        enrolled_alias,
        caplog,
    ):
        """Wrong shard-A that is NOT a decoy returns 401 but no 'decoy_detected' log.

        An attacker guessing random shard-A values must not trigger alerts —
        only a shard-A explicitly enrolled as decoy should fire the tripwire.
        """
        alias, _, _ = enrolled_alias

        import logging

        with caplog.at_level(logging.WARNING, logger="worthless.proxy.app"):
            transport = httpx.ASGITransport(app=proxy_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    headers={
                        # Present a wrong (non-decoy) shard_a for the known alias
                        "authorization": "Bearer sk-wrong-shard-aaaaaaaaaa",
                        "content-type": "application/json",
                    },
                    content=b'{"model": "gpt-4", "messages": []}',
                )

        import asyncio

        await asyncio.sleep(0.05)  # let any background task settle

        assert resp.status_code == 401
        decoy_logs = [r for r in caplog.records if "decoy_detected" in r.getMessage()]
        assert not decoy_logs, (
            "Non-decoy wrong key triggered 'decoy_detected' alert — "
            "only explicitly enrolled decoys should fire the tripwire"
        )

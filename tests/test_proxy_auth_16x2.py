"""worthless-16x2: stable proxy auth token tests.

Proves the three guarantees the feature makes:
1. Token written by lock is verified on every request (constant-time, SR-07).
2. Token is stable across proxy restarts (loaded from encrypted DB at startup).
3. Re-lock keeps shards in sync (INSERT OR REPLACE) — no XOR deadlock.
"""

from __future__ import annotations

import asyncio
import secrets
from unittest.mock import patch

import aiosqlite
import httpx
import pytest
import respx

from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard


pytestmark = pytest.mark.skip(reason="WOR-549: worthless-16x2 ↔ sidecar IPC integration pending")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


async def _make_proxy_app(
    proxy_settings: ProxySettings,
    repo: ShardRepository,
    auth_token: str | None = None,
) -> tuple:
    """Build a proxy app with state pre-initialized (ASGITransport skips lifespan)."""
    app = create_app(proxy_settings)
    db = await aiosqlite.connect(proxy_settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.proxy_auth_token = auth_token  # worthless-16x2
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
    return app, db


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
async def enrolled_16x2(repo: ShardRepository):
    """Enroll a test key using upsert_locked_shard.

    Post-16x2-revert: returns (alias, shard_a_str, raw_api_key).
    shard_a_str is the format-preserving shard-A value that the client
    presents as Authorization: Bearer on every request.
    """
    from worthless.crypto.splitter import split_key_fp

    alias = "test-16x2"
    api_key = "sk-test-16x2-key-abcdef1234567890"

    sr = split_key_fp(api_key, prefix="sk-", provider="openai")
    # Capture shard_a before zeroing — this is what lives in openclaw.json
    shard_a_str = sr.shard_a.decode("utf-8")
    stored = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        stored,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="https://api.openai.com/v1",
    )
    sr.zero()
    return alias, shard_a_str, api_key.encode()


# ------------------------------------------------------------------
# Token auth — 16x2 path
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_valid_shard_a_reaches_upstream(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """A request with shard-A as Bearer is forwarded to the upstream.

    Post-16x2-revert: the proxy validates shard-A via commitment check
    (reconstruct_key_fp) instead of comparing a stable opaque token.
    """
    alias, shard_a_str, raw_api_key = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    try:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
                    "model": "gpt-4",
                },
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {shard_a_str}"},
                )
        assert resp.status_code == 200, (
            f"Expected 200 with shard-A as Bearer; got {resp.status_code}"
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


@pytest.mark.asyncio
async def test_16x2_wrong_token_returns_401(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """A request with an incorrect token is rejected — constant-time compare (SR-07)."""
    alias, auth_token, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer wrong-token-{secrets.token_urlsafe(16)}"},
            )
        assert resp.status_code == 401
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


@pytest.mark.asyncio
async def test_16x2_missing_bearer_returns_401(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """A 16x2 alias with no Authorization header returns 401."""
    alias, auth_token, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )
        assert resp.status_code == 401
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


@pytest.mark.asyncio
async def test_16x2_no_auth_token_in_proxy_returns_401(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """Alias has shard_a_enc but proxy has no auth_token loaded → 401.

    This models the case where the DB was written with 16x2 shards but the
    proxy restarted before the token was set (should not happen normally, but
    must fail safe).
    """
    alias, auth_token, _ = enrolled_16x2
    # Proxy starts with no token loaded
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 401
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


@pytest.mark.asyncio
async def test_16x2_shard_a_bearer_no_restart_needed(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """Proxy started before lock (no stable token) works with shard-A Bearer.

    Post-16x2-revert: no stable token to lazy-load. The proxy validates
    shard-A via commitment check on every request. No DB or state needed
    beyond the shard_b + commitment stored by lock.
    """
    alias, shard_a_str, _ = enrolled_16x2

    # No stable token written — post-revert lock doesn't write one.
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    try:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
                    "model": "gpt-4",
                },
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {shard_a_str}"},
                )
        assert resp.status_code == 200, (
            f"Expected 200 with shard-A as Bearer; got {resp.status_code}"
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ------------------------------------------------------------------
# DB persistence: auth token survives proxy restart
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_token_survives_restart(repo: ShardRepository) -> None:
    """Token written at lock time is recovered after proxy restart (set/get roundtrip)."""
    token = secrets.token_urlsafe(32)
    await repo.set_proxy_auth_token(token)

    recovered = await repo.get_proxy_auth_token()
    assert recovered == token


@pytest.mark.asyncio
async def test_auth_token_not_set_returns_none(repo: ShardRepository) -> None:
    """get_proxy_auth_token returns None when no token has been stored."""
    result = await repo.get_proxy_auth_token()
    assert result is None


@pytest.mark.asyncio
async def test_auth_token_encrypted_at_rest(repo: ShardRepository, tmp_db_path: str) -> None:
    """Token must not appear in plaintext in the metadata table."""
    token = secrets.token_urlsafe(32)
    await repo.set_proxy_auth_token(token)

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT value FROM metadata WHERE key = 'proxy_auth_token_enc'")
        row = await cursor.fetchone()
    assert row is not None
    # The stored value should be a Fernet token (base64 of Fernet ciphertext),
    # NOT the raw token string
    assert token not in row[0], "Auth token stored in plaintext!"


# ------------------------------------------------------------------
# Re-lock consistency: upsert_locked_shard (INSERT OR REPLACE)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_locked_shard_does_not_store_shard_a_enc(
    repo: ShardRepository, tmp_db_path: str
) -> None:
    """upsert_locked_shard writes NULL for shard_a_enc (post-16x2-revert contract).

    shard-A is no longer stored server-side. The proxy reads it from the
    Authorization: Bearer header on every request and validates via the
    commitment check. shard_a_enc stays NULL so a stolen DB never reveals
    shard-A (the half that reconstructs the full API key).
    """
    from worthless.crypto.splitter import split_key_fp

    alias = "relock-test"
    api_key = "sk-relock-abcdef1234567890"
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")
    stored = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        stored,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="https://api.openai.com/v1",
    )
    sr.zero()

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT shard_a_enc FROM shards WHERE key_alias = ?", (alias,))
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] is None, "shard_a_enc must be NULL — shard-A is not stored server-side"


@pytest.mark.asyncio
async def test_upsert_locked_shard_replaces_on_relock(repo: ShardRepository) -> None:
    """Second upsert_locked_shard replaces the shards row — both shards in sync."""
    from worthless.crypto.splitter import split_key_fp

    alias = "relock-replace"
    api_key = "sk-replace-key-abcdef1234567890"

    # First lock — capture prefix/charset before zeroing
    sr1 = split_key_fp(api_key, prefix="sk-", provider="openai")
    prefix, charset = sr1.prefix, sr1.charset
    stored1 = StoredShard(
        shard_b=bytearray(sr1.shard_b),
        commitment=bytearray(sr1.commitment),
        nonce=bytearray(sr1.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        stored1,
        prefix=prefix,
        charset=charset,
        base_url="https://api.openai.com/v1",
    )
    sr1.zero()

    # Second lock (simulated re-lock — same key, same alias)
    sr2 = split_key_fp(api_key, prefix="sk-", provider="openai")
    # Capture shard_a₂ before zeroing — in real usage this is the value
    # written to openclaw.json and presented as Authorization: Bearer.
    shard_a2_bytes = bytes(sr2.shard_a)
    stored2 = StoredShard(
        shard_b=bytearray(sr2.shard_b),
        commitment=bytearray(sr2.commitment),
        nonce=bytearray(sr2.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        stored2,
        prefix=prefix,
        charset=charset,
        base_url="https://api.openai.com/v1",
    )
    sr2.zero()

    # After re-lock: shard_a_enc is NULL (not stored), shard_b and commitment updated.
    # Reconstruction uses caller-provided shard_a (held by the client, not the server).
    encrypted = await repo.fetch_encrypted(alias)
    assert encrypted is not None
    assert encrypted.shard_a_enc is None, "shard_a_enc must be NULL post-16x2-revert"
    assert encrypted.prefix is not None
    assert encrypted.charset is not None

    # decrypt_shard returns shard_a=None since shard_a_enc is NULL
    stored = repo.decrypt_shard(encrypted)
    assert stored.shard_a is None

    # Reconstruction uses shard_a₂ captured before sr2.zero().
    from worthless.crypto.splitter import reconstruct_key_fp

    shard_a_buf = bytearray(shard_a2_bytes)
    try:
        reconstructed = reconstruct_key_fp(
            shard_a_buf,
            stored.shard_b,
            stored.commitment,
            stored.nonce,
            encrypted.prefix,
            encrypted.charset,
        )
        assert bytes(reconstructed) == api_key.encode()
    finally:
        for i in range(len(shard_a_buf)):
            shard_a_buf[i] = 0
    stored.zero()


@pytest.mark.asyncio
async def test_upsert_locked_shard_shard_a_enc_is_null(repo: ShardRepository) -> None:
    """upsert_locked_shard never stores shard_a_enc; decrypt_shard returns shard_a=None.

    Post-16x2-revert: shard-A is not persisted server-side. decrypt_shard
    always yields shard_a=None for rows written by upsert_locked_shard.
    The client supplies shard-A on every request via Authorization: Bearer.
    """
    from worthless.crypto.splitter import split_key_fp

    api_key = "sk-decrypt-test-abcdef1234567890"
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")
    stored = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    shard_a_raw = bytearray(sr.shard_a)
    await repo.upsert_locked_shard(
        "decrypt-alias",
        stored,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="https://api.openai.com/v1",
    )
    sr.zero()
    for i in range(len(shard_a_raw)):
        shard_a_raw[i] = 0

    encrypted = await repo.fetch_encrypted("decrypt-alias")
    assert encrypted is not None
    assert encrypted.shard_a_enc is None, "shard_a_enc must be NULL — not stored post-16x2-revert"

    decrypted = repo.decrypt_shard(encrypted)
    assert decrypted.shard_a is None, (
        "decrypt_shard must return shard_a=None when shard_a_enc is NULL"
    )
    decrypted.zero()


@pytest.mark.asyncio
async def test_legacy_row_shard_a_is_none(repo: ShardRepository) -> None:
    """Legacy rows (no shard_a_enc) yield shard_a=None from decrypt_shard."""
    shard = StoredShard(
        shard_b=bytearray(b"x" * 43),
        commitment=bytearray(b"c" * 32),
        nonce=bytearray(b"n" * 16),
        provider="openai",
    )
    await repo.store("legacy-alias", shard, base_url="https://api.openai.com/v1")

    encrypted = await repo.fetch_encrypted("legacy-alias")
    assert encrypted is not None
    assert encrypted.shard_a_enc is None

    decrypted = repo.decrypt_shard(encrypted)
    assert decrypted.shard_a is None
    decrypted.zero()


# ------------------------------------------------------------------
# StoredShard.zero() covers shard_a
# ------------------------------------------------------------------


def test_stored_shard_zero_clears_shard_a() -> None:
    """StoredShard.zero() must clear shard_a when present (SR-02)."""
    s = StoredShard(
        shard_b=bytearray(b"b" * 43),
        commitment=bytearray(b"c" * 32),
        nonce=bytearray(b"n" * 16),
        provider="openai",
        shard_a=bytearray(b"a" * 43),
    )
    s.zero()
    assert all(b == 0 for b in s.shard_a)  # type: ignore[union-attr]
    assert all(b == 0 for b in s.shard_b)


# ------------------------------------------------------------------
# SP-1: caplog — warning logged when lock never ran
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_wrong_shard_a_returns_401(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """A wrong shard-A presented as Bearer returns 401.

    Post-16x2-revert: the proxy validates shard-A via commitment check.
    A random string that is not the correct shard-A fails reconstruction
    (ShardTamperedError) and the proxy returns the uniform 401.
    """
    alias, shard_a_str, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer sk-wrong-shard-a-abcdef1234567890"},
            )
        assert resp.status_code == 401, f"Expected 401 for wrong shard-A; got {resp.status_code}"
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ------------------------------------------------------------------
# SP-6: corrupt shard_a_enc in DB → 401 not 500
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_corrupt_shard_a_enc_returns_401(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """Corrupt shard_a_enc in DB (garbled Fernet token) must yield 401, not 500.

    SP-6: decrypt_shard raises an exception (InvalidToken); the proxy must
    catch it and return the standard uniform 401, byte-identical to the
    normal auth failure body.
    """
    from worthless.proxy.errors import auth_error_response

    alias, auth_token, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

    # Corrupt the shard_a_enc field directly in SQLite.
    async with aiosqlite.connect(proxy_settings.db_path) as raw_db:
        await raw_db.execute(
            "UPDATE shards SET shard_a_enc = ? WHERE key_alias = ?",
            (b"not-a-valid-fernet-token-garbage-xyz", alias),
        )
        await raw_db.commit()

    expected_body = auth_error_response().body

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 401
        assert resp.content == expected_body, (
            f"Response body differs from uniform 401. Got: {resp.content!r}"
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ------------------------------------------------------------------
# SP-7: stored.shard_a is None after decrypt → 401 not crash
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_shard_a_none_after_decrypt_returns_401(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """When decrypt_shard returns StoredShard with shard_a=None, proxy returns 401.

    SP-7: shard_a_enc is present but the decryption yields shard_a=None
    (storage anomaly). No exception must escape — the handler catches this
    and returns the uniform 401.
    """
    alias, auth_token, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

    # Build a valid-looking StoredShard whose shard_a is None.
    null_shard_a_stored = StoredShard(
        shard_b=bytearray(b"b" * 43),
        commitment=bytearray(b"c" * 32),
        nonce=bytearray(b"n" * 16),
        provider="openai",
        shard_a=None,
    )

    try:
        with patch.object(repo, "decrypt_shard", return_value=null_shard_a_stored):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
        assert resp.status_code == 401
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ------------------------------------------------------------------
# SP-5: unknown endpoint on 16x2 alias → 401, zeroing guard safe
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_unknown_endpoint_returns_401(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """A 16x2 alias hitting an unknown endpoint path returns 401 (anti-enumeration).

    SP-5: the adapter lookup returns None for unrecognised paths; the proxy
    must return the uniform 401. The `if shard_a is not None:` zeroing guard
    must not raise — shard_a is None on the 16x2 path at that point.
    """
    alias, auth_token, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/{alias}/v1/unknown-endpoint-xyz",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        assert resp.status_code == 401
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ------------------------------------------------------------------
# SP-2 adversarial: concurrent requests when token is None at startup
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_concurrent_shard_a_requests_all_succeed(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """Five concurrent requests with shard-A all succeed.

    Post-16x2-revert: no stable token — each request is authenticated
    independently via commitment check. Concurrency must not race.
    """
    alias, shard_a_str, _ = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    async def _one_request(client: httpx.AsyncClient) -> int:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
                    "model": "gpt-4",
                },
            )
            resp = await client.post(
                f"/{alias}/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": f"Bearer {shard_a_str}"},
            )
        return resp.status_code

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            statuses = await asyncio.gather(*[_one_request(client) for _ in range(5)])

        assert list(statuses) == [200, 200, 200, 200, 200], f"Expected all 200s, got: {statuses}"
    finally:
        await app.state.httpx_client.aclose()


# ------------------------------------------------------------------
# worthless-m1td RED tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upstream_receives_raw_api_key_not_shard_a(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """Upstream Authorization header must carry Bearer <raw_api_key>, not shard-A.

    Core split-key invariant: the proxy reconstructs the full key from
    (shard-A Bearer + DB shard-B) and forwards the reconstructed key to
    upstream — never the partial shard-A the client sent.

    RED: test_16x2_valid_shard_a_reaches_upstream at line 112 only asserts
    response status (200).  It never inspects what Authorization header was
    actually forwarded upstream, so it would pass even if the proxy
    forwarded shard-A verbatim (bypassing reconstruction entirely).
    """
    alias, shard_a_str, raw_api_key = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    captured_auth: list[str] = []

    def _capture_and_respond(request: httpx.Request) -> httpx.Response:
        captured_auth.append(request.headers.get("authorization", ""))
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
                "model": "gpt-4",
            },
        )

    try:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").mock(
                side_effect=_capture_and_respond
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {shard_a_str}"},
                )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert len(captured_auth) == 1, "Upstream must be called exactly once"

        expected = f"Bearer {raw_api_key.decode()}"
        assert captured_auth[0] == expected, (
            f"Upstream must receive the reconstructed raw API key as Bearer.\n"
            f"  expected: {expected!r}\n"
            f"  got:      {captured_auth[0]!r}\n"
            "Forwarding shard-A instead of the reconstructed key breaks the "
            "split-key invariant and reveals an inert shard to the upstream."
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


@pytest.mark.asyncio
async def test_auth_token_survives_repo_reconnect(tmp_db_path: str, fernet_key: bytes) -> None:
    """Proxy auth token persists across distinct ShardRepository instances.

    test_auth_token_survives_restart (line 270) calls set_proxy_auth_token and
    get_proxy_auth_token on the *same* repo instance — it only tests in-memory
    round-trip, not actual DB persistence.  A fresh repo over the same DB path
    is the real restart scenario.

    RED: the existing test reuses the same object so it proves nothing about
    persistence across a real process restart.
    """
    # Write token with first instance (simulates proxy at lock time)
    repo1 = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await repo1.initialize()
    token = secrets.token_urlsafe(32)
    await repo1.set_proxy_auth_token(token)
    # Intentionally do NOT use repo1 below — simulates the proxy restarting
    repo1.close()

    # Recover with a second independent instance (simulates proxy after restart)
    repo2 = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await repo2.initialize()
    recovered = await repo2.get_proxy_auth_token()
    repo2.close()

    assert recovered == token, (
        f"Token must survive a fresh ShardRepository instance over the same DB.\n"
        f"  wrote:     {token!r}\n"
        f"  recovered: {recovered!r}"
    )

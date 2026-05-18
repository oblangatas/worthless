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
    """Enroll a test key using upsert_locked_shard (16x2 path).

    Returns (alias, auth_token, raw_api_key).
    """
    from worthless.crypto.splitter import split_key_fp

    alias = "test-16x2"
    api_key = "sk-test-16x2-key-abcdef1234567890"
    auth_token = secrets.token_urlsafe(32)

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
        shard_a=bytearray(sr.shard_a),
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="https://api.openai.com/v1",
    )
    sr.zero()
    return alias, auth_token, api_key.encode()


# ------------------------------------------------------------------
# Token auth — 16x2 path
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_16x2_valid_token_reaches_upstream(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """A request with the correct stable token is forwarded to the upstream."""
    alias, auth_token, raw_api_key = enrolled_16x2
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=auth_token)

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
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
        assert resp.status_code == 200
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
async def test_16x2_lazy_load_when_proxy_started_before_lock(
    enrolled_16x2, repo: ShardRepository, proxy_settings: ProxySettings
) -> None:
    """Proxy started before lock (auth_token=None at startup) lazy-loads from DB.

    Normal fresh-install flow: `worthless up` runs first, then `worthless lock`
    writes the token to DB. The proxy must not require a restart — it loads the
    token on the first 16x2 request and caches it.
    """
    alias, auth_token, _ = enrolled_16x2

    # Simulate: lock ran and wrote the token to DB, but proxy started before that
    await repo.set_proxy_auth_token(auth_token)
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)  # None = pre-lock start

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
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
        assert resp.status_code == 200
        # Token should now be cached in app.state
        assert app.state.proxy_auth_token == auth_token
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
async def test_upsert_locked_shard_stores_shard_a_enc(
    repo: ShardRepository, tmp_db_path: str
) -> None:
    """upsert_locked_shard writes shard_a_enc to the shards table."""
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
        alias, stored, shard_a=bytearray(sr.shard_a), base_url="https://api.openai.com/v1"
    )
    sr.zero()

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT shard_a_enc FROM shards WHERE key_alias = ?", (alias,))
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] is not None, "shard_a_enc should be set after upsert_locked_shard"


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
        shard_a=bytearray(sr1.shard_a),
        prefix=prefix,
        charset=charset,
        base_url="https://api.openai.com/v1",
    )
    sr1.zero()

    # Second lock (simulated re-lock — same key, same alias)
    sr2 = split_key_fp(api_key, prefix="sk-", provider="openai")
    stored2 = StoredShard(
        shard_b=bytearray(sr2.shard_b),
        commitment=bytearray(sr2.commitment),
        nonce=bytearray(sr2.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        stored2,
        shard_a=bytearray(sr2.shard_a),
        prefix=prefix,
        charset=charset,
        base_url="https://api.openai.com/v1",
    )
    sr2.zero()

    # After re-lock: decrypt should give back both shards and reconstruction should succeed
    encrypted = await repo.fetch_encrypted(alias)
    assert encrypted is not None
    assert encrypted.shard_a_enc is not None
    assert encrypted.prefix is not None
    assert encrypted.charset is not None

    stored = repo.decrypt_shard(encrypted)
    assert stored.shard_a is not None

    from worthless.crypto.splitter import reconstruct_key_fp

    reconstructed = reconstruct_key_fp(
        stored.shard_a,
        stored.shard_b,
        stored.commitment,
        stored.nonce,
        encrypted.prefix,
        encrypted.charset,
    )
    assert bytes(reconstructed) == api_key.encode()
    stored.zero()


@pytest.mark.asyncio
async def test_decrypt_shard_populates_shard_a(repo: ShardRepository) -> None:
    """decrypt_shard returns shard_a in StoredShard when shard_a_enc is set."""
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
        "decrypt-alias", stored, shard_a=shard_a_raw, base_url="https://api.openai.com/v1"
    )
    sr.zero()

    encrypted = await repo.fetch_encrypted("decrypt-alias")
    assert encrypted is not None
    assert encrypted.shard_a_enc is not None

    decrypted = repo.decrypt_shard(encrypted)
    assert decrypted.shard_a is not None
    assert decrypted.shard_a == shard_a_raw
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
async def test_16x2_no_auth_token_logs_warning(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When shard_a_enc is present but no token exists in DB, a WARNING is logged.

    SP-1: proxy has auth_token=None AND no token in DB (lock never ran).
    Must return 401 AND log the 'no proxy_auth_token in DB' warning with the alias name.
    """
    import logging

    alias, auth_token, _ = enrolled_16x2
    # Do NOT write a token to DB — simulates lock never having run.
    app, db = await _make_proxy_app(proxy_settings, repo, auth_token=None)

    try:
        with caplog.at_level(logging.WARNING, logger="worthless.proxy.app"):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
        assert resp.status_code == 401
        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        msgs = [r.message for r in warning_records]
        assert any("no proxy_auth_token in DB" in m for m in msgs), (
            f"Expected 'no proxy_auth_token in DB' in caplog. Got: {msgs}"
        )
        assert any(alias in m for m in msgs), (
            f"Expected alias {alias!r} in caplog warning. Got: {msgs}"
        )
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
async def test_16x2_concurrent_lazy_load_all_succeed(
    enrolled_16x2,
    repo: ShardRepository,
    proxy_settings: ProxySettings,
) -> None:
    """Five concurrent requests all succeed when proxy starts before lock.

    SP-2 adversarial: auth_token=None at startup, token in DB. All 5
    concurrent requests must return 200 (lazy-load on the 16x2 path). The
    token is effectively cached after the first request; subsequent ones
    use the cached value.
    """
    alias, auth_token, _ = enrolled_16x2

    # Write the token to DB (lock ran), but proxy started before it.
    await repo.set_proxy_auth_token(auth_token)
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
                headers={"Authorization": f"Bearer {auth_token}"},
            )
        return resp.status_code

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            statuses = await asyncio.gather(*[_one_request(client) for _ in range(5)])

        assert list(statuses) == [200, 200, 200, 200, 200], f"Expected all 200s, got: {statuses}"
        assert app.state.proxy_auth_token == auth_token, (
            "Expected lazy-loaded token to be cached in app.state"
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()

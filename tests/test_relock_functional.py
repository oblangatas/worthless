"""Failing tests for the post-16x2-revert target state.

Target state contract:
- Proxy accepts shard-A directly as ``Authorization: Bearer <shard-A>``.
- No stable proxy_auth_token in DB or app.state.
- No shard_a_enc column written by lock.
- openclaw.json apiKey field contains shard-A, not an opaque token.

These tests are RED on the current (16x2) code because:
- Tests 1, 2: proxy currently dispatches via shard_a_enc + stable-token path
  (enrolled via upsert_locked_shard); shard-A as Bearer returns 401.
- Test 5: upsert_locked_shard writes shard_a_enc; assertion that it is None fails.
- Test 3: doctor has no openclaw.json consistency check yet.
- Test 4: lock writes a stable opaque token to openclaw.json, not shard-A.
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import httpx
import pytest
import respx
from typer.testing import CliRunner

from worthless.cli.app import app as cli_app
from worthless.cli.bootstrap import ensure_home
from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard


pytestmark = pytest.mark.skip(reason="WOR-549: worthless-16x2 ↔ sidecar IPC integration pending")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proxy_settings(tmp_db_path: str, fernet_key: bytes) -> ProxySettings:
    return ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )


async def _build_proxy_app_with_token(
    settings: ProxySettings,
    repo: ShardRepository,
    auth_token: str | None,
):
    """Build proxy app pre-wired with a stable auth token (current 16x2 behavior)."""
    app = create_app(settings)
    db = await aiosqlite.connect(settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.proxy_auth_token = auth_token
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[
            SpendCapRule(db=db),
            RateLimitRule(
                default_rps=settings.default_rate_limit_rps,
                db_path=settings.db_path,
            ),
        ]
    )
    return app, db


async def _enroll_16x2(
    repo: ShardRepository,
    alias: str,
    api_key: str,
    provider: str = "openai",
    base_url: str = "https://api.openai.com/v1",
) -> bytes:
    """Enroll via current lock path (upsert_locked_shard → writes shard_a_enc).

    Returns the raw shard-A bytes. The proxy currently requires auth_token,
    not shard-A, so sending shard-A as Bearer produces 401.
    """
    sr = split_key_fp(api_key, prefix="sk-", provider=provider)
    try:
        stored = StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider=provider,
        )
        await repo.upsert_locked_shard(
            alias,
            stored,
            prefix=sr.prefix,
            charset=sr.charset,
            base_url=base_url,
        )
        return bytes(sr.shard_a)
    finally:
        sr.zero()


# ---------------------------------------------------------------------------
# Test 1 — shard-A from openclaw.json works as Bearer (target state)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_shard_a_in_openclaw_is_usable_as_bearer(
    tmp_db_path: str,
    fernet_key: bytes,
    tmp_path: Path,
) -> None:
    """Contract: shard-A is accepted as Bearer token (no stable-token mediation).

    After the revert, openclaw.json carries shard-A as apiKey. Sending it
    as ``Authorization: Bearer <shard-A>`` must reach the upstream with 200.

    FAILS on 16x2 code: the proxy recognises the row has shard_a_enc and
    validates the request against proxy_auth_token — NOT shard-A.
    Sending shard-A returns 401 even when the key is correctly enrolled.
    """
    settings = _make_proxy_settings(tmp_db_path, fernet_key)
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()

    alias = "test-openclaw-bearer"
    api_key = "sk-test-openclaw-key-abcdef1234"
    auth_token = secrets.token_urlsafe(32)

    # Enroll via 16x2 path (current lock behavior) — writes shard_a_enc
    shard_a_bytes = await _enroll_16x2(repo, alias, api_key)
    shard_a_str = shard_a_bytes.decode("utf-8")

    # In the target state openclaw.json would carry shard-A as apiKey.
    # An agent reads apiKey and sends it as Bearer.
    # Set proxy_auth_token so the proxy is in its current (16x2) operational state.
    app, db = await _build_proxy_app_with_token(settings, repo, auth_token=auth_token)
    try:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                    "model": "gpt-4",
                },
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                # Target state: send shard-A as Bearer — proxy must accept it.
                resp = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {shard_a_str}"},
                )
        assert resp.status_code == 200, (
            f"Expected 200 when sending shard-A as Bearer; got {resp.status_code}.\n"
            "SHOULD FAIL on 16x2 code: proxy checks proxy_auth_token, not shard-A.\n"
            "shard-A as Bearer produces 401 on the 16x2 stable-token path."
        )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ---------------------------------------------------------------------------
# Test 2 — old shard-A rejected after re-lock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_old_shard_a_rejected_after_relock(
    tmp_db_path: str,
    fernet_key: bytes,
) -> None:
    """After re-lock, shard-A₁ must return 401; shard-A₂ must return 200.

    Target-state mechanism: proxy verifies shard-A by reconstructing the key
    (XOR + commitment). After re-lock the DB has shard-B₂; XOR(shard-A₁,
    shard-B₂) fails the commitment check → 401. shard-A₂ passes → 200.

    FAILS on 16x2 code: proxy validates the STABLE TOKEN, not shard-A.
    Both shard-A₁ and shard-A₂ produce 401 because they're not the stable
    token. Only the stable token produces 200.
    """
    settings = _make_proxy_settings(tmp_db_path, fernet_key)
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()

    alias = "test-relock-rotate"
    api_key = "sk-relock-rotation-test-0123456789ab"
    auth_token = secrets.token_urlsafe(32)

    # Lock 1: enroll, get shard-A₁
    shard_a1_bytes = await _enroll_16x2(repo, alias, api_key)
    shard_a1_str = shard_a1_bytes.decode("utf-8")

    # Lock 2: re-split and overwrite with upsert_locked_shard (what lock does on re-lock).
    sr2 = split_key_fp(api_key, prefix="sk-", provider="openai")
    try:
        stored2 = StoredShard(
            shard_b=bytearray(sr2.shard_b),
            commitment=bytearray(sr2.commitment),
            nonce=bytearray(sr2.nonce),
            provider="openai",
        )
        await repo.upsert_locked_shard(
            alias,
            stored2,
            prefix=sr2.prefix,
            charset=sr2.charset,
            base_url="https://api.openai.com/v1",
        )
        shard_a2_str = sr2.shard_a.decode("utf-8")
    finally:
        sr2.zero()

    app, db = await _build_proxy_app_with_token(settings, repo, auth_token=auth_token)
    try:
        with respx.mock:
            respx.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"total_tokens": 10},
                    "model": "gpt-4",
                },
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                # Old shard-A₁ must be rejected (post-relock DB has shard-B₂)
                resp_old = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": f"Bearer {shard_a1_str}"},
                )
                assert resp_old.status_code == 401, (
                    f"Old shard-A₁ must be rejected after re-lock; got {resp_old.status_code}.\n"
                    "SHOULD FAIL on 16x2: stable-token path accepts auth_token regardless of "
                    "shard-A mismatch — shard-A isn't validated at all."
                )

                # New shard-A₂ must be accepted
                resp_new = await client.post(
                    f"/{alias}/v1/chat/completions",
                    json={"model": "gpt-4", "messages": []},
                    headers={"Authorization": f"Bearer {shard_a2_str}"},
                )
                assert resp_new.status_code == 200, (
                    f"New shard-A₂ must be accepted after re-lock; got {resp_new.status_code}.\n"
                    "SHOULD FAIL on 16x2: shard-A₂ also returns 401 (proxy checks stable token)."
                )
    finally:
        await app.state.httpx_client.aclose()
        await db.close()


# ---------------------------------------------------------------------------
# Test 3 — doctor detects stale openclaw.json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_doctor_detects_stale_openclaw(
    tmp_path: Path,
) -> None:
    """Doctor must warn when openclaw.json apiKey no longer matches DB shards.

    Scenario: lock once (shard-A₁ in openclaw.json), DB is overwritten with
    new shards WITHOUT updating openclaw.json (crash / Crestodian revert).
    ``worthless doctor`` must report the inconsistency.

    FAILS on 16x2 code: doctor has no openclaw.json ↔ DB consistency check.
    """
    home_dir = ensure_home(tmp_path / ".worthless")
    api_key = "sk-doctor-stale-openclaw-abcdef0123"

    # Lock 1: split and store
    sr1 = split_key_fp(api_key, prefix="sk-", provider="openai")
    try:
        repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
        await repo.initialize()
        stored1 = StoredShard(
            shard_b=bytearray(sr1.shard_b),
            commitment=bytearray(sr1.commitment),
            nonce=bytearray(sr1.nonce),
            provider="openai",
        )
        alias = "openai-stale"
        await repo.upsert_locked_shard(
            alias,
            stored1,
            prefix=sr1.prefix,
            charset=sr1.charset,
            base_url="https://api.openai.com/v1",
        )
        shard_a1_str = sr1.shard_a.decode("utf-8")
    finally:
        sr1.zero()

    # Write openclaw.json with shard-A₁
    openclaw_dir = tmp_path / ".openclaw"
    openclaw_dir.mkdir()
    openclaw_path = openclaw_dir / "openclaw.json"
    openclaw_path.write_text(
        json.dumps(
            {
                "providers": {
                    "worthless-openai": {
                        "baseUrl": f"http://127.0.0.1:8787/{alias}/v1",
                        "apiKey": shard_a1_str,
                        "api": "openai-completions",
                        "models": [],
                    }
                }
            }
        )
    )

    # Simulate crash/revert: overwrite DB with shard-B₂ WITHOUT updating openclaw.json
    sr2 = split_key_fp(api_key, prefix="sk-", provider="openai")
    try:
        stored2 = StoredShard(
            shard_b=bytearray(sr2.shard_b),
            commitment=bytearray(sr2.commitment),
            nonce=bytearray(sr2.nonce),
            provider="openai",
        )
        await repo.upsert_locked_shard(
            alias,
            stored2,
            prefix=sr2.prefix,
            charset=sr2.charset,
            base_url="https://api.openai.com/v1",
        )
    finally:
        sr2.zero()

    # Run doctor — must warn about stale openclaw.json.
    # Patch HOME so openclaw detection finds the tmp openclaw_dir.
    runner = CliRunner()
    with patch.dict("os.environ", {"HOME": str(tmp_path)}):
        result = runner.invoke(
            cli_app,
            ["doctor"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

    output = (result.output or "").lower()
    assert any(
        keyword in output
        for keyword in ("openclaw", "stale", "out of sync", "mismatch", "inconsistent")
    ), (
        f"Doctor must warn about stale openclaw.json. Got:\n{result.output!r}\n"
        "SHOULD FAIL on 16x2: doctor has no openclaw ↔ DB consistency check."
    )


# ---------------------------------------------------------------------------
# Test 4 — lock writes shard-A (not a stable token) to openclaw.json
# ---------------------------------------------------------------------------


def test_lock_writes_shard_a_not_stable_token_to_openclaw(tmp_path: Path) -> None:
    """``worthless lock`` must write shard-A as apiKey in openclaw.json, not a stable token.

    Target-state contract: the proxy_auth_token concept is removed. lock does not
    generate or store a stable token. Instead, openclaw.json carries the raw
    shard-A value — the same bytes that appear in the .env file after locking.

    FAILS on 16x2 code: lock generates a ``secrets.token_urlsafe(32)`` stable
    token and writes THAT as apiKey. A URL-safe base64 token is 43+ chars with
    only ``[A-Za-z0-9_-]`` and no ``sk-`` prefix — distinctly different from
    a format-preserving shard-A (which starts with ``sk-`` per OpenAI format).
    """
    home_dir = ensure_home(tmp_path / ".worthless")

    # Create openclaw workspace dir so apply_lock detects OpenClaw
    openclaw_dir = tmp_path / ".openclaw"
    workspace_dir = openclaw_dir / "workspace"
    workspace_dir.mkdir(parents=True)
    openclaw_path = openclaw_dir / "openclaw.json"

    env_file = tmp_path / ".env"
    api_key = "sk-locktest-openclaw-apikey-abcdef01"
    env_file.write_text(f"OPENAI_API_KEY={api_key}\n")

    runner = CliRunner(mix_stderr=False)
    worthless_home_env = {"WORTHLESS_HOME": str(home_dir.base_dir)}

    # Run lock — writes openclaw.json via apply_lock
    with patch.dict("os.environ", {"HOME": str(tmp_path)}):
        result = runner.invoke(
            cli_app,
            ["lock", "--env", str(env_file), "--allow-hardcoded-urls", "--keys-only"],
            env=worthless_home_env,
        )

    assert result.exit_code == 0, (
        f"lock must succeed. exit={result.exit_code}\nstderr={result.stderr!r}"
    )

    # Read the openclaw.json that lock wrote
    assert openclaw_path.exists(), "openclaw.json must be created by lock"
    config = json.loads(openclaw_path.read_text())
    # openclaw.json schema: config["models"]["providers"]
    providers = config.get("models", {}).get("providers", {})
    assert providers, f"openclaw.json must have providers. Got: {config!r}"

    provider_entry = next(iter(providers.values()))
    api_key_in_openclaw = provider_entry.get("apiKey", "")

    # In target state: apiKey must be the shard-A value (starts with "sk-",
    # same length as original key, format-preserving).
    # In 16x2 state: apiKey is a URL-safe base64 stable token (no "sk-" prefix,
    # 43+ chars of [A-Za-z0-9_-]).
    _stable_token_pattern = re.compile(r"^[A-Za-z0-9_-]{40,}$")
    assert not _stable_token_pattern.match(api_key_in_openclaw), (
        f"openclaw.json apiKey must NOT be a stable opaque token.\n"
        f"Got: {api_key_in_openclaw!r}\n"
        "SHOULD FAIL on 16x2: lock writes secrets.token_urlsafe(32) as apiKey, "
        "which is a URL-safe base64 string matching [A-Za-z0-9_-]{43}."
    )
    assert api_key_in_openclaw.startswith("sk-"), (
        f"openclaw.json apiKey must be a format-preserving shard-A (starts with 'sk-').\n"
        f"Got: {api_key_in_openclaw!r}\n"
        "SHOULD FAIL on 16x2: stable token does not start with 'sk-'."
    )


# ---------------------------------------------------------------------------
# Test 5 — openclaw.json apiKey must be shard-A, not a stable token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_openclaw_json_has_shard_a_not_token(
    tmp_db_path: str,
    fernet_key: bytes,
    tmp_path: Path,
) -> None:
    """After lock, shard_a_enc must NOT be stored in DB; apiKey must XOR with shard-B = key.

    Target-state assertion: shard_a_enc is None (no server-side shard-A storage),
    and the apiKey in openclaw.json is the raw shard-A such that
    XOR(apiKey, shard-B) == original API key.

    FAILS on 16x2 code:
    - upsert_locked_shard writes shard_a_enc → encrypted.shard_a_enc is not None.
    - openclaw.json carries a stable opaque token, not shard-A.
    """
    from worthless.crypto.splitter import reconstruct_key_fp

    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()

    api_key = "sk-xor-verify-openclaw-key-0123456"
    alias = "openai-xortest"

    # Enroll via 16x2 path (what current lock does) — writes shard_a_enc
    shard_a_bytes = await _enroll_16x2(repo, alias, api_key)
    shard_a_str = shard_a_bytes.decode("utf-8")

    # openclaw.json in target state carries shard-A as apiKey
    openclaw_dir = tmp_path / ".openclaw"
    openclaw_dir.mkdir()
    openclaw_path = openclaw_dir / "openclaw.json"
    openclaw_path.write_text(
        json.dumps(
            {
                "providers": {
                    "worthless-openai": {
                        "baseUrl": f"http://127.0.0.1:8787/{alias}/v1",
                        "apiKey": shard_a_str,
                        "api": "openai-completions",
                        "models": [],
                    }
                }
            }
        )
    )

    # --- Assertion 1: DB must NOT store shard_a_enc (target state) ---
    encrypted = await repo.fetch_encrypted(alias)
    assert encrypted is not None, "alias must be in DB"

    assert encrypted.shard_a_enc is None, (
        "Target state: shard_a_enc must be None — lock does NOT store shard-A server-side.\n"
        f"Got shard_a_enc with {len(encrypted.shard_a_enc)} bytes.\n"
        "SHOULD FAIL on 16x2: upsert_locked_shard always writes shard_a_enc."
    )

    # --- Assertion 2: apiKey XOR shard-B must equal the original key ---
    config_data = json.loads(openclaw_path.read_text())
    api_key_from_openclaw = config_data["providers"]["worthless-openai"]["apiKey"]

    assert encrypted.prefix is not None
    assert encrypted.charset is not None

    decrypted = repo.decrypt_shard(encrypted)
    shard_a_buf: bytearray | None = None
    reconstructed: bytearray | None = None
    try:
        shard_a_buf = bytearray(api_key_from_openclaw, "utf-8")
        reconstructed = reconstruct_key_fp(
            shard_a_buf,
            decrypted.shard_b,
            decrypted.commitment,
            decrypted.nonce,
            encrypted.prefix,
            encrypted.charset,
        )
        reconstructed_str = reconstructed.decode("utf-8")
        assert reconstructed_str == api_key, (
            f"XOR(apiKey, shard-B) must equal original key.\n"
            f"Got: {reconstructed_str!r}\nExpected: {api_key!r}\n"
            "SHOULD FAIL on 16x2: openclaw.json carries a stable token, not shard-A."
        )
    finally:
        if shard_a_buf is not None:
            shard_a_buf[:] = b"\x00" * len(shard_a_buf)
        if reconstructed is not None:
            reconstructed[:] = b"\x00" * len(reconstructed)
        decrypted.zero()

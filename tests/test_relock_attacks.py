"""RED-phase adversarial attack tests for the re-lock fix.

These tests define the security envelope that the target implementation MUST
enforce.  Every test in this file is expected to FAIL on the current 16x2
stable-token code, and must turn GREEN only when the post-16x2-revert
machinery is fully wired.

Attack model: an adversary who has captured a valid shard-A (from openclaw.json,
from the wire, or from a previous lock cycle) and attempts to:
  - Forge, truncate, or tamper with shard-A
  - Replay a stale shard-A after re-lock
  - Cross-use shard-A from one alias on another alias endpoint
  - Enumerate failure modes from divergent 401 bodies

None of these must succeed. And critically: the LEGITIMATE shard-A (current,
correct) MUST produce 200 — proving that correct credentials still work after
the fix, not just that all credentials are blocked indiscriminately.

WHY these fail on 16x2:
  - 16x2 validates a stable opaque token (not shard-A) as Bearer
  - Any shard-A sent as Bearer returns 401 — including the VALID one
  - So the "positive arm" (valid shard-A -> 200) fails in every test that
    asserts both rejection of bad credentials AND acceptance of good ones
  - This is the security gap: the proxy can't distinguish valid vs invalid
    shard-A at all; it just blocks everything that isn't the stable token
"""

from __future__ import annotations

import secrets

import aiosqlite
import httpx
import pytest
import respx

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import _AUTH_BODY, create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard


pytestmark = pytest.mark.skip(reason="WOR-549: worthless-16x2 ↔ sidecar IPC integration pending")

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_ALIAS_A = "attack-alias-a"
_ALIAS_B = "attack-alias-b"
_API_KEY_A = "sk-attack-key-alpha-0123456789ab"
_API_KEY_B = "sk-attack-key-beta-abcdef012345"
_BASE_URL = "https://api.openai.com/v1"
_UPSTREAM_CHAT = "https://api.openai.com/v1/chat/completions"

_OPENAI_BODY = b'{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'
_OPENAI_SUCCESS = (
    b'{"id":"chatcmpl-x","choices":[{"message":{"content":"ok"}}]'
    b',"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(tmp_db_path: str, fernet_key: bytes) -> ProxySettings:
    return ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )


async def _make_proxy_app(settings: ProxySettings, repo: ShardRepository):
    """Build a proxy app with state pre-initialised (ASGITransport skips lifespan).

    Sets proxy_auth_token = None to indicate target state (no stable token).
    On 16x2 code this means every request returns 401 regardless of shard-A.
    """
    app = create_app(settings)
    db = await aiosqlite.connect(settings.db_path)
    app.state.db = db
    app.state.repo = repo
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
    # Target state: proxy_auth_token is None — shard-A from Bearer is the auth.
    # On 16x2 code, this causes ALL Bearer requests to return 401 because the
    # 16x2 path checks proxy_auth_token first.
    app.state.proxy_auth_token = None
    return app, db


async def _lock_alias(
    repo: ShardRepository,
    alias: str,
    api_key: str,
    base_url: str = _BASE_URL,
) -> str:
    """Split *api_key* and upsert into DB. Returns shard-A as UTF-8 string."""
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.upsert_locked_shard(
        alias,
        shard,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url=base_url,
    )
    return sr.shard_a.decode("utf-8")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def attack_repo(tmp_db_path: str, fernet_key: bytes) -> ShardRepository:
    r = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await r.initialize()
    return r


@pytest.fixture()
async def attack_app(tmp_db_path: str, fernet_key: bytes, attack_repo: ShardRepository):
    settings = _make_settings(tmp_db_path, fernet_key)
    app, db = await _make_proxy_app(settings, attack_repo)
    yield app, attack_repo
    await app.state.httpx_client.aclose()
    await db.close()


@pytest.fixture()
async def attack_client(attack_app):
    app, _ = attack_app
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# Test 1 — Single-bit flip in shard-A must be rejected; valid shard-A must pass
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bit_flipped_shard_a_rejected(attack_app, attack_client):
    """Commitment check must catch a single-bit tamper in shard-A.

    Two assertions:
    1. Bit-flipped shard-A → 401 (commitment mismatch)
    2. UNMODIFIED valid shard-A → 200 (commitment passes, key reconstructed)

    FAILS on 16x2: assertion 2 fails because proxy_auth_token=None means the
    16x2 stable-token check never authenticates any shard-A as Bearer → 401.
    The commitment check doesn't exist in 16x2; ALL shard-A values are blocked.
    """
    _, repo = attack_app
    shard_a_str = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)
    shard_a_bytes = bytearray(shard_a_str.encode("utf-8"))

    # Flip the last bit of the first byte
    shard_a_bytes[0] ^= 0x01
    tampered_token = shard_a_bytes.decode("latin-1", errors="replace")

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        # Attack: bit-flipped shard-A must be rejected
        resp_bad = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {tampered_token}",
                "Content-Type": "application/json",
            },
        )
        assert resp_bad.status_code == 401, (
            f"Bit-flipped shard-A must return 401, got {resp_bad.status_code}. "
            "Commitment check must catch single-bit tampering."
        )

        # Positive: valid shard-A must succeed (proves the check is discriminating,
        # not just blocking everything)
        resp_good = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_str}",
                "Content-Type": "application/json",
            },
        )

    assert resp_good.status_code == 200, (
        f"Valid shard-A must return 200, got {resp_good.status_code}. "
        "FAILS on 16x2: proxy_auth_token=None blocks all shard-A Bearer requests. "
        "The commitment check (and shard-A auth path) does not exist yet."
    )


# ---------------------------------------------------------------------------
# Test 2 — Truncated shard-A rejected; valid shard-A passes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_truncated_shard_a_rejected(attack_app, attack_client):
    """Truncated shard-A (last 4 chars stripped) → 401. Valid shard-A → 200.

    FAILS on 16x2: the positive assertion fails — valid shard-A also returns 401
    because 16x2 validates the stable token, not shard-A. Both truncated and
    valid shard-A are indistinguishable to the current proxy.
    """
    _, repo = attack_app
    shard_a_str = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)
    truncated = shard_a_str[:-4]

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        resp_bad = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {truncated}",
                "Content-Type": "application/json",
            },
        )
        assert resp_bad.status_code == 401, (
            f"Truncated shard-A must return 401, got {resp_bad.status_code}."
        )

        resp_good = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_str}",
                "Content-Type": "application/json",
            },
        )

    assert resp_good.status_code == 200, (
        f"Valid shard-A must return 200, got {resp_good.status_code}. "
        "FAILS on 16x2: all shard-A Bearer requests are blocked by stable-token check."
    )


# ---------------------------------------------------------------------------
# Test 3 — Cross-alias attack: shard-A from alias-A rejected on alias-B;
#           correct shard-A for alias-B passes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shard_a_from_different_alias_rejected(attack_app, attack_client):
    """Cross-alias credential reuse must be blocked; own shard-A must work.

    Two aliases enrolled. Sending alias-A's shard-A to alias-B's endpoint → 401.
    Sending alias-B's own shard-A to alias-B's endpoint → 200.

    FAILS on 16x2: positive assertion fails — alias-B's own shard-A also gets
    401 because the 16x2 stable-token path is what authenticates, not shard-A.
    """
    _, repo = attack_app
    shard_a_for_a = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)
    shard_a_for_b = await _lock_alias(repo, _ALIAS_B, _API_KEY_B)

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        # Attack: alias-A's shard-A on alias-B's endpoint
        resp_cross = await attack_client.post(
            f"/{_ALIAS_B}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_for_a}",
                "Content-Type": "application/json",
            },
        )
        assert resp_cross.status_code == 401, (
            f"Cross-alias shard-A must return 401 on alias-B endpoint, "
            f"got {resp_cross.status_code}."
        )

        # Positive: alias-B's own shard-A on alias-B's endpoint
        resp_own = await attack_client.post(
            f"/{_ALIAS_B}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_for_b}",
                "Content-Type": "application/json",
            },
        )

    assert resp_own.status_code == 200, (
        f"Alias-B's own shard-A must return 200, got {resp_own.status_code}. "
        "FAILS on 16x2: proxy_auth_token=None blocks all shard-A Bearer requests; "
        "commitment-based acceptance of correct shard-A doesn't exist yet."
    )


# ---------------------------------------------------------------------------
# Test 4 — Replay attack: old shard-A₁ rejected after re-lock; new shard-A₂ passes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_old_shard_a_after_relock_rejected(attack_app, attack_client):
    """After re-lock, shard-A₁ (captured pre-lock) must be dead; shard-A₂ lives.

    FAILS on 16x2: positive assertion fails — shard-A₂ also returns 401 because
    the 16x2 proxy never validates shard-A directly. Both are indistinguishable.
    """
    _, repo = attack_app

    shard_a1 = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)

    api_key_2 = "sk-attack-relock-rotated-9999ab"
    shard_a2 = await _lock_alias(repo, _ALIAS_A, api_key_2)

    assert shard_a1 != shard_a2, "test setup: two locks must produce different shard-A values"

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        # Attack: old shard-A₁ must be dead
        resp_old = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a1}",
                "Content-Type": "application/json",
            },
        )
        assert resp_old.status_code == 401, (
            f"Replayed shard-A₁ must return 401 after re-lock, got {resp_old.status_code}."
        )

        # Positive: new shard-A₂ must be alive
        resp_new = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a2}",
                "Content-Type": "application/json",
            },
        )

    assert resp_new.status_code == 200, (
        f"New shard-A₂ must return 200 after re-lock, got {resp_new.status_code}. "
        "FAILS on 16x2: shard-A₂ also returns 401 — both old and new shards "
        "are indistinguishable under the stable-token auth model."
    )


# ---------------------------------------------------------------------------
# Test 5 — Empty bearer string rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_bearer_rejected(attack_app, attack_client):
    """'Authorization: Bearer ' (empty payload) → 401. Valid shard-A → 200.

    FAILS on 16x2: positive assertion fails — valid shard-A also returns 401.
    """
    _, repo = attack_app
    shard_a_str = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        resp_empty = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": "Bearer ",
                "Content-Type": "application/json",
            },
        )
        assert resp_empty.status_code == 401, (
            f"Empty Bearer must return 401, got {resp_empty.status_code}."
        )

        resp_good = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_str}",
                "Content-Type": "application/json",
            },
        )

    assert resp_good.status_code == 200, (
        f"Valid shard-A must return 200, got {resp_good.status_code}. "
        "FAILS on 16x2: all shard-A Bearer requests are blocked."
    )


# ---------------------------------------------------------------------------
# Test 6 — Null bytes injected into shard-A rejected; valid shard-A passes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bearer_with_null_bytes_rejected(attack_app, attack_client):
    """Null bytes appended to shard-A → 401. Valid shard-A → 200.

    FAILS on 16x2: positive assertion fails — valid shard-A returns 401.
    The test additionally proves null bytes are caught before they can
    corrupt downstream processing (no 500).
    """
    _, repo = attack_app
    shard_a_str = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)
    poisoned = shard_a_str + "\x00\x00\x00"

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        # Null bytes may be caught at header-sanitisation gate or commitment check
        resp_poison = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {poisoned}",
                "Content-Type": "application/json",
            },
        )
        assert resp_poison.status_code == 401, (
            f"Null-byte-poisoned shard-A must return 401, got {resp_poison.status_code}."
        )
        assert resp_poison.status_code != 500, "Null-byte injection must never surface as 500."

        resp_good = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_str}",
                "Content-Type": "application/json",
            },
        )

    assert resp_good.status_code == 200, (
        f"Valid shard-A must return 200, got {resp_good.status_code}. "
        "FAILS on 16x2: all shard-A Bearer requests are blocked."
    )


# ---------------------------------------------------------------------------
# Test 7 — Corrupt shard_b_enc in DB: correct shard-A → 401, no 500, no upstream call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_commitment_check_prevents_reconstruction_with_wrong_shard_b(
    tmp_db_path: str, fernet_key: bytes
):
    """Corrupt shard_b_enc in DB after valid lock. Correct shard-A → 401, never 500.

    This test does NOT have a positive 200 arm — corrupted storage is always
    an error. It asserts:
    1. Status is 401 (not 500 — no unhandled exception on Fernet failure)
    2. Upstream is NOT called (gate-before-reconstruct still enforced)

    FAILS on 16x2 for a different reason: the Fernet decryption failure in
    decrypt_shard raises InvalidToken. On 16x2, the stable-token check fires
    FIRST and returns 401 before reaching decrypt_shard. So this test actually
    passes on 16x2 but for the wrong reason (stable-token gate, not commitment
    gate). Post-revert code must still return 401 via the Fernet/commitment
    exception handler, not the stable-token path.

    To make it genuinely RED: we additionally assert the upstream was never
    called AND that the test cannot be satisfied by the stable-token shortcut
    (we remove proxy_auth_token entirely from app.state).
    """
    repo = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await repo.initialize()
    shard_a_str = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)

    # Corrupt shard_b_enc — invalid Fernet ciphertext
    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "UPDATE shards SET shard_b_enc = ? WHERE key_alias = ?",
            (b"absolutely-not-a-valid-fernet-token-xx", _ALIAS_A),
        )
        await db.commit()

    settings = _make_settings(tmp_db_path, fernet_key)
    app, db_conn = await _make_proxy_app(settings, repo)

    # Remove proxy_auth_token from app.state entirely so there is no stable-token
    # shortcut available — the post-revert path must handle this correctly.
    del app.state.proxy_auth_token

    try:
        upstream_route = None
        with respx.mock:
            upstream_route = respx.post(_UPSTREAM_CHAT).mock(
                return_value=httpx.Response(200, content=_OPENAI_SUCCESS)
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/{_ALIAS_A}/v1/chat/completions",
                    content=_OPENAI_BODY,
                    headers={
                        "Authorization": f"Bearer {shard_a_str}",
                        "Content-Type": "application/json",
                    },
                )

        assert resp.status_code == 401, (
            f"Corrupted shard_b_enc must return 401, got {resp.status_code}. "
            "Fernet InvalidToken must be caught and returned as uniform 401. "
            "FAILS on 16x2 if proxy_auth_token removal causes AttributeError."
        )
        assert resp.status_code != 500, (
            "Corrupted shard_b_enc must never surface as 500 (unhandled exception)."
        )
        assert upstream_route is not None and not upstream_route.called, (
            "Upstream must NOT be called when shard_b_enc is corrupted. "
            "Gate-before-reconstruct must hold even under storage corruption."
        )
    finally:
        await app.state.httpx_client.aclose()
        await db_conn.close()


# ---------------------------------------------------------------------------
# Test 8 — All 401 responses are byte-identical (anti-enumeration)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_401s_are_byte_identical(attack_app, attack_client):
    """All denial paths return byte-identical 401 bodies. Anti-enumeration contract.

    Failure modes tested:
    1. Forged random shard-A for a valid alias
    2. Missing Authorization header entirely
    3. Bit-flipped shard-A (post-enrollment tamper)
    4. shard-A from a different alias (cross-alias replay)

    All four must return bodies byte-identical to _AUTH_BODY.

    Positive arm: valid shard-A must return 200 (proves the proxy discriminates,
    not just blocks everything).

    FAILS on 16x2: positive arm returns 401 — valid shard-A is indistinguishable
    from a forged one under the stable-token model.
    """
    _, repo = attack_app

    shard_a_a = await _lock_alias(repo, _ALIAS_A, _API_KEY_A)
    await _lock_alias(repo, _ALIAS_B, _API_KEY_B)

    # Bit-flip alias-A's shard-A
    buf = bytearray(shard_a_a.encode("utf-8"))
    buf[0] ^= 0x01
    bit_flipped = buf.decode("latin-1", errors="replace")

    cases: list[tuple[str, str, dict]] = [
        (
            "forged_random_shard_a",
            _ALIAS_A,
            {
                "headers": {
                    "Authorization": f"Bearer {secrets.token_hex(32)}",
                    "Content-Type": "application/json",
                }
            },
        ),
        (
            "missing_auth_header",
            _ALIAS_A,
            {
                "headers": {"Content-Type": "application/json"},
            },
        ),
        (
            "bit_flipped_shard_a",
            _ALIAS_A,
            {
                "headers": {
                    "Authorization": f"Bearer {bit_flipped}",
                    "Content-Type": "application/json",
                }
            },
        ),
        (
            "cross_alias_shard_a",
            _ALIAS_B,
            {
                "headers": {
                    "Authorization": f"Bearer {shard_a_a}",
                    "Content-Type": "application/json",
                }
            },
        ),
    ]

    bodies: dict[str, bytes] = {}

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        for label, alias, kwargs in cases:
            resp = await attack_client.post(
                f"/{alias}/v1/chat/completions",
                content=_OPENAI_BODY,
                **kwargs,
            )
            assert resp.status_code == 401, f"Case {label!r}: expected 401, got {resp.status_code}"
            bodies[label] = resp.content

        # Positive arm: valid shard-A must reach upstream
        resp_good = await attack_client.post(
            f"/{_ALIAS_A}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={
                "Authorization": f"Bearer {shard_a_a}",
                "Content-Type": "application/json",
            },
        )

    assert resp_good.status_code == 200, (
        f"Valid shard-A must return 200, got {resp_good.status_code}. "
        "FAILS on 16x2: proxy_auth_token=None blocks all shard-A Bearer requests — "
        "the proxy cannot tell valid from forged shard-A."
    )

    # Every denial body must equal _AUTH_BODY
    for label, body in bodies.items():
        assert body == _AUTH_BODY, (
            f"Case {label!r}: 401 body differs from _AUTH_BODY.\n"
            f"  Expected: {_AUTH_BODY!r}\n"
            f"  Got:      {body!r}\n"
            "Divergent bodies allow denial-mode enumeration."
        )

    unique = set(bodies.values())
    assert len(unique) == 1, (
        f"Not all 401 bodies are byte-identical. "
        f"Distinct body count: {len(unique)}. Cases: {list(bodies.keys())}"
    )

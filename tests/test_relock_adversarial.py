"""Adversarial tests for the re-lock (ON CONFLICT DO UPDATE) security model.

These are RED-phase tests. They define the target behavior after the 16x2
stable-token machinery is reverted and replaced with the simpler fix:
  - shard-A travels in the Bearer header (legacy path)
  - shard-B lives in the DB
  - re-lock uses ON CONFLICT DO UPDATE to keep both shards in sync
  - commitment check gates reconstruction for every request

Security model under test:
  shard-A (Bearer header) XOR shard-B (DB) = reconstructed key
  Neither party alone holds both halves.

All six tests WILL fail until the target code is implemented. That is correct.
"""

from __future__ import annotations

import asyncio
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
# Constants shared across tests
# ---------------------------------------------------------------------------

_ALIAS = "adversarial-key"
_API_KEY = "sk-adv-test-key-1234567890abcdef"
_BASE_URL = "https://api.openai.com/v1"
_UPSTREAM_CHAT = "https://api.openai.com/v1/chat/completions"

_OPENAI_BODY = b'{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'
_OPENAI_SUCCESS = (
    b'{"id":"chatcmpl-1","choices":[{"message":{"content":"ok"}}],'
    b'"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}'
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
    """Build a proxy app with state pre-initialised (ASGITransport skips lifespan)."""
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
    # Target behavior: no stable auth token in DB — Bearer carries shard-A directly.
    app.state.proxy_auth_token = None
    return app, db


async def _do_relock(
    repo: ShardRepository,
    alias: str,
    api_key: str,
    base_url: str,
) -> tuple[str, bytes]:
    """Simulate a re-lock: split the key and upsert both shards atomically.

    Returns (shard_a_utf8, raw_api_key_bytes).
    Under the target behavior, upsert_locked_shard stores shard-A encrypted
    in the DB and the caller sends shard-A as the Bearer token.

    The TARGET behavior after reverting 16x2: shard-A goes back to the
    Bearer header; this helper returns the shard-A string the client must
    send and the raw key for verification.
    """
    sr = split_key_fp(api_key, prefix="sk-", provider="openai")
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    # Target: use the new upsert_locked_shard (ON CONFLICT DO UPDATE)
    # which keeps both shards atomically in sync.
    await repo.upsert_locked_shard(
        alias,
        shard,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url=base_url,
    )
    shard_a_utf8 = sr.shard_a.decode("utf-8")
    return shard_a_utf8, api_key.encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def adv_repo(tmp_db_path: str, fernet_key: bytes) -> ShardRepository:
    r = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await r.initialize()
    return r


@pytest.fixture()
async def adv_app(tmp_db_path: str, fernet_key: bytes, adv_repo: ShardRepository):
    settings = _make_settings(tmp_db_path, fernet_key)
    app, db = await _make_proxy_app(settings, adv_repo)
    yield app, adv_repo
    await app.state.httpx_client.aclose()
    await db.close()


@pytest.fixture()
def adv_client(adv_app):
    app, _ = adv_app
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# Test 1 — Commitment check survives re-lock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_old_shard_a_rejected_after_relock(adv_app, adv_client):
    """After re-lock (new shard-A₂, new shard-B₂), the old shard-A₁ must return 401.

    Proves: commitment check is not bypassed by a previously-valid credential.
    Target behavior: the proxy reads shard-B from DB (updated by re-lock) and
    runs reconstruct_key(shard_a_from_header, shard_b_from_db, commitment, nonce).
    The old shard-A₁ paired with new shard-B₂ produces a mismatched commitment
    → must fail with 401, not 200 or 500.
    """
    _, repo = adv_app

    # First lock — enroll the alias with a fresh split
    shard_a1, _ = await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)

    # Second lock — re-lock with the SAME underlying key but a new split
    # (new shard-A₂, new shard-B₂, new nonce/commitment).
    api_key2 = "sk-adv-test-key-RELOCKED-9876543"
    shard_a2, _ = await _do_relock(repo, _ALIAS, api_key2, _BASE_URL)

    # shard_a1 is now stale — it was valid before re-lock but is no longer.
    # The commitment in the DB now corresponds to the second split.
    assert shard_a1 != shard_a2, "test setup: shards must differ after re-lock"

    # Using old shard-A₁ must return 401 (commitment mismatch)
    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))
        resp = await adv_client.post(
            f"/{_ALIAS}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={"Authorization": f"Bearer {shard_a1}", "Content-Type": "application/json"},
        )

    assert resp.status_code == 401, (
        f"Old shard-A₁ must return 401 after re-lock, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Test 2 — Forged shard-A returns 401, not 500
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forged_shard_a_returns_uniform_401(adv_app, adv_client):
    """A random 32-byte Bearer token for a valid alias must return 401, never 500.

    Proves: the proxy handles malformed shard-A gracefully without leaking
    internal state through a 500 or a divergent error body.
    """
    _, repo = adv_app
    await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)

    # Random bytes encoded as hex — definitely not a valid shard-A for this alias
    forged_token = secrets.token_hex(32)

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))
        resp = await adv_client.post(
            f"/{_ALIAS}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={"Authorization": f"Bearer {forged_token}", "Content-Type": "application/json"},
        )

    assert resp.status_code == 401, (
        f"Forged shard-A must return 401, got {resp.status_code}. "
        "A 500 leaks internal state; a 200 is catastrophic."
    )
    assert resp.status_code != 500, "500 must never be returned for bad credentials"


# ---------------------------------------------------------------------------
# Test 3 — Commitment mismatch never reaches upstream
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_commitment_mismatch_never_calls_upstream(adv_app, adv_client):
    """When commitment check fails, the proxy must make zero upstream calls.

    Proves: gate-before-reconstruct is enforced — key material never flows
    upstream when shard-A is invalid (SR-03).
    """
    _, repo = adv_app
    await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)

    forged_token = secrets.token_hex(32)
    upstream_called = False

    with respx.mock:
        route = respx.post(_UPSTREAM_CHAT).mock(
            return_value=httpx.Response(200, content=_OPENAI_SUCCESS)
        )
        resp = await adv_client.post(
            f"/{_ALIAS}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={"Authorization": f"Bearer {forged_token}", "Content-Type": "application/json"},
        )
        upstream_called = route.called

    assert resp.status_code == 401
    assert not upstream_called, (
        "Upstream must NEVER be called when commitment check fails. "
        f"Upstream was called {route.call_count} time(s)."
    )


# ---------------------------------------------------------------------------
# Test 4 — Re-lock does not accept old shard-A after update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_second_lock_invalidates_first_shard_a(adv_app, adv_client):
    """Lock twice; assert old shard-A → 401 and new shard-A → 200.

    Proves the ON CONFLICT DO UPDATE truly replaces both shards atomically.
    If only shard-B were updated, the commitment would mismatch the new
    shard-A → old shard-A might still reconstruct the old key → security hole.
    """
    _, repo = adv_app

    # First lock
    shard_a1, raw_key1 = await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)

    # Second lock — different underlying key to force a new commitment
    api_key2 = "sk-adv-second-lock-9876543210ab"
    shard_a2, raw_key2 = await _do_relock(repo, _ALIAS, api_key2, _BASE_URL)

    assert shard_a1 != shard_a2, "test setup: re-lock must produce different shard-A"

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        # Old shard-A₁ must be rejected
        resp_old = await adv_client.post(
            f"/{_ALIAS}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={"Authorization": f"Bearer {shard_a1}", "Content-Type": "application/json"},
        )
        assert resp_old.status_code == 401, (
            f"Old shard-A₁ must return 401 after second lock, got {resp_old.status_code}"
        )

        # New shard-A₂ must be accepted
        resp_new = await adv_client.post(
            f"/{_ALIAS}/v1/chat/completions",
            content=_OPENAI_BODY,
            headers={"Authorization": f"Bearer {shard_a2}", "Content-Type": "application/json"},
        )
        assert resp_new.status_code == 200, (
            f"New shard-A₂ must return 200 after second lock, got {resp_new.status_code}"
        )


# ---------------------------------------------------------------------------
# Test 5 — Timing: shard-B update is atomic (no torn reads → no 500)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_requests_around_relock_never_500(tmp_db_path: str, fernet_key: bytes):
    """Two concurrent requests straddling a re-lock must each get 200 or 401, never 500.

    Proves: the ON CONFLICT DO UPDATE write is atomic from the proxy's POV.
    A torn read (half-old / half-new shard-B) must not surface as a 500.

    Setup:
    - Request A fires just before re-lock commits.
    - Request B fires just after re-lock commits.
    Both responses must be 200 or 401 — never 500 or an unhandled exception.
    """
    # First enrollment
    repo = ShardRepository(tmp_db_path, bytearray(fernet_key))
    await repo.initialize()
    shard_a1, _ = await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)

    settings = _make_settings(tmp_db_path, fernet_key)
    app, db = await _make_proxy_app(settings, repo)

    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with respx.mock:
            respx.post(_UPSTREAM_CHAT).mock(
                return_value=httpx.Response(200, content=_OPENAI_SUCCESS)
            )

            async def request_with_shard(shard_a: str) -> int:
                resp = await client.post(
                    f"/{_ALIAS}/v1/chat/completions",
                    content=_OPENAI_BODY,
                    headers={
                        "Authorization": f"Bearer {shard_a}",
                        "Content-Type": "application/json",
                    },
                )
                return resp.status_code

            # Fire request A (old shard-A) and re-lock concurrently
            api_key2 = "sk-adv-concurrent-lock-abcdef01"

            async def relock_task():
                # Small delay so request A starts first
                await asyncio.sleep(0.005)
                return await _do_relock(repo, _ALIAS, api_key2, _BASE_URL)

            results = await asyncio.gather(
                request_with_shard(shard_a1),
                relock_task(),
                return_exceptions=True,
            )

        status_a = results[0]
        relock_result = results[1]

        assert not isinstance(status_a, Exception), f"Request A raised an exception: {status_a}"
        assert status_a in (200, 401), (
            f"Request A straddling re-lock must return 200 or 401, got {status_a}. "
            "A 500 indicates a torn read from the atomic upsert."
        )

        # Now fire request B with the new shard-A
        shard_a2, _ = relock_result  # type: ignore[misc]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client2:
            with respx.mock:
                respx.post(_UPSTREAM_CHAT).mock(
                    return_value=httpx.Response(200, content=_OPENAI_SUCCESS)
                )
                resp_b = await client2.post(
                    f"/{_ALIAS}/v1/chat/completions",
                    content=_OPENAI_BODY,
                    headers={
                        "Authorization": f"Bearer {shard_a2}",
                        "Content-Type": "application/json",
                    },
                )
        assert resp_b.status_code in (200, 401), (
            f"Request B after re-lock must return 200 or 401, got {resp_b.status_code}"
        )
        assert resp_b.status_code != 500, "Post-relock request must never return 500"

    await app.state.httpx_client.aclose()
    await db.close()


# ---------------------------------------------------------------------------
# Test 6 — Uniform 401 body is byte-identical across all failure paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_uniform_401_body_across_all_relock_failure_paths(adv_app, adv_client):
    """All failure paths must return byte-identical 401 bodies (anti-enumeration).

    Failure paths tested:
    1. Old shard-A after re-lock (commitment mismatch)
    2. Completely forged shard-A (random bytes)
    3. Missing Authorization header
    4. Wrong alias (alias not in DB)

    If any path returns a different body, an attacker can fingerprint which
    denial reason applies and enumerate DB state.

    The reference body is _AUTH_BODY (pre-computed in app.py).
    """
    _, repo = adv_app

    # Enroll then re-lock to set up a stale shard-A
    shard_a1, _ = await _do_relock(repo, _ALIAS, _API_KEY, _BASE_URL)
    api_key2 = "sk-adv-uniform-second-1234567890"
    _, _ = await _do_relock(repo, _ALIAS, api_key2, _BASE_URL)

    forged_token = secrets.token_hex(32)

    failure_cases: list[tuple[str, dict]] = [
        # (label, request kwargs)
        (
            "old_shard_a_after_relock",
            {
                "headers": {
                    "Authorization": f"Bearer {shard_a1}",
                    "Content-Type": "application/json",
                }
            },
        ),
        (
            "forged_shard_a",
            {
                "headers": {
                    "Authorization": f"Bearer {forged_token}",
                    "Content-Type": "application/json",
                }
            },
        ),
        (
            "missing_authorization_header",
            {"headers": {"Content-Type": "application/json"}},
        ),
        (
            "wrong_alias",
            {
                "headers": {
                    "Authorization": f"Bearer {shard_a1}",
                    "Content-Type": "application/json",
                },
                "_alias_override": "nonexistent-alias",
            },
        ),
    ]

    bodies: dict[str, bytes] = {}

    with respx.mock:
        respx.post(_UPSTREAM_CHAT).mock(return_value=httpx.Response(200, content=_OPENAI_SUCCESS))

        for label, kwargs in failure_cases:
            alias = kwargs.pop("_alias_override", _ALIAS)
            resp = await adv_client.post(
                f"/{alias}/v1/chat/completions",
                content=_OPENAI_BODY,
                **kwargs,
            )
            assert resp.status_code == 401, f"Case {label!r}: expected 401, got {resp.status_code}"
            bodies[label] = resp.content

    # All bodies must be byte-identical to _AUTH_BODY
    for label, body in bodies.items():
        assert body == _AUTH_BODY, (
            f"Case {label!r}: 401 body differs from _AUTH_BODY.\n"
            f"  Expected: {_AUTH_BODY!r}\n"
            f"  Got:      {body!r}\n"
            "Divergent bodies leak which denial reason fired (anti-enumeration failure)."
        )

    # Cross-check: all bodies are identical to each other
    unique_bodies = set(bodies.values())
    assert len(unique_bodies) == 1, (
        f"Not all 401 bodies are byte-identical. "
        f"Distinct bodies found: {len(unique_bodies)}. Labels: {list(bodies.keys())}"
    )

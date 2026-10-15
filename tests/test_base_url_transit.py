"""A2 transit proof (WOR-784): a real SDK request set via base_url TRANSITS the proxy.

Closes the honesty gap behind the install docs' "set OPENAI_BASE_URL /
ANTHROPIC_BASE_URL" claim. It is not enough that the upstream is *reachable* —
the proof here is that a request issued by the **official** ``openai`` /
``anthropic`` Python SDKs, with ``base_url`` pointed at the worthless proxy,
physically passes THROUGH the proxy and only then reaches the upstream.

How transit is forced (no real keys, no real network):

* The worthless proxy ASGI app is booted in-process via
  :class:`httpx.ASGITransport` — no port is bound (8787 is often busy locally).
* The proxy's *outbound* ``httpx_client`` is itself an ``ASGITransport`` client
  wrapping the existing mock upstream at ``tests/openclaw/mock-upstream/app.py``.
  So the only way bytes reach the mock is *out the far side of the proxy*.
* The SDKs talk to the proxy through ``http_client=`` (a third ASGITransport
  client) so the SDK request never leaves the process either. Both ``openai``
  and ``anthropic`` are built on ``httpx2`` internally, so that client is an
  ``httpx2.AsyncClient`` for both. (``anthropic`` rejects a plain ``httpx``
  client outright; ``openai`` merely tolerates one today.)

Two independent witnesses confirm the request went THROUGH the proxy, not
around it:

1. **Upstream witness** — the mock upstream's captured-headers log gained an
   entry, and the auth it saw is the *reconstructed* original key, never the
   shard-A token the SDK actually sent. A request that bypassed the proxy could
   not have turned shard-A into the original key.
2. **Ledger witness** — ``/healthz`` ``requests_billed`` (the row count of the
   proxy's ``spend_log``) went from 0 to 1. That row is written by the proxy's
   post-response spend recorder, a separate path from the forward call.

``requests_proxied`` is also checked to tick 0 -> 1, but it is NOT independent:
it is an in-memory counter bumped inline right after the same upstream
``send()`` that feeds witness #1 (worthless-ax9d), so it can't fail on its own.

This runs in the default (non-docker) ``Tests`` job: it is unmarked, uses only
the in-process ASGITransport, and ``openai`` / ``anthropic`` / ``httpx2`` are
declared in the ``test`` extra that CI installs.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import aiosqlite
import anthropic
import httpx
import httpx2
import openai
import pytest

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard

from tests._fakes import pin_shard_b

pytestmark = pytest.mark.asyncio

# The mock upstream lives under a hyphenated directory, so it cannot be a normal
# importable package. Load it by path — same pattern as tests/test_deploy_start.py.
_MOCK_UPSTREAM_PATH = Path(__file__).parent / "openclaw" / "mock-upstream" / "app.py"


def _load_mock_upstream(unique_name: str) -> ModuleType:
    """Load a FRESH instance of the mock upstream module.

    The mock stores captured headers in a module-global list. Loading a fresh
    module per test (unique ``unique_name``) gives each parametrized case — and
    each xdist worker — its own isolated capture log, so assertions can't see a
    sibling test's request.
    """
    spec = importlib.util.spec_from_file_location(unique_name, _MOCK_UPSTREAM_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Per-SDK wiring. The proxy joins ``base_url`` + the adapter suffix
# ("/chat/completions" for OpenAI, "/messages" for Anthropic), so ``base_url``
# below is the mock's per-provider prefix WITHOUT that suffix. The mock app
# exposes both ``/openai/v1/...`` and ``/anthropic/v1/...`` aliases.
_SDK_CASES = {
    "openai": {
        "provider": "openai",
        "api_key": "sk-transit-key-1234567890abcdef",
        "prefix": "sk-",
        # base_url stored at enrollment → where the proxy forwards.
        "upstream_base_url": "http://upstream/openai/v1",
        # base_url the SDK is pointed at → the proxy, with the alias in path.
        "sdk_path_suffix": "/v1",
    },
    "anthropic": {
        "provider": "anthropic",
        "api_key": "sk-ant-transit-key-1234567890ab",
        "prefix": "sk-ant-",
        "upstream_base_url": "http://upstream/anthropic/v1",
        # The Anthropic SDK appends "/v1/messages" itself, so its base_url is
        # the proxy root + alias (no "/v1").
        "sdk_path_suffix": "",
    },
}


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


async def _make_proxy_app(
    proxy_settings: ProxySettings,
    repo: ShardRepository,
    upstream_app: ModuleType,
):
    """Boot the proxy with its outbound client wired INTO the mock upstream.

    The crucial wiring: ``app.state.httpx_client`` uses an ASGITransport over
    the mock upstream's FastAPI app. The proxy forwards to ``base_url`` through
    this client, so a forwarded request is delivered straight into the mock —
    in-process, no socket — and only via the proxy's forward path.
    """
    app = create_app(proxy_settings)
    db = await aiosqlite.connect(proxy_settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream_app.app),
        follow_redirects=False,
    )
    app.state.rules_engine = RulesEngine(
        rules=[
            SpendCapRule(db=db),
            RateLimitRule(default_rps=proxy_settings.default_rate_limit_rps),
        ]
    )
    return app, db


async def _enroll(
    repo: ShardRepository,
    proxy_app,
    *,
    alias: str,
    api_key: str,
    prefix: str,
    provider: str,
    base_url: str,
) -> str:
    """Enroll an alias and return its shard-A (the token the SDK will send).

    ``base_url`` is the *upstream* the proxy must forward to. ``pin_shard_b``
    mirrors the plaintext shard-B onto the autouse FakeIPCSupervisor so the
    proxy's reconstruction yields the real original key (otherwise it 401s).
    """
    sr = split_key_fp(api_key, prefix=prefix, provider=provider)
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider=provider,
    )
    await repo.store(alias, shard, prefix=sr.prefix, charset=sr.charset, base_url=base_url)
    pin_shard_b(proxy_app, alias, sr.shard_b)
    return sr.shard_a.decode("utf-8")


async def _meters(proxy_client: httpx.AsyncClient) -> tuple[int, int]:
    """Read ``(requests_proxied, requests_billed)`` from the proxy's /healthz."""
    resp = await proxy_client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    return int(body["requests_proxied"]), int(body["requests_billed"])


@pytest.mark.parametrize("sdk_name", ["openai", "anthropic"])
async def test_base_url_request_transits_proxy_to_upstream(
    sdk_name: str,
    proxy_settings: ProxySettings,
    repo: ShardRepository,
) -> None:
    """A base_url-pointed SDK request must physically transit the proxy.

    Drives the official SDK with ``base_url`` set to the proxy. Proves the
    request went THROUGH the proxy (not around it) via two witnesses: the mock
    upstream captured it AND the proxy's own spend-ledger counter ticked.
    """
    case = _SDK_CASES[sdk_name]
    alias = f"transit-{sdk_name}"

    # Fresh, isolated mock upstream for this parametrization.
    upstream = _load_mock_upstream(f"_mock_upstream_transit_{sdk_name}")

    proxy_app, db = await _make_proxy_app(proxy_settings, repo, upstream)
    try:
        shard_a = await _enroll(
            repo,
            proxy_app,
            alias=alias,
            api_key=case["api_key"],
            prefix=case["prefix"],
            provider=case["provider"],
            base_url=case["upstream_base_url"],
        )

        # The SDK's outbound HTTP goes into the proxy via ASGITransport — never
        # a real socket. base_url carries the alias in the path; the proxy reads
        # the alias from the URL (SR-09), reconstructs the key, then forwards.
        proxy_base = f"http://proxy/{alias}{case['sdk_path_suffix']}"
        proxy_transport = httpx.ASGITransport(app=proxy_app)

        # Witness #2 (before): nothing proxied, nothing billed yet.
        async with httpx.AsyncClient(transport=proxy_transport, base_url="http://proxy") as probe:
            assert await _meters(probe) == (0, 0)

        # Use the SDKs' ASYNC clients: ASGITransport is async-only, and the
        # async clients let the proxy's post-response spend-recording
        # BackgroundTask settle on this same event loop before we read the meter.
        # Both SDKs run on httpx2 internally — hand both an httpx2 client.
        sdk_http_client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=proxy_app))
        if sdk_name == "openai":
            client = openai.AsyncOpenAI(
                api_key=shard_a,
                base_url=proxy_base,
                http_client=sdk_http_client,
                max_retries=0,
            )
            try:
                completion = await client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": "ping"}],
                )
            finally:
                await client.close()
            # The proxy relayed the mock's real response body back to the SDK.
            assert completion.choices[0].message.content == "Hello from mock upstream!"
        else:
            client = anthropic.AsyncAnthropic(
                api_key=shard_a,
                base_url=proxy_base,
                http_client=sdk_http_client,
                max_retries=0,
            )
            try:
                message = await client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=16,
                    messages=[{"role": "user", "content": "ping"}],
                )
            finally:
                await client.close()
            assert message.content[0].text == "Hello from mock upstream!"

        # --- Witness #1: the UPSTREAM received the request via the proxy. ---
        captured = upstream._captured_headers
        assert len(captured) == 1, (
            f"mock upstream saw {len(captured)} request(s); expected exactly 1 "
            f"forwarded through the proxy"
        )
        entry = captured[0]
        assert entry["provider"] == case["provider"]

        # And it must be the RECONSTRUCTED original key, never shard-A. Only a
        # request that went THROUGH the proxy can carry the reconstructed key;
        # a request that reached the upstream by any other route would still
        # carry shard-A (or nothing).
        if sdk_name == "openai":
            upstream_auth = entry["authorization"]
            assert upstream_auth == f"Bearer {case['api_key']}", (
                f"upstream saw {upstream_auth!r}; expected the reconstructed key"
            )
            assert shard_a not in upstream_auth, "shard-A leaked to the upstream"
        else:
            upstream_key = entry["x-api-key"]
            assert upstream_key == case["api_key"], (
                f"upstream saw {upstream_key!r}; expected the reconstructed key"
            )
            assert shard_a != upstream_key, "shard-A leaked to the upstream"

        # --- Witness #2: the proxy's spend LEDGER recorded the transit. ---
        async with httpx.AsyncClient(transport=proxy_transport, base_url="http://proxy") as probe:
            proxied, billed = await _meters(probe)
        assert billed == 1, (
            f"proxy spend_log has {billed} row(s); expected 1 — the request did "
            "not reach the proxy's post-response spend recorder"
        )
        # Not independent of witness #1 (see module docstring); a sanity tick only.
        assert proxied == 1, f"requests_proxied={proxied}; expected 1"
    finally:
        await proxy_app.state.httpx_client.aclose()
        await db.close()

"""WOR-658 — proxy-side ``/_bind_probe/{alias}`` endpoint contract.

The lock-side bind-confirmation needs a counter on the proxy that ticks
WITHOUT auth. The existing ``requests_proxied`` field on ``/healthz`` is
``SELECT COUNT(*) FROM spend_log`` — it only increments after a request
clears auth + reconstruction + a real upstream call. A synthetic probe
fired before any real client traffic can never move it.

The fix is a dedicated endpoint, intentionally public:

* ``/_bind_probe/{alias}`` returns 204 No Content immediately, no auth,
  no validation. The alias parameter is captured but not checked —
  ANY string yields the same response (no info-leak about which aliases
  exist on this host).
* The endpoint increments an in-memory ``app.state.bind_probe_count``.
  This counter is SEPARATE from ``requests_proxied`` — neither pollutes
  the other.
* ``/healthz`` exposes the new counter as ``bind_probe_count`` alongside
  the existing fields. Additive; old readers ignore it.

These tests are the contract. They will fail today (the endpoint does
not exist; ``/healthz`` does not surface ``bind_probe_count``) and must
pass once the GREEN endpoint is wired.
"""

from __future__ import annotations

import httpx
import pytest

from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings


@pytest.fixture
def proxy_app(tmp_path):
    """Build the FastAPI app with the minimum settings the new probe needs.

    The probe endpoint is intentionally state-light — no DB, no httpx
    client, no rules engine. ``ASGITransport`` skips ``_lifespan`` so the
    lifespan-owned state never gets attached, and ``healthz`` tolerates a
    missing ``state.db`` (its except-pass returns ``requests_proxied: 0``).
    """
    settings = ProxySettings(
        db_path=str(tmp_path / "wor658-probe.db"),
        fernet_key=bytearray(b"x" * 32),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )
    return create_app(settings)


@pytest.fixture
def client(proxy_app):
    """In-process ASGI test client — no real network bind."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app),
        base_url="http://probe.test",
    )


# ---------------------------------------------------------------------------
# Endpoint existence and shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bind_probe_returns_204_get(client: httpx.AsyncClient) -> None:
    """GET /_bind_probe/<alias> -> 204 No Content. No auth."""
    async with client as c:
        r = await c.get("/_bind_probe/openai-abc123")
    assert r.status_code == 204, (
        f"WOR-658: probe must return 204 (no auth required); got {r.status_code} body={r.text!r}"
    )
    # 204 carries no body.
    assert r.text == ""


@pytest.mark.asyncio
async def test_bind_probe_returns_204_head(client: httpx.AsyncClient) -> None:
    """HEAD /_bind_probe/<alias> -> 204. The lock-side fire uses HEAD."""
    async with client as c:
        r = await c.head("/_bind_probe/openai-abc123")
    assert r.status_code == 204, (
        f"WOR-658: HEAD must be accepted (lock fires HEAD); got {r.status_code}"
    )


@pytest.mark.asyncio
async def test_bind_probe_accepts_any_alias_string_no_leak(
    client: httpx.AsyncClient,
) -> None:
    """Probe must not reveal whether an alias exists. Any string -> 204."""
    aliases = ["openai-real", "definitely-not-real", "x", "a" * 200]
    async with client as c:
        for alias in aliases:
            r = await c.get(f"/_bind_probe/{alias}")
            assert r.status_code == 204, (
                f"alias={alias!r} must return 204 regardless of registration"
            )


# ---------------------------------------------------------------------------
# Counter behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_surfaces_bind_probe_count_field(
    client: httpx.AsyncClient,
) -> None:
    """/healthz JSON includes the new ``bind_probe_count`` field. Additive
    only — existing fields unchanged."""
    async with client as c:
        r = await c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert "bind_probe_count" in body, (
        f"WOR-658: /healthz must surface bind_probe_count; got keys={list(body)}"
    )
    assert isinstance(body["bind_probe_count"], int)
    # Existing fields preserved.
    assert "status" in body and body["status"] == "ok"
    assert "requests_proxied" in body
    assert "pid" in body


@pytest.mark.asyncio
async def test_bind_probe_increments_dedicated_counter(
    client: httpx.AsyncClient,
) -> None:
    """Each probe request increments bind_probe_count by exactly 1."""
    async with client as c:
        before = (await c.get("/healthz")).json()["bind_probe_count"]
        await c.get("/_bind_probe/alias-1")
        await c.get("/_bind_probe/alias-2")
        await c.head("/_bind_probe/alias-3")
        after = (await c.get("/healthz")).json()["bind_probe_count"]
    assert after - before == 3, (
        f"WOR-658: probe must tick the counter on every hit; before={before} "
        f"after={after} (expected delta=3)"
    )


@pytest.mark.asyncio
async def test_bind_probe_does_not_pollute_requests_proxied(
    client: httpx.AsyncClient,
) -> None:
    """Probe traffic must NOT increment ``requests_proxied`` (spend_log).
    The two counters are independent so real-traffic accounting stays
    clean and the probe can't be confused for a billable request."""
    async with client as c:
        before = (await c.get("/healthz")).json()["requests_proxied"]
        for i in range(5):
            await c.get(f"/_bind_probe/alias-{i}")
        after = (await c.get("/healthz")).json()["requests_proxied"]
    assert after == before, (
        f"WOR-658: probe must NOT tick requests_proxied (real-traffic counter); "
        f"before={before} after={after}"
    )


# ---------------------------------------------------------------------------
# Squatter-resistance signal
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# LAN attacker resistance: an unauthenticated probe reachable from non-
# loopback peers would reintroduce silent-bypass (brutus #1) — an attacker
# can spam the endpoint to inflate the counter, making lock conclude "pass"
# on a config that isn't actually routing.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bind_probe_rejects_non_loopback_peer(
    proxy_app,
) -> None:
    """A non-loopback peer must be REFUSED with 404, AND the counter must
    NOT tick. 404 (not 403) so the endpoint isn't advertised to remote
    scanners as existing. Brutus #1 (WOR-658 Gate-6): without this check,
    an attacker on the LAN can spam the endpoint to fake a successful
    bind-confirmation and reintroduce the silent-bypass class WOR-658
    exists to prevent.
    """
    transport = httpx.ASGITransport(
        app=proxy_app, client=("203.0.113.42", 51234)
    )  # documentation IP range; non-loopback
    async with httpx.AsyncClient(transport=transport, base_url="http://probe.test") as c:
        before = (await c.get("/healthz")).json()["bind_probe_count"]
        r1 = await c.get("/_bind_probe/openai-abc123")
        r2 = await c.head("/_bind_probe/openai-abc123")
        after = (await c.get("/healthz")).json()["bind_probe_count"]
    assert r1.status_code == 404, (
        f"WOR-658 brutus #1: non-loopback GET must be refused with 404 "
        f"(not 403, to avoid advertising the endpoint). Got {r1.status_code}."
    )
    assert r2.status_code == 404, (
        f"WOR-658 brutus #1: non-loopback HEAD must be refused with 404. Got {r2.status_code}."
    )
    assert after == before, (
        f"WOR-658 brutus #1: refused probes must NOT tick the counter. "
        f"A LAN attacker who hits the endpoint cannot move the verdict. "
        f"before={before} after={after}."
    )


@pytest.mark.asyncio
async def test_healthz_bind_probe_count_present_proves_worthless_proxy(
    client: httpx.AsyncClient,
) -> None:
    """The presence of ``bind_probe_count`` in /healthz is the lock side's
    signal that it's talking to a worthless proxy, not a squatter on the
    port. A random HTTP server returning ``{"requests_proxied": <int>}``
    must NOT be mistaken for a worthless proxy."""
    async with client as c:
        body = (await c.get("/healthz")).json()
    # The lock-side check is "if 'bind_probe_count' in healthz: trust the
    # delta on this port, else: skipped, reason=proxy_unrecognised".
    assert "bind_probe_count" in body


# ---------------------------------------------------------------------------
# WOR-650 follow-up: per-alias probe counts so lock can tell WHICH alias a
# probe named (not merely that some probe reached the proxy) — proves per-alias
# acknowledgment, not that the rewrite is a working route. Alias names are
# loopback-only (more sensitive than the bare count).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_surfaces_bind_probe_aliases_on_loopback(
    client: httpx.AsyncClient,
) -> None:
    """/healthz surfaces ``bind_probe_aliases`` (a dict) to loopback callers.
    Additive — existing fields unchanged."""
    async with client as c:
        await c.get("/_bind_probe/openai-seen")
        body = (await c.get("/healthz")).json()
    assert "bind_probe_aliases" in body, (
        f"WOR-650: loopback /healthz must surface per-alias counts; got keys={list(body)}"
    )
    assert isinstance(body["bind_probe_aliases"], dict)
    assert body["bind_probe_aliases"].get("openai-seen") == 1
    # The global counter is still there — the squatter-resistance signal.
    assert "bind_probe_count" in body


@pytest.mark.asyncio
async def test_bind_probe_increments_per_alias_independently(
    client: httpx.AsyncClient,
) -> None:
    """Each alias gets its OWN tally — a probe for one alias never ticks
    another. This is what lets _confirm_bind reject a global-counter pass
    that doesn't prove the specific provider routes."""
    async with client as c:
        await c.get("/_bind_probe/alias-1")
        await c.head("/_bind_probe/alias-1")
        await c.get("/_bind_probe/alias-2")
        per_alias = (await c.get("/healthz")).json()["bind_probe_aliases"]
    assert per_alias.get("alias-1") == 2, f"alias-1 probed twice; got {per_alias!r}"
    assert per_alias.get("alias-2") == 1, f"alias-2 probed once; got {per_alias!r}"


@pytest.mark.asyncio
async def test_healthz_omits_alias_names_for_non_loopback(
    proxy_app,
) -> None:
    """Alias names reveal which providers are locked, so a non-loopback
    /healthz reader gets the bare count but NOT the names. (The probe itself
    is already 404 for non-loopback, so the dict would be empty regardless —
    but the field must be absent so a remote reader can't enumerate aliases
    on a host that DID lock via loopback.)"""
    transport = httpx.ASGITransport(
        app=proxy_app, client=("203.0.113.42", 51234)
    )  # documentation IP range; non-loopback
    async with httpx.AsyncClient(transport=transport, base_url="http://probe.test") as c:
        body = (await c.get("/healthz")).json()
    assert "bind_probe_count" in body, "non-loopback still gets the bare count"
    assert "bind_probe_aliases" not in body, (
        "WOR-650: alias names must NOT be exposed to non-loopback /healthz "
        f"readers (provider-enumeration leak). Got keys={list(body)}"
    )

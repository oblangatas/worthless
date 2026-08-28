"""WOR-650 follow-up — chaos + contract: the bind classifier vs the REAL proxy.

``test_lock_bind_confirmation.py`` feeds ``_classify_bind_per_alias`` hand-made
dicts. These feed it REAL ``/healthz`` payloads from a real ``create_app()``
proxy — including ACROSS a real state reset. A fresh app instance *is* a restart
(``bind_probe_count`` / ``bind_probe_aliases`` are in-memory), so this proves:

* the classifier's assumptions match the proxy's actual healthz shape (rename a
  field on either side and this breaks, where the pure-dict unit tests wouldn't);
* a real bounce is classified inconclusive (``proxy_restarted``), never a false
  ``fail`` — the chaos analogue of the unit test;
* the 256-distinct-alias memory cap is fail-safe: an over-cap alias is dropped,
  reads 0, and so can never be mistaken for "routing" (no false pass).

In-process via ``ASGITransport`` (no docker, deterministic), mirroring
``tests/test_proxy_bind_probe.py``.
"""

from __future__ import annotations

import httpx
import pytest

from worthless.cli.commands import lock as lock_mod
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings


def _settings(db_path: str) -> ProxySettings:
    return ProxySettings(
        db_path=db_path,
        fernet_key=bytearray(b"x" * 32),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )


def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://probe.test")


async def _probe(app: object, alias: str, times: int = 1) -> None:
    async with _client(app) as c:
        for _ in range(times):
            r = await c.get(f"/_bind_probe/{alias}")
            assert r.status_code == 204, r.status_code


async def _healthz(app: object) -> dict:
    async with _client(app) as c:
        return (await c.get("/healthz")).json()


@pytest.mark.asyncio
async def test_real_proxy_restart_is_classified_inconclusive(tmp_path) -> None:
    """Chaos: bounce the proxy (fresh instance = counters reset) BETWEEN the
    before/after reads and confirm a mix of previously-counted + fresh aliases.
    The classifier must call it ``proxy_restarted`` (skipped), never ``fail`` —
    proven on REAL healthz payloads, not hand-made dicts."""
    # World before the bounce: alias-1 has been probed heavily.
    app1 = create_app(_settings(str(tmp_path / "before.db")))
    await _probe(app1, "alias-1", times=100)
    before = await _healthz(app1)

    # RESTART — a fresh app instance; in-memory counters are back to 0. After
    # the restart both aliases re-probe to ~1, so the fresh alias-2 looks
    # "routed" (1 > 0) while alias-1 looks stale (1 <= 100).
    app2 = create_app(_settings(str(tmp_path / "after.db")))
    await _probe(app2, "alias-1", times=1)
    await _probe(app2, "alias-2", times=1)
    after = await _healthz(app2)

    delta = after["bind_probe_count"] - before["bind_probe_count"]
    assert delta < 0, (
        f"a real bounce must read as a negative delta; got {delta} ({before} -> {after})"
    )

    result = lock_mod._classify_bind_per_alias(
        ["alias-1", "alias-2"],
        before["bind_probe_aliases"],
        after["bind_probe_aliases"],
        delta=delta,
        reached=2,
    )
    assert result["status"] == "skipped", result
    assert result.get("reason") == "proxy_restarted", result


@pytest.mark.asyncio
async def test_256_alias_cap_is_failsafe_never_a_false_pass(tmp_path) -> None:
    """The proxy caps DISTINCT aliases at 256 to bound memory on the unauth
    loopback endpoint. A 257th distinct alias is dropped from the per-alias
    tally — so it reads 0 and can NEVER look 'routed'. The cap is fail-safe:
    worst case a >256 lock degrades to a visible non-pass, never a false pass."""
    app = create_app(_settings(str(tmp_path / "cap.db")))
    async with _client(app) as c:
        for i in range(256):
            await c.get(f"/_bind_probe/filler-{i}")
        await c.get("/_bind_probe/over-the-cap")  # 257th distinct -> dropped
        per_alias = (await c.get("/healthz")).json()["bind_probe_aliases"]

    assert "over-the-cap" not in per_alias, (
        f"the 257th distinct alias must be dropped by the 256 cap; got {len(per_alias)} aliases"
    )
    # Consequence for the classifier: a confirmed alias beyond the cap reads 0,
    # lands in not_routing, and so is NOT a pass.
    result = lock_mod._classify_bind_per_alias(
        ["over-the-cap"], {}, per_alias, delta=257, reached=1
    )
    assert result["status"] != "pass", result

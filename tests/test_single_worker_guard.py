"""ProxySettings.validate refuses multi-worker launch (WOR-662).

The spend cap / token-budget tally is process-local in memory, so it is only
exact with one proxy process per database. WEB_CONCURRENCY>1 (uvicorn workers)
would spawn N processes that each reserve independently against the same stale
spend_log SUM, overshooting the cap ~Nx. We refuse it at boot. This is the
interim fail-closed belt; durable cross-process correctness lands with the
WOR-659 pre-charge ledger (after which this guard can be relaxed).
"""

from __future__ import annotations

import pytest

from worthless.proxy.config import ConfigError, ProxySettings


@pytest.mark.parametrize("value", ["2", "4", "16"])
def test_validate_refuses_multi_worker(monkeypatch, value):
    monkeypatch.setenv("WEB_CONCURRENCY", value)
    with pytest.raises(ConfigError, match="single worker per database"):
        ProxySettings().validate()


@pytest.mark.parametrize("value", ["", "1"])
def test_validate_allows_single_worker(monkeypatch, value):
    if value == "":
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("WEB_CONCURRENCY", value)
    # Default loopback / 127.0.0.1 passes deploy-mode checks → no raise.
    ProxySettings().validate()


def test_validate_rejects_non_integer_concurrency(monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "lots")
    with pytest.raises(ConfigError, match="not an integer"):
        ProxySettings().validate()

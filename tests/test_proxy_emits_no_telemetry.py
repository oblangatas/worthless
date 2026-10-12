"""The proxy records no request telemetry, even with a telemetry backend present.

fastapi >= 0.142 instruments every request (spans, metrics, logs) through the
global OpenTelemetry providers. With only ``opentelemetry-api`` installed those
are no-ops — but whether they stay that way is decided by whatever else is in
the environment. The Docker image runs ``pip install .`` and ``install.sh`` runs
``uv tool install``; neither reads uv.lock, and a user's venv may already hold
an SDK or ``fastapi[opentelemetry]``. worthless-3jjl, karen on PR #670.

So the proxy switches fastapi telemetry off itself. This test installs
recording providers — the stand-in for "an SDK is present" — sends a real
request through the proxy, and requires that nothing asked them for a tracer,
meter or logger.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from opentelemetry import _logs, metrics, trace

from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[str] = []


class _TracerProvider(trace.TracerProvider):
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec

    def get_tracer(self, *args: Any, **kwargs: Any) -> trace.Tracer:
        self._rec.calls.append("tracer")
        return trace.NoOpTracer()


class _MeterProvider(metrics.MeterProvider):
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec

    def get_meter(self, *args: Any, **kwargs: Any) -> metrics.Meter:
        self._rec.calls.append("meter")
        return metrics.NoOpMeter("worthless-test")


class _LoggerProvider(_logs.LoggerProvider):
    def __init__(self, rec: _Recorder) -> None:
        self._rec = rec

    def get_logger(self, *args: Any, **kwargs: Any) -> _logs.Logger:
        self._rec.calls.append("logger")
        return _logs.NoOpLogger("worthless-test")


@pytest.fixture
def telemetry_backend(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """Make the global providers look like a configured SDK, without one installed."""
    rec = _Recorder()
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: _TracerProvider(rec))
    monkeypatch.setattr(metrics, "get_meter_provider", lambda: _MeterProvider(rec))
    monkeypatch.setattr(_logs, "get_logger_provider", lambda: _LoggerProvider(rec))
    return rec


@pytest.fixture
def proxy_app(tmp_path):
    settings = ProxySettings(
        db_path=str(tmp_path / "telemetry.db"),
        fernet_key=bytearray(b"x" * 32),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )
    return create_app(settings)


@pytest.mark.asyncio
async def test_a_proxied_request_records_no_telemetry(
    proxy_app: Any, telemetry_backend: _Recorder
) -> None:
    transport = httpx.ASGITransport(app=proxy_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy.test") as client:
        health = await client.get("/healthz")
        probe = await client.get("/_bind_probe/some-alias")
    assert health.status_code == 200
    assert probe.status_code == 204
    assert telemetry_backend.calls == [], (
        "fastapi asked a telemetry backend for "
        f"{sorted(set(telemetry_backend.calls))} while serving proxy requests — "
        "with an SDK installed this would record (and could export) request data"
    )

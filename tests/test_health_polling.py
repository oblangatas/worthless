"""Unit tests for the CLI's `/healthz` polling helpers.

`poll_health_pid` is the authoritative-PID variant: it polls ``GET /healthz``
and returns the PID the proxy self-reports. The CLI uses this to write a PID
file that references the actual listening process rather than whatever
``subprocess.Popen(...).pid`` happens to be on this platform.

These tests cover the helper in isolation (mocked httpx). The end-to-end
behavior — that the daemon writes the self-reported PID and that a second
`worthless up` refuses — lives in ``test_daemon_duplicate_detection.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from worthless.cli.process import poll_health_pid


class _FakeClient:
    """Minimal stand-in for ``httpx.Client`` context manager used in poll_health_pid."""

    def __init__(self, responses: list[object]) -> None:
        self._responses = list(responses)

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, _url: str) -> object:
        if not self._responses:
            raise httpx.ConnectError("exhausted")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _response(status: int, payload: object) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    if isinstance(payload, Exception):
        resp.json.side_effect = payload
    else:
        resp.json.return_value = payload
    return resp


class TestPollHealthPidHappyPath:
    """`poll_health_pid` returns the PID the proxy self-reports."""

    def test_returns_pid_on_first_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(200, {"status": "ok", "requests_proxied": 0, "pid": 4321})
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient([resp]),
        )
        assert poll_health_pid(8787, timeout=1.0) == 4321

    def test_waits_through_initial_connect_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(200, {"status": "ok", "requests_proxied": 0, "pid": 777})
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient(
                [httpx.ConnectError("not yet"), httpx.ConnectError("still not"), resp]
            ),
        )
        assert poll_health_pid(8787, timeout=5.0) == 777


class TestPollHealthPidFallback:
    """Malformed or incomplete responses fall back to ``None`` so the caller
    can substitute ``proc.pid`` — covers in-place upgrades where an older
    daemon is still answering ``/healthz`` without a ``pid`` field.
    """

    def test_returns_none_when_pid_field_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(200, {"status": "ok", "requests_proxied": 0})
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient([resp]),
        )
        assert poll_health_pid(8787, timeout=1.0) is None

    def test_returns_none_on_malformed_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(200, ValueError("not json"))
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient([resp]),
        )
        assert poll_health_pid(8787, timeout=1.0) is None

    def test_returns_none_when_pid_not_an_int(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(200, {"status": "ok", "pid": "not-an-int"})
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient([resp]),
        )
        assert poll_health_pid(8787, timeout=1.0) is None

    def test_returns_none_on_pid_out_of_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rejects ``pid <= 1`` and ``pid > MAX_VALID_PID``.

        A malicious or misbehaving ``/healthz`` responder that echoed
        ``pid: 1`` could trick the CLI into recording init's PID. The
        validator must drop it.
        """
        for bad in (-1, 0, 1, 99_999_999):
            resp = _response(200, {"status": "ok", "pid": bad})
            monkeypatch.setattr(
                "worthless.cli.process.httpx.Client",
                lambda *_a, **_kw: _FakeClient([resp]),
            )
            assert poll_health_pid(8787, timeout=1.0) is None, f"accepted pid={bad}"


class TestPollHealthPidTimeout:
    """Full-timeout path returns ``None``."""

    def test_returns_none_on_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A client that only ever raises ConnectError — emulates port never binding.
        class _NeverReadyClient(_FakeClient):
            def get(self, _url: str) -> object:
                raise httpx.ConnectError("port closed")

        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _NeverReadyClient([]),
        )
        # Tiny timeout to keep the test fast — the loop polls at 300 ms so we
        # give it one iteration plus slack.
        assert poll_health_pid(8787, timeout=0.1) is None

    def test_returns_none_when_non_200(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _response(500, {"error": "internal"})
        monkeypatch.setattr(
            "worthless.cli.process.httpx.Client",
            lambda *_a, **_kw: _FakeClient([resp]),
        )
        assert poll_health_pid(8787, timeout=0.1) is None

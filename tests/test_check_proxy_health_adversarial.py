"""Adversarial coverage for ``check_proxy_health`` — the probe behind F7.

F7 (WOR-648 / WOR-621 AC5) makes ``worthless lock`` abort when the proxy is
down. The decision hinges on :func:`worthless.cli.process.check_proxy_health`
returning ``healthy=False``. Existing tests cover the happy path (200 + JSON,
healthy=True) and the absent path (connection refused, healthy=False).

This file pins the ADVERSARIAL cases — every shape of "the proxy is wrong but
not silent" that could plausibly bypass the gate if the probe trusted its
input. The shared expectation: probe FAILS CLOSED (healthy=False) on anything
that isn't a clean 200 + JSON dict.

Each test spins up a tiny loopback ``ThreadingHTTPServer`` returning the
target adversarial body, then calls ``check_proxy_health`` against it. The
server lifecycle mirrors ``fake_proxy_health`` in the install-incident
harness.
"""

from __future__ import annotations

import contextlib
import http.server
import threading
from collections.abc import Callable, Iterator

import pytest

from worthless.cli.process import check_proxy_health


def _make_handler(status: int, body: bytes, content_type: str = "application/json"):
    """Build a one-shot handler that always responds ``status`` + ``body``."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — http.server API
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    return Handler


@contextlib.contextmanager
def _server(
    handler_factory: Callable[[], type[http.server.BaseHTTPRequestHandler]],
) -> Iterator[int]:
    """Bind a fresh ephemeral 127.0.0.1 port, yield it, tear down cleanly."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_factory())
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Happy-path control — confirm the rig itself works
# ---------------------------------------------------------------------------


def test_check_proxy_health_happy_path() -> None:
    """A clean 200 + JSON dict yields ``healthy=True``."""
    handler = _make_handler(200, b'{"mode": "up", "requests_proxied": 42}')
    with _server(lambda: handler) as port:
        result = check_proxy_health(port)
    assert result == {"healthy": True, "port": port, "mode": "up", "requests_proxied": 42}


# ---------------------------------------------------------------------------
# Adversarial: 200 with non-dict JSON body
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b'"a-bare-string"',  # JSON string
        b"42",  # JSON number
        b"true",  # JSON bool
        b"null",  # JSON null
        b"[]",  # JSON array
        b'[{"mode": "up"}]',  # JSON array of dicts
    ],
    ids=["string", "number", "bool", "null", "empty-array", "array-of-dicts"],
)
def test_check_proxy_health_fails_closed_on_non_dict_json(body: bytes) -> None:
    """Probe must FAIL CLOSED when 200 body is valid JSON but not a dict.

    A non-dict response would raise ``AttributeError`` on ``data.get(...)`` —
    that exception falls into the catch-all and the function returns
    ``healthy=False``. We pin that the gate can NEVER be bypassed by a
    misbehaving (or malicious) server that returns 200 with a non-dict body.
    """
    handler = _make_handler(200, body)
    with _server(lambda: handler) as port:
        result = check_proxy_health(port)
    assert result == {"healthy": False, "port": port, "mode": None, "requests_proxied": 0}


# ---------------------------------------------------------------------------
# Adversarial: 200 with malformed JSON / non-JSON body
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",  # empty body
        b"   ",  # whitespace only
        b"<html>not json at all</html>",  # HTML
        b"{",  # truncated JSON
        b'{"mode": "up"',  # unterminated JSON
        b'{"mode": un}',  # invalid JSON token
        # NUL byte in body — common cause of "200 but actually corrupted upstream"
        b'{"mode": "u\x00p"}',
    ],
    ids=["empty", "whitespace", "html", "truncated", "unterminated", "invalid-token", "nul-byte"],
)
def test_check_proxy_health_fails_closed_on_malformed_body(body: bytes) -> None:
    """A 200 with a body httpx can't parse must yield ``healthy=False``."""
    handler = _make_handler(200, body)
    with _server(lambda: handler) as port:
        result = check_proxy_health(port)
    assert result["healthy"] is False
    assert result["port"] == port


# ---------------------------------------------------------------------------
# Adversarial: 200 dict missing the expected fields (NOT a fail-closed case)
# ---------------------------------------------------------------------------


def test_check_proxy_health_dict_missing_fields_still_healthy_with_defaults() -> None:
    """A 200 dict that's missing ``mode``/``requests_proxied`` falls through to
    documented defaults — and is treated as healthy.

    This pins the *documented* behaviour at ``cli/process.py``: ``mode``
    defaults to ``"up"`` and ``requests_proxied`` to ``0`` when absent. The
    contract is: a 200 + JSON dict from ``/healthz`` is enough for "healthy."
    A future tightening could require both fields, but until then this is the
    behaviour every consumer relies on (status command, wrap, MCP server,
    F7 gate). Locked in to catch silent drift.
    """
    handler = _make_handler(200, b"{}")
    with _server(lambda: handler) as port:
        result = check_proxy_health(port)
    assert result == {"healthy": True, "port": port, "mode": "up", "requests_proxied": 0}


# ---------------------------------------------------------------------------
# Adversarial: non-200 status codes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 401, 404, 418, 500, 502, 503])
def test_check_proxy_health_fails_closed_on_non_200(status: int) -> None:
    """Any non-200 status must yield ``healthy=False`` regardless of body.

    Specifically caught: a redirect (301) that would otherwise follow to an
    unintended endpoint; an upstream error (5xx) that the proxy might bubble
    up while still answering; an auth-required (401) on a misconfigured
    /healthz endpoint.
    """
    handler = _make_handler(status, b'{"mode": "up"}')
    with _server(lambda: handler) as port:
        result = check_proxy_health(port)
    assert result["healthy"] is False
    assert result["port"] == port

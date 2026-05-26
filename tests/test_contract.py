"""Proxy HTTP surface contract tests.

These tests start the real proxy with a mock upstream and hit it over HTTP,
validating the external interface contract that TestSprite confirmed works.
They run in CI and break the build if the contract is violated.

Requires: the proxy + mock upstream to be running (handled by the
``live_proxy`` fixture which reuses the harness machinery).
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography.fernet import Fernet

from tests._fakes import pin_shard_b
from tests.helpers import fake_anthropic_key, fake_openai_key
from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.storage.repository import ShardRepository, StoredShard

# Import mock app from harness (same mock upstream)

# Inline the mock app to avoid importing scripts/ with sys.path hacks
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


MOCK_OPENAI_RESPONSE = {
    "id": "chatcmpl-contract-test",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-4",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "contract test"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
}

MOCK_ANTHROPIC_RESPONSE = {
    "id": "msg-contract-test",
    "type": "message",
    "role": "assistant",
    "content": [{"type": "text", "text": "contract test"}],
    "model": "claude-3-5-sonnet-20241022",
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 5, "output_tokens": 3},
}


async def _mock_openai(request: Request) -> JSONResponse:
    return JSONResponse(MOCK_OPENAI_RESPONSE)


async def _mock_anthropic(request: Request) -> JSONResponse:
    return JSONResponse(MOCK_ANTHROPIC_RESPONSE)


async def _mock_catchall(request: Request) -> JSONResponse:
    return JSONResponse(
        {"error": {"message": f"Unknown: {request.url.path}", "type": "invalid_request_error"}},
        status_code=404,
    )


_mock_app = Starlette(
    routes=[
        Route("/v1/chat/completions", _mock_openai, methods=["POST"]),
        Route("/v1/messages", _mock_anthropic, methods=["POST"]),
        Route("/{path:path}", _mock_catchall),
    ]
)


def _bind_listening_socket() -> tuple[socket.socket, int]:
    """Bind to an ephemeral port and KEEP THE SOCKET OPEN.

    Closing the socket between port allocation and uvicorn startup creates
    a TOCTOU race under pytest-xdist: two workers can each call
    ``socket.bind(0)``, the kernel hands them the same port from the
    ephemeral pool (the close immediately released it), and whichever
    uvicorn binds second dies with ``EADDRINUSE``. Discovered via flake on
    PR #146 CI 2026-05-07 (errno 98 on 127.0.0.1:60261). WOR-459.

    Returning the live socket lets uvicorn take ownership directly via
    ``Server.run(sockets=[sock])`` — the port stays reserved by THIS
    process from bind() through uvicorn handover, no window for collision.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock, sock.getsockname()[1]


@pytest.fixture(scope="module")
def live_proxy():
    """Start mock upstream + real proxy, yield base URL, tear down."""
    tmpdir = tempfile.mkdtemp(prefix="worthless-contract-")
    db_path = str(Path(tmpdir) / "worthless.db")
    fernet_key = Fernet.generate_key()

    mock_sock, mock_port = _bind_listening_socket()
    proxy_sock, proxy_port = _bind_listening_socket()

    # Enroll fake keys and collect shard_a tokens for Bearer auth
    shard_a_tokens: dict[str, str] = {}
    # Capture each alias's plaintext shard-B so we can later pin it into
    # the autouse FakeIPCSupervisor — without this the fake returns the
    # wrong plaintext, reconstruction fails, and the proxy 401s.
    plaintexts: dict[str, bytes] = {}

    prefixes = {"openai": "sk-proj-", "anthropic": "sk-ant-api03-"}
    # 8rqs Phase 5+6: each enrollment carries its own base_url. Point both at
    # the local mock upstream so the per-enrollment routing in proxy/app.py
    # delivers the request there.
    mock_upstream = f"http://127.0.0.1:{mock_port}"
    enrollment_base_urls = {
        "openai": f"{mock_upstream}/v1",
        "anthropic": f"{mock_upstream}/v1",
    }

    async def _enroll():
        repo = ShardRepository(db_path, fernet_key)
        await repo.initialize()
        for provider, key_fn in [("openai", fake_openai_key), ("anthropic", fake_anthropic_key)]:
            api_key = key_fn()
            prefix = prefixes[provider]
            sr = split_key_fp(api_key, prefix=prefix, provider=provider)
            shard = StoredShard(
                shard_b=bytearray(sr.shard_b),
                commitment=bytearray(sr.commitment),
                nonce=bytearray(sr.nonce),
                provider=provider,
            )
            await repo.store_enrolled(
                f"{provider}-contract",
                shard,
                var_name=f"{provider.upper()}_API_KEY",
                env_path=None,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=enrollment_base_urls[provider],
            )
            shard_a_tokens[provider] = sr.shard_a.decode("utf-8")
            plaintexts[f"{provider}-contract"] = bytes(sr.shard_b)

    asyncio.run(_enroll())

    try:
        # Create proxy app
        settings = ProxySettings(
            db_path=db_path,
            fernet_key=bytearray(fernet_key),
            allow_insecure=True,
            default_rate_limit_rps=100.0,
        )
        proxy_app = create_app(settings)

        for alias, pt in plaintexts.items():
            pin_shard_b(proxy_app, alias, pt)

        # Start both servers in background threads.
        # `sockets=[sock]` hands the pre-bound listening socket to uvicorn
        # so the port is never released between allocation and bind — closes
        # the WOR-459 TOCTOU race window. host/port in Config become
        # advisory in this mode; we keep them for log-readability.
        mock_server = uvicorn.Server(
            uvicorn.Config(_mock_app, host="127.0.0.1", port=mock_port, log_level="error")
        )
        proxy_server = uvicorn.Server(
            uvicorn.Config(proxy_app, host="127.0.0.1", port=proxy_port, log_level="error")
        )

        mock_thread = threading.Thread(
            target=mock_server.run, kwargs={"sockets": [mock_sock]}, daemon=True
        )
        proxy_thread = threading.Thread(
            target=proxy_server.run, kwargs={"sockets": [proxy_sock]}, daemon=True
        )
        mock_thread.start()
        proxy_thread.start()

        # Wait for both servers to be ready
        for label, port in [("Mock upstream", mock_port), ("Proxy", proxy_port)]:
            for _ in range(30):
                try:
                    httpx.get(f"http://127.0.0.1:{port}/", timeout=1.0)
                    break
                except (httpx.ConnectError, httpx.ReadError):
                    time.sleep(0.2)
            else:
                raise RuntimeError(f"{label} did not start within 6 seconds")
        base_url = f"http://127.0.0.1:{proxy_port}"

        yield base_url, shard_a_tokens

        # Teardown
        mock_server.should_exit = True
        proxy_server.should_exit = True
        mock_thread.join(timeout=3)
        proxy_thread.join(timeout=3)
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------


class TestHealthEndpoints:
    def test_root_returns_200(self, live_proxy) -> None:
        base_url, _ = live_proxy
        r = httpx.get(f"{base_url}/")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_healthz_returns_200(self, live_proxy) -> None:
        base_url, _ = live_proxy
        r = httpx.get(f"{base_url}/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_readyz_returns_200(self, live_proxy) -> None:
        base_url, _ = live_proxy
        r = httpx.get(f"{base_url}/readyz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# OpenAI proxy
# ---------------------------------------------------------------------------


class TestOpenAIProxy:
    def test_chat_completions_returns_200(self, live_proxy) -> None:
        base_url, tokens = live_proxy
        r = httpx.post(
            f"{base_url}/openai-contract/v1/chat/completions",
            headers={"authorization": f"Bearer {tokens['openai']}"},
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 200
        body = r.json()
        assert "choices" in body
        assert "usage" in body

    def test_chat_completions_no_worthless_headers_leaked(self, live_proxy) -> None:
        base_url, tokens = live_proxy
        r = httpx.post(
            f"{base_url}/openai-contract/v1/chat/completions",
            headers={"authorization": f"Bearer {tokens['openai']}"},
            json={"model": "gpt-4", "messages": []},
        )
        assert r.status_code == 200
        for header in r.headers:
            assert not header.lower().startswith("x-worthless-"), (
                f"Internal header leaked: {header}"
            )


# ---------------------------------------------------------------------------
# Anthropic proxy
# ---------------------------------------------------------------------------


class TestAnthropicProxy:
    def test_messages_returns_200(self, live_proxy) -> None:
        base_url, tokens = live_proxy
        r = httpx.post(
            f"{base_url}/anthropic-contract/v1/messages",
            headers={"authorization": f"Bearer {tokens['anthropic']}"},
            json={
                "model": "claude-3-5-sonnet-20241022",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 100,
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert "content" in body
        assert "usage" in body

    def test_messages_no_worthless_headers_leaked(self, live_proxy) -> None:
        base_url, tokens = live_proxy
        r = httpx.post(
            f"{base_url}/anthropic-contract/v1/messages",
            headers={"authorization": f"Bearer {tokens['anthropic']}"},
            json={
                "model": "claude-3-5-sonnet-20241022",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 100,
            },
        )
        assert r.status_code == 200
        for header in r.headers:
            assert not header.lower().startswith("x-worthless-"), (
                f"Internal header leaked: {header}"
            )


# ---------------------------------------------------------------------------
# Anti-enumeration (uniform 401)
# ---------------------------------------------------------------------------


class TestAntiEnumeration:
    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/v1/models"),
            ("GET", "/nonexistent/path"),
            ("POST", "/v1/embeddings"),
            ("GET", "/admin"),
            ("GET", "/.env"),
        ],
    )
    def test_unknown_paths_return_uniform_401(self, live_proxy, method: str, path: str) -> None:
        base_url, _ = live_proxy
        r = httpx.request(method, f"{base_url}{path}")
        assert r.status_code == 401, f"{method} {path} returned {r.status_code}"
        body = r.json()
        assert body["error"]["type"] == "authentication_error"

    def test_all_401s_have_identical_body(self, live_proxy) -> None:
        base_url, _ = live_proxy
        bodies = []
        for path in ["/v1/models", "/nonexistent", "/admin", "/.env"]:
            r = httpx.get(f"{base_url}{path}")
            assert r.status_code == 401
            bodies.append(r.text)
        assert len(set(bodies)) == 1, "401 responses differ -- anti-enumeration broken"


# ---------------------------------------------------------------------------
# Response format
# ---------------------------------------------------------------------------


class TestResponseFormat:
    def test_health_returns_json_content_type(self, live_proxy) -> None:
        base_url, _ = live_proxy
        r = httpx.get(f"{base_url}/healthz")
        assert "application/json" in r.headers.get("content-type", "")

    def test_401_returns_json_content_type(self, live_proxy) -> None:
        base_url, _ = live_proxy
        r = httpx.get(f"{base_url}/v1/models")
        assert r.status_code == 401
        assert "application/json" in r.headers.get("content-type", "")

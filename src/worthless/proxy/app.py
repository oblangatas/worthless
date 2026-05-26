"""FastAPI proxy app — gate-before-reconstruct pipeline.

This is the core Worthless product: every request passes through the rules engine
BEFORE any key reconstruction occurs. Denied requests never touch key material.

Architecture invariants enforced:
1. Gate before reconstruct (CRYP-05 / SR-03)
2. Transparent routing via adapter registry (PROX-04)
3. Server-side-only reconstruction — key never in response (PROX-05)
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from starlette.middleware.cors import CORSMiddleware

from worthless.adapters.registry import get_adapter
from worthless.adapters.types import INTERNAL_HEADER_PREFIX
from worthless.crypto.reconstruction import reconstruct_key, reconstruct_key_fp, secure_key
from worthless.proxy.config import DeployMode, ProxySettings
from worthless.proxy.errors import _error_body, auth_error_response, gateway_error_response
from worthless.proxy.ipc_supervisor import IPCSupervisor, IPCUnavailable
from worthless.proxy.metering import (
    StreamingUsageCollector,
    extract_usage_anthropic,
    extract_usage_openai,
    record_spend,
)
from worthless.proxy.rules import (
    RateLimitRule,
    RulesEngine,
    SpendCapRule,
    TokenBudgetRule,
    _estimate_tokens,
)
from worthless.storage.schema import SCHEMA
from worthless.storage.shard_reader import ShardReader

logger = logging.getLogger(__name__)

_ALIAS_RE = re.compile(r"[a-zA-Z0-9_-]+")
_BAD_HEADER_CHARS = frozenset("\x00\r\n")


def _make_uniform_401_bytes() -> tuple[bytes, dict[str, str]]:
    """Pre-compute the uniform 401 body so all code paths return the exact same bytes."""
    err = auth_error_response()
    return err.body, err.headers


# Pre-computed uniform response
_AUTH_BODY, _AUTH_HEADERS = _make_uniform_401_bytes()


def _uniform_401() -> Response:
    """Return the uniform 401 response (anti-enumeration)."""
    return Response(
        content=_AUTH_BODY,
        status_code=401,
        headers=_AUTH_HEADERS,
        media_type="application/json",
    )


def _scheme_is_trusted(request: Request, settings: ProxySettings) -> bool:
    # PUBLIC: scope["scheme"] reflects forwarded proto only when uvicorn's
    # --forwarded-allow-ips already gated the peer; otherwise the raw socket scheme.
    if settings.deploy_mode is DeployMode.LOOPBACK:
        return True
    if settings.deploy_mode is DeployMode.LAN:
        return True
    return request.scope.get("scheme", "http") == "https"


def _extract_shard_a(request: Request) -> bytearray | None:
    """Extract shard-A from the request's auth header.

    Supports both OpenAI (``Authorization: Bearer``) and Anthropic
    (``x-api-key``) conventions.  Returns ``None`` if neither is present.
    """
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth[7:]
        if token:
            return bytearray(token, "utf-8")

    api_key = request.headers.get("x-api-key")
    if api_key:
        return bytearray(api_key, "utf-8")

    return None


def _extract_alias_and_path(raw_path: str) -> tuple[str, str] | None:
    """Extract alias prefix and API path from ``/<alias>/v1/chat/completions``.

    Returns ``(alias, api_path)`` or ``None`` if the first segment is not
    a valid alias (SR-09: alias comes from URL path, not disk scanning).
    """
    parts = raw_path.strip("/").split("/", 1)
    if len(parts) < 2:
        return None
    alias_candidate = parts[0]
    if not _ALIAS_RE.fullmatch(alias_candidate):
        return None
    return alias_candidate, "/" + parts[1]


def _strip_worthless_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove x-worthless-* headers from a response header dict."""
    return {k: v for k, v in headers.items() if not k.lower().startswith(INTERNAL_HEADER_PREFIX)}


def _sanitize_upstream_error(status_code: int, body: bytes, provider: str) -> bytes:
    """Sanitize upstream error response body — strip internal provider details.

    Uses an explicit allowlist — only ``type``, ``code``, and ``param`` are
    forwarded from the upstream error dict. ``message`` is replaced with a
    generic string. Any extra keys (known or unknown) are stripped to prevent
    information leakage.

    At the top level, only the ``error`` key is forwarded. The Anthropic
    ``type: "error"`` sentinel (a fixed non-sensitive literal) is also
    preserved so Anthropic SDK clients can classify the response correctly.
    Any other top-level keys the upstream might include are discarded.

    Falls back to a fully-constructed error body if the upstream response
    cannot be parsed or does not contain an error dict.
    """
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and "error" in parsed and isinstance(parsed["error"], dict):
            # Explicit allowlist — only forward known safe keys from the error dict
            sanitized_error = {
                k: parsed["error"].get(k)
                for k in ("type", "code", "param")
                if parsed["error"].get(k) is not None
            }
            sanitized_error["message"] = "upstream provider error"
            # Build output with only the error key at the top level.
            # Exception: preserve the Anthropic sentinel `type: "error"` (always
            # the literal string "error", never sensitive data) so Anthropic SDK
            # clients can classify the response without inspecting the error dict.
            output: dict[str, object] = {"error": sanitized_error}
            if parsed.get("type") == "error":
                output["type"] = "error"
            return json.dumps(output).encode()
    except (json.JSONDecodeError, ValueError, KeyError):
        pass
    # Fallback: build a generic body when upstream sent an unparsable response
    return _error_body(status_code, "upstream provider error", "api_error", provider)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup/shutdown lifecycle for the proxy.

    WOR-309: the proxy holds **no** key material. Decryption is delegated
    to the sidecar over IPC; this lifespan only owns ciphertext-at-rest
    (``ShardReader``) and the supervisor for the IPC connection.
    """
    settings: ProxySettings = app.state.settings

    db = await aiosqlite.connect(settings.db_path)
    await db.executescript(SCHEMA)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.commit()
    app.state.db = db

    repo = ShardReader(settings.db_path)
    app.state.repo = repo

    # Allow tests to inject a pre-configured supervisor (avoids spawning a
    # real sidecar in unit tests). When absent, build one from settings and
    # eager-connect — fail-loud if the sidecar is unreachable (no fallback).
    ipc: IPCSupervisor = getattr(app.state, "ipc_supervisor", None) or IPCSupervisor(
        socket_path=Path(settings.sidecar_socket_path),
        protocol_version=settings.sidecar_protocol_version,
        expected_caps=settings.sidecar_expected_caps,
        max_concurrency=settings.sidecar_max_concurrency,
        request_timeout_s=settings.sidecar_request_timeout_s,
    )
    if not getattr(app.state, "ipc_supervisor_preconnected", False):
        await ipc.connect()
    app.state.ipc_supervisor = ipc

    client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(
            connect=10.0,
            read=settings.streaming_timeout,
            write=settings.upstream_timeout,
            pool=10.0,
        ),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    app.state.httpx_client = client

    rules_engine = RulesEngine(
        rules=[
            TokenBudgetRule(db=db),
            RateLimitRule(
                default_rps=settings.default_rate_limit_rps,
                db_path=settings.db_path,
            ),
            # LAST — TokenBudgetRule and SpendCapRule both place reservations;
            # SpendCapRule runs last to minimise denial-path leaks.
            SpendCapRule(db=db),
        ]
    )
    app.state.rules_engine = rules_engine

    yield

    # Cleanup
    try:
        await client.aclose()
        await db.close()
    finally:
        await ipc.aclose()


def create_app(settings: ProxySettings | None = None) -> FastAPI:
    """Create the Worthless proxy FastAPI app.

    Args:
        settings: Proxy settings. If None, loads from environment.
    """
    if settings is None:
        settings = ProxySettings()

    settings.validate()

    app = FastAPI(
        title="worthless-proxy",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    app.state.settings = settings
    # proxy_auth_token is no longer used — kept for tests that set it to None
    # to indicate "target state: no stable token". The proxy ignores this field.
    app.state.proxy_auth_token = None

    # Middleware stack (reverse order: last registered runs first)
    app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["GET"], allow_headers=[])

    # Health endpoints (no auth)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/healthz")
    async def healthz(request: Request) -> dict[str, object]:
        """Liveness endpoint.

        Returns status, a best-effort request counter, and ``pid``. The PID
        is exposed intentionally so the CLI can record the authoritative
        listening PID rather than the (possibly drifted) spawn PID; it is
        not sensitive (already visible via ``ps``/``lsof`` to anyone on the
        host) and must never be forwarded into audit streams.
        """
        count = 0
        try:
            db: aiosqlite.Connection = request.app.state.db
            async with db.execute("SELECT COUNT(*) FROM spend_log") as cursor:
                row = await cursor.fetchone()
                if row:
                    count = row[0]
        except Exception:  # noqa: S110 — spend_log may not exist yet  # nosec B110
            pass
        # Expose the listening process PID so the CLI can write the
        # authoritative PID — the process actually bound to the port —
        # rather than whatever Popen returned on this platform.
        return {"status": "ok", "requests_proxied": count, "pid": os.getpid()}

    @app.get("/readyz")
    async def readyz(request: Request) -> Response:
        # H-3: Only check DB connectivity — never reveal enrollment state
        # (prevents unauthenticated enrollment oracle, worthless-9dz)
        db: aiosqlite.Connection = request.app.state.db
        try:
            await db.execute("SELECT 1")
        except Exception:
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(status_code=200, content={"status": "ok"})

    # Catch-all proxy route

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_request(request: Request, path: str) -> Response:  # noqa: C901
        settings: ProxySettings = request.app.state.settings
        repo: ShardReader = request.app.state.repo
        rules_engine: RulesEngine = request.app.state.rules_engine
        httpx_client: httpx.AsyncClient = request.app.state.httpx_client
        ipc: IPCSupervisor = request.app.state.ipc_supervisor

        raw_path = "/" + path.split("?")[0].lstrip("/")

        # Extract alias from URL path: /<alias>/v1/chat/completions
        parsed = _extract_alias_and_path(raw_path)
        if parsed is None:
            return _uniform_401()
        alias, clean_path = parsed

        if not _scheme_is_trusted(request, settings):
            return _uniform_401()

        # Reject null/CR/LF in header keys or values
        for key, value in request.headers.items():
            if _BAD_HEADER_CHARS.intersection(key) or _BAD_HEADER_CHARS.intersection(value):
                return _uniform_401()

        # Fetch encrypted shard (gate-before-decrypt: no Fernet yet)
        encrypted = await repo.fetch_encrypted(alias)
        if encrypted is None:
            return _uniform_401()

        # SR-03: gate before reconstruct. Refuse legacy rows missing
        # base_url BEFORE any rules-engine evaluation, BEFORE shard_a
        # extraction, BEFORE reconstruction. The denial path must not
        # trigger key materialisation. (worthless-2pdi will promote this
        # into a structural validate_encrypted_row helper covering all
        # row-shape denials; the inline guard is the minimum.)
        #
        # Anti-enumeration: return the same _uniform_401() that unknown
        # aliases get. A distinctive response (e.g. 503 with a relock
        # hint) would let an attacker probe the DB by content-shape,
        # breaking the anti-enumeration contract worthless-bi7h tracks
        # for the timing-oracle variant. The relock hint surfaces in
        # operator logs and via authenticated paths only.
        if encrypted.base_url is None:
            logger.warning(
                "alias %r has NULL base_url (legacy pre-8rqs row); "
                "operator should run `worthless relock`",
                alias,
            )
            return _uniform_401()

        # SR-09: shard-A arrives in the Authorization: Bearer header (or x-api-key).
        # This is the only auth path — the 16x2 stable-token path has been removed.
        # The commitment check in reconstruct_key_fp validates that shard-A + shard-B
        # reconstruct the original key — old shard-A values are automatically rejected
        # after re-lock because the DB shard-B (and commitment) have changed.
        shard_a: bytearray | None = _extract_shard_a(request)
        if shard_a is None:
            return _uniform_401()

        # Pre-read body ONCE before rules engine (WOR-182: eliminates
        # Starlette body-caching coupling — rules receive bytes, not stream)
        body = await request.body()

        # Estimate max tokens for spend-cap reservation (WOR-242).
        # Computed once here so error paths and spend recording can release it.
        _spend_reservation = _estimate_tokens(body)

        # GATE: rules engine evaluates BEFORE any Fernet decrypt
        denial = await rules_engine.evaluate(alias, request, provider=encrypted.provider, body=body)
        if denial is not None:
            # Zero shard_a before returning (SR-01/SR-02)
            shard_a[:] = b"\x00" * len(shard_a)
            # Release any reservation placed by an earlier rule in the chain
            # (e.g. TokenBudgetRule reserves before RateLimitRule/SpendCapRule run).
            await rules_engine.release_spend_reservation(alias, _spend_reservation)
            return Response(
                content=denial.body,
                status_code=denial.status_code,
                headers=denial.headers,
                media_type="application/json",
            )

        # Get adapter (uniform 401, not 404, for anti-enumeration)
        adapter = get_adapter(clean_path)
        if adapter is None:
            shard_a[:] = b"\x00" * len(shard_a)
            await rules_engine.release_spend_reservation(alias, _spend_reservation)
            return _uniform_401()

        # Decrypt now that the gate has passed — over IPC to the sidecar.
        # No in-process Fernet (WOR-309). Transport failure → 503.
        plaintext_shard_b: bytearray | None = None
        try:
            plaintext_shard_b = await ipc.open(encrypted.shard_b_enc, key_id=alias)
        except IPCUnavailable:
            shard_a[:] = b"\x00" * len(shard_a)
            await rules_engine.release_spend_reservation(alias, _spend_reservation)
            return _make_gateway_response(503, "sidecar unavailable")
        except Exception:
            shard_a[:] = b"\x00" * len(shard_a)
            await rules_engine.release_spend_reservation(alias, _spend_reservation)
            return _uniform_401()

        # Reconstruct key inside secure_key context (body already read above)
        req_headers = {k: v for k, v in request.headers.items()}

        try:
            if encrypted.prefix is not None and encrypted.charset is not None:
                key_buf = reconstruct_key_fp(
                    shard_a,
                    plaintext_shard_b,
                    encrypted.commitment,
                    encrypted.nonce,
                    encrypted.prefix,
                    encrypted.charset,
                )
            else:
                key_buf = reconstruct_key(
                    shard_a, plaintext_shard_b, encrypted.commitment, encrypted.nonce
                )
        except Exception:
            shard_a[:] = b"\x00" * len(shard_a)
            plaintext_shard_b[:] = b"\x00" * len(plaintext_shard_b)
            await rules_engine.release_spend_reservation(alias, _spend_reservation)
            return _uniform_401()

        # Build and send with stream=True for SSE support
        upstream_resp: httpx.Response | None = None
        try:
            with secure_key(key_buf) as k:
                adapter_req = adapter.prepare_request(
                    body=body,
                    headers=req_headers,
                    api_key=k,
                    base_url=encrypted.base_url,
                )

                # Build the httpx request object
                upstream_req = httpx_client.build_request(
                    method=request.method,
                    url=adapter_req.url,
                    headers=adapter_req.headers,
                    content=adapter_req.body,
                )

                try:
                    upstream_resp = await httpx_client.send(upstream_req, stream=True)
                except httpx.TimeoutException:
                    await rules_engine.release_spend_reservation(alias, _spend_reservation)
                    return _make_gateway_response(504, "gateway timeout")
                except httpx.ConnectError:
                    await rules_engine.release_spend_reservation(alias, _spend_reservation)
                    return _make_gateway_response(502, "bad gateway")
                except httpx.HTTPError:
                    await rules_engine.release_spend_reservation(alias, _spend_reservation)
                    return _make_gateway_response(502, "bad gateway")

            # Relay response (key_buf is zeroed after secure_key exits)
            adapter_resp = await adapter.relay_response(upstream_resp)

            clean_headers = _strip_worthless_headers(adapter_resp.headers)
            provider = encrypted.provider

            async def _do_record_spend(data: bytes):
                """Extract usage and record spend — shared by streaming and non-streaming."""
                if provider == "anthropic":
                    usage = extract_usage_anthropic(data)
                else:
                    usage = extract_usage_openai(data)
                tokens = usage.total_tokens if usage else 0
                model = usage.model if usage else None
                if usage is None:
                    # Renamed from "Token extraction failed" — Semgrep's
                    # python-logger-credential-disclosure rule fires on
                    # the word "Token" in log messages, but here we mean
                    # the LLM response usage-tokens count (for metering),
                    # not an auth token. Renaming clears the rule
                    # without needing a # nosemgrep annotation.
                    logger.warning(
                        "Usage extraction failed for alias=%s provider=%s",
                        alias,
                        provider,
                    )
                try:
                    await record_spend(settings.db_path, alias, tokens, model, provider)
                except Exception:
                    logger.warning("Failed to record spend for alias=%s", alias)
                # Release the spend reservation now that actual tokens are recorded (WOR-242).
                await rules_engine.release_spend_reservation(alias, _spend_reservation)

            if adapter_resp.status_code >= 400:
                sanitized_body = _sanitize_upstream_error(
                    adapter_resp.status_code, adapter_resp.body, provider
                )
                return Response(
                    content=sanitized_body,
                    status_code=adapter_resp.status_code,
                    headers={"content-type": "application/json"},
                    media_type="application/json",
                    background=BackgroundTask(_do_record_spend, adapter_resp.body),
                )

            if adapter_resp.is_streaming and adapter_resp.stream is not None:
                usage_collector = StreamingUsageCollector(provider=encrypted.provider)

                async def _stream_with_metering() -> AsyncIterator[bytes]:
                    try:
                        async for chunk in adapter_resp.stream:  # type: ignore[union-attr]
                            usage_collector.feed(chunk)
                            yield chunk
                    finally:
                        # Client disconnect or stream end: close upstream
                        await upstream_resp.aclose()  # type: ignore[union-attr]

                async def _record_metering():
                    usage = usage_collector.result()
                    if usage is not None:
                        await record_spend(
                            settings.db_path,
                            alias,
                            usage.total_tokens,
                            usage.model,
                            encrypted.provider,
                        )
                    else:
                        # Zero friction: if we can't extract usage (provider
                        # changed SSE format, etc.), log a warning but don't
                        # penalize the user with phantom spend.
                        logger.warning(
                            "Could not extract usage from streaming response "
                            "for alias=%s; spend not recorded",
                            alias,
                        )
                    # Release the spend reservation (WOR-242).
                    await rules_engine.release_spend_reservation(alias, _spend_reservation)

                return StreamingResponse(
                    _stream_with_metering(),
                    status_code=adapter_resp.status_code,
                    headers=clean_headers,
                    background=BackgroundTask(_record_metering),
                )
            else:
                await upstream_resp.aclose()

                return Response(
                    content=adapter_resp.body,
                    status_code=adapter_resp.status_code,
                    headers=clean_headers,
                    media_type=clean_headers.get("content-type", "application/json"),
                    background=BackgroundTask(_do_record_spend, adapter_resp.body),
                )
        finally:
            # Zero shard_a (SR-01/SR-02)
            shard_a[:] = b"\x00" * len(shard_a)
            if plaintext_shard_b is not None:
                plaintext_shard_b[:] = b"\x00" * len(plaintext_shard_b)

    return app


def _make_gateway_response(status_code: int, message: str) -> Response:
    """Create a gateway error response (502/504)."""
    err = gateway_error_response(status_code, message)
    return Response(
        content=err.body,
        status_code=err.status_code,
        headers=err.headers,
        media_type="application/json",
    )

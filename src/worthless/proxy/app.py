"""FastAPI proxy app — gate-before-reconstruct pipeline.

This is the core Worthless product: every request passes through the rules engine
BEFORE any key reconstruction occurs. Denied requests never touch key material.

Architecture invariants enforced:
1. Gate before reconstruct (CRYP-05 / SR-03)
2. Transparent routing via adapter registry (PROX-04)
3. Server-side-only reconstruction — key never in response (PROX-05)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import time
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
from worthless.proxy.response_model_audit import bounded_increment, extract_response_model
from worthless.proxy.rules import (
    RateLimitRule,
    RulesEngine,
    SpendCapRule,
    TokenBudgetRule,
    _estimate_tokens,
    extract_model,
)
from worthless.storage.schema import SCHEMA, migrate_db
from worthless.storage.shard_reader import ShardReader
from worthless.storage.spend_ledger import SpendLedger

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


async def _sweep_loop(ledger: SpendLedger, interval: float, max_age: float) -> None:
    """Background task: periodically settle orphaned holds at their estimate.

    Runs forever until cancelled (typically at proxy shutdown). Any exception
    from ``ledger.sweep()`` is swallowed and logged so a transient DB error
    never crashes the loop — the next iteration will retry.

    Args:
        ledger: The SpendLedger instance to sweep.
        interval: Seconds between sweeps (WORTHLESS_SWEEP_INTERVAL_SECONDS).
        max_age: Holds older than this many seconds are billed at estimate
            (WORTHLESS_SWEEP_MAX_AGE_SECONDS).
    """
    while True:
        await asyncio.sleep(interval)
        try:
            await ledger.sweep(max_age)
        except Exception:  # noqa: BLE001
            logger.warning("sweeper: sweep() raised an exception", exc_info=True)


async def _refresh_decoy_hashes(app: FastAPI, reader: ShardReader) -> None:
    """Re-read the retired-decoy set into ``app.state.decoy_hashes`` (worthless-ibw1).

    The set is preloaded once at startup; without this a shard-A retired by
    ``unlock`` *while the proxy is running* would not be in the tripwire until a
    restart. Best-effort: a transient DB error keeps the current set rather than
    blanking the tripwire.
    """
    try:
        app.state.decoy_hashes = await reader.fetch_decoy_hashes()
    except Exception:  # noqa: BLE001
        logger.warning("decoy reload: fetch_decoy_hashes() raised", exc_info=True)


async def _decoy_reload_loop(app: FastAPI, reader: ShardReader, interval: float) -> None:
    """Background task: refresh the decoy tripwire on *interval* until cancelled."""
    while True:
        await asyncio.sleep(interval)
        await _refresh_decoy_hashes(app, reader)


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
    # executescript(SCHEMA) is CREATE TABLE IF NOT EXISTS only — it never adds
    # new columns to a pre-existing table. A proxy restarted on a DB enrolled by
    # an older version would lack columns like WOR-705's ceiling_override, which
    # the fail-closed settle/sweep path reads on every disconnect. Apply
    # forward-only migrations here too, mirroring ShardRepository.initialize().
    await migrate_db(settings.db_path)
    app.state.db = db

    repo = ShardReader(settings.db_path)
    app.state.repo = repo
    # WOR-640: preload decoy hashes for O(1) per-request tripwire check.
    app.state.decoy_hashes = await repo.fetch_decoy_hashes()

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

    # One transaction lock per connection: every BEGIN IMMEDIATE path on `db`
    # (the ledger inside SpendCapRule, and TokenBudgetRule) must share it, or two
    # concurrent requests could nest a transaction on the one connection → crash.
    db_lock = asyncio.Lock()
    app.state.db_lock = db_lock
    rules_engine = RulesEngine(
        rules=[
            TokenBudgetRule(db=db, lock=db_lock),
            RateLimitRule(
                default_rps=settings.default_rate_limit_rps,
                db_path=settings.db_path,
            ),
            # LAST — TokenBudgetRule and SpendCapRule both place reservations;
            # SpendCapRule runs last to minimise denial-path leaks.
            SpendCapRule(db=db, lock=db_lock),
        ]
    )
    app.state.rules_engine = rules_engine

    # Sweeper background task: settle orphaned holds left by SIGKILL/crash.
    # SpendCapRule's internal ledger shares the same db + db_lock, so we build
    # a SpendLedger here with the same connection to avoid opening a second one.
    ledger = SpendLedger(db, db_lock)
    app.state.ledger = ledger
    sweep_task = asyncio.create_task(
        _sweep_loop(ledger, settings.sweep_interval_seconds, settings.sweep_max_age_seconds),
        name="worthless-sweeper",
    )
    # worthless-ibw1: refresh the decoy tripwire on the same cadence so a key
    # retired mid-session is caught without a proxy restart.
    decoy_reload_task = asyncio.create_task(
        _decoy_reload_loop(app, repo, settings.sweep_interval_seconds),
        name="worthless-decoy-reload",
    )

    try:
        yield
    finally:
        # Cancel background tasks before closing the DB — they MUST NOT race
        # db.close(). Both cancel() and await are required: cancel() alone leaves
        # the task running until the event loop closes, causing "task was
        # destroyed but it is pending" ResourceWarnings (errors on Python 3.13+).
        sweep_task.cancel()
        decoy_reload_task.cancel()
        for _bg in (sweep_task, decoy_reload_task):
            with contextlib.suppress(asyncio.CancelledError):
                await _bg
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
    # WOR-696 T7: response-model mismatch counter. Dict keyed by
    # (request_model, response_model) → int. Observation only — surfaces
    # silent provider re-routes (gpt-4o-mini → gpt-5) in metrics. Init at
    # app construction (not in lifespan) so tests that build app.state by
    # hand still see it.
    app.state.response_model_mismatch_counter = {}
    # WOR-658: dedicated counter for the bind-confirmation probe. Lives
    # in-memory only — survives the process lifetime and resets on restart,
    # exactly the lifecycle ``worthless lock`` cares about (it reads
    # before + after within a single CLI invocation). Intentionally
    # SEPARATE from ``requests_proxied`` (spend_log) so probe traffic can
    # never inflate the real-traffic meter and a real-traffic burst can
    # never fake a probe pass.
    app.state.bind_probe_count = 0

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
        # WOR-658: surface ``bind_probe_count`` so ``worthless lock`` can
        # observe a delta across the synthetic probe and also use the
        # field's presence as proof the responder is a worthless proxy
        # (a squatter on the port serving plain ``/healthz`` won't have
        # this field — lock classifies that case as ``skipped``, not ``pass``).
        bind_probe_count = getattr(request.app.state, "bind_probe_count", 0)
        return {
            "status": "ok",
            "requests_proxied": count,
            "pid": os.getpid(),
            "bind_probe_count": bind_probe_count,
        }

    @app.get("/_bind_probe/{alias}")
    @app.head("/_bind_probe/{alias}")
    async def bind_probe(request: Request, alias: str) -> Response:  # noqa: ARG001
        """WOR-658 bind-confirmation probe — loopback-only.

        ``worthless lock`` fires one GET/HEAD per managed alias here
        immediately after rewriting the OpenClaw config. We bump an
        in-memory counter and return 204 No Content; the lock side reads
        the delta on ``/healthz`` to prove the rewritten URL actually
        routes through this proxy.

        Security posture (this is by design — review carefully if changing):

        * **Loopback-only.** Non-127.0.0.1/::1 peers get a 404 and the
          counter does NOT tick. Brutus #1 (WOR-658 Gate-6 adversarial
          review): an unauthenticated probe reachable from the LAN would
          reintroduce silent-bypass — a co-located attacker on a non-
          loopback deploy could spam the endpoint to inflate the counter
          and make ``worthless lock`` conclude "pass" on a config that
          isn't actually routing. The probe is a self-test only; no
          legitimate remote caller has a reason to hit it. 404 (not 403)
          so the endpoint isn't advertised to remote scanners.
        * No auth on the loopback path. The probe runs BEFORE auth on
          purpose; the whole point is to exercise routing without
          needing a real key.
        * Response is identical for every alias (204, no body). No
          information about which aliases are registered leaks here.
        * Counter is in-memory and isolated from ``requests_proxied``.
          Probe traffic can't pollute the spend ledger and a real-traffic
          burst can't fake a probe pass.
        * The presence of ``bind_probe_count`` in ``/healthz`` is the
          lock side's signal that it's talking to a worthless proxy. A
          squatter on the port answering plain ``/healthz`` won't have it.
        """
        client_host = request.client.host if request.client else None
        if client_host not in ("127.0.0.1", "::1"):
            return Response(status_code=404)
        # WOR-658 Fix 5: counter increment is atomic-by-construction —
        # asyncio is cooperative + GIL holds across the synchronous
        # ``getattr ... + 1`` and the assignment, with NO ``await`` between
        # them. Adding any ``await`` between read and write would
        # re-introduce a lost-update race; keep this body await-free.
        request.app.state.bind_probe_count = getattr(request.app.state, "bind_probe_count", 0) + 1
        return Response(status_code=204)

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

        # WOR-640: decoy tripwire — detect stolen .env replay attacks.
        # When a .env is unlocked its shard-A is RETIRED: HMAC-SHA256(shard_a) is
        # recorded in the retired_decoys table and preloaded into
        # app.state.decoy_hashes at startup. The currently-active shard-A is never
        # in this set, so a legitimate Bearer passes; a replayed retired one is
        # caught. We ask the sidecar to MAC the incoming Bearer value (best-effort:
        # if IPC fails we let the request through rather than block legit traffic).
        # SR-04: do NOT log the matched value — only the alias.
        _decoy_hashes: frozenset[str] = getattr(request.app.state, "decoy_hashes", frozenset())
        if _decoy_hashes:
            try:
                _mac_tag = await ipc.mac(shard_a)
                if _mac_tag.hex() in _decoy_hashes:
                    logger.warning("decoy bearer token detected for alias %r", alias)
                    shard_a[:] = b"\x00" * len(shard_a)
                    return _uniform_401()
            except Exception:  # noqa: BLE001,S110  # nosec B110 — best-effort, IPC errors must not block requests
                pass

        # Pre-read body ONCE before rules engine (WOR-182: eliminates
        # Starlette body-caching coupling — rules receive bytes, not stream)
        body = await request.body()

        # WOR-696 T7: request model for the response-model mismatch audit.
        # Shares the same helper the rules engine uses for hold bookkeeping
        # (single source of truth for "best-effort model from body bytes").
        _request_model = extract_model(body)

        # Token-budget reservation amount (WOR-242). The spend CAP no longer uses
        # this — its reservation is the durable ledger hold below.
        _spend_reservation = _estimate_tokens(body)

        # GATE: rules engine evaluates BEFORE any Fernet decrypt
        gate = await rules_engine.evaluate(alias, request, provider=encrypted.provider, body=body)
        spend_handle = gate.spend_handle

        async def _release_reservations() -> None:
            """Failure / denial exit: drop the durable spend hold (if any) + the
            in-memory token-budget reservation. Single seam for every exit path."""
            await rules_engine.refund_spend(spend_handle)
            await rules_engine.release_spend_reservation(alias, amount=_spend_reservation)

        if gate.denial is not None:
            # Zero shard_a before returning (SR-01/SR-02). The engine already
            # refunded any spend hold on denial; this also drops the token budget.
            shard_a[:] = b"\x00" * len(shard_a)
            await _release_reservations()
            return Response(
                content=gate.denial.body,
                status_code=gate.denial.status_code,
                headers=gate.denial.headers,
                media_type="application/json",
            )

        # Get adapter (uniform 401, not 404, for anti-enumeration)
        adapter = get_adapter(clean_path)
        if adapter is None:
            shard_a[:] = b"\x00" * len(shard_a)
            await _release_reservations()
            return _uniform_401()

        # Decrypt now that the gate has passed — over IPC to the sidecar.
        # No in-process Fernet (WOR-309). Transport failure → 503.
        plaintext_shard_b: bytearray | None = None
        try:
            plaintext_shard_b = await ipc.open(encrypted.shard_b_enc, key_id=alias)
        except IPCUnavailable:
            shard_a[:] = b"\x00" * len(shard_a)
            await _release_reservations()
            return _make_gateway_response(503, "sidecar unavailable")
        except Exception:
            shard_a[:] = b"\x00" * len(shard_a)
            await _release_reservations()
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
            await _release_reservations()
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
                    await _release_reservations()
                    return _make_gateway_response(504, "gateway timeout")
                except httpx.ConnectError:
                    await _release_reservations()
                    return _make_gateway_response(502, "bad gateway")
                except httpx.HTTPError:
                    await _release_reservations()
                    return _make_gateway_response(502, "bad gateway")

            # Relay response (key_buf is zeroed after secure_key exits)
            adapter_resp = await adapter.relay_response(upstream_resp)

            clean_headers = _strip_worthless_headers(adapter_resp.headers)
            provider = encrypted.provider

            async def _do_record_spend(data: bytes, *, provider_succeeded: bool = True):
                """Settle / record spend after the upstream call.

                * If the provider reported usage, honour it (provider DID bill input
                  tokens even on a 4xx error response).
                * If usage is absent and provider FAILED (>= 400): refund the hold
                  (capped) / skip (uncapped) — the provider rejected the call.
                * If usage is absent and provider SUCCEEDED (200 but parse failure /
                  mid-stream disconnect): settle at estimate (capped) so the cap is
                  billed immediately — closes the cost-griefing window where the
                  sweeper TTL would otherwise let an attacker pay only estimate via
                  many aborted streams. For uncapped: warn-only, no phantom spend.
                """
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
                    # not an auth token.
                    logger.warning(
                        "Usage extraction failed for alias=%s provider=%s",
                        alias,
                        provider,
                    )
                if spend_handle is not None:
                    if usage is not None:
                        # Bill at provider-reported actual; on failure fall back to
                        # admission estimate so the cap is still updated promptly.
                        try:
                            await rules_engine.settle_spend(spend_handle, tokens)
                        except Exception:
                            logger.warning(
                                "settle failed for alias=%s; falling back to estimate",
                                alias,
                            )
                            try:
                                await rules_engine.settle_spend_at_estimate(spend_handle)
                            except Exception:
                                logger.warning(
                                    "settle_at_estimate also failed for alias=%s; "
                                    "sweeper is the last backstop",
                                    alias,
                                )
                    elif provider_succeeded:
                        # Success but unreadable usage (stream disconnect / parse fail):
                        # bill at admission estimate immediately (closes cost-griefing).
                        try:
                            await rules_engine.settle_spend_at_estimate(spend_handle)
                        except Exception:
                            logger.warning(
                                "settle_at_estimate failed for alias=%s; "
                                "sweeper is the last backstop",
                                alias,
                            )
                    else:
                        # Upstream error (4xx/5xx) with no usage: refund — the user
                        # must NOT pay for a request the provider rejected. A refund
                        # failure must retry refund, never fall through to billing.
                        try:
                            await rules_engine.refund_spend(spend_handle)
                        except Exception:
                            logger.warning(
                                "refund failed for alias=%s on upstream error; "
                                "retrying refund, never billing",
                                alias,
                            )
                            try:
                                await rules_engine.refund_spend(spend_handle)
                            except Exception:
                                logger.warning(
                                    "refund retry also failed for alias=%s; sweeper "
                                    "will bill at estimate (worst-case soft-overcharge)",
                                    alias,
                                )
                elif usage is not None or not provider_succeeded:
                    # Uncapped: record actual usage when present; on error paths with
                    # no usage, still record(0) as an audit trail of the failed call.
                    try:
                        await record_spend(settings.db_path, alias, tokens, model, provider)
                    except Exception:
                        logger.warning("Failed to record spend for alias=%s", alias)
                # Else: uncapped + success + no usage → warn-only, no phantom spend.
                # Release the in-memory token-budget reservation (WOR-242).
                await rules_engine.release_spend_reservation(alias, amount=_spend_reservation)

            if adapter_resp.status_code >= 400:
                sanitized_body = _sanitize_upstream_error(
                    adapter_resp.status_code, adapter_resp.body, provider
                )
                return Response(
                    content=sanitized_body,
                    status_code=adapter_resp.status_code,
                    headers={"content-type": "application/json"},
                    media_type="application/json",
                    background=BackgroundTask(
                        _do_record_spend, adapter_resp.body, provider_succeeded=False
                    ),
                )

            if adapter_resp.is_streaming and adapter_resp.stream is not None:
                usage_collector = StreamingUsageCollector(provider=encrypted.provider)
                # WOR-696: stream wall-clock + idle-chunk kills. Tests may pin
                # tight values via app.state; production reads from settings.
                # time.monotonic() — NOT wall clock — so system clock skew on a
                # long stream doesn't falsely fire or skip the cap.
                _max_stream_duration = float(
                    getattr(
                        app.state,
                        "max_stream_duration_seconds",
                        settings.max_stream_duration_seconds,
                    )
                )
                _max_idle_between_chunks = float(
                    getattr(
                        app.state,
                        "max_idle_between_chunks_seconds",
                        settings.max_idle_between_chunks_seconds,
                    )
                )

                async def _stream_with_metering() -> AsyncIterator[bytes]:
                    start = time.monotonic()
                    stream_iter = adapter_resp.stream.__aiter__()  # type: ignore[union-attr]
                    # WOR-696 T7: response.model can only be observed once per
                    # stream (it doesn't change mid-stream). Skip the per-chunk
                    # audit after the first observation — saves ~9999 JSON
                    # parses on a 10k-chunk stream.
                    audit_done = False
                    try:
                        while True:
                            kill_reason: tuple[str, float] | None = None
                            if time.monotonic() - start > _max_stream_duration:
                                kill_reason = (
                                    "max_stream_duration_seconds",
                                    _max_stream_duration,
                                )
                            else:
                                try:
                                    chunk = await asyncio.wait_for(
                                        stream_iter.__anext__(),
                                        timeout=_max_idle_between_chunks,
                                    )
                                except StopAsyncIteration:
                                    break
                                except asyncio.TimeoutError:
                                    kill_reason = (
                                        "max_idle_between_chunks_seconds",
                                        _max_idle_between_chunks,
                                    )
                            if kill_reason is not None:
                                logger.warning(
                                    "WOR-696: stream killed at %s=%s for "
                                    "alias=%s; settling at ceiling",
                                    *kill_reason,
                                    alias,
                                )
                                break
                            usage_collector.feed(chunk)
                            if not audit_done:
                                # extract_response_model() and the dict
                                # mutation below both swallow internally; the
                                # outer try is a final stream-boundary guard.
                                try:
                                    response_model = extract_response_model(chunk)
                                    if response_model is not None:
                                        audit_done = True
                                        if _request_model and response_model != _request_model:
                                            # Bounded counter (worthless-cchq):
                                            # hostile upstream can't OOM by
                                            # flooding unique model pairs.
                                            bounded_increment(
                                                app.state.response_model_mismatch_counter,
                                                (_request_model, response_model),
                                            )
                                except Exception:
                                    logger.debug(
                                        "WOR-696: response-model audit failed",
                                        exc_info=True,
                                    )
                            yield chunk
                    finally:
                        # On any exit (disconnect / end / kill), close upstream.
                        # settle_at_estimate then runs in the BackgroundTask and
                        # floors at GLOBAL_CEILING_TOKENS when usage is unreadable.
                        await upstream_resp.aclose()  # type: ignore[union-attr]

                async def _record_metering():
                    usage = usage_collector.result()
                    if spend_handle is not None:
                        # Capped: settle hold to actual, or to estimate if usage is
                        # unreadable (mid-stream client disconnect, SSE format change).
                        # Settling at estimate IMMEDIATELY closes the cost-griefing
                        # window where an attacker aborts streams to pay only estimate
                        # via the sweeper TTL backstop.
                        try:
                            if usage is not None:
                                await rules_engine.settle_spend(spend_handle, usage.total_tokens)
                            else:
                                logger.warning(
                                    "Could not extract usage from streaming response "
                                    "for alias=%s; settling at estimate",
                                    alias,
                                )
                                await rules_engine.settle_spend_at_estimate(spend_handle)
                        except Exception:
                            logger.warning(
                                "settle failed for alias=%s; falling back to estimate", alias
                            )
                            try:
                                await rules_engine.settle_spend_at_estimate(spend_handle)
                            except Exception:
                                logger.warning(
                                    "settle_at_estimate also failed for alias=%s; "
                                    "sweeper is the last backstop",
                                    alias,
                                )
                    elif usage is not None:
                        try:
                            await record_spend(
                                settings.db_path,
                                alias,
                                usage.total_tokens,
                                usage.model,
                                encrypted.provider,
                            )
                        except Exception:
                            logger.warning("Failed to record spend for alias=%s", alias)
                    else:
                        # Uncapped + no usage: zero friction, don't penalise the user
                        # with phantom spend (the cap mechanism isn't engaged here).
                        logger.warning(
                            "Could not extract usage from streaming response "
                            "for alias=%s; spend not recorded",
                            alias,
                        )
                    # Release the in-memory token-budget reservation (WOR-242).
                    await rules_engine.release_spend_reservation(alias, amount=_spend_reservation)

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

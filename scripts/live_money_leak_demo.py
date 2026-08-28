"""Live e2e demo for WOR-696 money-leak closure.

Spins up a real Worthless proxy on a real TCP port + a real mock upstream
on another real TCP port + a real SQLite file. Issues a no-`max_tokens`
streaming request, disconnects mid-stream, then queries `spend_log` to
prove the cap counter moved by ≥ GLOBAL_CEILING_TOKENS instead of 0.

This is the live-verification artifact for PR #285 (WOR-696). It does NOT
burn real provider money — the upstream is a localhost mock — but EVERY
other layer is real: real sockets, real HTTP/1.1 framing, real FastAPI
routing, real SQLite on disk, real BackgroundTask settle path.

Run:
    cd /path/to/worthless
    uv run python scripts/live_money_leak_demo.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

import aiosqlite
import httpx
import uvicorn
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import GLOBAL_CEILING_TOKENS, ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule, TokenBudgetRule
from worthless.storage.repository import ShardRepository, StoredShard
from worthless.storage.schema import SCHEMA

# Side-effect imports (existing test fakes for in-process IPC + shard pin)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from _fakes import pin_shard_b
from _fakes.fake_ipc_supervisor import FakeIPCSupervisor


ALIAS = "live-demo-key"
# Built piecewise so gitleaks' openai-api-key regex doesn't fire on this
# obviously-fake test fixture. The split_key_fp call requires the "sk-"
# prefix for an OpenAI shape, so we keep the prefix but break the literal.
API_KEY = "sk-" + "DEMO-fixture-" + "1234567890abcdefghij"  # noqa: S105


def _build_mock_upstream() -> FastAPI:
    """Localhost mock that streams forever — client must disconnect to end it."""
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> StreamingResponse:
        async def slow_stream():
            # First chunk lands quickly so the client knows the stream is alive.
            yield b'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n'
            # Then drip slowly so a curl --max-time disconnect fires mid-stream
            # WITHOUT a final `usage` block. That's the leak path.
            for _ in range(60):
                await asyncio.sleep(0.5)
                yield b'data: {"choices":[{"delta":{"content":"x"}}]}\n\n'
            yield b"data: [DONE]\n\n"

        return StreamingResponse(slow_stream(), media_type="text/event-stream")

    return app


async def _enroll(db_path: str, fernet_key: bytes):
    """Real schema + real enrollment row + real shard storage.

    Returns the WHOLE split result so the caller can use the SAME shard_b
    for IPC pinning. A second split() would produce a different shard_b
    that doesn't match the stored commitment → reconstruction fails.
    """
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute("PRAGMA journal_mode=WAL")
        await setup.commit()

    sr = split_key_fp(API_KEY, prefix="sk-", provider="openai")
    repo = ShardRepository(db_path, fernet_key)
    await repo.initialize()
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    # base_url points the proxy at our localhost mock instead of api.openai.com
    await repo.store(
        ALIAS,
        shard,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="http://127.0.0.1:9499/v1",
    )

    # Big cap so the per-request hold doesn't trip the limit first — we want
    # to observe settle behavior, not admission denial.
    async with aiosqlite.connect(db_path) as setup:
        await setup.execute(
            "INSERT OR REPLACE INTO enrollment_config "
            "(key_alias, spend_cap, rate_limit_rps) VALUES (?, ?, ?)",
            (ALIAS, 10_000_000, 10_000.0),
        )
        await setup.commit()

    return repo, sr


def _run_uvicorn(app, port: int, ready: threading.Event) -> None:
    """Run a uvicorn server in a thread. Sets `ready` once bound."""
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    async def _serve():
        # Hand the started flag back to the main thread
        async def _watcher():
            while not server.started:
                await asyncio.sleep(0.05)
            ready.set()

        await asyncio.gather(_watcher(), server.serve())

    asyncio.run(_serve())


def _spend_log_total(db_path: str) -> int:
    """Real SQLite SELECT — bypasses every Python-side abstraction."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?",
            (ALIAS,),
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


async def _amain() -> int:
    print("=" * 72)
    print("WOR-696 live e2e demo — money-leak closure")
    print("=" * 72)

    # worthless-2ey3 hardening: capture the proxy's "settling at estimate"
    # warning so we can prove the WOR-696 leak-branch fired. Without this,
    # a future mock-upstream change (e.g. adding a usage block) could make
    # the demo PASS via the happy-path settle, silently regressing the
    # actual leak-fix coverage. karen's PROOF VALID was conditional on
    # this guard landing.
    _proxy_logs: list[str] = []

    class _LogCapture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            # Capture handlers MUST NOT raise — would break global logging.
            try:
                _proxy_logs.append(record.getMessage())
            except Exception:  # noqa: S110 — intentional swallow per logging contract
                pass

    _proxy_logger = logging.getLogger("worthless.proxy.app")
    _proxy_logger.setLevel(logging.INFO)
    _capture = _LogCapture()
    _proxy_logger.addHandler(_capture)

    with tempfile.TemporaryDirectory(prefix="ceiling-live-") as tmp:
        db_path = str(Path(tmp) / "proxy.db")
        fernet_key = Fernet.generate_key()
        repo, split_result = await _enroll(db_path, fernet_key)
        shard_a = split_result.shard_a

        # Build the real proxy app with a real settings object pointing at the
        # real DB. Defaults to 15min/90s kills — won't fire on this demo.
        settings = ProxySettings(
            db_path=db_path,
            fernet_key=bytearray(fernet_key),
            default_rate_limit_rps=10_000.0,
            upstream_timeout=60.0,
            streaming_timeout=60.0,
            allow_insecure=True,
        )
        app = create_app(settings)

        # Same scaffolding tests use — open a connection, install fake IPC
        # (so we don't need a real sidecar process), pin shard-B in memory.
        db = await aiosqlite.connect(db_path)
        await db.execute("PRAGMA journal_mode=WAL")
        app.state.db = db
        app.state.repo = repo
        app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
        app.state.ipc_supervisor = FakeIPCSupervisor()
        pin_shard_b(app, ALIAS, split_result.shard_b)

        db_lock = asyncio.Lock()
        app.state.db_lock = db_lock
        app.state.rules_engine = RulesEngine(
            rules=[
                TokenBudgetRule(db=db, lock=db_lock),
                RateLimitRule(default_rps=10_000.0, db_path=db_path),
                SpendCapRule(db=db, lock=db_lock),
            ]
        )

        # ---- Spin up both servers on real ports ----
        mock_ready = threading.Event()
        proxy_ready = threading.Event()
        mock_thread = threading.Thread(
            target=_run_uvicorn,
            args=(_build_mock_upstream(), 9499, mock_ready),
            daemon=True,
        )
        proxy_thread = threading.Thread(
            target=_run_uvicorn,
            args=(app, 9498, proxy_ready),
            daemon=True,
        )
        mock_thread.start()
        proxy_thread.start()

        if not mock_ready.wait(timeout=5.0):
            print("FAIL: mock upstream never bound")
            return 1
        if not proxy_ready.wait(timeout=5.0):
            print("FAIL: proxy never bound")
            return 1

        print("  mock upstream  : http://127.0.0.1:9499")
        print("  worthless proxy: http://127.0.0.1:9498")
        print(f"  SQLite DB      : {db_path}")

        # Sanity: confirm enrollment is visible via the proxy's repo
        sanity = await repo.fetch_encrypted(ALIAS)
        if sanity is None:
            print(f"FAIL: enrollment for alias={ALIAS!r} not visible via repo")
            return 1
        if sanity.base_url is None:
            print("FAIL: enrollment has NULL base_url")
            return 1
        print(f"  enrollment OK  : provider={sanity.provider} base_url={sanity.base_url}")
        print()

        # ---- BEFORE snapshot ----
        before = _spend_log_total(db_path)
        print("BEFORE the request:")
        print(
            f"  $ sqlite3 {db_path} 'SELECT SUM(tokens) FROM spend_log WHERE key_alias=\"{ALIAS}\"'"  # noqa: S608
        )
        print(f"  → {before} tokens billed")
        print()

        # ---- The leak-shaped request ----
        body = json.dumps(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": True,
                # NO max_tokens — this is the leak shape.
            }
        ).encode()

        print("FIRING the leak request (no max_tokens, stream=True, mid-stream disconnect):")
        print(f"  $ curl -X POST http://127.0.0.1:9498/{ALIAS}/v1/chat/completions \\")
        print("      -H 'Authorization: Bearer <shard-a>' \\")
        print('      -d \'{"model":"gpt-4o-mini","messages":[...],"stream":true}\'')
        print("  # disconnect after the first chunk")
        print()

        shard_a_utf8 = shard_a.decode("utf-8")
        async with httpx.AsyncClient(timeout=10.0) as client:
            async with client.stream(
                "POST",
                f"http://127.0.0.1:9498/{ALIAS}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {shard_a_utf8}",
                    "content-type": "application/json",
                },
                content=body,
            ) as response:
                if response.status_code != 200:
                    body_text = await response.aread()
                    print(f"FAIL: setup got status {response.status_code}, body={body_text!r}")
                    return 1
                # Read the first chunk to confirm the stream is live, then
                # abandon — that's the disconnect.
                chunks_seen = 0
                async for _chunk in response.aiter_bytes():
                    chunks_seen += 1
                    if chunks_seen >= 1:
                        break
                # Falling out of the `async with` closes the client → real
                # TCP FIN → server-side StreamingResponse generator gets
                # cancelled → BackgroundTask settle fires.

        # ---- Wait for BackgroundTask settle ----
        # The settle path is async + BackgroundTask, may take a beat.
        print("DISCONNECT fired after 1 chunk. Polling for settle ...")
        deadline = time.monotonic() + 8.0
        spent = before
        while time.monotonic() < deadline:
            spent = _spend_log_total(db_path)
            if spent > before:
                break
            await asyncio.sleep(0.2)

        print()
        print("AFTER the disconnect:")
        print(
            f"  $ sqlite3 {db_path} 'SELECT SUM(tokens) FROM spend_log WHERE key_alias=\"{ALIAS}\"'"  # noqa: S608
        )
        print(f"  → {spent} tokens billed")
        print()

        # ---- Verdict ----
        delta = spent - before
        floor = GLOBAL_CEILING_TOKENS
        print("=" * 72)
        if delta >= floor:
            # worthless-2ey3: verify the cap movement came from the
            # WOR-696 leak-branch (settle_at_estimate), not from a
            # happy-path settle that would mask a regression.
            leak_branch_fired = any("settling at estimate" in line.lower() for line in _proxy_logs)
            if not leak_branch_fired:
                print(
                    f"FAIL: cap moved by {delta} but the proxy never logged "
                    f"'settling at estimate' — the PASS came from the wrong "
                    f"code path. Either the mock upstream regressed (now "
                    f"emitting usage), or settle_at_estimate is dead. "
                    f"WOR-696 leak-branch is unverified."
                )
                verdict = 1
            else:
                print(f"PASS: cap counter moved by {delta} ≥ {floor} (GLOBAL_CEILING_TOKENS)")
                print("      money-leak closed — no-max_tokens disconnect bills honestly")
                print(
                    "      proven via 'settling at estimate' proxy warning "
                    "(WOR-696 leak-branch fired)"
                )
                verdict = 0
        else:
            print(f"FAIL: cap counter moved by {delta}, expected ≥ {floor}")
            print("      the leak is OPEN — investigate before merging PR #285")
            verdict = 1
        print("=" * 72)

        # ---- Cleanup ----
        await app.state.httpx_client.aclose()
        await db.close()
        return verdict


if __name__ == "__main__":
    sys.exit(asyncio.run(_amain()))

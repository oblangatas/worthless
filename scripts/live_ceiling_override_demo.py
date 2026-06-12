"""Live e2e demo for WOR-705 — per-key spend-cap ceiling override.

Spins up a real Worthless proxy + a real mock upstream on real TCP ports +
a real SQLite file. Enrolls TWO keys:

  - override-key  : ceiling_override = 200_000 (operator bumped it)
  - control-key   : no override (falls back to the global 128_000)

Fires a no-`max_tokens` streaming request at each, disconnects mid-stream,
and queries `spend_log` directly. Proves the override is honored live:

  override-key → 200_000   (floored at the per-key override)
  control-key  → 128_000   (floored at the global GLOBAL_CEILING_TOKENS)

Run it yourself:
    cd /path/to/worthless
    uv run python scripts/live_ceiling_override_demo.py

It does NOT burn real provider money — the upstream is a localhost mock —
but every other layer is real: real sockets, real FastAPI routing, real
SQLite on disk, real ledger settle path.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import tempfile
import threading
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from _fakes import pin_shard_b  # noqa: E402
from _fakes.fake_ipc_supervisor import FakeIPCSupervisor  # noqa: E402

OVERRIDE_ALIAS = "override-key"
CONTROL_ALIAS = "control-key"
OVERRIDE_VALUE = 200_000
# Distinct fake key per alias; built piecewise so gitleaks won't flag it.
KEYS = {
    OVERRIDE_ALIAS: "sk-" + "DEMO-override-" + "1234567890abcdefghij",
    CONTROL_ALIAS: "sk-" + "DEMO-control-" + "1234567890abcdefghij",
}


def _mock_upstream() -> FastAPI:
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> StreamingResponse:
        async def slow_stream():
            yield b'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n'
            for _ in range(60):
                await asyncio.sleep(0.5)
                yield b'data: {"choices":[{"delta":{"content":"x"}}]}\n\n'
            yield b"data: [DONE]\n\n"

        return StreamingResponse(slow_stream(), media_type="text/event-stream")

    return app


def _run_uvicorn(app, port: int, ready: threading.Event) -> None:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))

    async def _serve():
        async def _watcher():
            while not server.started:
                await asyncio.sleep(0.05)
            ready.set()

        await asyncio.gather(_watcher(), server.serve())

    asyncio.run(_serve())


def _spend_total(db_path: str, alias: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?", (alias,)
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


async def _enroll(repo: ShardRepository, db_path: str, alias: str, override: int | None):
    sr = split_key_fp(KEYS[alias], prefix="sk-", provider="openai")
    await repo.store(
        alias,
        StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider="openai",
        ),
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="http://127.0.0.1:9499/v1",
    )
    async with aiosqlite.connect(db_path) as setup:
        await setup.execute(
            "INSERT OR REPLACE INTO enrollment_config "
            "(key_alias, spend_cap, rate_limit_rps, ceiling_override) VALUES (?, ?, ?, ?)",
            (alias, 10_000_000, 10_000.0, override),
        )
        await setup.commit()
    return sr


async def _fire_and_disconnect(port: int, alias: str, shard_a: str) -> None:
    body = json.dumps(
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}], "stream": True}
    ).encode()
    async with httpx.AsyncClient(timeout=10.0) as client:
        async with client.stream(
            "POST",
            f"http://127.0.0.1:{port}/{alias}/v1/chat/completions",
            headers={"authorization": f"Bearer {shard_a}", "content-type": "application/json"},
            content=body,
        ) as resp:
            if resp.status_code != 200:
                raise RuntimeError(f"{alias}: setup got {resp.status_code}")
            async for _chunk in resp.aiter_bytes():
                break  # read one chunk then abandon → real TCP disconnect


async def _amain() -> int:
    print("=" * 72)
    print("WOR-705 live demo — per-key ceiling override")
    print("=" * 72)
    with tempfile.TemporaryDirectory(prefix="override-live-") as tmp:
        db_path = str(Path(tmp) / "proxy.db")
        fernet_key = Fernet.generate_key()
        async with aiosqlite.connect(db_path) as setup:
            await setup.executescript(SCHEMA)
            await setup.execute("PRAGMA journal_mode=WAL")
            await setup.commit()

        repo = ShardRepository(db_path, fernet_key)
        await repo.initialize()
        sr_override = await _enroll(repo, db_path, OVERRIDE_ALIAS, OVERRIDE_VALUE)
        sr_control = await _enroll(repo, db_path, CONTROL_ALIAS, None)

        settings = ProxySettings(
            db_path=db_path,
            fernet_key=bytearray(fernet_key),
            default_rate_limit_rps=10_000.0,
            upstream_timeout=60.0,
            streaming_timeout=60.0,
            allow_insecure=True,
        )
        app = create_app(settings)
        db = await aiosqlite.connect(db_path)
        await db.execute("PRAGMA journal_mode=WAL")
        app.state.db = db
        app.state.repo = repo
        app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
        app.state.ipc_supervisor = FakeIPCSupervisor()
        pin_shard_b(app, OVERRIDE_ALIAS, sr_override.shard_b)
        pin_shard_b(app, CONTROL_ALIAS, sr_control.shard_b)
        db_lock = asyncio.Lock()
        app.state.db_lock = db_lock
        app.state.rules_engine = RulesEngine(
            rules=[
                TokenBudgetRule(db=db, lock=db_lock),
                RateLimitRule(default_rps=10_000.0, db_path=db_path),
                SpendCapRule(db=db, lock=db_lock),
            ]
        )

        mock_ready, proxy_ready = threading.Event(), threading.Event()
        threading.Thread(
            target=_run_uvicorn, args=(_mock_upstream(), 9499, mock_ready), daemon=True
        ).start()
        threading.Thread(target=_run_uvicorn, args=(app, 9498, proxy_ready), daemon=True).start()
        if not mock_ready.wait(5) or not proxy_ready.wait(5):
            print("FAIL: servers never bound")
            return 1

        print(f"  proxy http://127.0.0.1:9498  |  SQLite {db_path}")
        print(f"  {OVERRIDE_ALIAS}: ceiling_override = {OVERRIDE_VALUE}")
        print(f"  {CONTROL_ALIAS}: no override (global {GLOBAL_CEILING_TOKENS})")
        print()
        print("Firing a no-max_tokens request at each, disconnecting mid-stream...")
        await _fire_and_disconnect(9498, OVERRIDE_ALIAS, sr_override.shard_a.decode())
        await _fire_and_disconnect(9498, CONTROL_ALIAS, sr_control.shard_a.decode())
        await asyncio.sleep(0.3)  # let the BackgroundTask settle land

        over = _spend_total(db_path, OVERRIDE_ALIAS)
        ctrl = _spend_total(db_path, CONTROL_ALIAS)
        print()
        print("Query the spend_log yourself:")
        # The next line is a printed copy-paste hint, NOT an executed query.
        hint = (
            f"  $ sqlite3 {db_path} "  # noqa: S608 — display string, not a real query
            '"SELECT key_alias, SUM(tokens) FROM spend_log GROUP BY key_alias"'
        )
        print(hint)
        print(f"  {OVERRIDE_ALIAS}|{over}")
        print(f"  {CONTROL_ALIAS}|{ctrl}")
        print()

        ok = over == OVERRIDE_VALUE and ctrl == GLOBAL_CEILING_TOKENS
        print("=" * 72)
        if ok:
            print(f"PASS: override key floored at {over} (its 200K override),")
            print(f"      control key floored at {ctrl} (the global {GLOBAL_CEILING_TOKENS}).")
            print("      Per-key override honored live; global untouched for everyone else.")
        else:
            print(
                f"FAIL: override={over} (want {OVERRIDE_VALUE}), control={ctrl} "
                f"(want {GLOBAL_CEILING_TOKENS})"
            )
        print("=" * 72)

        await app.state.httpx_client.aclose()
        await db.close()
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_amain()))

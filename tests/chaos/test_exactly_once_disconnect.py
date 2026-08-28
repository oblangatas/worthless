"""Chaos test — row-check no-op after consumed hold (WOR-695).

> Make sure the spend cap actually holds on every request — so once the budget's
> blown, the key stops forming, no matter who's spending or why.

**Scope (honest):** this test guards the ROW-CHECK inside `settle_at_estimate`
ONLY. It does NOT exercise the asyncio.Lock or the `BEGIN IMMEDIATE` transaction
under contention. The reason: `httpx.ASGITransport` does not expose an in-flight
window — by the time `client.post()` returns, the BackgroundTask has already run
its settle. We tried `client.stream()`; the same race-skip pattern fired on
100/100 iterations. So the forced double-fire here happens AFTER the BG task
already drained the hold, which means the test exercises:

   "second `settle_at_estimate` against a hold that's already been consumed
    by the BG task returns a no-op without inserting a duplicate spend_log row."

That's the row-check guard (the third of the three guards the cap depends on).
It is NOT a guard for the lock or BEGIN IMMEDIATE — those are exercised by the
sibling test in `tests/chaos/test_ledger_lock_contention.py`, which fires
`asyncio.gather(settle, settle)` directly against an active hold at the
SpendLedger layer, where contention is observable.

**What this proves:** if a future refactor breaks the row-check (e.g. removes
the `if row is None: return` short-circuit inside the BEGIN IMMEDIATE
transaction), this test goes red.

**What this does NOT prove:** if a future refactor removes the asyncio.Lock
or downgrades `BEGIN IMMEDIATE` to a deferred transaction, this test stays
green. That's `test_ledger_lock_contention.py`'s job.

**Why this still ships:** the row-check is the cheapest of the three guards
and the most likely to drift in a refactor (the lock and BEGIN IMMEDIATE are
attention-grabbing; the row-check is a tiny conditional). It's worth a
regression guard.

How this works:

* boots the real proxy app against a real SQLite tempfile,
* enrolls a real (mocked-upstream) key,
* spies on `SpendLedger.hold` at the CLASS level to capture handles as they
  issue (ASGITransport hides the in-flight pending_charges window, so spying
  is the only honest way),
* fires N=100 streaming requests; after each, fires two concurrent
  `settle_at_estimate(handle)` calls AGAINST AN ALREADY-CONSUMED hold,
* asserts via raw SQL: spend_log row-count moved by exactly 1, total tokens
  moved by exactly one settle's worth, hold's pending_charges row is gone,
* `race_skipped < N // 2` keeps the green honest — if the spy ever fails to
  capture handles, the test fails loudly (no silent false-positive).

Out of scope (do NOT add here):
* lock + BEGIN IMMEDIATE contention — `test_ledger_lock_contention.py`
* per-(provider, model) ceiling table — WOR-696
* max-stream-duration / idle-timeout kills — WOR-696
* divergence telemetry — WOR-697
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import aiosqlite
import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import (
    RateLimitRule,
    RulesEngine,
    SpendCapRule,
    TokenBudgetRule,
)
from worthless.storage.repository import ShardRepository, StoredShard
from worthless.storage.schema import SCHEMA
from worthless.storage.spend_ledger import SpendLedger

from tests._fakes import pin_shard_b
from tests._fakes.fake_ipc_supervisor import FakeIPCSupervisor


# How many iterations of the disconnect+double-fire race to run.
# Per panel: race is per-request, not per-process — one app boot is enough.
# 100 iterations is the floor for "this isn't a one-time fluke."
N_ITERATIONS = 100

# Exact tokens the BG task's settle should write per iteration. Pinned to
# the `total_tokens` value in the SSE usage chunk below — invariant 2
# asserts exact equality so a double-count bug is caught.
EXPECTED_SETTLE_TOKENS = 15

ALIAS = "chaos-key"
API_KEY = "sk-CHAOS-1234567890abcdefghij"
OPENAI_COMPLETIONS = "https://api.openai.com/v1/chat/completions"


def _sse_chunks() -> list[bytes]:
    """A minimal OpenAI-shaped SSE stream the proxy will forward chunk-by-chunk."""
    return [
        b'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n',
        b'data: {"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n\n',
        b"data: [DONE]\n\n",
    ]


async def _setup_app(db_path: str) -> tuple:
    """Build the real proxy app, enrolment, and DB connection.

    Returns: (app, db, repo, rules_engine, shard_a_utf8).
    """
    # Schema + WAL.
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute("PRAGMA journal_mode=WAL")
        # PRAGMA tuning per sql-pro panel — keeps -wal from ballooning over
        # N iterations and masking lock contention as IO stalls.
        await setup.execute("PRAGMA journal_size_limit=1048576")
        await setup.execute("PRAGMA wal_autocheckpoint=50")
        await setup.execute("PRAGMA busy_timeout=5000")
        await setup.commit()

    # Real split key + repo with real Fernet.
    sr = split_key_fp(API_KEY, prefix="sk-", provider="openai")
    fernet_key = Fernet.generate_key()
    repo = ShardRepository(db_path, fernet_key)
    await repo.initialize()
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.store(
        ALIAS,
        shard,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url="https://api.openai.com/v1",
    )

    # Cap high enough that no iteration is blocked by it — we want every request
    # to reach settle, not bounce at the gate.
    async with aiosqlite.connect(db_path) as setup:
        await setup.execute(
            "INSERT OR REPLACE INTO enrollment_config "
            "(key_alias, spend_cap, rate_limit_rps) VALUES (?, ?, ?)",
            (ALIAS, 10_000_000, 10_000.0),
        )
        await setup.commit()

    # Build the app with the real rules engine + shared db_lock (T4 invariant).
    settings = ProxySettings(
        db_path=db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=10_000.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
    )
    app = create_app(settings)
    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.ipc_supervisor = FakeIPCSupervisor()
    pin_shard_b(app, ALIAS, sr.shard_b)

    db_lock = asyncio.Lock()
    app.state.db_lock = db_lock
    rules_engine = RulesEngine(
        rules=[
            TokenBudgetRule(db=db, lock=db_lock),
            RateLimitRule(default_rps=settings.default_rate_limit_rps, db_path=db_path),
            SpendCapRule(db=db, lock=db_lock),
        ]
    )
    app.state.rules_engine = rules_engine

    return app, db, repo, rules_engine, sr.shard_a.decode("utf-8")


async def _snapshot(db_path: str, handle: str | None) -> tuple[int, int, int, set[str]]:
    """Return (spend_log_row_count, total_tokens, pending_for_handle, all_pending).

    `spend_log` has no `handle` column in the current schema (sql-pro panel
    finding — adding it is deferred defense-in-depth, tracked separately).
    So we prove exactly-once via row-count delta + tokens delta + per-handle
    pending check. The tokens delta is what catches a "double-counted into one
    row" bug that row-count alone would miss.
    """
    async with aiosqlite.connect(db_path) as audit:
        async with audit.execute("SELECT COUNT(*), COALESCE(SUM(tokens), 0) FROM spend_log") as cur:
            row = await cur.fetchone()
            assert row is not None
            log_rows, total_tokens = int(row[0]), int(row[1])
        if handle is not None:
            async with audit.execute(
                "SELECT COUNT(*) FROM pending_charges WHERE handle=?", (handle,)
            ) as cur:
                row = await cur.fetchone()
                assert row is not None
                pending_for_handle = int(row[0])
        else:
            pending_for_handle = 0
        async with audit.execute("SELECT handle FROM pending_charges") as cur:
            all_pending = {r[0] for r in await cur.fetchall()}
    return log_rows, total_tokens, pending_for_handle, all_pending


@pytest.mark.asyncio
async def test_row_check_blocks_settle_after_consumed_hold() -> None:
    """N≥100 requests; after each, force two more settles vs the consumed hold.

    Invariants after every iteration:
    - exactly one new spend_log row (BG task's settle wins; forced settles no-op)
    - zero pending_charges rows for the handle (BG task drained it)
    - tokens delta > 0 (settle did move the counter at least once)

    If the row-check inside settle_at_estimate's BEGIN IMMEDIATE ever stops
    short-circuiting on an already-consumed hold, this test goes red.

    Does NOT guard the asyncio.Lock or BEGIN IMMEDIATE itself — see
    `test_ledger_lock_contention.py` for those invariants.
    """
    # TemporaryDirectory auto-cleans on context exit — avoids tmpdir leak
    # if the test fails partway through (post-code panel finding).
    with tempfile.TemporaryDirectory(prefix="chaos-exactly-once-") as tmp:
        db_path = str(Path(tmp) / "proxy.db")

        app, db, _repo, rules_engine, shard_a_utf8 = await _setup_app(db_path)
        transport = httpx.ASGITransport(app=app)

        body = json.dumps(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 50,
                "stream": True,
            }
        ).encode()

        # Count iterations where we couldn't spy out a handle. (Should be
        # zero — the spy captures on every successful hold.)
        race_skipped = 0

        # Spy on SpendLedger.hold so we capture every issued handle as the
        # request is admitted. ASGITransport doesn't expose the in-flight
        # window before the BG task settles, so spying is the only honest
        # way to know what handle to race a forced double-fire against.
        # Post-code panel: the original test relied on a window that doesn't
        # exist under ASGITransport — 100% of iterations missed the race.
        # SpendLedger uses __slots__, so patch at the CLASS level and
        # restore in finally.
        issued_handles: list[str] = []
        original_hold = SpendLedger.hold

        async def _spying_hold(self, *args, **kwargs):
            handle = await original_hold(self, *args, **kwargs)
            issued_handles.append(handle)
            return handle

        SpendLedger.hold = _spying_hold  # type: ignore[method-assign]

        try:
            with respx.mock(assert_all_called=False) as router:
                # Streaming SSE — the stream-forwarder path runs the
                # BackgroundTask settle once the client finishes/disconnects.
                router.post(OPENAI_COMPLETIONS).mock(
                    return_value=httpx.Response(
                        200,
                        headers={"content-type": "text/event-stream"},
                        stream=httpx.ByteStream(b"".join(_sse_chunks())),
                    )
                )

                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    for i in range(N_ITERATIONS):
                        # Snapshot BEFORE: row count, total tokens, pending set.
                        (
                            log_before,
                            tokens_before,
                            _,
                            pending_before,
                        ) = await _snapshot(db_path, None)

                        handles_before_request = len(issued_handles)

                        response = await client.post(
                            f"/{ALIAS}/v1/chat/completions",
                            headers={
                                "authorization": f"Bearer {shard_a_utf8}",
                                "content-type": "application/json",
                            },
                            content=body,
                        )
                        if response.status_code == 200:
                            await response.aread()
                        assert response.status_code == 200, (
                            f"iter {i}: expected 200, got "
                            f"{response.status_code} body={response.text[:200]}"
                        )

                        # Spy must have captured exactly one new handle for
                        # this request (the hold the rules engine issued).
                        new_handles = issued_handles[handles_before_request:]
                        if len(new_handles) != 1:
                            race_skipped += 1
                            handle: str | None = None
                        else:
                            handle = new_handles[0]
                            # FORCE the double-fire AFTER the BG task already
                            # settled. Two more settle attempts against the
                            # consumed handle MUST no-op via the row-check
                            # inside BEGIN IMMEDIATE.
                            # CodeRabbit: don't swallow real settle errors —
                            # the no-op path should NEVER raise; if it does,
                            # the test must fail loudly.
                            results = await asyncio.gather(
                                rules_engine.settle_spend_at_estimate(handle),
                                rules_engine.settle_spend_at_estimate(handle),
                                return_exceptions=True,
                            )
                            for r in results:
                                if isinstance(r, BaseException):
                                    raise AssertionError(
                                        f"iter {i}: settle_at_estimate raised "
                                        f"{type(r).__name__}: {r}"
                                    )

                        # Real yield so any in-flight BG task lands.
                        await asyncio.sleep(0.01)

                        (
                            log_final,
                            tokens_final,
                            pending_for_handle_final,
                            _,
                        ) = await _snapshot(db_path, handle)

                        # Invariant 1: exactly ONE new spend_log row, no
                        # matter how many settle calls fired.
                        rows_added = log_final - log_before
                        assert rows_added == 1, (
                            f"iter {i} handle={handle!r}: expected exactly 1 "
                            f"new spend_log row, got {rows_added} "
                            f"(log_before={log_before} log_final={log_final}) "
                            f"— double-fire produced {rows_added} rows = "
                            f"cap counter dishonest"
                        )

                        # Invariant 2: total tokens moved by EXACTLY one
                        # settle amount. The SSE mock in _sse_chunks()
                        # hard-codes total_tokens=15 in the usage block, so
                        # the BG task's settle(handle, 15) is deterministic.
                        # An "anything > 0" check would let a double-count-
                        # into-one-row bug pass; asserting exact 15 catches
                        # it. CodeRabbit catch: tighten the assertion to
                        # match the deterministic settled amount.
                        tokens_added = tokens_final - tokens_before
                        assert tokens_added == EXPECTED_SETTLE_TOKENS, (
                            f"iter {i} handle={handle!r}: expected tokens "
                            f"delta == {EXPECTED_SETTLE_TOKENS} (one settle's "
                            f"worth from the SSE mock), got {tokens_added}. "
                            f"Counter is dishonest — settle either no-op'd "
                            f"(0), double-counted into one row (>15), or the "
                            f"adapter silently downgraded settle → "
                            f"settle_at_estimate (different value)."
                        )

                        # Invariant 3: the hold is consumed (no orphan).
                        if handle is not None:
                            assert pending_for_handle_final == 0, (
                                f"iter {i} handle={handle[:12]}: "
                                f"pending_charges still holds "
                                f"{pending_for_handle_final} row(s) — settle "
                                f"never consumed the hold"
                            )

            # Test-meta invariant: enough iterations must have ACTUALLY
            # exercised the forced double-fire. If >50% silently fell
            # through (BG task always won the capture race), we proved
            # nothing about the lock — the green is a false positive.
            # Post-code panel: this is the false-positive-green guard.
            assert race_skipped < N_ITERATIONS // 2, (
                f"{race_skipped}/{N_ITERATIONS} iterations skipped the "
                f"forced double-fire — BG task drained pending before "
                f"handle capture. Test is not exercising the race; the "
                f"green is a false positive."
            )

        finally:
            # Restore the patched class method so other tests aren't poisoned.
            SpendLedger.hold = original_hold  # type: ignore[method-assign]

            # sql-pro fixture teardown: explicit WAL checkpoint truncate
            # to collapse -wal/-shm side files before tempdir cleanup.
            async with aiosqlite.connect(db_path) as cleanup:
                await cleanup.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                await cleanup.commit()

            await app.state.httpx_client.aclose()
            await db.close()

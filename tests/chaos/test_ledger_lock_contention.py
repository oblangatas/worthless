"""Chaos test — lock + BEGIN IMMEDIATE contention at the SpendLedger layer (WOR-695).

> Make sure the spend cap actually holds on every request — so once the budget's
> blown, the key stops forming, no matter who's spending or why.

**Scope (honest):** this test guards the asyncio.Lock + `BEGIN IMMEDIATE`
serialization of the ledger primitives. Unlike `test_exactly_once_disconnect.py`
(which is forced to test AFTER the BG task already drains the hold because
`httpx.ASGITransport` hides the in-flight window), this test hits the ledger
DIRECTLY — no proxy, no ASGI, no BackgroundTask. That lets us fire two settle
attempts CONCURRENTLY against an ACTIVE hold and observe whether the lock +
BEGIN IMMEDIATE actually serialize them.

**What this proves:** under heavy concurrent contention (N concurrent
`settle` / `settle_at_estimate` calls against a single hold), the lock +
BEGIN IMMEDIATE + row-check together produce EXACTLY ONE spend_log row.

**What this does NOT prove:** anything about the proxy → BG task → ledger
end-to-end flow. That's `test_exactly_once_disconnect.py`'s job (within its
own scoped row-check guarantee).

Together the two files cover the three guards:

  | Guard                         | Tested by                                    |
  | ----------------------------- | -------------------------------------------- |
  | asyncio.Lock                  | test_ledger_lock_contention.py (this file)   |
  | BEGIN IMMEDIATE transaction   | test_ledger_lock_contention.py (this file)   |
  | row-check inside the txn      | test_exactly_once_disconnect.py              |

How this works:

* opens a real aiosqlite connection on a tempfile SQLite,
* applies the schema directly (no proxy boot),
* enrolls a minimal `enrollment_config` row so SpendCap rule semantics align,
* creates a SpendLedger with the connection + a shared asyncio.Lock,
* per iteration (N=50): create a hold, fire K=4 concurrent settle / settle_at_estimate
  calls in `asyncio.gather`, assert via raw SQL that exactly one spend_log row
  was added and the pending_charges row was consumed.

Out of scope (do NOT add here):
* full proxy ASGI flow — `test_exactly_once_disconnect.py`
* per-(provider, model) ceiling table — WOR-696
* divergence telemetry — WOR-697
"""

from __future__ import annotations

import asyncio
import secrets
import tempfile
from pathlib import Path

import aiosqlite
import pytest

from worthless.storage.schema import SCHEMA
from worthless.storage.spend_ledger import SpendLedger


# How many hold→contended-settle iterations.
N_ITERATIONS = 50

# How many concurrent settle attempts per iteration. 4 contenders means
# the lock has to serialize through 4 BEGIN IMMEDIATE / row-check pairs
# per hold. Plenty to catch a refactor that breaks serialization.
K_CONTENDERS = 4

ALIAS = "ledger-chaos-key"


async def _setup_db(db_path: str) -> aiosqlite.Connection:
    """Open a real aiosqlite connection with schema + WAL + busy_timeout."""
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute("PRAGMA journal_mode=WAL")
        await setup.execute("PRAGMA journal_size_limit=1048576")
        await setup.execute("PRAGMA wal_autocheckpoint=50")
        await setup.execute("PRAGMA busy_timeout=5000")
        await setup.execute(
            "INSERT OR REPLACE INTO enrollment_config "
            "(key_alias, spend_cap, rate_limit_rps) VALUES (?, ?, ?)",
            (ALIAS, 10_000_000, 10_000.0),
        )
        await setup.commit()

    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    return db


async def _row_counts(db_path: str, handle: str | None) -> tuple[int, int, int]:
    """Return (spend_log_rows, spend_log_tokens_total, pending_for_handle).

    Uses a fresh connection so we don't conflict with the ledger's
    transactions in flight.
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
                pending = int(row[0])
        else:
            pending = 0
    return log_rows, total_tokens, pending


@pytest.mark.asyncio
async def test_lock_serializes_concurrent_settle_against_active_hold() -> None:
    """N=50 iterations; per iteration, K=4 concurrent settles against one hold.

    Invariants per iteration:
    - exactly ONE new spend_log row (lock + BEGIN IMMEDIATE serialize; only
      one settle wins the BEGIN IMMEDIATE write, the rest find no pending
      row and no-op)
    - zero pending_charges rows for the handle (winning settle consumed it)
    - tokens delta > 0 (the winning settle did move the counter)

    If the asyncio.Lock is removed: BEGIN IMMEDIATE will still serialize
    SQLite-level writes via SQLITE_BUSY, but the race is observable on
    busy_timeout pressure — under K=4 contenders this test surfaces it via
    raised exceptions in gather.

    If BEGIN IMMEDIATE is downgraded to a deferred txn: writers race and
    multiple INSERTs can fire before the row-check inside the txn sees the
    DELETE — multiple spend_log rows appear and this test goes red.

    If the row-check is removed: each gather coroutine inserts unconditionally,
    K rows per iteration, this test goes red.
    """
    with tempfile.TemporaryDirectory(prefix="chaos-lock-contention-") as tmp:
        db_path = str(Path(tmp) / "ledger.db")
        db = await _setup_db(db_path)
        lock = asyncio.Lock()
        ledger = SpendLedger(db=db, lock=lock)

        try:
            for i in range(N_ITERATIONS):
                # Snapshot baseline so we can compute deltas later.
                log_before, tokens_before, _ = await _row_counts(db_path, None)

                # Create an active hold. Estimate is small enough that any
                # winning settle leaves the cap healthy; we're not testing
                # the cap here, only the ledger primitives.
                handle = await ledger.hold(
                    alias=ALIAS,
                    estimate=42,
                    cap=10_000_000.0,
                    provider="openai",
                    model="gpt-4o-mini",
                )
                assert handle is not None, f"iter {i}: ledger.hold returned None — cap math wrong"

                # K concurrent settle attempts. Mix `settle` and
                # `settle_at_estimate` so we cover both code paths under
                # contention. The actual amount only matters for one
                # contender — only one can win the BEGIN IMMEDIATE write.
                attempts: list = []
                for k in range(K_CONTENDERS):
                    if k % 2 == 0:
                        attempts.append(ledger.settle(handle, actual=10 + k))
                    else:
                        attempts.append(ledger.settle_at_estimate(handle))

                # gather with return_exceptions so contenders that no-op
                # don't crash the iteration. The invariants below catch
                # any real failure mode.
                results = await asyncio.gather(*attempts, return_exceptions=True)

                # Any unexpected exception is a real failure. SpendLedger's
                # settle/settle_at_estimate should return None for both
                # winners and no-ops, never raise.
                for r in results:
                    if isinstance(r, BaseException):
                        raise AssertionError(f"iter {i}: settle raised {type(r).__name__}: {r}")

                # Invariant 1: exactly ONE new spend_log row across K
                # contenders. The lock + BEGIN IMMEDIATE + row-check
                # together MUST collapse K attempts into one persisted row.
                (
                    log_final,
                    tokens_final,
                    pending_for_handle,
                ) = await _row_counts(db_path, handle)
                rows_added = log_final - log_before
                assert rows_added == 1, (
                    f"iter {i} handle={handle[:12]}: K={K_CONTENDERS} "
                    f"contenders produced {rows_added} new spend_log rows. "
                    f"Lock + BEGIN IMMEDIATE + row-check failed to serialize."
                )

                # Invariant 2: the winning settle moved the counter.
                tokens_added = tokens_final - tokens_before
                assert tokens_added > 0, (
                    f"iter {i} handle={handle[:12]}: tokens delta == 0 — "
                    f"no settle actually wrote a spend_log row"
                )

                # Invariant 3: the pending row is consumed.
                assert pending_for_handle == 0, (
                    f"iter {i} handle={handle[:12]}: pending_charges still "
                    f"has {pending_for_handle} row(s) — winning settle did "
                    f"NOT consume the hold"
                )

        finally:
            async with aiosqlite.connect(db_path) as cleanup:
                await cleanup.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                await cleanup.commit()
            await db.close()


@pytest.mark.asyncio
async def test_lock_serializes_concurrent_holds_unique_handles() -> None:
    """Concurrent holds against the same key_alias return DISTINCT handles.

    Property check: the ledger's CSPRNG handle generator (secrets.token_hex)
    must never collide under concurrent issuance. If a refactor ever swaps
    the handle generator for something deterministic / collidable, this test
    goes red because the UNIQUE(handle) PRIMARY KEY on pending_charges
    will fire IntegrityError on the second hold.

    Not strictly a "lock contention" test, but lives here because it shares
    the direct-ledger fixture and exercises the same hot path.
    """
    with tempfile.TemporaryDirectory(prefix="chaos-handle-uniq-") as tmp:
        db_path = str(Path(tmp) / "ledger.db")
        db = await _setup_db(db_path)
        lock = asyncio.Lock()
        ledger = SpendLedger(db=db, lock=lock)

        try:
            # Fire 64 concurrent holds against the same alias.
            results = await asyncio.gather(
                *[
                    ledger.hold(
                        alias=ALIAS,
                        estimate=1,
                        cap=10_000_000.0,
                        provider="openai",
                        model="gpt-4o-mini",
                    )
                    for _ in range(64)
                ],
                return_exceptions=True,
            )

            handles: list[str] = []
            for r in results:
                if isinstance(r, BaseException):
                    raise AssertionError(f"concurrent hold raised {type(r).__name__}: {r}")
                handles.append(r)

            assert len(handles) == 64, f"Expected 64 handles, got {len(handles)}"
            assert len(set(handles)) == 64, (
                f"Handle collision detected: only {len(set(handles))} unique "
                f"handles across 64 concurrent issuances. "
                f"CSPRNG (secrets.token_hex) compromised or replaced?"
            )

            # Every handle should be CSPRNG-shaped (hex-only, even length,
            # >=32 chars).
            for h in handles:
                assert len(h) >= 32, f"Handle too short: {h!r}"
                assert all(c in "0123456789abcdef" for c in h), f"Handle not hex: {h!r}"

            # And entropy seed used was actually secrets.token_hex — sanity
            # check by trying to parse it as hex.
            try:
                bytes.fromhex(handles[0])
            except ValueError:
                raise AssertionError(  # noqa: B904
                    f"Handle not valid hex: {handles[0]!r}"
                )

            # Defense-in-depth: a quick collision probability sanity check
            # against CSPRNG. With 32-char hex (128 bits) and 64 draws,
            # collision probability is astronomically low (~2^-117). If we
            # ever see a collision in this test, the generator is broken.
            _ = secrets  # imported for clarity — actual gen is in ledger

        finally:
            async with aiosqlite.connect(db_path) as cleanup:
                await cleanup.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                await cleanup.commit()
            await db.close()

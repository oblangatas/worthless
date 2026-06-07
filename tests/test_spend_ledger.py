"""Unit tests for ``SpendLedger`` — the durable write-ahead hold/settle/refund/
sweep ledger (WOR-659 Task 2). RED first: ``SpendLedger`` does not exist yet.

Invariants pinned here:
- ``hold`` DENIES (returns None, writes nothing) when committed + held + estimate > cap.
- ``hold`` under cap inserts a pending row and returns a unique handle.
- ``settle`` atomically swaps the hold for ONE ``spend_log`` row at the actual amount.
- ``settle`` is idempotent by handle (never double-writes ``spend_log``).
- ``refund`` deletes the hold and writes no ``spend_log`` row.
- ``sweep`` settles stale holds at their own estimate (never refunds); fresh holds survive.
- the ledger uses the INJECTED connection, never opens its own (busy_timeout discipline).

Note (surfaced by TDD): a hold stores ``provider`` so ``settle``/``sweep`` can write a
valid ``spend_log`` row (provider is NOT NULL) without caller context. Panel to confirm
this vs looking the provider up from ``shards``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import aiosqlite
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from worthless.storage.schema import SCHEMA
from worthless.storage.spend_ledger import SpendLedger


async def _open(tmp_path) -> aiosqlite.Connection:
    """Open a fresh DB with the full schema applied."""
    db = await aiosqlite.connect(str(tmp_path / "ledger.db"))
    await db.executescript(SCHEMA)
    await db.commit()
    return db


async def _committed(db: aiosqlite.Connection, alias: str) -> int:
    """Total recorded (settled) spend for an alias."""
    cur = await db.execute(
        "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?", (alias,)
    )
    (n,) = await cur.fetchone()
    return n


async def _held(db: aiosqlite.Connection, alias: str) -> int:
    """Total open (un-settled) hold estimate for an alias."""
    cur = await db.execute(
        "SELECT COALESCE(SUM(estimate), 0) FROM pending_charges WHERE key_alias = ?", (alias,)
    )
    (n,) = await cur.fetchone()
    return n


async def _spend_rows(db: aiosqlite.Connection, alias: str) -> int:
    """Count of spend_log rows for an alias."""
    cur = await db.execute("SELECT COUNT(*) FROM spend_log WHERE key_alias = ?", (alias,))
    (n,) = await cur.fetchone()
    return n


@pytest.mark.asyncio
async def test_hold_denies_when_estimate_exceeds_cap(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, provider) VALUES ('k1', 90, 'openai')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        # remaining = 100 - 90 = 10; estimate 20 -> deny, reserve nothing.
        handle = await ledger.hold("k1", estimate=20, cap=100, provider="openai")
        assert handle is None
        assert await _held(db, "k1") == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hold_inserts_pending_row_and_returns_unique_handle(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h1 = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        h2 = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        assert h1 and h2 and h1 != h2
        assert await _held(db, "k1") == 20
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_swaps_hold_for_spend_log_atomically(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=50, cap=100, provider="openai")
        await ledger.settle(h, actual=37)
        assert await _held(db, "k1") == 0  # hold gone
        assert await _committed(db, "k1") == 37  # exactly the actual
        assert await _spend_rows(db, "k1") == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_is_idempotent_by_handle(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=50, cap=100, provider="openai")
        await ledger.settle(h, actual=37)
        await ledger.settle(h, actual=37)  # second call MUST be a no-op
        assert await _spend_rows(db, "k1") == 1
        assert await _committed(db, "k1") == 37
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_bills_the_stored_estimate(tmp_path) -> None:
    """When actual usage can't be read (mid-stream disconnect, parse failure),
    settle_at_estimate must atomically convert the hold to a spend_log row at
    the hold's STORED estimate — same shape as settle, but with the conservative
    admission value instead of waiting for the background sweeper.
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=42, cap=100, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _held(db, "k1") == 0  # hold gone
        assert await _committed(db, "k1") == 42  # exactly the estimate
        assert await _spend_rows(db, "k1") == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_is_idempotent_by_handle(tmp_path) -> None:
    """A double call (e.g. a retry after a logged settle failure) must be a no-op
    — the cap can't be double-billed when the hold is already gone."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=42, cap=100, provider="openai")
        await ledger.settle_at_estimate(h)
        await ledger.settle_at_estimate(h)  # second call must do nothing
        assert await _spend_rows(db, "k1") == 1
        assert await _committed(db, "k1") == 42
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_unblocks_cap_without_waiting_for_sweep(tmp_path) -> None:
    """Cost-griefing guard: an aborted/unreadable request must IMMEDIATELY bill
    the cap so the next request sees an honest budget, not a stale one. Without
    settle_at_estimate the hold would only be cleared by the background sweeper —
    a window an attacker could use to fire many requests cheaply.
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        # Fill the cap to 90/100 with a hold; usage is unreadable.
        h1 = await ledger.hold("k1", estimate=90, cap=100, provider="openai")
        await ledger.settle_at_estimate(h1)
        # The very next request sees the cap honestly accounted for — only 10 left.
        h2 = await ledger.hold("k1", estimate=11, cap=100, provider="openai")
        assert h2 is None  # would exceed cap
        h3 = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        assert h3 is not None  # fits exactly
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refund_deletes_hold_without_spend_log_write(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=50, cap=100, provider="openai")
        await ledger.refund(h)
        assert await _held(db, "k1") == 0
        assert await _committed(db, "k1") == 0  # no spend recorded on a refund
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_settles_stale_holds_at_estimate_never_refunds(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        # A stale hold (created an hour ago) + a fresh one.
        await db.execute(
            "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
            "VALUES ('stale', 'k1', 42, datetime('now', '-1 hour'), 'openai')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        fresh = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")

        reaped = await ledger.sweep(max_age_seconds=60)

        assert reaped == 1
        assert await _committed(db, "k1") == 42  # stale hold settled at its estimate
        cur = await db.execute("SELECT COUNT(*) FROM pending_charges WHERE handle = ?", (fresh,))
        (cnt,) = await cur.fetchone()
        assert cnt == 1  # fresh hold untouched
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_concurrent_holds_serialise_and_respect_cap(tmp_path) -> None:
    """Two concurrent holds on ONE connection must not crash and must respect
    the cap. Without internal serialisation, the second BEGIN IMMEDIATE raises
    'cannot start a transaction within a transaction' — the proxy's real shape."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        # cap 100, estimate 60 each → at most ONE may win.
        results = await asyncio.gather(
            ledger.hold("k1", estimate=60, cap=100, provider="openai"),
            ledger.hold("k1", estimate=60, cap=100, provider="openai"),
        )
        granted = [h for h in results if h is not None]
        assert len(granted) == 1  # exactly one grant; no crash, no double-reserve
        assert await _held(db, "k1") == 60
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_many_concurrent_holds_respect_cap(tmp_path) -> None:
    """20 concurrent holds of 10 against cap 100 → exactly 10 may win. The
    serialisation must hold the cap exactly under load (rules.py's TOCTOU shape,
    on the ledger) with no crash and no overshoot."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        results = await asyncio.gather(
            *[ledger.hold("k1", estimate=10, cap=100, provider="openai") for _ in range(20)]
        )
        granted = [h for h in results if h is not None]
        assert len(granted) == 10  # exactly cap/estimate — no overshoot, no crash
        assert await _held(db, "k1") == 100
    finally:
        await db.close()


_LEDGER_OP = st.tuples(
    st.sampled_from(["hold", "settle", "refund"]), st.integers(min_value=0, max_value=30)
)


@settings(max_examples=40, deadline=None)
@given(ops=st.lists(_LEDGER_OP, max_size=40))
def test_property_cap_invariant_holds_over_random_sequences(ops) -> None:
    """Fuzzed: over ANY random hold/settle/refund sequence, committed spend never
    exceeds the cap and held + committed never over-reserves. Runs the async
    scenario per example via asyncio.run (Hypothesis-friendly)."""

    async def scenario() -> None:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = await aiosqlite.connect(path)
        try:
            await db.executescript(SCHEMA)
            await db.commit()
            ledger = SpendLedger(db)
            cap = 100
            live: list[tuple[str, int]] = []
            for kind, n in ops:
                if kind == "hold":
                    h = await ledger.hold("k1", estimate=n, cap=cap, provider="openai")
                    if h is not None:
                        live.append((h, n))
                elif kind == "settle" and live:
                    h, est = live.pop()
                    await ledger.settle(h, actual=min(n, est))
                elif kind == "refund" and live:
                    h, _ = live.pop()
                    await ledger.refund(h)
                committed = await _committed(db, "k1")
                held = await _held(db, "k1")
                assert committed <= cap, f"committed {committed} exceeded cap {cap}"
                assert committed + held <= cap, f"over-reserved: {committed}+{held} > {cap}"
        finally:
            await db.close()
            Path(path).unlink()

    asyncio.run(scenario())


@pytest.mark.asyncio
async def test_hold_rejects_negative_estimate(tmp_path) -> None:
    """A negative reservation would buy back cap headroom — reject it."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        with pytest.raises(ValueError):
            await ledger.hold("k1", estimate=-1, cap=100, provider="openai")
        assert await _held(db, "k1") == 0  # nothing written
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_rejects_negative_actual(tmp_path) -> None:
    """A negative charge would poison the committed SUM — reject it; the poison
    row must never land."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        with pytest.raises(ValueError):
            await ledger.settle(h, actual=-5_000_000)
        assert await _committed(db, "k1") == 0  # no negative spend_log row
        assert await _held(db, "k1") == 10  # hold untouched (settle raised early)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_ledger_uses_injected_connection_not_fresh_connect(tmp_path, monkeypatch) -> None:
    db = await _open(tmp_path)
    opened: list = []
    real_connect = aiosqlite.connect
    monkeypatch.setattr(
        aiosqlite, "connect", lambda *a, **k: (opened.append(a), real_connect(*a, **k))[1]
    )
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        await ledger.settle(h, actual=5)
        assert opened == []  # the ledger opened NO new connection
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hold_allows_spend_exactly_to_cap(tmp_path) -> None:
    """committed + held + estimate == cap MUST succeed — the `>` (not `>=`)
    boundary is where off-by-one flips fail-closed into fail-open."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        assert await ledger.hold("k1", estimate=100, cap=100, provider="openai") is not None
        assert await _held(db, "k1") == 100
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hold_alias_isolation(tmp_path) -> None:
    """A hold on one alias must not consume another's cap."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        await ledger.hold("k2", estimate=90, cap=100, provider="openai")
        assert await ledger.hold("k1", estimate=90, cap=100, provider="openai") is not None
        assert await _held(db, "k1") == 90 and await _held(db, "k2") == 90
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_persists_real_model_in_spend_log(tmp_path) -> None:
    """The settled row carries the hold's model/provider (every other test uses
    model=None, so a wrong-column write would slip past)."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=10, cap=100, provider="anthropic", model="claude-x")
        await ledger.settle(h, actual=8)
        cur = await db.execute("SELECT model, provider FROM spend_log WHERE key_alias='k1'")
        model, provider = await cur.fetchone()
        assert model == "claude-x" and provider == "anthropic"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refund_absent_handle_is_noop(tmp_path) -> None:
    """Refunding a never-issued handle does not raise and writes nothing."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        await ledger.refund("never-existed")
        assert await _held(db, "k1") == 0 and await _committed(db, "k1") == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_returns_zero_when_nothing_stale(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        await ledger.hold("k1", estimate=10, cap=100, provider="openai")  # fresh
        assert await ledger.sweep(max_age_seconds=60) == 0
        assert await _held(db, "k1") == 10  # fresh hold untouched
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_settles_multiple_stale_holds(tmp_path) -> None:
    db = await _open(tmp_path)
    try:
        for h in ("a", "b", "c"):
            await db.execute(
                "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
                "VALUES (?, 'k1', 5, datetime('now','-1 hour'), 'openai')",
                (h,),
            )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 3
        assert await _committed(db, "k1") == 15  # 3 x 5, billed at estimate
        assert await _held(db, "k1") == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_rejects_negative_max_age(tmp_path) -> None:
    """A negative age yields a future cutoff that would bill fresh holds."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        await ledger.hold("k1", estimate=10, cap=100, provider="openai")  # fresh
        with pytest.raises(ValueError):
            await ledger.sweep(max_age_seconds=-5)
        assert await _held(db, "k1") == 10  # fresh hold NOT billed
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hold_rolls_back_on_cancellation(tmp_path, monkeypatch) -> None:
    """A CancelledError mid-transaction (client disconnect) must roll back, not
    leave the connection stuck in an open transaction that breaks the NEXT
    request. CancelledError is BaseException, so `except Exception` misses it."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        real_execute = db.execute

        async def cancel_on_insert(sql, *a, **k):
            if sql.startswith("INSERT INTO pending_charges"):
                raise asyncio.CancelledError()
            return await real_execute(sql, *a, **k)

        monkeypatch.setattr(db, "execute", cancel_on_insert)
        with pytest.raises(asyncio.CancelledError):
            await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        monkeypatch.undo()
        # The transaction must have rolled back: the NEXT hold must succeed,
        # not raise "cannot start a transaction within a transaction".
        h = await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        assert h is not None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hold_rolls_back_on_db_error(tmp_path, monkeypatch) -> None:
    """A DB error mid-transaction rolls back — no orphan pending row lands."""
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        real_execute = db.execute

        async def boom(sql, *a, **k):
            if sql.startswith("INSERT INTO pending_charges"):
                raise aiosqlite.OperationalError("disk I/O error")
            return await real_execute(sql, *a, **k)

        monkeypatch.setattr(db, "execute", boom)
        with pytest.raises(aiosqlite.OperationalError):
            await ledger.hold("k1", estimate=10, cap=100, provider="openai")
        monkeypatch.undo()
        assert await _held(db, "k1") == 0  # rolled back, no orphan
    finally:
        await db.close()

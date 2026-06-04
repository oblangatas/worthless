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

import aiosqlite
import pytest

from worthless.storage.schema import SCHEMA
from worthless.storage.spend_ledger import SpendLedger


async def _open(tmp_path) -> aiosqlite.Connection:
    db = await aiosqlite.connect(str(tmp_path / "ledger.db"))
    await db.executescript(SCHEMA)
    await db.commit()
    return db


async def _committed(db: aiosqlite.Connection, alias: str) -> int:
    cur = await db.execute(
        "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?", (alias,)
    )
    (n,) = await cur.fetchone()
    return n


async def _held(db: aiosqlite.Connection, alias: str) -> int:
    cur = await db.execute(
        "SELECT COALESCE(SUM(estimate), 0) FROM pending_charges WHERE key_alias = ?", (alias,)
    )
    (n,) = await cur.fetchone()
    return n


async def _spend_rows(db: aiosqlite.Connection, alias: str) -> int:
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

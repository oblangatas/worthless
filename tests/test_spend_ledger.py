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

from worthless.proxy.config import GLOBAL_CEILING_TOKENS
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
    """When the stored estimate ALREADY exceeds the global ceiling floor,
    settle_at_estimate writes that estimate verbatim — no over-bill on top
    of an already-large reservation. The floor only applies when estimate
    is below the ceiling (see sibling leak-fix test below).
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        # Estimate > 128K floor → ledger writes estimate unchanged.
        h = await ledger.hold("k1", estimate=200_000, cap=1_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _held(db, "k1") == 0  # hold gone
        assert await _committed(db, "k1") == 200_000  # exactly the estimate
        assert await _spend_rows(db, "k1") == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_floors_small_estimate_at_global_ceiling(tmp_path) -> None:
    """WOR-696: when the stored estimate is BELOW the global ceiling (the
    common case for a request that omitted max_tokens — T3 estimator counts
    only input tokens, so estimate is tiny), settle_at_estimate must charge
    the global ceiling instead. Otherwise a disconnected no-max_tokens
    request silently writes a near-zero spend_log row and the cap leaks.
    Direction of error is conservative — we never under-bill on the
    fallback path.
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        # Tiny estimate (think: input-only, no max_tokens) — must floor at ceiling.
        h = await ledger.hold("k1", estimate=42, cap=GLOBAL_CEILING_TOKENS * 10, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _held(db, "k1") == 0
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS
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
        # Estimate above the 128K floor — exercises the same-estimate path.
        h = await ledger.hold("k1", estimate=200_000, cap=1_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        await ledger.settle_at_estimate(h)  # second call must do nothing
        assert await _spend_rows(db, "k1") == 1
        assert await _committed(db, "k1") == 200_000
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_unblocks_cap_without_waiting_for_sweep(tmp_path) -> None:
    """Cost-griefing guard: an aborted/unreadable request must IMMEDIATELY bill
    the cap so the next request sees an honest budget, not a stale one. Without
    settle_at_estimate the hold would only be cleared by the background sweeper —
    a window an attacker could use to fire many requests cheaply.

    Scaled above the 128K ceiling floor so the assertion shape matches the
    pre-WOR-696 behavior (estimate written verbatim above the floor).
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)
        # Fill the cap to 900K/1M with a hold; usage is unreadable.
        h1 = await ledger.hold("k1", estimate=900_000, cap=1_000_000, provider="openai")
        await ledger.settle_at_estimate(h1)
        # The very next request sees the cap honestly accounted for — only 100K left.
        h2 = await ledger.hold("k1", estimate=110_000, cap=1_000_000, provider="openai")
        assert h2 is None  # would exceed cap
        h3 = await ledger.hold("k1", estimate=100_000, cap=1_000_000, provider="openai")
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
    # Estimate sized ABOVE GLOBAL_CEILING_TOKENS so the WOR-696 sweep floor
    # (max(estimate, ceiling)) is a no-op here — test pins the original
    # "sweep bills the stored estimate, never refunds" contract for legit
    # large reservations. The leak-fix branch (estimate < ceiling) is
    # covered by test_sweep_floors_orphans_at_ceiling_blocking_sigkill_attack.
    legit_estimate = GLOBAL_CEILING_TOKENS + 50_000
    db = await _open(tmp_path)
    try:
        # A stale hold (created an hour ago) + a fresh one.
        await db.execute(
            "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
            "VALUES ('stale', 'k1', ?, datetime('now', '-1 hour'), 'openai')",
            (legit_estimate,),
        )
        await db.commit()
        ledger = SpendLedger(db)
        fresh = await ledger.hold("k1", estimate=10, cap=10_000_000, provider="openai")

        reaped = await ledger.sweep(max_age_seconds=60)

        assert reaped == 1
        assert await _committed(db, "k1") == legit_estimate  # legit estimate preserved
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
    # Estimates above the GLOBAL_CEILING_TOKENS floor so the WOR-696
    # sweep floor is a no-op for THIS test — pins the multi-hold reap
    # behavior on legit large estimates. The small-estimate floor path
    # is covered by test_sweep_floors_orphans_at_ceiling_blocking_sigkill_attack.
    legit_estimate = GLOBAL_CEILING_TOKENS + 50_000
    db = await _open(tmp_path)
    try:
        for h in ("a", "b", "c"):
            await db.execute(
                "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
                "VALUES (?, 'k1', ?, datetime('now','-1 hour'), 'openai')",
                (h, legit_estimate),
            )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 3
        assert await _committed(db, "k1") == 3 * legit_estimate
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


# ---------------------------------------------------------------------------
# Adversarial: SIGKILL-orphan sweeper attack (worthless-osgt, brutus finding)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sweep_floors_orphans_at_ceiling_blocking_sigkill_attack(tmp_path) -> None:
    """ATTACK NARRATIVE — first person, attacker POV.

    I want to drain my victim's OpenAI account past their $10 cap.
    I know the cap floors at GLOBAL_CEILING_TOKENS on every normal
    settle path — disconnect, idle kill, duration kill, BackgroundTask
    exception. So I can't just disconnect; the floor would fire.

    But there's a gap: settle runs in a FastAPI BackgroundTask. If I can
    kill the proxy process BETWEEN stream-start and BackgroundTask
    completion, the floor never executes. The pending_charges row sits
    in the DB with estimate=0 (I sent no max_tokens, so the estimator
    reserved zero output tokens, T3 passthrough principle).

    The sweeper is the backstop — runs on TTL, reaps orphan holds. But
    today it bills the STORED estimate, which is 0 for my no-max_tokens
    requests. Cap counter never moves. I loop forever.

    My attack:
        1. Send no-max_tokens request to a $10-capped alias
        2. SIGKILL the proxy mid-stream before BackgroundTask fires
        3. Repeat 1000x
        4. Wait for sweeper TTL — it bills 1000 × 0 = 0 tokens to my cap
        5. My alias is still under cap. Provider bill is unbounded.

    THIS TEST FAILS on production code without the sweep-at-ceiling
    floor — proves the leak exists.

    With the fix (max(estimate, GLOBAL_CEILING_TOKENS) in sweep), my
    attack PAYS: sweeper bills 1000 × 128K = 128M tokens, my cap is
    demolished, key stops reassembling.
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)

        # Simulate 10 SIGKILL'd no-max_tokens requests. Insert pending_charges
        # rows directly — that's the post-mortem DB state after the attack.
        # estimate=0 because no max_tokens was sent (T3 passthrough estimator).
        # created_at is set 3600s ago so the sweeper picks them up.
        for i in range(10):
            await db.execute(
                "INSERT INTO pending_charges"
                " (handle, key_alias, estimate, provider, model, created_at)"
                " VALUES (?, 'victim', 0, 'openai', 'gpt-4o-mini',"
                " datetime('now', '-3600 seconds'))",
                (f"sigkill-orphan-{i}",),
            )
        await db.commit()

        # Sanity: 10 orphans exist, victim's spend_log is empty.
        assert await _held(db, "victim") == 0  # estimate is 0 each
        assert await _committed(db, "victim") == 0
        cur = await db.execute("SELECT COUNT(*) FROM pending_charges WHERE key_alias = 'victim'")
        (orphan_count,) = await cur.fetchone()
        assert orphan_count == 10, "setup: expected 10 orphan holds"

        # Fire the sweeper. max_age_seconds=0 means "reap everything older
        # than now" — production runs with a TTL like 60s; same code path.
        reaped = await ledger.sweep(max_age_seconds=0)
        assert reaped == 10, "sweeper should have reaped all 10 orphans"

        # THE LOAD-BEARING ASSERTION.
        # Without the fix: total_spent = 10 * 0 = 0. Cap unmoved.
        # With the fix: total_spent = 10 * GLOBAL_CEILING_TOKENS.
        committed = await _committed(db, "victim")
        expected = 10 * GLOBAL_CEILING_TOKENS
        assert committed == expected, (
            f"SIGKILL-orphan attack: sweeper billed {committed} tokens, "
            f"expected {expected} ({10} orphans × {GLOBAL_CEILING_TOKENS} "
            f"ceiling). At {committed} the attacker drains the provider "
            f"account without the cap moving — the leak documented in "
            f"worthless-osgt (brutus P1)."
        )

        # No orphans remain. Sweeper consumed every row.
        assert await _held(db, "victim") == 0

    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_preserves_legitimate_estimates_above_ceiling(tmp_path) -> None:
    """Companion test: the floor must NOT cap honest estimates downward.

    A request that legitimately reserved 500_000 tokens (big max_tokens)
    and got SIGKILL'd should bill its full 500K reservation, not the
    128K floor. The fix is `max(estimate, GLOBAL_CEILING_TOKENS)` —
    upward-only floor, never a ceiling.
    """
    db = await _open(tmp_path)
    try:
        ledger = SpendLedger(db)

        # An honest 500K-token reservation that got orphaned.
        await db.execute(
            "INSERT INTO pending_charges"
            " (handle, key_alias, estimate, provider, model, created_at)"
            " VALUES ('honest-orphan', 'victim', 500000, 'openai',"
            " 'gpt-4o', datetime('now', '-3600 seconds'))"
        )
        await db.commit()

        await ledger.sweep(max_age_seconds=0)

        committed = await _committed(db, "victim")
        assert committed == 500_000, (
            f"sweeper truncated an honest 500K estimate to {committed}; "
            f"the floor is UPWARD-only — never cap legit estimates down"
        )

    finally:
        await db.close()


# ---------------------------------------------------------------------------
# WOR-705: per-key ceiling override (raise-only + clamp-at-read)
# ---------------------------------------------------------------------------


async def _set_override(db: aiosqlite.Connection, alias: str, override: int | None) -> None:
    """Seed enrollment_config with a per-key ceiling override (or NULL)."""
    await db.execute(
        "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) VALUES (?, ?)",
        (alias, override),
    )
    await db.commit()


@pytest.mark.asyncio
async def test_settle_at_estimate_honors_per_key_override(tmp_path) -> None:
    """A key with a 200K override floors there, not at the 128K global.

    Use case: a heavy-reasoning customer running a model whose max-output
    exceeds the global ceiling. Their no-max_tokens disconnect should bill
    closer to reality (200K), not be under-floored at 128K.
    """
    db = await _open(tmp_path)
    try:
        await _set_override(db, "k1", 200_000)
        ledger = SpendLedger(db)
        # Tiny estimate (no max_tokens) — would floor at 128K globally.
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == 200_000, "override should raise the floor to 200K"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_null_override_falls_back_to_global(tmp_path) -> None:
    """No override (NULL) → the global 128K ceiling applies, unchanged."""
    db = await _open(tmp_path)
    try:
        await _set_override(db, "k1", None)
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_below_global_override_cannot_weaken_floor(tmp_path) -> None:
    """SAFETY: a below-global override (from direct SQL, a stale row, any
    source that bypassed write-validation) must NOT drop the floor below the
    audited global. The read path clamps to GLOBAL_CEILING_TOKENS.
    """
    db = await _open(tmp_path)
    try:
        # 50K stored directly — bypasses the setter's raise-only validation.
        await _set_override(db, "k1", 50_000)
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS, (
            "a below-global override must clamp UP to the global floor — "
            "the global is an inviolable minimum at read time"
        )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_honors_per_key_override(tmp_path) -> None:
    """The crash-orphan sweeper path also honors the per-key override."""
    db = await _open(tmp_path)
    try:
        await _set_override(db, "k1", 200_000)
        # Orphan hold (created an hour ago) with a zero estimate.
        await db.execute(
            "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
            "VALUES ('orphan', 'k1', 0, datetime('now', '-1 hour'), 'openai')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 1
        assert await _committed(db, "k1") == 200_000, "sweep should honor the override"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# WOR-705 hardening (brutus PR #294): poisoned-row, sweep batching, floats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poisoned_text_override_fails_closed_to_global(tmp_path) -> None:
    """worthless-8xdq: a non-numeric override (only reachable via direct SQL —
    SQLite INTEGER affinity stores unconvertible text as text) must NOT crash
    the settle transaction. It fails closed to the global floor.
    """
    db = await _open(tmp_path)
    try:
        # Text in the INTEGER-affinity column → stays text in SQLite.
        await db.execute(
            "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) "
            "VALUES ('k1', 'not-a-number')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)  # must not raise
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS, (
            "poisoned override must fail closed to the global floor, not crash"
        )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_poisoned_override_does_not_break_sweep(tmp_path) -> None:
    """worthless-8xdq: one poisoned row must not crash/rollback the whole sweep
    batch (which would leave every orphan unbilled indefinitely)."""
    db = await _open(tmp_path)
    try:
        await db.execute(
            "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) "
            "VALUES ('k1', 'garbage')"
        )
        await db.execute(
            "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
            "VALUES ('o1', 'k1', 0, datetime('now', '-1 hour'), 'openai')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 1  # must not raise
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_resolves_each_alias_own_ceiling(tmp_path) -> None:
    """worthless-v2mr: batched ceiling resolution must still give each alias its
    OWN ceiling — k1 (override 200K), k2 (override 300K), k3 (no override)."""
    db = await _open(tmp_path)
    try:
        await _set_override(db, "k1", 200_000)
        await _set_override(db, "k2", 300_000)
        await _set_override(db, "k3", None)
        for h, alias in (("a", "k1"), ("b", "k2"), ("c", "k3")):
            await db.execute(
                "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
                "VALUES (?, ?, 0, datetime('now', '-1 hour'), 'openai')",
                (h, alias),
            )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 3
        assert await _committed(db, "k1") == 200_000
        assert await _committed(db, "k2") == 300_000
        assert await _committed(db, "k3") == GLOBAL_CEILING_TOKENS
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_float_override_truncates_down_conservatively(tmp_path) -> None:
    """worthless-y14x: a float override (only via direct SQL) truncates toward
    zero — conservative for a floor, never rounds the bill UP."""
    db = await _open(tmp_path)
    try:
        await db.execute(
            "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) "
            "VALUES ('k1', 200000.7)"
        )
        await db.commit()
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == 200_000, "float must truncate down, not up"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Upgrade-safety: proxy restarted on a DB that predates the ceiling_override
# column (executescript(SCHEMA) never adds columns). The fail-closed settle /
# sweep path must bill the global floor, not crash and orphan the charge.
# ---------------------------------------------------------------------------


async def _open_unmigrated(tmp_path) -> aiosqlite.Connection:
    """Full schema, then DROP ceiling_override to mimic a pre-WOR-705 DB."""
    db = await _open(tmp_path)
    await db.execute("ALTER TABLE enrollment_config DROP COLUMN ceiling_override")
    await db.commit()
    return db


@pytest.mark.asyncio
async def test_settle_at_estimate_fails_closed_on_unmigrated_db(tmp_path) -> None:
    """A missing ceiling_override column must NOT crash settle — it bills the
    global floor. Otherwise the SELECT raises OperationalError, the txn rolls
    back, the hold orphans, and the disconnect goes un-billed (under-billing).
    """
    db = await _open_unmigrated(tmp_path)
    try:
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS, (
            "missing column must fail CLOSED to the global floor, not crash"
        )
        assert await _held(db, "k1") == 0, "hold must not be orphaned"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_fails_closed_on_unmigrated_db(tmp_path) -> None:
    """The sweeper backstop also bills the global floor when the column is
    missing — it reads ceilings via the batch path, which must fail closed too.
    """
    db = await _open_unmigrated(tmp_path)
    try:
        await db.execute(
            "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
            "VALUES ('orphan', 'k1', 0, datetime('now', '-1 hour'), 'openai')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 1
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_oversized_override_fails_closed_to_global(tmp_path) -> None:
    """worthless-8xdq follow-up (brutus PR #294): a stored override >= 2^63
    PARSES via int() but is too large for SQLite's signed-64-bit INTEGER, so
    charge=max(estimate, huge) would crash the spend_log INSERT with
    OverflowError (NOT OperationalError — the fail-closed guards miss it).
    Treat a non-representable value as garbage -> the global floor, no crash.
    """
    db = await _open(tmp_path)
    try:
        # Forced in via direct SQL (text; SQLite INTEGER affinity keeps it).
        await db.execute(
            "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) "
            "VALUES ('k1', '99999999999999999999999')"
        )
        await db.commit()
        ledger = SpendLedger(db)
        h = await ledger.hold("k1", estimate=0, cap=10_000_000, provider="openai")
        await ledger.settle_at_estimate(h)
        assert await _committed(db, "k1") == GLOBAL_CEILING_TOKENS, (
            "oversized override must fail closed to the global floor, not crash"
        )
        assert await _held(db, "k1") == 0, "hold must not be orphaned"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_oversized_override_does_not_block_sweep_batch(tmp_path) -> None:
    """A single oversized-override orphan must NOT roll back the whole sweep
    batch (which would re-hit it forever). Both orphans get billed."""
    db = await _open(tmp_path)
    try:
        await db.execute(
            "INSERT OR REPLACE INTO enrollment_config (key_alias, ceiling_override) "
            "VALUES ('poison', '99999999999999999999999')"
        )
        for alias in ("poison", "ok"):
            await db.execute(
                "INSERT INTO pending_charges (handle, key_alias, estimate, created_at, provider) "
                "VALUES (?, ?, 0, datetime('now', '-1 hour'), 'openai')",
                (f"h_{alias}", alias),
            )
        await db.commit()
        ledger = SpendLedger(db)
        assert await ledger.sweep(max_age_seconds=60) == 2
        assert await _committed(db, "poison") == GLOBAL_CEILING_TOKENS
        assert await _committed(db, "ok") == GLOBAL_CEILING_TOKENS
    finally:
        await db.close()

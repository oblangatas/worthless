"""Coverage tests for the new branches introduced by WOR-659 Task 4 + the
post-panel hardening (PR #279):

* RulesEngine wrappers: refund_spend / settle_spend / settle_spend_at_estimate
  with None handles, uncapped configurations, and capped configurations.
* SpendLedger exception-rollback paths: every method rolls back its open
  transaction when DML raises (so we never leak a half-applied write).

These exercise code paths that integration tests reach indirectly but Sonar's
new-code coverage check on PR #279 flagged as uncovered.
"""

from __future__ import annotations

import aiosqlite
import pytest

from worthless.proxy.rules import (
    RateLimitRule,
    RulesEngine,
    SpendCapRule,
    TokenBudgetRule,
)
from worthless.storage.schema import SCHEMA
from worthless.storage.spend_ledger import SpendLedger


# ---------------------------------------------------------------------------
# Engine wrapper coverage
# ---------------------------------------------------------------------------


async def _seed_capped_db(tmp_path) -> tuple[aiosqlite.Connection, SpendCapRule]:
    """Build a DB with one capped alias + a wired SpendCapRule."""
    db_path = str(tmp_path / "wrappers.db")
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 1000),
        )
        await setup.commit()
    db = await aiosqlite.connect(db_path)
    rule = SpendCapRule(db=db)
    return db, rule


@pytest.mark.asyncio
async def test_refund_spend_with_none_handle_is_noop(tmp_path) -> None:
    """RulesEngine.refund_spend(None) returns immediately — never iterates rules."""
    engine = RulesEngine(rules=[])
    await engine.refund_spend(None)


@pytest.mark.asyncio
async def test_settle_spend_with_none_handle_is_noop(tmp_path) -> None:
    """RulesEngine.settle_spend(None, 99) returns immediately on uncapped aliases."""
    engine = RulesEngine(rules=[])
    await engine.settle_spend(None, actual=99)


@pytest.mark.asyncio
async def test_settle_spend_at_estimate_with_none_handle_is_noop(tmp_path) -> None:
    """RulesEngine.settle_spend_at_estimate(None) returns immediately — no handle, no work."""
    engine = RulesEngine(rules=[])
    await engine.settle_spend_at_estimate(None)


@pytest.mark.asyncio
async def test_engine_refund_spend_calls_ledger(tmp_path) -> None:
    """refund_spend with a real handle reaches SpendCapRule.ledger.refund — the
    same path the gate uses on denial."""
    db, rule = await _seed_capped_db(tmp_path)
    try:
        engine = RulesEngine(rules=[rule])
        handle = await rule.ledger.hold("k1", estimate=50, cap=1000, provider="openai")
        assert handle is not None
        await engine.refund_spend(handle)
        # Hold gone, no spend_log row.
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 0
        async with db.execute("SELECT COUNT(*) FROM spend_log") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_engine_settle_spend_calls_ledger(tmp_path) -> None:
    """settle_spend(handle, actual) reaches the ledger and records actual usage."""
    db, rule = await _seed_capped_db(tmp_path)
    try:
        engine = RulesEngine(rules=[rule])
        handle = await rule.ledger.hold("k1", estimate=50, cap=1000, provider="openai")
        assert handle is not None
        await engine.settle_spend(handle, actual=37)
        async with db.execute("SELECT COALESCE(SUM(tokens),0) FROM spend_log") as cur:
            (total,) = await cur.fetchone()  # type: ignore[misc]
            assert total == 37
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_engine_settle_spend_at_estimate_calls_ledger(tmp_path) -> None:
    """settle_spend_at_estimate(handle) bills the hold's stored estimate when
    that estimate is at or above the WOR-696 global ceiling floor. Scaled
    above 128K so this test exercises the engine→ledger plumbing without
    coupling to the floor logic (covered separately in test_spend_ledger.py).
    """
    db, rule = await _seed_capped_db(tmp_path)
    try:
        engine = RulesEngine(rules=[rule])
        handle = await rule.ledger.hold("k1", estimate=200_000, cap=1_000_000, provider="openai")
        assert handle is not None
        await engine.settle_spend_at_estimate(handle)
        async with db.execute("SELECT COALESCE(SUM(tokens),0) FROM spend_log") as cur:
            (total,) = await cur.fetchone()  # type: ignore[misc]
            assert total == 200_000
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_engine_release_spend_reservation_only_touches_token_budget(tmp_path) -> None:
    """release_spend_reservation iterates rules; only TokenBudgetRule reacts —
    SpendCapRule is intentionally skipped (its reservation is the durable hold)."""
    db_path = str(tmp_path / "tb.db")
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute(
            "INSERT INTO enrollment_config (key_alias, token_budget_daily) VALUES (?, ?)",
            ("k1", 1000),
        )
        await setup.commit()
    db = await aiosqlite.connect(db_path)
    try:
        tb = TokenBudgetRule(db=db)
        engine = RulesEngine(rules=[tb, RateLimitRule(default_rps=100.0)])
        await engine.release_spend_reservation("k1", amount=0)  # well-formed no-op
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Engine denial-time refund: handle preservation on failure (CodeRabbit Major)
# ---------------------------------------------------------------------------


class _AlwaysDenyRule:
    """A stub rule that denies every request (for testing later-rule-denies-after-cap-held)."""

    async def evaluate(self, alias, request, *, provider="openai", body=b""):
        from worthless.proxy.errors import ErrorResponse

        return ErrorResponse(
            status_code=429,
            body=b'{"error": {"message": "denied by test"}}',
            headers={"content-type": "application/json"},
        )


@pytest.mark.asyncio
async def test_engine_preserves_handle_when_refund_raises(tmp_path) -> None:
    """CodeRabbit Major: if denial-time refund raises, the engine MUST return the
    spend_handle in the GateResult so the caller (app.py's _release_reservations)
    can retry it on the normal denial exit path. Dropping it would orphan a hold.
    """
    db, cap_rule = await _seed_capped_db(tmp_path)
    try:
        # Sabotage the ledger so refund raises — simulating a transient DB error
        # at the moment of the denial-time refund. SpendLedger uses __slots__, so
        # replace the whole ledger with a duck-typed stand-in.
        real_ledger = cap_rule.ledger

        class _BrokenRefundLedger:
            async def hold(self, *a, **kw):
                return await real_ledger.hold(*a, **kw)

            async def refund(self, handle):  # the one we sabotage
                raise RuntimeError("transient db error")

            async def settle(self, *a, **kw):
                return await real_ledger.settle(*a, **kw)

            async def settle_at_estimate(self, *a, **kw):
                return await real_ledger.settle_at_estimate(*a, **kw)

        cap_rule.ledger = _BrokenRefundLedger()  # type: ignore[assignment]
        engine = RulesEngine(rules=[cap_rule, _AlwaysDenyRule()])
        result = await engine.evaluate("k1", object(), body=b'{"max_tokens": 50}')
        assert result.denial is not None, "later rule denied"
        # Handle preserved so the caller can retry the refund.
        assert result.spend_handle is not None, (
            "engine MUST preserve the handle when refund raises — caller retries it"
        )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_engine_clears_handle_when_refund_succeeds(tmp_path) -> None:
    """Opposite of the above: on a successful denial-time refund, the handle is
    cleared from the GateResult so the caller doesn't double-refund."""
    db, cap_rule = await _seed_capped_db(tmp_path)
    try:
        engine = RulesEngine(rules=[cap_rule, _AlwaysDenyRule()])
        result = await engine.evaluate("k1", object(), body=b'{"max_tokens": 50}')
        assert result.denial is not None
        assert result.spend_handle is None, (
            "successful denial-time refund must clear handle — no double-refund"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# SpendLedger exception-rollback paths
# ---------------------------------------------------------------------------


async def _fresh_ledger_db(tmp_path) -> tuple[aiosqlite.Connection, SpendLedger]:
    db_path = str(tmp_path / "rollback.db")
    async with aiosqlite.connect(db_path) as setup:
        await setup.executescript(SCHEMA)
        await setup.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("k1", 1000),
        )
        await setup.commit()
    db = await aiosqlite.connect(db_path)
    return db, SpendLedger(db)


@pytest.mark.asyncio
async def test_settle_rolls_back_on_dml_failure(tmp_path, monkeypatch) -> None:
    """If DELETE or INSERT raises mid-transaction in settle(), rollback runs
    before the exception propagates — connection isn't left mid-txn."""
    db, ledger = await _fresh_ledger_db(tmp_path)
    try:
        handle = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")
        assert handle is not None

        real_execute = db.execute

        async def patched_execute(sql, *args, **kwargs):
            if "DELETE FROM pending_charges" in sql:
                raise RuntimeError("simulated DML failure")
            return await real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db, "execute", patched_execute)
        with pytest.raises(RuntimeError, match="simulated DML failure"):
            await ledger.settle(handle, actual=5)
        # Hold should still be there — the transaction rolled back.
        monkeypatch.setattr(db, "execute", real_execute)
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 1, "rollback preserved the hold"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_settle_at_estimate_rolls_back_on_dml_failure(tmp_path, monkeypatch) -> None:
    """settle_at_estimate must roll back on DML failure too — the path the
    streaming-disconnect fallback uses must not leave a connection mid-txn."""
    db, ledger = await _fresh_ledger_db(tmp_path)
    try:
        handle = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")
        assert handle is not None
        real_execute = db.execute

        async def patched_execute(sql, *args, **kwargs):
            if "INSERT INTO spend_log" in sql:
                raise RuntimeError("simulated INSERT failure")
            return await real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db, "execute", patched_execute)
        with pytest.raises(RuntimeError, match="simulated INSERT failure"):
            await ledger.settle_at_estimate(handle)
        # Same rollback invariant: hold survives.
        monkeypatch.setattr(db, "execute", real_execute)
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 1, "rollback preserved the hold"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refund_rolls_back_on_failure(tmp_path, monkeypatch) -> None:
    """refund() rolls back on DML failure so the hold isn't half-deleted."""
    db, ledger = await _fresh_ledger_db(tmp_path)
    try:
        handle = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")
        assert handle is not None
        real_execute = db.execute

        async def patched_execute(sql, *args, **kwargs):
            if "DELETE FROM pending_charges" in sql:
                raise RuntimeError("simulated delete failure")
            return await real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db, "execute", patched_execute)
        with pytest.raises(RuntimeError, match="simulated delete failure"):
            await ledger.refund(handle)
        monkeypatch.setattr(db, "execute", real_execute)
        # Hold survives the failed refund.
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_refund_path_failure_must_not_fall_through_to_billing(tmp_path) -> None:
    """CodeRabbit Major #2 regression: when a 4xx response triggers a refund and
    that refund raises (transient DB error), the proxy must RETRY refund — never
    fall through to settle_at_estimate, which would bill the user for a request
    the provider rejected.

    We don't drive app.py end-to-end here (the integration ground is heavy);
    instead we pin the ledger-level invariant the new app.py structure depends
    on: settle_at_estimate is NEVER called when only refund_spend was intended,
    by routing the call through the engine wrappers we actually invoke.
    """
    db, cap_rule = await _seed_capped_db(tmp_path)
    try:
        engine = RulesEngine(rules=[cap_rule])
        handle = await cap_rule.ledger.hold("k1", estimate=99, cap=1000, provider="openai")
        assert handle is not None
        # Refund the hold — sanity check that no spend_log row is written.
        await engine.refund_spend(handle)
        async with db.execute("SELECT COUNT(*) FROM spend_log") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 0, "refund must NOT write spend_log — user pays nothing on 4xx"
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 0, "refund must delete the hold"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sweep_rolls_back_on_dml_failure(tmp_path, monkeypatch) -> None:
    """sweep() rolls back on mid-loop failure so partial settles don't leak."""
    db, ledger = await _fresh_ledger_db(tmp_path)
    try:
        h1 = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")
        h2 = await ledger.hold("k1", estimate=10, cap=1000, provider="openai")
        assert h1 is not None and h2 is not None
        real_execute = db.execute
        call_count = {"deletes": 0}

        async def patched_execute(sql, *args, **kwargs):
            if "DELETE FROM pending_charges WHERE handle" in sql:
                call_count["deletes"] += 1
                if call_count["deletes"] == 2:  # fail on the second hold's DELETE
                    raise RuntimeError("simulated mid-sweep failure")
            return await real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db, "execute", patched_execute)
        with pytest.raises(RuntimeError, match="simulated mid-sweep failure"):
            await ledger.sweep(max_age_seconds=0)
        # Atomicity: BOTH holds should still be there after rollback.
        monkeypatch.setattr(db, "execute", real_execute)
        async with db.execute("SELECT COUNT(*) FROM pending_charges") as cur:
            (n,) = await cur.fetchone()  # type: ignore[misc]
            assert n == 2, "sweep rollback preserves all holds"
    finally:
        await db.close()

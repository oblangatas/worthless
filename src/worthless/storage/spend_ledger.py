"""Durable write-ahead spend ledger (WOR-659).

A request HOLDs its estimated cost before the upstream call, then SETTLEs to the
actual after; a crash leaves the hold standing (fail-closed) and :meth:`sweep`
bills it at estimate, never lost. Runs on the injected proxy connection (never a
fresh one) and serialises its own transactions with an ``asyncio.Lock`` so
concurrent callers can't collide on ``BEGIN IMMEDIATE``. Every transaction rolls
back on ANY exit — including ``asyncio.CancelledError`` (a client disconnect),
which is a ``BaseException`` and would otherwise leave the connection mid-txn.
"""

from __future__ import annotations

import asyncio
import secrets

import aiosqlite

from worthless.defaults import GLOBAL_CEILING_TOKENS

__all__ = ["SpendLedger"]

# 128-bit CSPRNG handle (SR-08: CSPRNG only — never the stdlib ``random``).
_HANDLE_BYTES = 16

# Largest value SQLite can store in a signed-64-bit INTEGER column. A charge
# above this raises OverflowError on INSERT (brutus PR #294, _effective_ceiling).
_SQLITE_INT64_MAX = 2**63 - 1


class SpendLedger:
    """Hold / settle / refund / sweep over the ``pending_charges`` table."""

    __slots__ = ("_db", "_lock")

    def __init__(self, db: aiosqlite.Connection, lock: asyncio.Lock | None = None) -> None:
        self._db = db
        # One lock per CONNECTION serialises BEGIN IMMEDIATE. Share it with every other
        # code path that opens a txn on this same connection (e.g. TokenBudgetRule), or two
        # different locks would let concurrent requests nest a transaction → crash.
        self._lock = lock if lock is not None else asyncio.Lock()

    async def hold(
        self,
        alias: str,
        estimate: int,
        cap: float,
        *,
        provider: str,
        model: str | None = None,
    ) -> str | None:
        """Reserve *estimate* against *cap*; return a handle, or None if it would
        exceed the cap (deny, nothing written). Token-denominated; to-cap is OK."""
        if estimate < 0:
            raise ValueError("SpendLedger.hold: estimate must be non-negative")
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._db.execute(
                    "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?",
                    (alias,),
                )
                crow = await cur.fetchone()
                committed = crow[0] if crow is not None else 0
                cur = await self._db.execute(
                    "SELECT COALESCE(SUM(estimate), 0) FROM pending_charges WHERE key_alias = ?",
                    (alias,),
                )
                hrow = await cur.fetchone()
                held = hrow[0] if hrow is not None else 0

                if committed + held + estimate > cap:
                    await self._db.rollback()
                    return None

                handle = secrets.token_hex(_HANDLE_BYTES)
                await self._db.execute(
                    "INSERT INTO pending_charges (handle, key_alias, estimate, provider, model)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (handle, alias, estimate, provider, model),
                )
                await self._db.commit()
                return handle
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

    async def settle(self, handle: str, actual: int) -> None:
        """Atomically swap the hold for one ``spend_log`` row at *actual*.
        Idempotent: a no-op if the hold is gone — safe once on every exit path."""
        if actual < 0:
            # A negative charge would poison the committed SUM for this alias.
            raise ValueError("SpendLedger.settle: actual must be non-negative")
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._db.execute(
                    "SELECT key_alias, provider, model FROM pending_charges WHERE handle = ?",
                    (handle,),
                )
                row = await cur.fetchone()
                if row is None:
                    await self._db.rollback()
                    return
                alias, provider, model = row
                await self._db.execute("DELETE FROM pending_charges WHERE handle = ?", (handle,))
                await self._db.execute(
                    "INSERT INTO spend_log (key_alias, tokens, model, provider)"
                    " VALUES (?, ?, ?, ?)",
                    (alias, actual, model, provider),
                )
                await self._db.commit()
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

    async def _ceiling_for(self, alias: str) -> int:
        """Per-key fail-closed ceiling for *alias*, clamped to the global floor.

        WOR-705: an operator may raise the ceiling for one key via
        ``enrollment_config.ceiling_override`` (e.g. a heavy-reasoning customer
        whose model's max-output exceeds the global 128K). The override can only
        RAISE the floor — a NULL, or any value below ``GLOBAL_CEILING_TOKENS``
        however it got there (direct SQL, a pre-validation row), falls back to
        the audited global. The global is an inviolable minimum at read time,
        independent of the setter's write-side validation.

        Runs on the same connection inside the caller's open transaction.
        """
        try:
            cur = await self._db.execute(
                "SELECT ceiling_override FROM enrollment_config WHERE key_alias = ?",
                (alias,),
            )
            row = await cur.fetchone()
        except aiosqlite.OperationalError:
            # Schema drift: e.g. the proxy was restarted on a DB enrolled by an
            # older version, so executescript(SCHEMA) (CREATE TABLE IF NOT
            # EXISTS) never added the ceiling_override column. Fail CLOSED to
            # the global floor rather than crashing — and rolling back — the
            # settle/sweep billing transaction (which would orphan the hold and
            # under-bill). A prepare error does not abort the open txn, so the
            # caller's DELETE+INSERT still commit at the global floor.
            return GLOBAL_CEILING_TOKENS
        return self._effective_ceiling(row[0] if row else None)

    @staticmethod
    def _effective_ceiling(override: object) -> int:
        """Clamp a raw stored override value to a safe int >= the global floor.

        worthless-8xdq: SQLite INTEGER affinity does NOT reject text/blob/inf,
        so a value forced in via direct SQL could be non-numeric. Coerce
        defensively — any conversion failure fails CLOSED to the global floor
        rather than crashing (and rolling back) the settle/sweep transaction.
        worthless-y14x: a float truncates toward zero, conservative for a floor.
        brutus PR #294: a value >= 2**63 PARSES via int() but is too large for
        SQLite's signed-64-bit INTEGER, so charging it would crash the spend_log
        INSERT with OverflowError — which is NOT OperationalError, so the
        settle/sweep guards would miss it and roll back (orphan + under-bill).
        Treat a non-representable value as garbage → the global floor too.
        NULL → the global floor. The global is an inviolable minimum regardless
        of what is stored.
        """
        if override is None:
            return GLOBAL_CEILING_TOKENS
        try:
            value = int(override)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError):
            return GLOBAL_CEILING_TOKENS
        if value > _SQLITE_INT64_MAX:
            # Not storable as a spend_log charge — fail closed, never crash.
            return GLOBAL_CEILING_TOKENS
        return max(value, GLOBAL_CEILING_TOKENS)

    async def _ceilings_for(self, aliases: set[str]) -> dict[str, int]:
        """Batch form of :meth:`_ceiling_for` — one query for many aliases.

        worthless-v2mr: the sweeper can process a large orphan batch after a
        mass crash; a per-orphan SELECT inside the write lock serialises N
        round-trips. Resolve them all in one query. Aliases absent from
        enrollment_config, or with a NULL/garbage override, fall back to the
        global floor via :meth:`_effective_ceiling`.
        """
        if not aliases:
            return {}
        ordered = list(aliases)
        placeholders = ",".join("?" * len(ordered))
        query = (
            "SELECT key_alias, ceiling_override FROM enrollment_config "  # noqa: S608  # nosec B608 — IN placeholders only; values are parameterized
            f"WHERE key_alias IN ({placeholders})"
        )
        try:
            cur = await self._db.execute(query, ordered)
            stored = {r[0]: r[1] for r in await cur.fetchall()}
        except aiosqlite.OperationalError:
            # Schema drift (missing ceiling_override on an un-migrated DB):
            # fail CLOSED to the global floor for every alias so the sweeper
            # backstop still bills orphans instead of crashing. See _ceiling_for.
            return {a: GLOBAL_CEILING_TOKENS for a in ordered}
        return {a: self._effective_ceiling(stored.get(a)) for a in ordered}

    async def settle_at_estimate(self, handle: str) -> None:
        """Atomically swap the hold for one ``spend_log`` row at the hold's STORED
        estimate (fail-closed fallback when the provider's actual usage can't be
        read — e.g. mid-stream client disconnect, malformed response). Idempotent:
        a no-op if the hold is gone. Same shape as :meth:`settle` but bills the
        admission estimate instead of waiting for the background sweeper.
        """
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._db.execute(
                    "SELECT key_alias, estimate, provider, model FROM pending_charges"
                    " WHERE handle = ?",
                    (handle,),
                )
                row = await cur.fetchone()
                if row is None:
                    await self._db.rollback()
                    return
                alias, estimate, provider, model = row
                # WOR-696: fail-closed metering. settle_at_estimate fires when
                # the actual usage is unreadable (disconnect, parse fail, stream
                # kill). The stored estimate may be tiny — or zero — for a
                # request that omitted max_tokens. Charge at least the ceiling
                # so the cap counter moves honestly. Direction of error is
                # conservative; we never under-bill on the fallback path.
                # WOR-705: the ceiling is per-key (override) clamped to global.
                charge = max(estimate, await self._ceiling_for(alias))
                await self._db.execute("DELETE FROM pending_charges WHERE handle = ?", (handle,))
                await self._db.execute(
                    "INSERT INTO spend_log (key_alias, tokens, model, provider)"
                    " VALUES (?, ?, ?, ?)",
                    (alias, charge, model, provider),
                )
                await self._db.commit()
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

    async def refund(self, handle: str) -> None:
        """Drop the hold with no ``spend_log`` write (pre-spend failure). Idempotent."""
        async with self._lock:
            try:
                await self._db.execute("DELETE FROM pending_charges WHERE handle = ?", (handle,))
                await self._db.commit()
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

    async def sweep(self, max_age_seconds: float) -> int:
        """Settle holds older than *max_age_seconds* at their estimate (fail-closed:
        bill orphans, never refund). Returns the count reaped."""
        if max_age_seconds < 0:
            # A negative age -> future cutoff that would bill fresh holds.
            raise ValueError("SpendLedger.sweep: max_age_seconds must be non-negative")
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._db.execute(
                    "SELECT handle, key_alias, estimate, provider, model FROM pending_charges"
                    " WHERE created_at <= datetime('now', ?)",
                    (f"-{int(max_age_seconds)} seconds",),
                )
                stale = list(await cur.fetchall())
                # worthless-v2mr: resolve every distinct alias's ceiling in ONE
                # query rather than a per-orphan SELECT inside the write lock.
                ceilings = await self._ceilings_for({alias for _, alias, *_ in stale})
                for handle, alias, estimate, provider, model in stale:
                    # WOR-696 / worthless-osgt: orphans from SIGKILL'd or
                    # crashed BackgroundTasks bypass the normal settle floor.
                    # Apply the same ceiling floor here so the sweeper backstop
                    # can't be exploited by killing the proxy between
                    # stream-start and settle. Upward-only — honest large
                    # estimates pass through unchanged.
                    # WOR-705: per-key override (clamped to global) applies here too.
                    charge = max(estimate, ceilings[alias])
                    await self._db.execute(
                        "DELETE FROM pending_charges WHERE handle = ?", (handle,)
                    )
                    await self._db.execute(
                        "INSERT INTO spend_log (key_alias, tokens, model, provider)"
                        " VALUES (?, ?, ?, ?)",
                        (alias, charge, model, provider),
                    )
                await self._db.commit()
                return len(stale)
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

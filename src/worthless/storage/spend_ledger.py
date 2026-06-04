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

__all__ = ["SpendLedger"]

# 128-bit CSPRNG handle (SR-08: CSPRNG only — never the stdlib ``random``).
_HANDLE_BYTES = 16


class SpendLedger:
    """Hold / settle / refund / sweep over the ``pending_charges`` table."""

    __slots__ = ("_db", "_lock")

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._lock = asyncio.Lock()  # serialise our txns so BEGIN IMMEDIATE can't collide

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
                for handle, alias, estimate, provider, model in stale:
                    await self._db.execute(
                        "DELETE FROM pending_charges WHERE handle = ?", (handle,)
                    )
                    await self._db.execute(
                        "INSERT INTO spend_log (key_alias, tokens, model, provider)"
                        " VALUES (?, ?, ?, ?)",
                        (alias, estimate, model, provider),
                    )
                await self._db.commit()
                return len(stale)
            except BaseException:  # noqa: BLE001 — roll back open txn on any exit (incl. cancel)
                await self._db.rollback()
                raise

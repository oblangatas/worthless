"""Durable write-ahead spend ledger (WOR-659).

A request HOLDs its estimated cost in ``pending_charges`` before the upstream
call, then SETTLEs to the actual amount after. A crash between hold and settle
leaves the hold standing — it counts against the cap (fail-closed) and is reaped
by :meth:`sweep` at its own estimate, never lost.

All SQL runs on the INJECTED connection (never a fresh ``aiosqlite.connect``) so
it inherits ``busy_timeout`` and serialises with the proxy's other writes. A
per-instance ``asyncio.Lock`` serialises this ledger's own transactions so
concurrent callers sharing the one connection can't collide on ``BEGIN
IMMEDIATE`` (``cannot start a transaction within a transaction``) — mirroring the
rules engine's ``_reserve_lock``.
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
        # Serialises this ledger's transactions on the shared connection so
        # concurrent BEGIN IMMEDIATE calls can't collide.
        self._lock = asyncio.Lock()

    async def hold(
        self,
        alias: str,
        estimate: int,
        cap: float,
        *,
        provider: str,
        model: str | None = None,
    ) -> str | None:
        """Reserve *estimate* against *cap* in one transaction.

        Returns a fresh handle, or ``None`` if ``committed + held + estimate``
        would exceed the cap (deny — nothing is written). *estimate* and *cap*
        are token-denominated; spending exactly to the cap is allowed (``>``).
        """
        if estimate < 0:
            # A negative reservation would buy back cap headroom — never legitimate.
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
            except BaseException:  # noqa: BLE001
                # Roll back the open transaction on ANY abnormal exit — including
                # asyncio.CancelledError (a client disconnect), which is a
                # BaseException and would otherwise leave the transaction dangling
                # and break the next request ("transaction within transaction").
                await self._db.rollback()
                raise

    async def settle(self, handle: str, actual: int) -> None:
        """Atomically swap the hold for one ``spend_log`` row at *actual*.

        Idempotent: if the hold is already gone (settled or swept), this is a
        no-op — so it is safe to call on every request exit path exactly once.
        """
        if actual < 0:
            # A negative charge would drive the committed SUM down and poison the
            # running cap total for every future request on this alias.
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
            except BaseException:  # noqa: BLE001
                # Roll back the open transaction on ANY abnormal exit — including
                # asyncio.CancelledError (a client disconnect), which is a
                # BaseException and would otherwise leave the transaction dangling
                # and break the next request ("transaction within transaction").
                await self._db.rollback()
                raise

    async def refund(self, handle: str) -> None:
        """Drop the hold with NO ``spend_log`` write (pre-spend failure path).

        Idempotent — deleting an absent handle is a no-op.
        """
        async with self._lock:
            try:
                await self._db.execute("DELETE FROM pending_charges WHERE handle = ?", (handle,))
                await self._db.commit()
            except BaseException:  # noqa: BLE001
                await self._db.rollback()  # cancel-safe (see hold/settle/sweep)
                raise

    async def sweep(self, max_age_seconds: float) -> int:
        """Settle every hold older than *max_age_seconds* at its own estimate.

        Fail-closed: a crash-orphaned hold is BILLED (at its estimate), never
        refunded — so a lost request over-charges by at most one estimate rather
        than letting spend escape the cap. Returns the number of holds reaped.
        """
        if max_age_seconds < 0:
            # A negative age yields a FUTURE cutoff that would bill fresh holds.
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
            except BaseException:  # noqa: BLE001
                # Roll back the open transaction on ANY abnormal exit — including
                # asyncio.CancelledError (a client disconnect), which is a
                # BaseException and would otherwise leave the transaction dangling
                # and break the next request ("transaction within transaction").
                await self._db.rollback()
                raise

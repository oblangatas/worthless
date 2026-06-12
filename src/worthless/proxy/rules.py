"""Rules engine — gate-before-reconstruct pipeline (SR-03 / CRYP-05).

The rules engine evaluates a request BEFORE any key reconstruction occurs.
A denied request means zero KMS calls, zero reconstruction, zero key material.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, time as dt_time
from typing import Protocol, runtime_checkable
from zoneinfo import ZoneInfo

import aiosqlite

from worthless.proxy.errors import (
    ErrorResponse,
    rate_limit_error_response,
    spend_cap_error_response,
    time_window_error_response,
    token_budget_error_response,
)
from worthless.proxy.estimation import estimate_request_tokens
from worthless.storage.spend_ledger import SpendLedger

logger = logging.getLogger(__name__)

# Conservative upper bound for spend-cap reservation when max_tokens is absent.
_DEFAULT_TOKEN_ESTIMATE: int = 4096


def extract_model(body: bytes) -> str | None:
    """Best-effort model name from the request body, for hold bookkeeping only.

    Public helper — also used by the proxy handler for the WOR-696
    response-model mismatch audit. Returns ``None`` on parse failure,
    non-dict payload, or missing/non-string ``model`` field.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(payload, dict):
        model = payload.get("model")
        if isinstance(model, str):
            return model
    return None


def _estimate_tokens(body: bytes) -> int:
    """Best-effort token reservation estimate from request body.

    Reads ``max_tokens`` from the JSON body.  Falls back to _DEFAULT_TOKEN_ESTIMATE — a
    conservative upper bound so the spend cap remains a hard limit even
    when the client omits the field.
    """
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            v = payload.get("max_tokens")
            if isinstance(v, int) and v > 0:
                return v
    except (json.JSONDecodeError, ValueError):
        pass
    return _DEFAULT_TOKEN_ESTIMATE


def _release_into(reserved: dict[str, int], alias: str, amount: int) -> None:
    """Drop *amount* from a reservation dict, removing the key when fully released.

    Callers everywhere read via ``reserved.get(alias, 0)``, so absent == zero
    is the convention — keeping zero-valued entries would leak one dict slot
    per alias the proxy has ever seen.

    A non-positive ``amount`` is a no-op; otherwise ``held - amount`` with a
    negative ``amount`` would *inflate* the reservation.
    """
    if amount <= 0:
        return
    held = reserved.get(alias, 0)
    if alias not in reserved:
        logger.debug("release_reservation called for unreserved alias=%s amount=%d", alias, amount)
    remaining = max(0, held - amount)
    if remaining == 0:
        reserved.pop(alias, None)
    else:
        reserved[alias] = remaining


@dataclass
class GateResult:
    """Outcome of the gate pipeline: a denial (``None`` = allow) plus the durable
    spend-hold handle (``None`` = no cap configured / nothing held) to settle on
    success or refund on failure at the request's exit."""

    denial: ErrorResponse | None = None
    spend_handle: str | None = None


@runtime_checkable
class Rule(Protocol):
    """Protocol for a single rule in the gate-before-reconstruct pipeline.

    Most rules return ``ErrorResponse | None`` (deny / allow). ``SpendCapRule``
    returns a ``GateResult`` so its durable spend-hold handle can thread out; the
    engine normalises both.
    """

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | GateResult | None: ...


@dataclass
class RulesEngine:
    """Ordered chain of rules. Short-circuits on first denial."""

    rules: list[Rule]

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> GateResult:
        spend_handle: str | None = None
        for rule in self.rules:
            result = await rule.evaluate(alias, request, provider=provider, body=body)
            if isinstance(result, GateResult):
                if result.spend_handle is not None:
                    spend_handle = result.spend_handle
                denial = result.denial
            else:
                denial = result
            if denial is not None:
                # A later rule denied after the cap placed a durable hold — refund it,
                # so a denied request leaves no pending charge behind. If the refund
                # raises (transient DB error), KEEP the handle in the returned
                # GateResult so app.py's `_release_reservations` seam can retry it on
                # the denial exit path. Dropping it would orphan a pending_charges row.
                if spend_handle is not None:
                    try:
                        await self._refund(spend_handle)
                        spend_handle = None
                    except Exception:
                        logger.warning(
                            "denial-time refund failed; handle preserved for caller retry",
                            exc_info=True,
                        )
                return GateResult(denial=denial, spend_handle=spend_handle)
        return GateResult(spend_handle=spend_handle)

    async def _refund(self, spend_handle: str | None) -> None:
        if spend_handle is None:
            return
        for rule in self.rules:
            if isinstance(rule, SpendCapRule):
                await rule.ledger.refund(spend_handle)
                return

    async def refund_spend(self, spend_handle: str | None) -> None:
        """Drop a durable spend hold (pre-spend failure path). No-op if None."""
        await self._refund(spend_handle)

    async def settle_spend(self, spend_handle: str | None, actual: int) -> None:
        """Atomically convert a durable spend hold into recorded spend at *actual*.
        No-op if there was no hold (uncapped alias)."""
        if spend_handle is None:
            return
        for rule in self.rules:
            if isinstance(rule, SpendCapRule):
                await rule.ledger.settle(spend_handle, actual)
                return

    async def settle_spend_at_estimate(self, spend_handle: str | None) -> None:
        """Settle a hold at its STORED estimate — fail-closed fallback when actual
        usage can't be read (e.g. client disconnect mid-stream, response parse
        failure). Bills the cap immediately rather than waiting for the sweeper.
        No-op if there was no hold."""
        if spend_handle is None:
            return
        for rule in self.rules:
            if isinstance(rule, SpendCapRule):
                await rule.ledger.settle_at_estimate(spend_handle)
                return

    async def release_spend_reservation(self, alias: str, amount: int) -> None:
        """Release an in-memory token-budget reservation placed during evaluate().

        SpendCapRule no longer uses this — its reservation is the durable ledger
        hold, released via ``refund_spend`` / ``settle_spend``. No-op if amount is 0.
        """
        for rule in self.rules:
            if isinstance(rule, TokenBudgetRule):
                await rule.release_reservation(alias, amount)


@dataclass
class SpendCapRule:
    """Denies a request whose estimated cost won't fit under the configured cap.

    The reservation is a DURABLE write-ahead hold in the ledger (WOR-659): the
    request's estimated cost is held in ``pending_charges`` BEFORE reconstruct, so
    a single unaffordable request is denied up front and concurrent in-flight holds
    are counted (``committed + held + estimate > cap`` → deny). The hold is settled
    to actual usage on success or refunded on failure at the request's exit
    (via the engine). Fails closed (402) on any DB/ledger error. Returns a
    ``GateResult`` — no cap configured → allow with no handle.
    """

    db: aiosqlite.Connection
    lock: asyncio.Lock | None = None
    ledger: SpendLedger = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Construct the ledger ONCE, sharing the per-connection lock so its
        # BEGIN IMMEDIATE can't collide with another rule's txn on this connection.
        self.ledger = SpendLedger(self.db, lock=self.lock)

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> GateResult:
        try:
            # Plain SELECT (no BEGIN IMMEDIATE) — the atomic check-and-debit lives in
            # ledger.hold; opening our own txn here would nest inside hold's and crash.
            async with self.db.execute(
                "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?",
                (alias,),
            ) as cur:
                row = await cur.fetchone()
            if row is None or row[0] is None:
                return GateResult()  # no cap configured → allow, nothing held

            estimate = estimate_request_tokens(body)
            handle = await self.ledger.hold(
                alias, estimate, row[0], provider=provider, model=extract_model(body)
            )
            if handle is None:
                return GateResult(denial=spend_cap_error_response(provider=provider))
            return GateResult(spend_handle=handle)
        except Exception:
            # Fail closed: any DB/ledger error denies the request.
            return GateResult(denial=spend_cap_error_response(provider=provider))


@dataclass
class TokenBudgetRule:
    """Denies requests when token usage exceeds daily/weekly/monthly budgets.

    Queries spend_log with time-windowed SUM against enrollment_config budgets.
    Uses BEGIN IMMEDIATE like SpendCapRule for serialization.
    Fails closed on any DB error.
    Budget periods are UTC-anchored (SQLite datetime('now') is always UTC).

    Reservation mechanism (WOR-242): when a request passes the budget check, an
    in-memory reservation is held until ``release_reservation`` is called.
    Concurrent requests include the reservation in their effective-total check,
    preventing the same TOCTOU overrun as SpendCapRule.
    """

    db: aiosqlite.Connection
    lock: asyncio.Lock | None = None
    _reserved: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _reserve_lock: asyncio.Lock = field(init=False, repr=False)

    _PERIODS: tuple[tuple[str, str], ...] = (
        ("daily", "-1 day"),
        ("weekly", "-7 days"),
        ("monthly", "-30 days"),
    )

    def __post_init__(self) -> None:
        # Share ONE lock per connection with the ledger / SpendCapRule so a
        # BEGIN IMMEDIATE here can't nest inside another path's txn (concurrency).
        self._reserve_lock = self.lock if self.lock is not None else asyncio.Lock()

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None:
        try:
            async with self._reserve_lock:
                await self.db.execute("BEGIN IMMEDIATE")
                try:
                    async with self.db.execute(
                        "SELECT token_budget_daily, token_budget_weekly,"
                        " token_budget_monthly"
                        " FROM enrollment_config WHERE key_alias = ?",
                        (alias,),
                    ) as cur:
                        row = await cur.fetchone()

                    if row is None:
                        await self.db.execute("ROLLBACK")
                        return None

                    budgets = {
                        "daily": row[0],
                        "weekly": row[1],
                        "monthly": row[2],
                    }

                    # If all budgets are NULL, no limit
                    if all(v is None for v in budgets.values()):
                        await self.db.execute("ROLLBACK")
                        return None

                    # Single scan with conditional aggregation (efficiency: 1 query not 3)
                    async with self.db.execute(
                        "SELECT"
                        " COALESCE(SUM(CASE WHEN created_at >= datetime('now','-1 day')"
                        "   THEN tokens END), 0),"
                        " COALESCE(SUM(CASE WHEN created_at >= datetime('now','-7 days')"
                        "   THEN tokens END), 0),"
                        " COALESCE(SUM(tokens), 0)"
                        " FROM spend_log"
                        " WHERE key_alias = ?"
                        " AND created_at >= datetime('now', '-30 days')",
                        (alias,),
                    ) as cur:
                        used_daily, used_weekly, used_monthly = await cur.fetchone()  # type: ignore[assignment]

                    await self.db.execute("ROLLBACK")  # read-only, release lock
                except Exception:
                    try:
                        await self.db.execute("ROLLBACK")
                    except Exception:  # noqa: S110  # nosec B110
                        pass
                    raise

                usage = {
                    "daily": int(used_daily),
                    "weekly": int(used_weekly),
                    "monthly": int(used_monthly),
                }

                # Include in-flight reservations from concurrent requests.
                already_reserved = self._reserved.get(alias, 0)

                # Check each active period (including reservations)
                for period, _interval in self._PERIODS:
                    limit = budgets[period]
                    if limit is None:
                        continue
                    if usage[period] + already_reserved >= limit:
                        return token_budget_error_response(
                            period=period,
                            used=usage[period],
                            limit=int(limit),
                            provider=provider,
                        )

                # Compute remaining budget across all active periods; use the
                # most-constrained period as the reservation cap.
                min_remaining: int | None = None
                for period, _interval in self._PERIODS:
                    limit = budgets[period]
                    if limit is None:
                        continue
                    remaining = int(limit) - usage[period] - already_reserved
                    if min_remaining is None or remaining < min_remaining:
                        min_remaining = remaining

                if min_remaining is not None and min_remaining > 0:
                    reservation = min(_estimate_tokens(body), min_remaining)
                    self._reserved[alias] = already_reserved + reservation

            return None
        except Exception:
            # Fail-closed: any DB error -> deny request
            return token_budget_error_response(period="unknown", used=0, limit=0, provider=provider)

    async def release_reservation(self, alias: str, amount: int) -> None:
        """Return *amount* reserved tokens to the available token budget.

        Called after the actual spend has been recorded (or when the upstream
        request fails with no tokens consumed).  Safe to call with amount=0.
        """
        async with self._reserve_lock:
            _release_into(self._reserved, alias, amount)


@dataclass
class TimeWindowRule:
    """Denies requests outside configured time windows.

    Reads time_window JSON from enrollment_config. No BEGIN IMMEDIATE needed —
    pure read of config + clock check. Fails closed on invalid tz, malformed
    JSON, or any error.

    JSON format: {"start":"09:00","end":"17:00","tz":"America/New_York","days":[1,2,3,4,5]}
    - days: isoweekday (1=Monday, 7=Sunday). Missing → all days allowed.
    - tz: IANA timezone. Missing → UTC.
    - Overnight windows supported (end < start spans midnight).
    """

    db: aiosqlite.Connection

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None:
        try:
            async with self.db.execute(
                "SELECT time_window FROM enrollment_config WHERE key_alias = ?",
                (alias,),
            ) as cur:
                row = await cur.fetchone()

            if row is None or row[0] is None:
                return None

            config = json.loads(row[0])
            tz = ZoneInfo(config.get("tz", "UTC"))
            now = datetime.now(tz)

            # Check day of week
            allowed_days = config.get("days", [1, 2, 3, 4, 5, 6, 7])
            if now.isoweekday() not in allowed_days:
                return time_window_error_response(
                    current_time=now.strftime("%H:%M %Z"),
                    window=f"{config.get('start', '?')}-{config.get('end', '?')}",
                    provider=provider,
                )

            # Parse start/end times
            start = dt_time.fromisoformat(config["start"])
            end = dt_time.fromisoformat(config["end"])
            current = now.time()

            # Check time range (handle overnight windows where end < start)
            if start <= end:
                in_window = start <= current < end
            else:
                in_window = current >= start or current < end

            if not in_window:
                return time_window_error_response(
                    current_time=now.strftime("%H:%M %Z"),
                    window=f"{config['start']}-{config['end']}",
                    provider=provider,
                )

            return None
        except Exception:
            return time_window_error_response(
                current_time="unknown", window="unknown", provider=provider
            )


@dataclass
class RateLimitRule:
    """In-memory sliding window rate limiter keyed by (alias, client_ip).

    Uses time.monotonic() for window tracking. Not persisted across restarts.
    Returns 429 ErrorResponse with Retry-After when rate is exceeded.

    Periodically cleans up expired entries to bound memory usage (M-2).

    Per-enrollment rate limits are read from enrollment_config.rate_limit_rps
    on first access and cached in memory. Falls back to default_rps.
    """

    default_rps: float = 100.0
    cleanup_interval: float = 60.0
    db_path: str | None = None
    _windows: dict[tuple[str, str], list[float]] = field(
        default_factory=dict, init=False, repr=False
    )
    _locks: dict[tuple[str, str], asyncio.Lock] = field(
        default_factory=dict, init=False, repr=False
    )
    _last_cleanup: float = field(default=0.0, init=False, repr=False)
    _limits: dict[str, float] = field(default_factory=dict, init=False, repr=False)

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None:
        client_ip = getattr(getattr(request, "client", None), "host", "unknown")
        now = time.monotonic()
        key = (alias, client_ip)

        # Periodic cleanup of stale entries (M-2: bound memory)
        if now - self._last_cleanup >= self.cleanup_interval:
            self._cleanup(now)
            self._last_cleanup = now

        # Per-key lock serializes the read-check-update cycle to prevent
        # concurrent requests from observing stale window state (worthless-ks6).
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()

        async with self._locks[key]:
            # Prune timestamps older than 1 second for this key
            window = self._windows.get(key, [])
            cutoff = now - 1.0
            window = [t for t in window if t > cutoff]

            # Use per-enrollment limit if available, otherwise default
            if alias not in self._limits and self.db_path is not None:
                await self._load_limit(alias)
            rps = self._limits.get(alias, self.default_rps)

            if len(window) >= rps:
                # Calculate retry-after: time until oldest entry expires
                retry_after = max(1, int(window[0] + 1.0 - now) + 1)
                self._windows[key] = window
                return rate_limit_error_response(retry_after=retry_after, provider=provider)

            window.append(now)
            self._windows[key] = window
            return None

    def _cleanup(self, now: float) -> None:
        """Remove all entries where the latest timestamp is older than 2 seconds."""
        ttl_cutoff = now - 2.0
        stale_keys = [
            k
            for k, timestamps in self._windows.items()
            if not timestamps or max(timestamps) < ttl_cutoff
        ]
        for k in stale_keys:
            del self._windows[k]
            self._locks.pop(k, None)

    async def _load_limit(self, alias: str) -> None:
        """Load per-enrollment rate limit from DB into cache."""
        async with aiosqlite.connect(self.db_path) as db:  # type: ignore[arg-type]
            async with db.execute(
                "SELECT rate_limit_rps FROM enrollment_config WHERE key_alias = ?",
                (alias,),
            ) as cur:
                row = await cur.fetchone()
        if row is not None and row[0] is not None:
            self._limits[alias] = float(row[0])

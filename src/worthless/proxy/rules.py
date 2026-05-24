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

logger = logging.getLogger(__name__)

# Conservative upper bound for spend-cap reservation when max_tokens is absent.
_DEFAULT_TOKEN_ESTIMATE: int = 4096


def _estimate_input_tokens(messages: list) -> int:
    """Estimate input token count from a messages list.

    Uses a character-count / 4 heuristic — a lower-bound approximation that
    avoids importing tiktoken at runtime. Image blocks are estimated at a
    fixed 1 000 tokens (4 000 chars) to capture vision cost.

    worthless-dupf.2: input tokens are the dominant cost for large-prompt
    abuse; not counting them lets an attacker bypass the spend cap by sending
    huge prompts with a tiny max_tokens value.
    """
    total_chars = 0
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")
                if btype == "text":
                    total_chars += len(block.get("text", ""))
                elif btype in ("image_url", "image"):
                    # Fixed estimate: ~1 000 tokens per image (4 chars / token)
                    total_chars += 4_000
    return total_chars // 4


def _estimate_tokens(body: bytes) -> int:
    """Best-effort token reservation estimate from request body.

    Combines output tokens (``max_tokens``) with input token cost estimated
    from the ``messages`` field. Falls back to _DEFAULT_TOKEN_ESTIMATE for
    the output side when the client omits max_tokens.

    worthless-dupf.2: reserving output tokens only lets an attacker bypass
    the spend cap by sending huge prompts — input cost goes untracked.
    Combining both makes the reservation conservative across all request shapes.
    """
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            v = payload.get("max_tokens")
            output_tokens = v if (isinstance(v, int) and v > 0) else _DEFAULT_TOKEN_ESTIMATE

            messages = payload.get("messages")
            input_tokens = _estimate_input_tokens(messages) if isinstance(messages, list) else 0

            return output_tokens + input_tokens
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


@runtime_checkable
class Rule(Protocol):
    """Protocol for a single rule in the gate-before-reconstruct pipeline."""

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None: ...


@dataclass
class RulesEngine:
    """Ordered chain of rules. Short-circuits on first denial."""

    rules: list[Rule]

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None:
        for rule in self.rules:
            result = await rule.evaluate(alias, request, provider=provider, body=body)
            if result is not None:
                return result
        return None

    async def release_spend_reservation(self, alias: str, amount: int) -> None:
        """Release a spend reservation placed by SpendCapRule and/or
        TokenBudgetRule during evaluate().

        No-op if neither rule is in the rule list or amount is 0.
        """
        for rule in self.rules:
            if isinstance(rule, SpendCapRule):
                await rule.release_reservation(alias, amount)
            elif isinstance(rule, TokenBudgetRule):
                await rule.release_reservation(alias, amount)


@dataclass
class SpendCapRule:
    """Denies requests when accumulated spend exceeds the configured cap.

    Queries spend_log and enrollment_config tables via a persistent aiosqlite
    connection. Uses BEGIN IMMEDIATE to serialize concurrent reads (H-3).
    Fails closed on any DB error (H-1/M-10).
    Returns None if no cap is configured (NULL spend_cap) or spend is under cap.
    Returns 402 ErrorResponse when cap is exceeded or on DB error.

    Reservation mechanism (WOR-242): when a request passes the cap check, an
    in-memory reservation of ``_estimate_tokens(body)`` tokens is held until
    ``release_reservation`` is called.  Subsequent concurrent requests include
    the reservation in their effective-total calculation, preventing the TOCTOU
    overrun that arises when N requests all read the same stale DB total.
    """

    db: aiosqlite.Connection
    _reserved: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _reserve_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def evaluate(
        self, alias: str, request: object, *, provider: str = "openai", body: bytes = b""
    ) -> ErrorResponse | None:
        try:
            async with self._reserve_lock:
                # BEGIN IMMEDIATE acquires a write lock, serialising concurrent
                # readers on this connection (H-3).
                await self.db.execute("BEGIN IMMEDIATE")
                try:
                    async with self.db.execute(
                        "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?",
                        (alias,),
                    ) as cur:
                        row = await cur.fetchone()

                    if row is None:
                        await self.db.execute("ROLLBACK")
                        return None

                    spend_cap = row[0]
                    if spend_cap is None:
                        await self.db.execute("ROLLBACK")
                        return None

                    async with self.db.execute(
                        "SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?",
                        (alias,),
                    ) as cur:
                        (total_tokens,) = await cur.fetchone()  # type: ignore[assignment]

                    await self.db.execute("ROLLBACK")
                except Exception:
                    try:
                        await self.db.execute("ROLLBACK")
                    except Exception:  # noqa: S110  # nosec B110
                        pass
                    raise

                # Include in-flight reservations from concurrent requests.
                already_reserved = self._reserved.get(alias, 0)
                if total_tokens + already_reserved >= spend_cap:
                    return spend_cap_error_response(provider=provider)

                # Reserve up to the remaining budget so concurrent requests
                # correctly observe that capacity is taken.
                remaining = int(spend_cap) - total_tokens - already_reserved
                reservation = min(_estimate_tokens(body), remaining)
                self._reserved[alias] = already_reserved + reservation

            return None
        except Exception:
            return spend_cap_error_response(provider=provider)

    async def release_reservation(self, alias: str, amount: int) -> None:
        """Return *amount* reserved tokens to the available budget.

        Called after the actual spend has been recorded (or when the upstream
        request fails with no tokens consumed).  Safe to call with amount=0.
        """
        async with self._reserve_lock:
            _release_into(self._reserved, alias, amount)


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
    _reserved: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _reserve_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    _PERIODS: tuple[tuple[str, str], ...] = (
        ("daily", "-1 day"),
        ("weekly", "-7 days"),
        ("monthly", "-30 days"),
    )

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

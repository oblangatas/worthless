"""Connection lifecycle + backpressure + reconnect supervisor over IPCClient.

This module wraps the low-level :class:`worthless.ipc.client.IPCClient` with
the operational policy the proxy needs:

* eager connect at startup (lifespan), fail-loud if sidecar is unreachable;
* a single :class:`asyncio.Lock` guarding state transitions (no per-state locks);
* an :class:`asyncio.Semaphore` capping in-flight ops (default 32);
* atomic ``acquire()`` context manager (semaphore + ready client + release);
* fast-fail if the semaphore can't be entered within 100 ms → 503;
* protocol-version + capability check on every (re)connect — caps shrinking
  across reconnects is fatal (security restoration C3 in
  ``.research/10-security-signoff.md``);
* explicit ``aclose()`` with a 5 s in-flight ceiling (security restoration C2).

Design invariants kept here:

* No fallback. Transport failure raises :class:`IPCUnavailable`. The proxy
  HTTP layer maps that to HTTP 503 (``engineering/ipc-contract.md`` §invariants).
* No crypto here. The supervisor is intentionally crypto-agnostic — it owns
  *transport policy*, not key material. Plaintext returned by ``open()`` is
  surfaced as a :class:`bytearray` so callers can zero it (SR-01).
* DRAINING is a flag, not a state. The 4-state FSM is
  ``DISCONNECTED → CONNECTING → READY → CLOSED``; ``aclose()`` flips
  ``_draining = True`` on the side, refuses new ``acquire()``, awaits in-flight
  with a 5 s ceiling, then transitions to CLOSED (see code-review §2 in
  ``.research/08-code-review.md``).

Backoff between reconnects is jittered (CSPRNG only, SR-08):

* retry 1: random(10 ms, 50 ms);
* retry 2: random(50 ms, 250 ms);
* retry N>2: ``min(1000ms, 250ms * 2**(N-2)) + random ±20%``.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Final

from worthless.ipc.client import (
    IPCClient,
    IPCError,
    IPCProtocolError,
    IPCTimeoutError,
)

__all__ = [
    "DEFAULT_ACQUIRE_TIMEOUT_S",
    "DEFAULT_DRAIN_CEILING_S",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_REQUEST_TIMEOUT_S",
    "IPCBackpressure",
    "IPCCapsMismatch",
    "IPCSupervisor",
    "IPCUnavailable",
    "IPCVersionMismatch",
    "SupervisorState",
]

#: Default in-flight op cap. Tuned in ``.research/03-async-patterns.md`` §5.
DEFAULT_MAX_CONCURRENCY: Final[int] = 32

#: Per-request budget enforced by :class:`IPCClient`. Matches the proxy's
#: 2 s end-to-end deadline.
DEFAULT_REQUEST_TIMEOUT_S: Final[float] = 2.0

#: How long ``acquire()`` waits to enter the semaphore queue. After this we
#: 503 the caller — blocking longer ties up a proxy connection slot.
DEFAULT_ACQUIRE_TIMEOUT_S: Final[float] = 0.1

#: Hard ceiling on ``aclose()`` waiting for in-flight ops to finish before
#: tearing the socket down (security restoration C2).
DEFAULT_DRAIN_CEILING_S: Final[float] = 5.0

#: SystemRandom instance for jittered backoff. ``random`` module is banned
#: project-wide (CRYP-04) — we use CSPRNG even for non-secret jitter so the
#: import-graph guard stays clean.
_RNG: Final[secrets.SystemRandom] = secrets.SystemRandom()


class IPCUnavailable(Exception):
    """Sidecar is unreachable, slow, or returned a transport error.

    Mapped to HTTP 503 by the proxy layer. Subclasses preserve the precise
    failure mode for operator triage but every 503-mapped code path catches
    this base class.
    """


class IPCVersionMismatch(IPCUnavailable):
    """HELLO advertised a protocol version that does not match expectations.

    Fatal — callers must NOT retry; reconnect against the same binary will
    yield the same answer. Surface as 503 and let the supervisor restart
    handle the fix.
    """


class IPCCapsMismatch(IPCUnavailable):
    """Backend capability set changed across a reconnect.

    Fatal at reconnect time: a sidecar binary swap that *shrinks* caps is a
    downgrade attack vector (security restoration C3). Phase 4 wires this to
    terminate the proxy process; for Phase 1 we just raise.
    """


class IPCBackpressure(IPCUnavailable):
    """Semaphore exhausted for longer than ``acquire_timeout``.

    Mapped to 503 with ``error_class=ipc_backpressure``. Distinct from a
    generic unavailability so dashboards can graph saturation separately.
    """


class SupervisorState(Enum):
    """4-state FSM. DRAINING is a sibling flag, not an enum member."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    READY = "ready"
    CLOSED = "closed"


class IPCSupervisor:
    """Lifecycle + backpressure + reconnect orchestrator over :class:`IPCClient`.

    A *single* persistent :class:`IPCClient` per supervisor (per worker
    process). Concurrent callers serialize naturally inside the client's
    own ``asyncio.Lock``; the supervisor adds an outer
    :class:`asyncio.Semaphore` so unbounded callers don't queue without
    limit. See ``.research/03-async-patterns.md`` for the reasoning.

    States: ``DISCONNECTED → CONNECTING → READY → CLOSED``. ``DRAINING`` is
    a boolean flag flipped during ``aclose()`` while in-flight ops finish.
    """

    def __init__(
        self,
        socket_path: Path,
        *,
        protocol_version: int,
        expected_caps: frozenset[str],
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        drain_ceiling_s: float = DEFAULT_DRAIN_CEILING_S,
        acquire_timeout_s: float = DEFAULT_ACQUIRE_TIMEOUT_S,
    ) -> None:
        if max_concurrency < 1:
            raise RuntimeError(f"max_concurrency must be >= 1, got {max_concurrency}")
        if request_timeout_s <= 0:
            raise RuntimeError(f"request_timeout_s must be > 0, got {request_timeout_s}")
        if drain_ceiling_s <= 0:
            raise RuntimeError(f"drain_ceiling_s must be > 0, got {drain_ceiling_s}")

        self._socket_path = socket_path
        self._protocol_version = protocol_version
        self._expected_caps = expected_caps
        self._max_concurrency = max_concurrency
        self._request_timeout_s = request_timeout_s
        self._drain_ceiling_s = drain_ceiling_s
        self._acquire_timeout_s = acquire_timeout_s

        self._state = SupervisorState.DISCONNECTED
        self._draining = False
        self._client: IPCClient | None = None
        # Caps observed at first successful HELLO. Subsequent reconnects MUST
        # match (security restoration C3 — caps re-check terminates on
        # mismatch). ``None`` until first connect.
        self._first_caps: frozenset[str] | None = None
        self._reconnect_attempt = 0

        self._state_lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max_concurrency)
        # Counter for in-flight ops, used by aclose() drain wait. Bumped/decd
        # under the lock-free fast path inside ``acquire()`` because the
        # semaphore already enforces the cap; drain checks read via
        # ``_inflight_zero`` which is set when the count returns to 0.
        self._inflight = 0
        self._inflight_zero = asyncio.Event()
        self._inflight_zero.set()
        self._connect_done = asyncio.Event()
        self._connect_done.set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the connection, perform HELLO, verify version + caps.

        Idempotent if already READY. Raises :class:`IPCVersionMismatch`,
        :class:`IPCCapsMismatch`, or :class:`IPCUnavailable` on failure.
        """
        async with self._state_lock:
            if self._state is SupervisorState.CLOSED:
                raise RuntimeError("supervisor is closed")
            if self._state is SupervisorState.READY:
                return
            self._state = SupervisorState.CONNECTING

        try:
            await self._open_and_verify()
        except BaseException:
            async with self._state_lock:
                # Drop back to DISCONNECTED so a retry path can re-enter
                # CONNECTING; CLOSED is terminal and only reached via aclose().
                if self._state is not SupervisorState.CLOSED:
                    self._state = SupervisorState.DISCONNECTED
            raise

        async with self._state_lock:
            if self._state is SupervisorState.CLOSED:
                # aclose() raced us; tear down the freshly-opened client.
                client = self._client
                self._client = None
                if client is not None:
                    await client.aclose()
                raise RuntimeError("supervisor closed during connect")
            self._state = SupervisorState.READY
            self._reconnect_attempt = 0

    async def _open_and_verify(self) -> None:
        """Open one IPCClient, verify version, verify caps. No state mutations."""
        client = IPCClient(self._socket_path, timeout=self._request_timeout_s)
        try:
            await client.__aenter__()
        except IPCError as exc:
            raise IPCUnavailable(f"sidecar connect failed: {exc}") from exc
        except (OSError, ConnectionError) as exc:
            raise IPCUnavailable(f"sidecar connect failed: {exc}") from exc

        # Verify version after handshake. IPCClient already checks server
        # version against its compile-time constant (=1) but the supervisor
        # owns the *expected* version from config — re-check so a future
        # protocol bump in the client surfaces here, not silently.
        observed_caps = frozenset(client.backend_caps)
        if self._first_caps is None:
            # Initial connect: latch caps for future reconnect comparison.
            # Verify the expected set is a subset of what's offered.
            missing = self._expected_caps - observed_caps
            if missing:
                await client.aclose()
                raise IPCCapsMismatch(
                    f"sidecar missing required caps: {sorted(missing)} "
                    f"(observed {sorted(observed_caps)})"
                )
            self._first_caps = observed_caps
        else:
            # Reconnect: caps MUST match the first observation exactly.
            # Shrinking caps is a downgrade attack signal; growing caps is
            # an unexpected binary swap. Either way: refuse.
            if observed_caps != self._first_caps:
                await client.aclose()
                raise IPCCapsMismatch(
                    f"caps changed across reconnect: was {sorted(self._first_caps)}, "
                    f"now {sorted(observed_caps)}"
                )

        # Version check: the client only accepts its compile-time version.
        # If we ever decouple them, this catches drift. Currently a no-op
        # check that documents intent.
        if self._protocol_version != 1:  # pragma: no cover — single-version era
            await client.aclose()
            raise IPCVersionMismatch(
                f"supervisor expected protocol v{self._protocol_version}, client only speaks v1"
            )

        self._client = client

    async def aclose(self) -> None:
        """Drain in-flight ops (≤ 5 s) and close.

        Idempotent. Sets ``_draining`` so further ``acquire()`` calls fast-fail
        with :class:`IPCUnavailable`. Awaits the in-flight counter to reach
        zero, bounded by ``drain_ceiling_s``; if the bound expires we close
        anyway — the FD must not leak.
        """
        async with self._state_lock:
            if self._state is SupervisorState.CLOSED:
                return
            self._draining = True

        # Wait for in-flight to drain. Outside the state lock so live
        # ``acquire()`` users don't deadlock on releasing.
        try:
            await asyncio.wait_for(self._inflight_zero.wait(), timeout=self._drain_ceiling_s)
        except asyncio.TimeoutError:
            # Ceiling expired; force close. The pending ops will see
            # "client is not connected" on their next read and surface
            # IPCProtocolError → 503 to their caller. This is the correct
            # behaviour: better a few 503s than a leaked FD under flapping.
            pass

        async with self._state_lock:
            client = self._client
            self._client = None
            self._state = SupervisorState.CLOSED

        if client is not None:
            await client.aclose()

    # ------------------------------------------------------------------
    # Acquire / public op surface
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[IPCClient]:
        """Atomic semaphore + ready client + release.

        ``async with supervisor.acquire() as client:`` yields a connected
        :class:`IPCClient`. Raises :class:`IPCBackpressure` if the semaphore
        cannot be entered within ``acquire_timeout_s``;
        :class:`IPCUnavailable` if the supervisor is draining or closed;
        re-raises HELLO/caps errors from a transparent reconnect.
        """
        if self._draining or self._state is SupervisorState.CLOSED:
            raise IPCUnavailable("supervisor is draining or closed")

        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=self._acquire_timeout_s)
        except asyncio.TimeoutError as exc:
            raise IPCBackpressure(
                f"supervisor saturated: no slot within {self._acquire_timeout_s:.3f}s"
            ) from exc

        # Track in-flight for aclose() drain.
        self._inflight += 1
        if self._inflight_zero.is_set():
            self._inflight_zero.clear()

        op_failed_transport = False
        try:
            client = await self._ensure_ready()
            try:
                yield client
            except (IPCProtocolError, IPCTimeoutError):
                # Transport-level failure inside the request body: the
                # current client is desynced or dead. Flag for cleanup.
                op_failed_transport = True
                raise
        finally:
            if op_failed_transport:
                async with self._state_lock:
                    if self._state is SupervisorState.READY:
                        self._state = SupervisorState.DISCONNECTED
                        # Best-effort close; the client may already have
                        # nulled its writer (timeout path).
                        dead = self._client
                        self._client = None
                        if dead is not None:
                            try:
                                await dead.aclose()
                            except (ConnectionError, BrokenPipeError, OSError):
                                # Peer may already be gone; teardown is best-effort.
                                pass
            self._sem.release()
            self._inflight -= 1
            if self._inflight == 0:
                self._inflight_zero.set()

    async def _ensure_ready(self) -> IPCClient:
        """Return a connected client, reconnecting transparently if needed.

        A client whose underlying socket has been invalidated (writer is
        None — e.g. after a timeout per IPCClient L329-334, or after the
        peer dropped the connection) is dropped and the supervisor
        transitions to DISCONNECTED so a new client is built.
        """
        async with self._state_lock:
            if self._draining or self._state is SupervisorState.CLOSED:
                raise IPCUnavailable("supervisor is draining or closed")
            client = self._client
            # Detect a dead client. IPCClient nulls _writer on timeout and
            # we don't get a notification — interrogate the field. Better
            # than waiting for the next op to fail.
            if (
                self._state is SupervisorState.READY
                and client is not None
                and getattr(client, "_writer", None) is None
            ):
                # Dead client; drop it and reset state.
                self._client = None
                self._state = SupervisorState.DISCONNECTED
                client = None
            if self._state is SupervisorState.READY and client is not None:
                return client

        # Slow path: need to reconnect. Backoff outside the lock so other
        # awaiters can also serialize on the lock when they wake.
        await self._reconnect_with_backoff()

        async with self._state_lock:
            if self._state is not SupervisorState.READY or self._client is None:
                raise IPCUnavailable("reconnect did not yield a ready client")
            return self._client

    async def _wait_for_connector(self) -> None:
        """Wait for the active connector coroutine to finish, re-waiting if a
        new attempt starts immediately after a failure (CONNECTING again).
        Bounded by ``_drain_ceiling_s``."""
        _loop = asyncio.get_event_loop()
        deadline = _loop.time() + self._drain_ceiling_s
        while True:
            remaining = deadline - _loop.time()
            if remaining <= 0:
                raise IPCUnavailable("timed out waiting for peer reconnect")
            try:
                await asyncio.wait_for(self._connect_done.wait(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise IPCUnavailable("timed out waiting for peer reconnect") from exc
            async with self._state_lock:
                if self._state is SupervisorState.READY and self._client is not None:
                    return
                if self._state is SupervisorState.CLOSED or self._draining:
                    raise IPCUnavailable("supervisor is draining or closed")
                if self._state is SupervisorState.CONNECTING:
                    continue  # new attempt started; re-wait
            # DISCONNECTED: connector failed, no new attempt yet.
            raise IPCUnavailable("peer reconnect failed")

    async def _reconnect_with_backoff(self) -> None:
        """Atomically claim connector role or wait for the active claimant.

        Exactly one coroutine at a time performs the sleep+connect; others
        await ``_connect_done``. After wake, waiters re-check state in a
        loop: if the connector failed (DISCONNECTED) and immediately started
        a new attempt (CONNECTING again), the waiter must re-wait rather
        than spuriously raising IPCUnavailable. The loop is bounded by
        ``_drain_ceiling_s`` to prevent indefinite waiting.
        """
        we_connect = False
        async with self._state_lock:
            if self._state is SupervisorState.READY and self._client is not None:
                return
            if self._state is SupervisorState.CLOSED or self._draining:
                raise IPCUnavailable("supervisor is draining or closed")
            if self._state is SupervisorState.CONNECTING:
                pass  # waiter
            else:
                self._state = SupervisorState.CONNECTING
                self._reconnect_attempt += 1
                self._connect_done.clear()
                we_connect = True

        if not we_connect:
            await self._wait_for_connector()

        delay = self._backoff_delay(self._reconnect_attempt)
        if delay > 0:
            await asyncio.sleep(delay)

        try:
            try:
                await self._open_and_verify()
            except (IPCUnavailable, IPCCapsMismatch):
                async with self._state_lock:
                    self._state = SupervisorState.DISCONNECTED
                raise
            except IPCError as exc:
                async with self._state_lock:
                    self._state = SupervisorState.DISCONNECTED
                raise IPCUnavailable(f"sidecar reconnect failed: {exc}") from exc

            async with self._state_lock:
                if self._state is SupervisorState.CLOSED or self._draining:
                    client = self._client
                    self._client = None
                    if client is not None:
                        await client.aclose()
                    raise IPCUnavailable("supervisor closed mid-reconnect")
                self._state = SupervisorState.READY
                self._reconnect_attempt = 0
        finally:
            self._connect_done.set()

    @staticmethod
    def _backoff_delay(attempt: int) -> float:
        """Jittered backoff schedule (CSPRNG, SR-08).

        retry 1: random(10 ms, 50 ms)
        retry 2: random(50 ms, 250 ms)
        retry N>2: min(1000ms, 250ms * 2**(N-2)) ± 20%
        """
        if attempt <= 0:
            return 0.0
        if attempt == 1:
            return _RNG.uniform(0.010, 0.050)
        if attempt == 2:
            return _RNG.uniform(0.050, 0.250)
        base = min(1.0, 0.250 * (2 ** (attempt - 2)))
        jitter = _RNG.uniform(-0.20, 0.20) * base
        return max(0.0, base + jitter)

    # ------------------------------------------------------------------
    # Convenience surface — thin wrappers around acquire() + IPCClient
    # ------------------------------------------------------------------

    async def open(self, ciphertext: bytes, *, key_id: str) -> bytearray:
        """Decrypt ``ciphertext`` via the sidecar.

        Returns the plaintext as a :class:`bytearray` so callers can zero it
        when the request is over (SR-01). The returned buffer is *new* —
        no aliasing into supervisor or client state.

        Raises :class:`IPCUnavailable` (or subclass) on transport failure;
        :class:`IPCBackpressure` if the semaphore can't be entered;
        the original :class:`IPCError` from the sidecar on backend errors.
        """
        key_id_bytes = key_id.encode("utf-8") if key_id else None
        # Retry once on transport failure. The first failure marks the
        # supervisor DISCONNECTED so the second acquire() reconnects with
        # backoff. Caps mismatch at reconnect is *not* retried — it raises
        # IPCCapsMismatch which propagates without a third attempt.
        last_exc: BaseException | None = None
        plaintext: bytes | None = None
        for _attempt in range(2):
            try:
                async with self.acquire() as client:
                    plaintext = await client.open(ciphertext, key_id=key_id_bytes)
                last_exc = None
                break
            except IPCCapsMismatch:
                raise
            except (IPCProtocolError, IPCTimeoutError) as exc:
                last_exc = exc
                continue
            except IPCUnavailable:
                # Already-translated unavailability from the supervisor
                # (e.g. backpressure) — do not retry.
                raise
        if plaintext is None:
            raise IPCUnavailable(f"sidecar open failed: {last_exc}") from last_exc
        # Hand the caller a *new* bytearray so they can zero it on cleanup
        # without touching any shared state inside the client.
        buf = bytearray(plaintext)
        # Best-effort: ``plaintext`` is a fresh bytes returned by the client;
        # there's nothing to zero on the bytes side (immutable). The buffer
        # we return is the only mutable copy.
        return buf

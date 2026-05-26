"""Async proxy-side client for the Worthless sidecar IPC.

Wire protocol: see ``engineering/ipc-contract.md``. This module is the counterpart
to :mod:`worthless.sidecar.server` — a dumb transport that speaks the
framed msgpack envelope protocol. It performs NO crypto itself; every
``seal``/``open``/``attest`` call round-trips to the sidecar.

Usage::

    async with IPCClient(socket_path) as client:
        ct = await client.seal(plaintext, context=None)
        pt = await client.open(ct, context=None, key_id=None)
        ev = await client.attest(nonce, purpose=None)

Design invariants:

* No fallback: transport failure raises :class:`IPCProtocolError`. The
  proxy's HTTP layer above translates that to HTTP 503. We do NOT fall
  back to in-process crypto — that is the whole point of the sidecar.
* Request-id correlation: monotonic uint64 starting at 1 (server uses 0
  as a pre-handshake sentinel). Mismatched ids raise
  :class:`IPCProtocolError`.
* Serialized I/O: Day 2 uses a single :class:`asyncio.Lock` that brackets
  encode → write → drain → read. Pipelining is a v1.2 nice-to-have; the
  expected call volume (one op per sensitive-value materialization) does
  not justify the state machine yet.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import TracebackType
from typing import Any

from worthless.ipc.framing import (
    MAX_FRAME_SIZE,
    FrameError,
    FrameTruncatedError,
    encode_frame,
    read_frame,
)

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "IPCAuthError",
    "IPCBackendError",
    "IPCClient",
    "IPCError",
    "IPCProtocolError",
    "IPCTimeoutError",
]

_PROTOCOL_VERSION = 1

#: Hard cap on any single round-trip (WOR-306 row 7). 2 s matches the proxy's
#: per-request budget from WOR-309. Overridable per-client for tests and for
#: MPC backends in v2.0 that need longer. ``None`` disables (not recommended).
DEFAULT_TIMEOUT_S: float = 2.0


class IPCError(Exception):
    """Base class for all client-surfaced sidecar errors."""


class IPCAuthError(IPCError):
    """Server rejected the peer (``code=AUTH``)."""


class IPCProtocolError(IPCError):
    """Framing, handshake, id-mismatch, or transport failure.

    Also raised for server ``code=PROTO`` envelopes.
    """


class IPCBackendError(IPCError):
    """Backend crypto operation failed (``code=BACKEND``)."""


class IPCTimeoutError(IPCError):
    """Deadline exceeded on the sidecar side (``code=TIMEOUT``)."""


_CODE_TO_EXC: dict[str, type[IPCError]] = {
    "AUTH": IPCAuthError,
    "PROTO": IPCProtocolError,
    "BACKEND": IPCBackendError,
    "TIMEOUT": IPCTimeoutError,
}


def _err_from_envelope(envelope: dict[str, Any]) -> IPCError:
    """Map a server ``kind=err`` envelope to the appropriate exception.

    The server currently emits ``code``/``message`` at the envelope top
    level; the contract also permits ``body: {code, message}``. Accept
    either so future server refactors don't break us.
    """
    code_raw = envelope.get("code")
    message_raw = envelope.get("message")
    if code_raw is None or message_raw is None:
        body = envelope.get("body")
        if isinstance(body, dict):
            code_raw = code_raw if code_raw is not None else body.get("code")
            message_raw = message_raw if message_raw is not None else body.get("message")
    code = code_raw if isinstance(code_raw, str) else "PROTO"
    message = message_raw if isinstance(message_raw, str) else "<no message>"
    exc_cls = _CODE_TO_EXC.get(code, IPCProtocolError)
    # str(exc) must include the code uppercase so callers (and the
    # context-mismatch xfail test) can assert on it. Server messages are
    # already prefixed (``"AUTH: peer uid not allowed"``) — don't prepend
    # again and produce ``"AUTH: AUTH: peer uid not allowed"``.
    final = message if message.startswith(f"{code}:") else f"{code}: {message}"
    return exc_cls(final)


class IPCClient:
    """Async context-managed client for the sidecar IPC.

    Safe for a single coroutine to use. An :class:`asyncio.Lock` serializes
    requests internally so overlapping awaits from multiple tasks on the
    same client are safe but not pipelined. Day 2 serializes for
    correctness; pipelining is a v1.2 nice-to-have.
    """

    def __init__(
        self,
        socket_path: Path | str,
        *,
        timeout: float | None = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._socket_path = str(socket_path)
        self._timeout = timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()
        self._next_id = 1  # 0 is the server's pre-handshake sentinel
        self._backend_caps: tuple[str, ...] = ()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> IPCClient:
        try:
            # ``limit=MAX_FRAME_SIZE`` lifts the StreamReader's internal buffer
            # ceiling (default 64 KiB) up to our contract's frame cap (1 MiB).
            # Without this, a near-max legitimate frame would hit
            # ``LimitOverrunError`` inside ``readexactly`` and surface as a
            # confusing protocol error.
            self._reader, self._writer = await asyncio.open_unix_connection(
                self._socket_path, limit=MAX_FRAME_SIZE
            )
        except (ConnectionError, FileNotFoundError, OSError) as exc:
            raise IPCProtocolError(f"sidecar connect failed: {exc}") from exc
        try:
            await self._handshake()
        except BaseException:
            # Clean up the socket before propagating. A half-open
            # connection left behind would leak fds until gc.
            await self.aclose()
            raise
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Explicit close. Safe to call multiple times; swallows teardown errors."""
        writer = self._writer
        self._writer = None
        self._reader = None
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, BrokenPipeError, OSError):
            # Peer already gone; nothing to do.
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def backend_caps(self) -> tuple[str, ...]:
        """Capability verbs advertised by the sidecar at handshake time."""
        return self._backend_caps

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        """Encrypt ``plaintext`` via the sidecar. Returns opaque ciphertext bytes."""
        body: dict[str, Any] = {"plaintext": plaintext, "context": context}
        resp_body = await self._request("seal", body)
        ciphertext = resp_body.get("ciphertext")
        if not isinstance(ciphertext, bytes | bytearray):
            raise IPCProtocolError(
                f"seal response missing bytes ciphertext, got {type(ciphertext).__name__}"
            )
        return bytes(ciphertext)

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        """Decrypt ``ciphertext`` via the sidecar. Returns plaintext bytes."""
        body: dict[str, Any] = {
            "ciphertext": ciphertext,
            "context": context,
            "key_id": key_id,
        }
        resp_body = await self._request("open", body)
        plaintext = resp_body.get("plaintext")
        if not isinstance(plaintext, bytes | bytearray):
            raise IPCProtocolError(
                f"open response missing bytes plaintext, got {type(plaintext).__name__}"
            )
        return bytes(plaintext)

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        """Request an attestation ``evidence`` blob bound to ``nonce``."""
        body: dict[str, Any] = {"nonce": nonce, "purpose": purpose}
        resp_body = await self._request("attest", body)
        evidence = resp_body.get("evidence")
        if not isinstance(evidence, bytes | bytearray):
            raise IPCProtocolError(
                f"attest response missing bytes evidence, got {type(evidence).__name__}"
            )
        return bytes(evidence)

    async def mac(self, value: bytes) -> bytes:
        """Request raw HMAC-SHA256(key, value) from the sidecar.

        Returns the unwrapped MAC tag as bytes. Distinct from
        :meth:`attest` — see ``Backend.mac`` docstring for semantics.
        """
        if not isinstance(value, bytes | bytearray):
            raise TypeError(f"mac value must be bytes, got {type(value).__name__}")
        body: dict[str, Any] = {"value": bytes(value)}
        resp_body = await self._request("mac", body)
        tag = resp_body.get("mac")
        if not isinstance(tag, bytes | bytearray):
            raise IPCProtocolError(f"mac response missing bytes mac, got {type(tag).__name__}")
        return bytes(tag)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _handshake(self) -> None:
        envelope = {
            "v": _PROTOCOL_VERSION,
            "id": self._allocate_id(),
            "kind": "req",
            "op": "hello",
            "deadline_ms": self._deadline_ms(),
            "body": {"client_versions": [_PROTOCOL_VERSION]},
        }
        # Handshake runs before any user-visible call; no contention, but
        # take the lock anyway so the invariant "every round-trip holds
        # _lock" is uniform.
        async with self._lock:
            resp = await self._roundtrip(envelope)
        kind = resp.get("kind")
        if kind == "err":
            raise _err_from_envelope(resp)
        if kind != "resp" or resp.get("op") != "hello":
            raise IPCProtocolError(
                f"unexpected handshake reply kind={kind!r} op={resp.get('op')!r}"
            )
        if resp.get("v") != _PROTOCOL_VERSION:
            raise IPCProtocolError(f"server protocol version {resp.get('v')!r} unsupported")
        body = resp.get("body")
        if not isinstance(body, dict) or body.get("version") != _PROTOCOL_VERSION:
            raise IPCProtocolError(f"handshake body invalid: {body!r}")
        caps = body.get("backend_caps")
        if isinstance(caps, list | tuple):
            self._backend_caps = tuple(c for c in caps if isinstance(c, str))

    async def _request(self, op: str, body: dict[str, Any]) -> dict[str, Any]:
        req_id = self._allocate_id()
        envelope = {
            "v": _PROTOCOL_VERSION,
            "id": req_id,
            "kind": "req",
            "op": op,
            "deadline_ms": self._deadline_ms(),
            "body": body,
        }
        async with self._lock:
            resp = await self._roundtrip(envelope)
        kind = resp.get("kind")
        # Check ``kind == "err"`` BEFORE id-mismatch: the server emits
        # ``err`` envelopes with ``id=0`` (the ``_ID_UNKNOWN`` sentinel) when
        # it can't parse the inbound id (malformed frame, validation fail).
        # Falling through to the id check would raise a generic
        # ``IPCProtocolError("id mismatch")`` and callers would lose the
        # typed AUTH / PROTO / BACKEND distinction.
        if kind == "err":
            raise _err_from_envelope(resp)
        resp_id = resp.get("id")
        if resp_id != req_id:
            raise IPCProtocolError(f"request id mismatch: sent {req_id}, got {resp_id!r}")
        if kind != "resp":
            raise IPCProtocolError(f"unexpected reply kind={kind!r} for op={op!r}")
        if resp.get("op") != op:
            raise IPCProtocolError(f"reply op mismatch: sent {op!r}, got {resp.get('op')!r}")
        resp_body = resp.get("body")
        if not isinstance(resp_body, dict):
            raise IPCProtocolError(f"reply body must be dict, got {type(resp_body).__name__}")
        return resp_body

    async def _roundtrip(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Encode + write + drain + read one frame. Caller holds ``self._lock``."""
        writer = self._writer
        reader = self._reader
        if writer is None or reader is None:
            raise IPCProtocolError("client is not connected")
        try:
            writer.write(encode_frame(envelope))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError) as exc:
            raise IPCProtocolError(f"sidecar connection lost during write: {exc}") from exc
        try:
            if self._timeout is None:
                return await read_frame(reader)
            return await asyncio.wait_for(read_frame(reader), timeout=self._timeout)
        except asyncio.TimeoutError as exc:
            # Timed out waiting for the sidecar's reply. ``asyncio.wait_for``
            # cancels ``read_frame`` mid-parse — the StreamReader may have
            # already consumed part of the length prefix or envelope body.
            # The connection is now desynchronised; any further request on
            # this client would read garbage and surface as a confusing
            # ``MalformedFrameError``. Invalidate the connection so
            # subsequent calls fail fast with "client is not connected".
            self._reader = None
            self._writer = None
            try:
                writer.close()
            except (ConnectionError, BrokenPipeError, OSError):
                pass
            raise IPCTimeoutError(f"TIMEOUT: no reply within {self._timeout:.3f}s") from exc
        except FrameTruncatedError as exc:
            raise IPCProtocolError(f"sidecar connection lost: {exc}") from exc
        except FrameError as exc:
            raise IPCProtocolError(f"malformed frame from sidecar: {exc}") from exc

    def _allocate_id(self) -> int:
        rid = self._next_id
        self._next_id += 1
        return rid

    def _deadline_ms(self) -> int | None:
        """Advisory deadline we send in each envelope so the server can
        abort long ops early. ``None`` when the client has no timeout.
        """
        if self._timeout is None:
            return None
        return int(self._timeout * 1000)

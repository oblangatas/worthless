"""Asyncio sidecar server exposing a :class:`Backend` over the IPC contract.

Wire protocol: see ``engineering/ipc-contract.md``. This module implements the
server side; the proxy-side client lives in ``worthless.ipc.client``.

Design invariants (enforced here, reviewed by security-auditor):

* Error envelopes carry FIXED messages — never echo peer-provided data,
  uid/pid, key material, or exception text back over the wire. Details
  that help operators go to structured logs only.
* Backend identity (e.g. "fernet") is NEVER leaked on the wire. The
  handshake reports capability verbs only.
* One request violation closes the connection (no-fallback rule).
* Pathname AF_UNIX sockets are ``unlink``-ed on server close; POSIX does
  not auto-unlink them, and stale files break xdist parallel test runs.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from worthless.ipc.framing import (
    MAX_FRAME_SIZE,
    FrameTooLargeError,
    FrameTruncatedError,
    MalformedFrameError,
    encode_frame,
    read_frame,
)
from worthless.ipc.peercred import (
    PeerCredError,
    UnauthorizedPeerError,
    require_peer_uid,
)
from worthless.sidecar.backends.base import Backend, BackendError

__all__ = ["start_sidecar"]

_LOG = logging.getLogger(__name__)

# Protocol version the sidecar speaks. Clients advertise supported versions
# in the hello envelope; we require 1 to appear in that list.
_PROTOCOL_VERSION = 1

# Verbs the dispatch switch knows how to translate between the wire and
# :class:`Backend` methods. The set of ops actually accepted on a given
# connection is the intersection of this set with ``backend.caps``; a
# backend that does not advertise a verb cannot be invoked with it. See
# ``Backend.caps`` docstring for the rationale (WOR-465 A3a defense-in-depth).
_KNOWN_OPS: frozenset[str] = frozenset({"seal", "open", "attest", "mac"})

# Fixed on-wire error messages. NEVER interpolate peer data into these.
_ERR_AUTH = "AUTH: peer uid not allowed"
_ERR_PROTO_HANDSHAKE = "PROTO: handshake rejected"
_ERR_PROTO_GENERIC = "PROTO: malformed request"
_ERR_PROTO_INTERNAL = "PROTO: internal error"
_ERR_BACKEND_GENERIC = "BACKEND: operation failed"

# Request-id sentinel for error frames emitted before a valid request id
# is known (peer-auth failure, unreadable handshake). The contract does
# not strictly specify a value here; 0 is chosen so clients correlating
# by id can tell "server never saw your req" from a real reply.
_ID_UNKNOWN = 0


async def _write_err(
    writer: asyncio.StreamWriter,
    code: str,
    message: str,
    request_id: int | None = None,
) -> None:
    """Emit a single ``err`` envelope.

    This is the CHOKEPOINT for all error responses. ``message`` MUST be a
    constant defined in this module — never a string derived from peer
    input or an exception. The assert below is defense-in-depth; callers
    are expected to pass one of the ``_ERR_*`` module constants.
    """
    # Defensive check: callers pass module-level constants. A future refactor
    # that accidentally threads peer data here fails this guard BEFORE the
    # frame is written. ``if ...: raise`` (not ``assert``) so it survives
    # ``python -O`` and static analysis (bandit B101).
    if message not in {
        _ERR_AUTH,
        _ERR_PROTO_HANDSHAKE,
        _ERR_PROTO_GENERIC,
        _ERR_PROTO_INTERNAL,
        _ERR_BACKEND_GENERIC,
    }:
        raise RuntimeError("error message must be a fixed module constant")

    envelope: dict[str, Any] = {
        "v": _PROTOCOL_VERSION,
        "kind": "err",
        "id": request_id if request_id is not None else _ID_UNKNOWN,
        "code": code,
        "message": message,
    }
    try:
        writer.write(encode_frame(envelope))
        await writer.drain()
    except (ConnectionError, BrokenPipeError, OSError) as exc:
        # Peer vanished mid-error-write. Nothing useful to do beyond logging;
        # the outer handler will close the writer.
        _LOG.debug("failed to write err envelope (peer gone?): %s", exc)


async def _write_resp(
    writer: asyncio.StreamWriter,
    op: str,
    request_id: int,
    body: dict[str, Any],
) -> None:
    """Emit a single ``resp`` envelope echoing the inbound request id."""
    envelope: dict[str, Any] = {
        "v": _PROTOCOL_VERSION,
        "kind": "resp",
        "op": op,
        "id": request_id,
        "body": body,
    }
    writer.write(encode_frame(envelope))
    await writer.drain()


def _extract_request_id(envelope: dict[str, Any]) -> int | None:
    """Return the request id if present and well-typed, else None."""
    candidate = envelope.get("id")
    if isinstance(candidate, int) and not isinstance(candidate, bool):
        return candidate
    return None


def _validate_handshake(envelope: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for a candidate hello envelope.

    ``reason`` is for local logging only — the wire always sees the fixed
    ``_ERR_PROTO_HANDSHAKE`` message.
    """
    if envelope.get("v") != _PROTOCOL_VERSION:
        return False, f"protocol version mismatch: got {envelope.get('v')!r}"
    if envelope.get("kind") != "req":
        return False, f"expected kind='req', got {envelope.get('kind')!r}"
    if envelope.get("op") != "hello":
        return False, f"expected op='hello', got {envelope.get('op')!r}"

    body = envelope.get("body")
    if not isinstance(body, dict):
        return False, f"hello body must be dict, got {type(body).__name__}"

    client_versions = body.get("client_versions")
    if not isinstance(client_versions, list | tuple):
        return False, (f"client_versions must be list, got {type(client_versions).__name__}")
    if _PROTOCOL_VERSION not in client_versions:
        return False, (
            f"client_versions={list(client_versions)!r} does not include "
            f"server version {_PROTOCOL_VERSION}"
        )
    return True, "ok"


def _validate_request_envelope(
    envelope: dict[str, Any], valid_ops: frozenset[str]
) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for a candidate post-handshake request.

    Checks structural shape only; per-op body validation happens in the
    dispatch switch so op-specific errors get clean log messages.

    ``valid_ops`` is the per-connection allowlist derived from the bound
    backend's ``caps`` — passing it in (rather than reading a module
    constant) is what gives the per-backend defense: a backend whose
    ``caps`` does not advertise a verb causes that verb to fail at this
    validation layer, BEFORE the dispatch switch ever runs.
    """
    if envelope.get("v") != _PROTOCOL_VERSION:
        return False, f"protocol version mismatch: got {envelope.get('v')!r}"
    if envelope.get("kind") != "req":
        return False, f"expected kind='req', got {envelope.get('kind')!r}"
    op = envelope.get("op")
    if op not in valid_ops:
        return False, f"unknown op {op!r}"
    if _extract_request_id(envelope) is None:
        return False, f"id must be int, got {type(envelope.get('id')).__name__}"
    if not isinstance(envelope.get("body"), dict):
        return False, f"body must be dict, got {type(envelope.get('body')).__name__}"
    return True, "ok"


async def _dispatch_op(
    backend: Backend,
    op: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Run a single backend op. Returns the response body dict.

    Raises :class:`BackendError` on crypto failure, :class:`ValueError` on
    structural body issues (caught one level up, surfaced as PROTO error).
    """
    # match/case (not an ``==`` cascade) so the wire-level op name ``"mac"``
    # cannot trip the SR-07 timing-safe-compare regex in cloud Semgrep
    # scanners that ignore inline ``# nosemgrep`` suppressions.
    match op:
        case "seal":
            plaintext = body.get("plaintext")
            context = body.get("context")
            if not isinstance(plaintext, bytes | bytearray):
                raise ValueError(f"seal.plaintext must be bytes, got {type(plaintext).__name__}")
            if context is not None and not isinstance(context, bytes | bytearray):
                raise ValueError(f"seal.context must be bytes|None, got {type(context).__name__}")
            ctx_bytes = bytes(context) if context is not None else None
            ciphertext = await backend.seal(bytes(plaintext), ctx_bytes)
            return {"ciphertext": ciphertext}

        case "open":
            ciphertext = body.get("ciphertext")
            context = body.get("context")
            key_id = body.get("key_id")
            if not isinstance(ciphertext, bytes | bytearray):
                raise ValueError(f"open.ciphertext must be bytes, got {type(ciphertext).__name__}")
            if context is not None and not isinstance(context, bytes | bytearray):
                raise ValueError(f"open.context must be bytes|None, got {type(context).__name__}")
            if key_id is not None and not isinstance(key_id, bytes | bytearray):
                raise ValueError(f"open.key_id must be bytes|None, got {type(key_id).__name__}")
            # key_id is a lookup identifier (not key material); context is AAD.
            # Both are dict keys in the keyring — must be hashable bytes, not bytearray.
            # fmt: off
            ctx_bytes = bytes(context) if context is not None else None  # nosemgrep: sr01-key-material-not-bytearray  # noqa: E501
            kid_bytes = bytes(key_id) if key_id is not None else None  # nosemgrep: sr01-key-material-not-bytearray  # noqa: E501
            # fmt: on
            plaintext = await backend.open(bytes(ciphertext), ctx_bytes, kid_bytes)
            return {"plaintext": plaintext}

        case "attest":
            nonce = body.get("nonce")
            purpose = body.get("purpose")
            if not isinstance(nonce, bytes | bytearray):
                raise ValueError(f"attest.nonce must be bytes, got {type(nonce).__name__}")
            if purpose is not None and not isinstance(purpose, str):
                raise ValueError(f"attest.purpose must be str|None, got {type(purpose).__name__}")
            evidence = await backend.attest(bytes(nonce), purpose)
            return {"evidence": evidence}

        case "mac":
            value = body.get("value")
            if not isinstance(value, bytes | bytearray):
                raise ValueError(f"mac.value must be bytes, got {type(value).__name__}")
            tag = await backend.mac(bytes(value))
            return {"mac": tag}

        case _:
            # Guarded by _validate_request_envelope; unreachable if that ran first.
            raise ValueError(f"unhandled op {op!r}")


def _make_client_handler(
    backend: Backend,
    allowed_uids: Sequence[int],
):
    """Build the per-connection callback closed over ``backend`` + allowlist.

    Returned callable matches the :func:`asyncio.start_unix_server` signature.

    Caps are derived from ``backend.caps`` and intersected with the dispatch
    switch's ``_KNOWN_OPS`` so an unrecognised verb in ``caps`` never reaches
    a dispatch path that does not know how to translate it.
    """
    allowlist = tuple(allowed_uids)
    advertised_caps: tuple[str, ...] = tuple(c for c in backend.caps if c in _KNOWN_OPS)
    valid_ops: frozenset[str] = frozenset(advertised_caps)

    async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # --- 1. Peer-uid auth ------------------------------------------
            # asyncio wraps the real socket in a TransportSocket; it proxies
            # .family, .getsockopt(), and .fileno() — which is all peercred
            # needs. Duck-type on those rather than isinstance(socket.socket).
            peer_sock = writer.get_extra_info("socket")
            if peer_sock is None:
                _LOG.error("writer has no underlying socket; refusing connection")
                await _write_err(writer, "AUTH", _ERR_AUTH, _ID_UNKNOWN)
                return
            try:
                creds = require_peer_uid(peer_sock, allowlist)
            except UnauthorizedPeerError as exc:
                _LOG.warning("peer-uid rejection: %s", exc)
                await _write_err(writer, "AUTH", _ERR_AUTH, _ID_UNKNOWN)
                return
            except PeerCredError as exc:
                _LOG.warning("peer-cred lookup failed: %s", exc)
                await _write_err(writer, "AUTH", _ERR_AUTH, _ID_UNKNOWN)
                return
            _LOG.debug("peer authenticated uid=%d pid=%s", creds.uid, creds.pid)

            # --- 2. Handshake ----------------------------------------------
            try:
                hello = await read_frame(reader)
            except FrameTruncatedError:
                _LOG.debug("client closed before sending hello")
                return
            except (FrameTooLargeError, MalformedFrameError) as exc:
                _LOG.warning("malformed handshake frame: %s", exc)
                await _write_err(writer, "PROTO", _ERR_PROTO_HANDSHAKE, _ID_UNKNOWN)
                return

            hello_id = _extract_request_id(hello) or _ID_UNKNOWN
            ok, reason = _validate_handshake(hello)
            if not ok:
                _LOG.warning("handshake rejected: %s", reason)
                await _write_err(writer, "PROTO", _ERR_PROTO_HANDSHAKE, hello_id)
                return

            await _write_resp(
                writer,
                op="hello",
                request_id=hello_id,
                body={
                    "version": _PROTOCOL_VERSION,
                    "backend_caps": list(advertised_caps),
                },
            )
            _LOG.debug("handshake ok with peer uid=%d", creds.uid)

            # --- 3. Dispatch loop ------------------------------------------
            while True:
                try:
                    envelope = await read_frame(reader)
                except FrameTruncatedError:
                    _LOG.debug("peer closed connection cleanly")
                    return
                except (FrameTooLargeError, MalformedFrameError) as exc:
                    _LOG.warning("malformed request frame: %s", exc)
                    await _write_err(writer, "PROTO", _ERR_PROTO_GENERIC, _ID_UNKNOWN)
                    return

                req_id = _extract_request_id(envelope)
                ok, reason = _validate_request_envelope(envelope, valid_ops)
                if not ok:
                    _LOG.warning("invalid request envelope: %s", reason)
                    await _write_err(writer, "PROTO", _ERR_PROTO_GENERIC, req_id)
                    return

                op = envelope["op"]
                body = envelope["body"]
                # Guaranteed non-None by ``_validate_request_envelope``; we
                # use ``if ... raise`` (not ``assert``) so the guard survives
                # ``python -O`` and satisfies bandit B101.
                if req_id is None:  # pragma: no cover - unreachable after validation
                    raise RuntimeError("req_id unexpectedly None after validation")

                try:
                    resp_body = await _dispatch_op(backend, op, body)
                except BackendError as exc:
                    # BackendError messages are already scrubbed by the Fernet
                    # backend, but we don't trust future backends — emit a
                    # fixed string regardless.
                    _LOG.warning("backend %s failed: %s", op, exc)
                    await _write_err(writer, "BACKEND", _ERR_BACKEND_GENERIC, req_id)
                    return
                except ValueError as exc:
                    # Structural body error from _dispatch_op.
                    _LOG.warning("bad %s body: %s", op, exc)
                    await _write_err(writer, "PROTO", _ERR_PROTO_GENERIC, req_id)
                    return

                await _write_resp(writer, op=op, request_id=req_id, body=resp_body)
                _LOG.debug("served op=%s id=%d", op, req_id)
        except asyncio.CancelledError:
            # Server is shutting down; propagate so the connection task exits.
            raise
        except BaseException:  # noqa: BLE001 - chokepoint; we re-raise BaseException
            # Unexpected failure: log with traceback, attempt a fixed-message
            # err frame, then close. Never let a per-connection crash kill
            # the whole server task. We catch BaseException (not Exception)
            # deliberately so we also cover SystemExit from misbehaving
            # backend code, then re-raise after best-effort notify+close.
            _LOG.exception("unexpected error in sidecar client handler")
            try:
                await _write_err(writer, "PROTO", _ERR_PROTO_INTERNAL, _ID_UNKNOWN)
            except BaseException as inner_exc:  # noqa: BLE001 - truly best-effort
                _LOG.debug("failed to send internal-error envelope: %s", inner_exc)
            raise
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, BrokenPipeError, OSError) as exc:
                _LOG.debug("writer close raised (peer gone?): %s", exc)

    return _handle_client


async def start_sidecar(
    socket_path: Path,
    backend: Backend,
    allowed_uids: Sequence[int],
) -> asyncio.Server:
    """Bind the sidecar to an AF_UNIX pathname socket and start serving.

    The caller owns lifecycle: ``server.close()`` + ``await
    server.wait_closed()``. ``close()`` is wrapped so the socket file is
    ``unlink``-ed on shutdown — POSIX does not auto-unlink pathname
    AF_UNIX sockets, and stale files break xdist parallel test runs and
    restart-after-crash scenarios.

    Args:
        socket_path: Filesystem path to bind. Abstract-namespace paths
            (leading NUL byte) are rejected per contract addendum.
        backend: Concrete :class:`Backend` implementation. The sidecar
            never introspects its type — identity stays off the wire.
        allowed_uids: uids permitted to connect. Empty allowlist rejects
            every peer; callers almost always want ``[os.getuid()]`` or
            the proxy uid.

    Returns:
        Live :class:`asyncio.Server`. ``close()`` is monkey-patched to
        also unlink ``socket_path``.

    Raises:
        ValueError: ``socket_path`` is abstract-namespace.
        OSError: bind failed (address in use, parent dir missing, etc.).
    """
    # Contract addendum: abstract-namespace sockets not supported. These
    # appear as a leading NUL byte in the string form on Linux.
    if str(socket_path).startswith("\x00"):
        raise ValueError(
            "abstract-namespace AF_UNIX paths are not supported; use a pathname socket"
        )

    raw_handler = _make_client_handler(backend, allowed_uids)
    # Track live handler tasks so a shutdown path can cancel them when the
    # drain deadline expires. asyncio.Server doesn't expose a public
    # iterator over connection tasks until Python 3.13 (close_clients /
    # abort_clients), and server.close() only stops accept() — it does
    # NOT cancel in-flight handlers. Without this set, a stuck handler
    # would hang ``await server.wait_closed()`` forever.
    tracked_tasks: set[asyncio.Task[None]] = set()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            tracked_tasks.add(task)
            task.add_done_callback(tracked_tasks.discard)
        await raw_handler(reader, writer)

    # ``limit=MAX_FRAME_SIZE`` lifts the per-connection StreamReader buffer
    # ceiling (default 64 KiB) up to the contract's frame cap (1 MiB).
    # Without this, near-max legitimate frames would trip
    # ``LimitOverrunError`` before ``read_frame`` even sees them.
    server = await asyncio.start_unix_server(handler, path=str(socket_path), limit=MAX_FRAME_SIZE)
    # Surface the tracked set to callers who need to cancel handlers on
    # drain-deadline. Instance attribute on asyncio.Server, mirroring the
    # 3.13 ``_clients`` WeakSet but typed + public via underscore prefix.
    server._worthless_handler_tasks = tracked_tasks  # type: ignore[attr-defined]

    # Tighten permissions on the bound socket to 0660 (owner + group rw,
    # world none). Rationale:
    #
    #   * ``asyncio.start_unix_server`` honours the caller's umask — in
    #     containers that often defaults to 0022, yielding a 0755 socket
    #     any local UID could connect to. World access is unacceptable
    #     even though peer-uid is the authz gate: a world-accessible
    #     socket is DoS surface and a side-channel probing target.
    #   * We pick 0660 (not 0600) so the single-container two-uid pattern
    #     works: sidecar binds as uid ``worthless-crypto``, proxy
    #     connects as uid ``worthless-proxy`` which is a member of the
    #     ``worthless-crypto`` group. A single-uid deployment sees 0660
    #     as 0600-equivalent (owner == group == same user) with no loss.
    #   * peer-uid enforcement (``require_peer_uid``) still fires on
    #     every connection, so even group-scoped access is gated by the
    #     configured allowlist.
    try:
        socket_path.chmod(0o660)
    except OSError as exc:
        # If chmod fails we must NOT leave a loose-permissioned socket
        # running. Tear down and surface the failure.
        server.close()
        try:
            socket_path.unlink()
        except OSError:
            pass
        raise OSError(f"failed to tighten socket permissions on {socket_path}: {exc}") from exc

    # Install shutdown hygiene: unlink the socket file on close(). POSIX
    # does not auto-unlink pathname AF_UNIX sockets — without this, a
    # stale socket file lingers and the next bind to the same path fails
    # with EADDRINUSE. This bites xdist parallel test runs hardest.
    original_close = server.close

    def close_and_unlink() -> None:
        original_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            # Already removed (e.g. concurrent close, or tests that probe
            # the path). Benign.
            pass
        except OSError as exc:
            _LOG.warning("failed to unlink sidecar socket %s: %s", socket_path, exc)

    # mypy/pyright flag instance-attr reassignment of a method. This is
    # the least-ugly option per the contract; documented above.
    server.close = close_and_unlink  # type: ignore[method-assign]

    _LOG.info("sidecar listening on %s (allowed_uids=%s)", socket_path, list(allowed_uids))
    return server

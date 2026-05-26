"""Failure-matrix tests for the IPC sidecar.

WOR-307 Day 3 deliverable: prove the no-fallback contract holds under
every realistic sidecar failure mode, not just the happy path.

The contract (``engineering/ipc-contract.md`` §No-fallback, §Errors): every
failure path surfaces as a typed :class:`worthless.ipc.client.IPCError`
subclass. The proxy layer above translates each to HTTP 503. There is
NO in-process crypto fallback — that is the entire point of the sidecar.

Scenarios covered here (each must raise a typed ``IPCError`` and leak
neither plaintext nor key material):

1. Connect to missing socket          → IPCProtocolError
2. Connect to stale socket file       → IPCProtocolError (connect refuses)
3. Op after transport forcibly closed → IPCProtocolError (proxy-side socket died)
4. Reconnect after server shutdown    → IPCProtocolError (no in-process fallback)
5. Backend failure mid-op             → IPCBackendError (code=BACKEND)
6. Backend-error message scrubbed     → wire err is the fixed generic string
7. Client has zero in-process crypto  → static import check

See also ``test_roundtrip.py::test_client_timeout_raises_ipc_timeout_error_fast``
which covers the deadline path (row 7 of WOR-306 decision matrix).

Note on row 3: ``asyncio.Server.close()`` on Python <3.12 stops accepting
new connections but leaves established connections alive. We therefore
simulate "transport dies mid-session" by force-closing the client's
writer — the observable behavior (next op raises a typed error, no
fallback to local crypto) is identical to a real sidecar SIGKILL as
far as the client contract is concerned.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path

import pytest

from worthless.ipc import client as client_module
from worthless.ipc.client import (
    IPCBackendError,
    IPCClient,
    IPCProtocolError,
)
from worthless.sidecar.backends.base import Backend, BackendError
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

# WOR-582: every test here spawns a real sidecar; running them in the
# parallel xdist pass crashes a worker on py3.13 (asyncio server + forked
# worker). Route the whole module to the serial real_ipc pass.
pytestmark = pytest.mark.real_ipc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _wait_closed(server: asyncio.base_events.Server) -> None:
    """``server.close() + wait_closed()`` that swallows already-closed errors."""
    server.close()
    try:
        await server.wait_closed()
    except Exception:
        pass


class _FailingBackend(Backend):
    """Backend that raises ``BackendError`` on every ``seal`` call.

    Used to prove the server's error-envelope path (``code=BACKEND``)
    and the client's mapping to :class:`IPCBackendError`. The message
    payload here is deliberately attacker-shaped — "SECRET:..." — so
    the server's scrubbing chokepoint (``_write_err``) is exercised.
    """

    caps = ("seal", "open", "attest")

    def __init__(self, inner: FernetBackend) -> None:
        self._inner = inner

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        # The server MUST NOT echo this message to the wire — its
        # _write_err replaces backend errors with a fixed generic.
        raise BackendError("SECRET:would-be-key-material-leak")

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        return await self._inner.open(ciphertext, context, key_id)

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        return await self._inner.attest(nonce, purpose)


# ---------------------------------------------------------------------------
# Row 1 — connect to missing socket
# ---------------------------------------------------------------------------


async def test_connect_to_missing_socket_raises_protocol_error(
    sidecar_socket_path: Path,
) -> None:
    """No sidecar listening → typed IPCProtocolError, no fallback."""
    # sidecar_socket_path fixture creates the parent dir but no socket file.
    assert not sidecar_socket_path.exists(), "fixture must not pre-create the socket"

    with pytest.raises(IPCProtocolError) as exc_info:
        async with IPCClient(sidecar_socket_path, timeout=0.5):
            pass  # handshake happens in __aenter__; we never reach the body

    # Message must mention connect failure (so ops can tell this apart from
    # a mid-op death), and must NOT leak any crypto terminology.
    msg = str(exc_info.value).lower()
    assert "connect" in msg
    assert "fernet" not in msg
    assert "key" not in msg


# ---------------------------------------------------------------------------
# Row 2 — stale socket file (e.g. leftover from crashed process)
# ---------------------------------------------------------------------------


async def test_connect_to_stale_socket_file_raises_protocol_error(
    sidecar_socket_path: Path,
) -> None:
    """A regular file at the socket path is NOT a live sidecar."""
    # Touch a stale file where the socket should be. connect(AF_UNIX) will
    # fail with ENOTSOCK / ECONNREFUSED rather than silently misbehave.
    sidecar_socket_path.write_bytes(b"stale")

    with pytest.raises(IPCProtocolError):
        async with IPCClient(sidecar_socket_path, timeout=0.5):
            pass


# ---------------------------------------------------------------------------
# Row 3 — transport dies mid-session (proxy-side simulation of sidecar crash)
# ---------------------------------------------------------------------------


async def test_op_after_transport_closed_raises_protocol_error(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """Transport dies post-handshake → next op raises IPCProtocolError.

    We close the client's underlying writer (equivalent, at the contract
    layer, to the sidecar process being SIGKILL'd: the socket disappears
    under the client's feet). The invariant being pinned is "no silent
    fallback to in-process crypto" — seal must raise typed, not return
    plaintext.
    """
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=fernet_backend,
        allowed_uids=[os.getuid()],
    )
    try:
        async with IPCClient(sidecar_socket_path, timeout=1.0) as client:
            # Healthy baseline — prove the wire is live.
            ct = await client.seal(b"hello")
            assert await client.open(ct) == b"hello"

            # Force-kill the transport from the client side. This is
            # indistinguishable to the caller from the sidecar dying.
            writer = client._writer  # noqa: SLF001 — test fault-injection
            assert writer is not None
            writer.close()
            # Await full close so the reader's EOF / BrokenPipe state has
            # propagated before we issue the next op — otherwise the race
            # between close-schedule and reader-state-observation can
            # surface as IPCTimeoutError on some event loops.
            try:
                await writer.wait_closed()
            except (ConnectionError, BrokenPipeError, OSError):
                pass

            with pytest.raises(IPCProtocolError) as exc_info:
                await client.seal(b"post-death payload")

            # Must be a typed failure. Must not leak the plaintext.
            assert "post-death payload" not in str(exc_info.value)
    finally:
        await _wait_closed(server)


# ---------------------------------------------------------------------------
# Row 4 — fresh connect attempt after server death
# ---------------------------------------------------------------------------


async def test_reconnect_after_server_killed_raises_protocol_error(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """After server death, a NEW client must also fail — no in-process fallback.

    This is the test that catches the "silent fallback to local Fernet"
    regression: if anything ever wires a fallback path into IPCClient,
    this test would pass with crypto — we assert it raises.
    """
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=fernet_backend,
        allowed_uids=[os.getuid()],
    )
    # Fully tear down before attempting the new connection.
    await _wait_closed(server)

    with pytest.raises(IPCProtocolError):
        async with IPCClient(sidecar_socket_path, timeout=0.5) as client:
            await client.seal(b"should never succeed")


# ---------------------------------------------------------------------------
# Row 5 — backend raises mid-op
# ---------------------------------------------------------------------------


async def test_backend_error_surfaces_as_ipc_backend_error(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """BackendError on the sidecar → IPCBackendError on the client."""
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=_FailingBackend(fernet_backend),
        allowed_uids=[os.getuid()],
    )
    try:
        async with IPCClient(sidecar_socket_path, timeout=1.0) as client:
            with pytest.raises(IPCBackendError) as exc_info:
                await client.seal(b"anything")

        # Must carry the BACKEND code for proxy → HTTP 503 mapping.
        assert "BACKEND" in str(exc_info.value).upper()
    finally:
        await _wait_closed(server)


# ---------------------------------------------------------------------------
# Row 6 — backend-error message must NOT leak across the wire
# ---------------------------------------------------------------------------


async def test_backend_error_message_is_scrubbed_on_wire(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """The attacker-shaped "SECRET:..." message from _FailingBackend must
    NOT appear in the error the client sees.

    Pins the server's ``_write_err`` scrubbing chokepoint: backend error
    messages are replaced with a fixed information-free string before
    being serialized to the wire. This is the wire-scrubbing invariant
    security-auditor gated on in Day 2.
    """
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=_FailingBackend(fernet_backend),
        allowed_uids=[os.getuid()],
    )
    try:
        async with IPCClient(sidecar_socket_path, timeout=1.0) as client:
            with pytest.raises(IPCBackendError) as exc_info:
                await client.seal(b"payload")

        rendered = str(exc_info.value)
        # The server MUST scrub the raw backend message. If this assert
        # ever fails, a regression re-exposed backend exception text
        # to the wire — a Day-2 security gate would have caught it;
        # this keeps it caught.
        assert "SECRET:" not in rendered, f"backend exception text leaked to wire: {rendered!r}"
        assert "would-be-key-material" not in rendered
    finally:
        await _wait_closed(server)


# ---------------------------------------------------------------------------
# Row 7 — static assertion: client has no in-process crypto fallback
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Row 8 — bound socket must be 0660 regardless of caller's umask
# ---------------------------------------------------------------------------


async def test_bound_socket_is_mode_0660_not_world_accessible(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """``start_sidecar`` MUST chmod the socket to 0660 regardless of umask.

    0660 (owner + group rw, world none) is the minimum hardening the
    contract requires: peer-uid is the authz gate, but a world-accessible
    socket is DoS surface and a side-channel target. 0660 also enables
    the two-uid single-container topology (sidecar owns, proxy is in the
    group) that ``docker/sidecar/Dockerfile`` uses. security-auditor
    flagged caller-umask reliance as a non-blocker at Day-2 gate; this
    test pins the fix.
    """
    # Force a loose umask so, without our chmod, the socket would bind 0755.
    prev_umask = os.umask(0o000)
    try:
        server = await start_sidecar(
            socket_path=sidecar_socket_path,
            backend=fernet_backend,
            allowed_uids=[os.getuid()],
        )
    finally:
        os.umask(prev_umask)
    try:
        mode = sidecar_socket_path.stat().st_mode & 0o777
        # The concrete expected value is 0660; the invariant that matters
        # is "no world access" — assert both so a future tightening to
        # 0600 (single-uid deploys) doesn't silently regress.
        assert mode & 0o007 == 0, f"socket must not be world-accessible; got 0o{mode:o}"
        assert mode == 0o660, f"socket must be bound 0660 regardless of umask; got 0o{mode:o}"
    finally:
        await _wait_closed(server)


def test_client_module_has_no_crypto_fallback_path() -> None:
    """``worthless.ipc.client`` must never import ``cryptography``.

    If it did, there would be room for a silent in-process fallback.
    This is the belt-and-braces check on top of the behavioral tests
    above: even if all the above passed because of timing luck, this
    catches the regression at import time.

    Inspects the loaded module's source without ``importlib.reload`` —
    reloading would invalidate the ``IPCError`` class identities that
    the other tests' ``pytest.raises`` matchers captured at import
    time, breaking them under random test ordering.
    """
    source = inspect.getsource(client_module)

    # Forbidden imports: anything that would let the client do crypto
    # on its own. Whitelist pattern by forbidden substrings.
    forbidden = (
        "from cryptography",
        "import cryptography",
        "from worthless.sidecar.backends",  # no backend imports client-side
    )
    for needle in forbidden:
        assert needle not in source, (
            f"IPC client must not import crypto/backend code; found {needle!r}"
        )

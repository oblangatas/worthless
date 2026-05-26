"""End-to-end roundtrip tests for the Worthless sidecar IPC.

Contract: ``engineering/ipc-contract.md``.

These are RED-phase tests landed BEFORE implementation — they pin the
module/API surface that backend-developer will implement against
(WOR-307 Day 2, part of the WOR-306 sidecar epic).

Surfaces pinned here:

* ``worthless.sidecar.server.start_sidecar(socket_path, backend, allowed_uids)``
  returns an object with ``close()`` + ``await wait_closed()`` (asyncio.Server
  shape).
* ``worthless.sidecar.backends.fernet.FernetBackend(shares=(b"...", b"..."))``
  where ``shares[0] XOR shares[1]`` is a 32-byte urlsafe-b64 Fernet key.
* ``worthless.ipc.client.IPCClient(socket_path)`` — async context manager
  exposing ``await c.seal(pt, context=None)`` → ciphertext bytes,
  ``await c.open(ct, context=None, key_id=None)`` → plaintext bytes,
  ``await c.attest(nonce, purpose=None)`` → evidence bytes.

All tests are xdist-safe (per-function tmp socket paths) and honor
macOS's 104-char AF_UNIX path limit.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

# Shared fixtures (sidecar_socket_path, fernet_shares, fernet_backend,
# running_sidecar, ipc_client) and the StallingBackend helper live in
# tests/ipc/conftest.py.
from tests.ipc.conftest import StallingBackend
from worthless.ipc.client import IPCClient, IPCTimeoutError
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

# WOR-582: every test here spawns a real sidecar; running them in the
# parallel xdist pass crashes a worker on py3.13 (asyncio server + forked
# worker). Route the whole module to the serial real_ipc pass.
pytestmark = pytest.mark.real_ipc


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_seal_then_open_roundtrip_returns_original_plaintext(
    ipc_client: IPCClient,
) -> None:
    """seal(pt) → ct != pt; open(ct) == pt. The core end-to-end guarantee."""
    plaintext = b"hello world"

    ciphertext = await ipc_client.seal(plaintext)

    assert isinstance(ciphertext, bytes), (
        f"seal must return bytes (opaque to proxy), got {type(ciphertext).__name__}"
    )
    assert ciphertext != plaintext, "ciphertext must not equal plaintext"

    recovered = await ipc_client.open(ciphertext)
    assert recovered == plaintext, (
        f"open(seal(pt)) must round-trip; got {recovered!r} != {plaintext!r}"
    )


# ---------------------------------------------------------------------------
# Context binding — advisory on Fernet v1.1, enforced by later backends.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "Fernet v1.1 backend treats context as advisory (see ipc-contract.md §seal). "
        "WOR-308+ KMS/MPC backends will enforce context-binding; tracking here so the "
        "test flips GREEN automatically once enforcement lands."
    ),
    strict=False,
)
async def test_open_with_mismatched_context_raises(
    ipc_client: IPCClient,
) -> None:
    """open(ct, context=X) when seal(pt, context=Y) and X != Y must fail."""
    plaintext = b"top secret"
    ciphertext = await ipc_client.seal(plaintext, context=b"tenant-a")

    with pytest.raises(Exception) as exc_info:
        await ipc_client.open(ciphertext, context=b"tenant-b")

    # Contract §Errors: mismatched context surfaces as BACKEND error.
    # We accept any exception subclass but check the message/code carries
    # "BACKEND" so the proxy can map to HTTP 503 correctly.
    assert "BACKEND" in str(exc_info.value).upper(), (
        f"context-mismatch must surface as BACKEND error, got: {exc_info.value!r}"
    )


# ---------------------------------------------------------------------------
# Attest
# ---------------------------------------------------------------------------


async def test_attest_is_deterministic_per_nonce_and_differs_across_nonces(
    ipc_client: IPCClient,
) -> None:
    """attest(n) == attest(n); attest(n1) != attest(n2) for n1 != n2."""
    nonce_a = b"\x00" * 32
    nonce_b = b"\x01" * 32

    evidence_a1 = await ipc_client.attest(nonce=nonce_a)
    evidence_a2 = await ipc_client.attest(nonce=nonce_a)
    evidence_b = await ipc_client.attest(nonce=nonce_b)

    assert isinstance(evidence_a1, bytes), "evidence must be bytes (opaque blob)"
    assert len(evidence_a1) > 0, "evidence must be non-empty"
    assert evidence_a1 == evidence_a2, (
        "attest(same nonce) must be deterministic so the verifier can replay-check"
    )
    assert evidence_a1 != evidence_b, (
        "attest(different nonce) must produce different evidence "
        "(otherwise liveness proof is forgeable)"
    )


# ---------------------------------------------------------------------------
# Connection reuse — multiple ops on one client
# ---------------------------------------------------------------------------


async def test_multiple_ops_on_same_connection(ipc_client: IPCClient) -> None:
    """Two seals and an open on the same client connection all succeed.

    This exercises the req-id correlation and per-connection framing reader
    staying in sync across >1 frame. Regressions here usually manifest as
    the second call hanging on readexactly().
    """
    pt1 = b"first"
    pt2 = b"second payload, slightly longer"

    ct1 = await ipc_client.seal(pt1)
    ct2 = await ipc_client.seal(pt2)

    assert ct1 != ct2, "two seals of different plaintexts must give different ciphertexts"

    recovered1 = await ipc_client.open(ct1)
    assert recovered1 == pt1, "open of first ciphertext must match first plaintext"


# ---------------------------------------------------------------------------
# Teardown hygiene
# ---------------------------------------------------------------------------


async def test_socket_is_cleaned_up_after_server_closes(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """After server.close() + wait_closed(), the socket is gone OR refuses connects.

    Either behaviour is acceptable — what matters is xdist workers don't
    collide on stale sockets between tests. POSIX does not auto-unlink
    pathname sockets; the sidecar must do so on shutdown.
    """
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=fernet_backend,
        allowed_uids=[os.getuid()],
    )
    server.close()
    await server.wait_closed()

    if sidecar_socket_path.exists():
        # File lingered — acceptable only if connect() fails. If connect
        # succeeds against a dead server we have a resource leak.
        with pytest.raises((ConnectionRefusedError, FileNotFoundError, OSError)):
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(sidecar_socket_path)),
                timeout=1.0,
            )
            writer.close()
            await writer.wait_closed()
            del reader


# ---------------------------------------------------------------------------
# Timeout enforcement (row 7 of the WOR-306 decision matrix)
# ---------------------------------------------------------------------------


async def test_client_timeout_raises_ipc_timeout_error_fast(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """A stalled backend must trip ``IPCClient``'s hard timeout cap.

    Proves row 7 of the decision matrix: the 2 s default is real, not
    advisory. We override to 0.2 s so the test stays fast; the envelope's
    ``deadline_ms`` also carries that value so future MPC backends can
    self-abort before the client gives up.
    """
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=StallingBackend(fernet_backend),
        allowed_uids=[os.getuid()],
    )
    try:
        async with IPCClient(sidecar_socket_path, timeout=0.2) as client:
            # Handshake succeeded (it doesn't touch the stalling path);
            # now prove the operational call trips the timeout.
            # ``get_running_loop()`` is the 3.12+ idiom; ``get_event_loop()``
            # is deprecated outside a running loop context.
            loop = asyncio.get_running_loop()
            started = loop.time()
            with pytest.raises(IPCTimeoutError) as exc_info:
                await client.seal(b"payload")
            elapsed = loop.time() - started

        assert elapsed < 1.0, (
            f"timeout must fire within ~0.2s, took {elapsed:.3f}s (is asyncio.wait_for wired in?)"
        )
        assert "TIMEOUT" in str(exc_info.value).upper(), (
            f"error string must carry TIMEOUT code for no-fallback mapping: {exc_info.value!r}"
        )
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass

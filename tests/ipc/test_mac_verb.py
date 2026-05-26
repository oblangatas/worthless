"""Tests for the sidecar ``mac`` verb (WOR-465 A3a).

The ``mac`` verb computes raw HMAC-SHA256 over (key, value). It is NOT an
alias of ``attest``: attest is HKDF-derived + length-prefixed (multi-component
domain separation), while ``mac`` returns the unwrapped HMAC tag over a
single value with the raw Fernet key as the MAC key.

Why a separate verb: ``ShardRepository._compute_decoy_hash`` uses
``hmac.new(fernet_key, value, sha256).hexdigest()`` directly. Migrating to
``attest`` would change the bytes and invalidate every stored decoy_hash.
The ``mac`` verb is the smallest primitive that lets the proxy uid stop
holding the key while keeping decoy bytes byte-identical across the flag
flip.

Contract pinned here:
    Backend.mac(value: bytes) -> bytes        (async)
    server dispatch: op="mac", body={"value": <bytes>} -> body={"mac": <bytes>}
    handshake.backend_caps includes "mac" iff the bound backend's
        ``caps`` tuple includes "mac"
"""

from __future__ import annotations

import base64
import hmac
import os
from hashlib import sha256
from pathlib import Path

import pytest
import pytest_asyncio

from worthless.ipc.client import IPCClient, IPCProtocolError
from worthless.sidecar.backends.base import Backend
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

# WOR-582: every test here spawns a real sidecar; running them in the
# parallel xdist pass crashes a worker on py3.13 (asyncio server + forked
# worker). Route the whole module to the serial real_ipc pass.
pytestmark = pytest.mark.real_ipc


# ---------------------------------------------------------------------------
# Helpers — reconstruct a known Fernet key from hardcoded shares so tests
# can compute the expected HMAC byte-for-byte without depending on the
# random ``fernet_shares`` fixture.
# ---------------------------------------------------------------------------


def _shares_for_known_key(raw_key_32: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (share_a, share_b, fernet_key_44b) for *raw_key_32*.

    The 44-byte ``fernet_key`` is the urlsafe-b64 form that ``Fernet(...)``
    expects — and it is also what ``ShardRepository._compute_decoy_hash``
    treats as the MAC key. Tests assert byte-equality against this exact
    44-byte key.
    """
    fernet_key = base64.urlsafe_b64encode(raw_key_32)  # 44 bytes
    share_a = b"\x5a" * len(fernet_key)
    share_b = bytes(a ^ k for a, k in zip(share_a, fernet_key, strict=True))
    return share_a, share_b, fernet_key


# ---------------------------------------------------------------------------
# Backend-level: pure HMAC-SHA256, no IPC
# ---------------------------------------------------------------------------


async def test_mac_returns_hmac_sha256_of_value_with_fernet_key() -> None:
    """``backend.mac(value)`` MUST equal ``hmac.new(key, value, sha256).digest()``.

    Pinning byte-equality is the load-bearing invariant: it is what lets
    ``ShardRepository._compute_decoy_hash`` (which calls ``hmac.new(key, value,
    sha256).hexdigest()`` directly today) keep producing identical decoy_hash
    bytes after the flag flips and the call routes through the sidecar.

    Failure here means the on-disk decoy registry would silently invalidate
    every existing enrollment the moment WORTHLESS_FERNET_IPC_ONLY=1 is set.
    """
    raw_key_32 = b"\x42" * 32
    share_a, share_b, fernet_key = _shares_for_known_key(raw_key_32)
    backend = FernetBackend(shares=(share_a, share_b))

    value = b"sk-anthropic-redacted-decoy-value"
    expected = hmac.new(fernet_key, value, sha256).digest()

    actual = await backend.mac(value)
    assert isinstance(actual, bytes)
    assert actual == expected, (
        "mac(value) must equal hmac.new(fernet_key, value, sha256).digest() "
        "byte-for-byte, otherwise decoy_hash bytes would change across the "
        "WORTHLESS_FERNET_IPC_ONLY flag flip and invalidate stored hashes."
    )


async def test_mac_is_deterministic() -> None:
    """Same key + same value MUST yield identical bytes across calls."""
    raw_key_32 = b"\x11" * 32
    share_a, share_b, _ = _shares_for_known_key(raw_key_32)
    backend = FernetBackend(shares=(share_a, share_b))

    value = b"deterministic-please"
    a = await backend.mac(value)
    b = await backend.mac(value)
    assert a == b


async def test_mac_empty_value_is_well_defined() -> None:
    """``mac(b"")`` MUST return HMAC-SHA256 of empty bytes, not crash.

    Edge case: ``hmac.new(key, b"", sha256).digest()`` is a well-defined
    32-byte value. Empty decoy values could plausibly appear in malformed
    enrollments; the verb must handle them without raising or returning
    a sentinel.
    """
    raw_key_32 = b"\xee" * 32
    share_a, share_b, fernet_key = _shares_for_known_key(raw_key_32)
    backend = FernetBackend(shares=(share_a, share_b))

    expected = hmac.new(fernet_key, b"", sha256).digest()
    actual = await backend.mac(b"")
    assert isinstance(actual, bytes)
    assert len(actual) == 32
    assert actual == expected


async def test_mac_differs_across_values() -> None:
    """Different values MUST produce different bytes (HMAC is a function of value)."""
    raw_key_32 = b"\x22" * 32
    share_a, share_b, _ = _shares_for_known_key(raw_key_32)
    backend = FernetBackend(shares=(share_a, share_b))

    a = await backend.mac(b"value-one")
    b = await backend.mac(b"value-two")
    assert a != b


async def test_mac_differs_across_keys() -> None:
    """Different keys MUST produce different bytes for the same value."""
    a_share_a, a_share_b, _ = _shares_for_known_key(b"\x33" * 32)
    b_share_a, b_share_b, _ = _shares_for_known_key(b"\x44" * 32)
    backend_a = FernetBackend(shares=(a_share_a, a_share_b))
    backend_b = FernetBackend(shares=(b_share_a, b_share_b))

    value = b"same-input"
    assert await backend_a.mac(value) != await backend_b.mac(value)


async def test_mac_is_not_alias_of_attest() -> None:
    """``mac`` and ``attest`` MUST produce different bytes for the same input.

    Defends against a future refactor that 'simplifies' both to one HMAC
    flavor. ``attest`` is HKDF-derived + length-prefixed (so the MAC input
    domain-separates ``(nonce, purpose)``); ``mac`` is the raw tag over a
    single value with the raw Fernet key. Any code path where they collide
    is a bug.
    """
    raw_key_32 = b"\x55" * 32
    share_a, share_b, _ = _shares_for_known_key(raw_key_32)
    backend = FernetBackend(shares=(share_a, share_b))

    same_input = b"\xab" * 32
    mac_out = await backend.mac(same_input)
    attest_out = await backend.attest(nonce=same_input, purpose=None)
    assert mac_out != attest_out, (
        "mac must NOT alias attest — they use different MAC keys "
        "(raw key vs HKDF-derived) and different message framing."
    )


# ---------------------------------------------------------------------------
# IPC-level: handshake caps + roundtrip dispatch
# ---------------------------------------------------------------------------


async def test_mac_advertised_in_backend_caps_via_handshake(
    ipc_client: IPCClient,
) -> None:
    """The sidecar's HELLO response MUST advertise ``mac`` in backend_caps
    when the bound backend is a FernetBackend.

    The proxy supervisor latches caps on first connect and refuses any change
    on reconnect. Adding ``mac`` to the advertised set is the contract the
    proxy expects; missing it would cause the flag-on path to fail at
    handshake.
    """
    assert "mac" in ipc_client.backend_caps, (
        f"FernetBackend must advertise 'mac' in handshake; got {ipc_client.backend_caps!r}"
    )


async def test_mac_op_dispatches_to_backend_via_ipc(
    ipc_client: IPCClient,
    fernet_shares: tuple[bytes, bytes],
) -> None:
    """``client.mac(value)`` over IPC MUST equal direct ``backend.mac(value)``.

    Roundtrip equivalence test: any byte difference between the IPC-routed
    result and the in-process result would mean wire-encoding loses
    information (e.g. truncation, ASCII-coercion of bytes, etc.).
    """
    backend = FernetBackend(shares=fernet_shares)
    value = b"\x00\xff\x10\x20payload-with-binary-bytes"

    expected = await backend.mac(value)
    actual = await ipc_client.mac(value)

    assert isinstance(actual, bytes)
    assert actual == expected


async def test_mac_invalid_value_type_rejected_as_proto_error(
    ipc_client: IPCClient,
) -> None:
    """A ``mac`` request with a non-bytes ``value`` MUST surface as PROTO error.

    Mirrors the existing dispatch-validation contract for seal/open/attest:
    structural body errors emit a fixed PROTO message and don't touch the
    backend. Without this guard, msgpack-decoded ``str`` could silently
    become ``b"..."`` after ``.encode()`` somewhere downstream and produce
    different bytes than a caller expecting strict bytes-in.
    """
    # ``IPCClient.mac`` will type-validate before sending; we have to bypass
    # by calling the lower-level ``_request`` with a malformed body.
    with pytest.raises(IPCProtocolError) as excinfo:
        await ipc_client._request("mac", {"value": "not-bytes-it-is-a-str"})
    assert "PROTO" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Defense-in-depth: a backend whose caps doesn't advertise ``mac``
# ---------------------------------------------------------------------------


class _MacLessBackend(Backend):
    """A backend stuck on the v1.0 verb set — ``mac`` is NOT in caps.

    Simulates a future v2.0 KMS/MPC backend that hasn't implemented
    raw-HMAC and shouldn't accept ``mac`` requests. The sidecar must
    refuse the op based on the backend's advertised capabilities — NOT
    only on a static module-level allowlist that future backends might
    not update.
    """

    caps: tuple[str, ...] = ("seal", "open", "attest")

    def __init__(self, inner: FernetBackend) -> None:
        self._inner = inner

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        return await self._inner.seal(plaintext, context)

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        return await self._inner.open(ciphertext, context, key_id)

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        return await self._inner.attest(nonce, purpose)


@pytest_asyncio.fixture
async def macless_sidecar(
    sidecar_socket_path: Path,
    fernet_backend: FernetBackend,
):
    """Sidecar bound to a backend whose caps deliberately omits ``mac``."""
    backend = _MacLessBackend(inner=fernet_backend)
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=backend,
        allowed_uids=[os.getuid()],
    )
    try:
        yield server
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass


async def test_mac_advertised_caps_match_backend(
    macless_sidecar,
    sidecar_socket_path: Path,
) -> None:
    """A backend whose ``caps`` lacks ``mac`` MUST NOT advertise it on the wire.

    Locks the invariant that handshake caps are derived from the bound
    backend, not a static module constant. Without this, a v2.0 backend
    could be plumbed in and the sidecar would silently advertise ``mac``
    despite the backend not implementing it.
    """
    async with IPCClient(sidecar_socket_path) as client:
        assert "mac" not in client.backend_caps, (
            f"sidecar must derive caps from backend; got {client.backend_caps!r}"
        )


async def test_mac_rejected_when_backend_lacks_capability(
    macless_sidecar,
    sidecar_socket_path: Path,
) -> None:
    """Calling ``mac`` against a backend whose caps lacks ``mac`` MUST raise.

    Defense-in-depth: defends against the failure mode where a future
    backend forgets to implement ``mac()`` but the dispatch layer still
    routes the op (e.g. via ``hasattr``-style introspection that finds
    a base-class default raising NotImplementedError). The check must
    happen at the validation layer, BEFORE any backend method is called,
    so the failure surfaces as a clean PROTO error rather than an
    opaque BackendError that could mask information leaks.
    """
    async with IPCClient(sidecar_socket_path) as client:
        with pytest.raises(IPCProtocolError) as excinfo:
            await client.mac(b"any-value")
        assert "PROTO" in str(excinfo.value)

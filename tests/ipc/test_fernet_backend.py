"""Unit tests for ``worthless.sidecar.backends.fernet.FernetBackend``.

Pure backend: no IPC, no sockets, no asyncio server. These tests pin the
contract the backend must satisfy in isolation so bugs at that layer
don't masquerade as IPC-framing bugs in the roundtrip suite.

Contract references:
    engineering/ipc-contract.md §seal, §open, §attest

Shape pinned here:
    FernetBackend(shares: tuple[bytes, bytes])
        .seal(plaintext: bytes, context: bytes | None = None)  -> bytes  (async)
        .open(ciphertext: bytes, context: bytes | None = None,
              key_id: bytes | None = None)                     -> bytes  (async)
        .attest(nonce: bytes, purpose: str | None = None)      -> bytes  (async)
"""

from __future__ import annotations

import base64
import secrets

import pytest

# --- import under test ----------------------------------------------------
# Module does not exist yet; collection fails RED with ModuleNotFoundError
# until backend-developer implements it.
from worthless.sidecar.backends.fernet import FernetBackend


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _random_shares() -> tuple[bytes, bytes]:
    """Two 44-byte shares whose XOR is a valid urlsafe-b64 Fernet key."""
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))  # 44 bytes
    a = secrets.token_bytes(len(key))
    b = bytes(x ^ y for x, y in zip(a, key, strict=True))
    return a, b


@pytest.fixture
def backend() -> FernetBackend:
    return FernetBackend(shares=_random_shares())


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


async def test_seal_then_open_roundtrip(backend: FernetBackend) -> None:
    """open(seal(pt)) == pt — the backend-level equivalent of the e2e test."""
    plaintext = b"x"
    ciphertext = await backend.seal(plaintext)

    assert isinstance(ciphertext, bytes)
    assert ciphertext != plaintext, "ciphertext must not trivially equal plaintext"

    recovered = await backend.open(ciphertext)
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# Tamper-detection
# ---------------------------------------------------------------------------


async def test_open_rejects_tampered_ciphertext(backend: FernetBackend) -> None:
    """Flipping a single byte must cause open() to raise.

    Fernet authenticates via HMAC; any flipped byte in the token breaks the
    MAC and Fernet raises ``InvalidToken``. The backend is free to wrap it
    (e.g. into a custom BackendError) — we only require "something raises".
    """
    plaintext = b"integrity matters"
    ciphertext = bytearray(await backend.seal(plaintext))

    # Flip a byte deep in the token — far enough past the version byte that
    # we're hitting either the IV, the payload, or the MAC.
    target_idx = len(ciphertext) // 2
    ciphertext[target_idx] ^= 0x01

    with pytest.raises(Exception):
        await backend.open(bytes(ciphertext))


# ---------------------------------------------------------------------------
# Attest determinism
# ---------------------------------------------------------------------------


async def test_attest_is_deterministic_same_nonce(backend: FernetBackend) -> None:
    """Two attest() calls with identical nonce must yield identical evidence."""
    nonce = b"\xab" * 32

    evidence_1 = await backend.attest(nonce=nonce)
    evidence_2 = await backend.attest(nonce=nonce)

    assert isinstance(evidence_1, bytes)
    assert len(evidence_1) > 0
    assert evidence_1 == evidence_2


async def test_attest_differs_across_nonces(backend: FernetBackend) -> None:
    """Different nonces must produce different evidence (no trivial constant)."""
    evidence_a = await backend.attest(nonce=b"\x00" * 32)
    evidence_b = await backend.attest(nonce=b"\xff" * 32)

    assert evidence_a != evidence_b, (
        "attest must be a function of the nonce, otherwise replay is trivial"
    )


async def test_attest_domain_separation_length_prefix(backend: FernetBackend) -> None:
    """attest(nonce, purpose) must not collide across (nonce, purpose) splits.

    Naive ``nonce + purpose.encode()`` is non-injective at the boundary:
    ``attest(b"abcde", "")`` and ``attest(b"abc", "de")`` concatenate to
    the same bytes. Once a proxy-side verifier exists that checks
    ``(nonce, purpose)`` independently, an attacker could harvest evidence
    under one purpose and replay it under another.

    The backend must length-prefix each component so these two pairs
    produce DIFFERENT MACs.
    """
    nonce_split_a = b"abcde"
    purpose_split_a = ""
    nonce_split_b = b"abc"
    purpose_split_b = "de"

    # Sanity: the naive concatenation is identical — this is the collision
    # that the fix must defeat.
    assert nonce_split_a + purpose_split_a.encode(
        "utf-8"
    ) == nonce_split_b + purpose_split_b.encode("utf-8")

    ev_a = await backend.attest(nonce=nonce_split_a, purpose=purpose_split_a)
    ev_b = await backend.attest(nonce=nonce_split_b, purpose=purpose_split_b)

    assert ev_a != ev_b, (
        "attest must length-prefix nonce and purpose separately; "
        "otherwise cross-purpose MAC collisions are trivial"
    )


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_share_length_mismatch_raises() -> None:
    """Shares of unequal length cannot XOR-reconstruct a key — reject eagerly."""
    short = secrets.token_bytes(10)
    long = secrets.token_bytes(44)

    with pytest.raises(ValueError):
        FernetBackend(shares=(short, long))


# ---------------------------------------------------------------------------
# Share reconstruction — pin the math
# ---------------------------------------------------------------------------


def test_share_reconstruction_produces_expected_fernet_key() -> None:
    """Hard-coded shares must XOR to a known Fernet key.

    This locks the XOR semantics: backend-developer cannot silently swap
    to "shares[0] + shares[1]" or "hkdf(shares[0], shares[1])" without
    this test failing. The *raw key bytes* are 32 bytes of zeros; the
    Fernet-form key is ``base64.urlsafe_b64encode(b"\\x00" * 32)``.
    """
    raw_key_32 = b"\x00" * 32
    fernet_key = base64.urlsafe_b64encode(raw_key_32)  # 44 bytes, ends with '='

    # Two shares whose XOR is exactly ``fernet_key``.
    share_a = b"\x5a" * len(fernet_key)
    share_b = bytes(a ^ k for a, k in zip(share_a, fernet_key, strict=True))

    # Sanity: local XOR reproduces the key.
    reconstructed = bytes(a ^ b for a, b in zip(share_a, share_b, strict=True))
    assert reconstructed == fernet_key

    # The backend must accept these shares without error. If it uses a
    # different reconstruction (concat, hash, etc.) the Fernet init inside
    # the constructor will raise on the malformed key.
    backend = FernetBackend(shares=(share_a, share_b))
    assert backend is not None

"""Shared HKDF key-derivation for keyed-MAC paths (WOR-637).

The sidecar ``FernetBackend.mac`` verb and the in-process
``ShardRepository._compute_decoy_hash`` path must key their HMAC with the
*same* derived subkey so the decoy-hash bytes are byte-identical across the
``WORTHLESS_FERNET_IPC_ONLY`` flag flip. Both import :func:`derive_mac_secret`
from here so the derivation exists in exactly one place — duplicating the HKDF
parameters in two modules is the failure mode that silently diverges detection.

Security (WOR-637): keying HMAC with the raw Fernet key turned the locked vault
into a chosen-message oracle on the master key. Deriving a dedicated subkey via
HKDF with a MAC-specific salt/info closes that oracle while preserving
determinism. The salt/info here are deliberately distinct from the ``attest``
path's ``worthless-attest-v1`` / ``attest`` so the two purposes domain-separate.

This module imports only HKDF primitives — never ``cryptography.fernet`` or
``worthless.crypto.splitter`` — so it is safe to import from any layer without
tripping the WOR-309 proxy-import guard.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["derive_mac_secret"]

_MAC_SALT = b"worthless-mac-v1"
_MAC_INFO = b"mac"
_MAC_SECRET_LEN = 32


def derive_mac_secret(fernet_key: bytes | bytearray) -> bytes:
    """Derive the 32-byte MAC subkey from *fernet_key* via HKDF-SHA256.

    *fernet_key* is the 44-byte urlsafe-base64 Fernet key (the same bytes the
    sidecar reconstructs from its XOR shares and the repository holds in its
    legacy in-process mode). Accepts a ``bytearray`` so the in-process caller
    can pass its zeroable key buffer directly without an un-zeroable ``bytes``
    copy (SR-01); HKDF reads the buffer identically either way. The returned 32
    bytes are used as the HMAC key for decoy-hash computation. Identical input
    always yields identical output, so callers on either side of the IPC
    boundary produce byte-identical MACs.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_MAC_SECRET_LEN,
        salt=_MAC_SALT,
        info=_MAC_INFO,
    )
    return hkdf.derive(fernet_key)

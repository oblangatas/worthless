"""Tell whether a Fernet key fits a token, without decrypting it (worthless-saaz).

A Fernet token is ``0x80 | timestamp(8) | iv(16) | ciphertext | hmac(32)``, the
HMAC being SHA-256 keyed by the first 16 bytes of the decoded key. Recomputing
it answers "would this key open this token?" with no plaintext produced:
``Fernet.decrypt`` would hand back immutable ``bytes`` we could never wipe.

Stdlib only, so the proxy import path never loads ``cryptography.fernet``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from worthless.crypto.types import zero_buf

_HMAC_LEN = 32
_MIN_TOKEN_LEN = 1 + 8 + 16 + 16 + _HMAC_LEN  # version, ts, iv, one block, hmac


def key_fits_token(key: bytearray, token: bytes) -> bool:
    """True iff *key* produced *token*'s HMAC. Leaves *key* untouched."""
    try:
        # ponytail: b64decode returns immutable bytes, so one copy of the key
        # outlives this call — same ceiling as every Fernet use in Python.
        decoded = bytearray(base64.urlsafe_b64decode(bytes(key)))
    except (binascii.Error, ValueError):
        return False
    signing = decoded[:16]
    try:
        data = base64.urlsafe_b64decode(token)
        if len(decoded) != 32 or len(data) < _MIN_TOKEN_LEN or data[0] != 0x80:
            return False
        expected = hmac.new(bytes(signing), data[:-_HMAC_LEN], hashlib.sha256).digest()
        return hmac.compare_digest(expected, data[-_HMAC_LEN:])
    except (binascii.Error, ValueError):
        return False
    finally:
        zero_buf(signing)
        zero_buf(decoded)

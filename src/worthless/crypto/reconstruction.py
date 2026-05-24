"""Proxy/CLI-side key reconstruction primitives (WOR-309).

Split out of :mod:`worthless.crypto.splitter` so the proxy can reconstruct
keys from sidecar-decrypted shard-B without importing the enrollment-side
splitter module. The AST CI guard at
``tests/architecture/test_proxy_imports.py`` bans
``worthless.crypto.splitter`` from the proxy package; this sibling module
is allowed.

Contains only the verification + reconstruction primitives — no Fernet,
no enrollment-side helpers (``split_key*``, ``derive_shard_a_fp``,
``_make_commitment``).
"""

from __future__ import annotations

import hmac
import hashlib
from collections.abc import Generator
from contextlib import contextmanager

from worthless.crypto.charsets import ALPHANUMERIC, BASE64URL, PRINTABLE
from worthless.crypto.types import zero_buf
from worthless.exceptions import ShardTamperedError

_CHAR_TO_IDX: dict[str, dict[str, int]] = {
    cs: {c: i for i, c in enumerate(cs)} for cs in (ALPHANUMERIC, BASE64URL, PRINTABLE)
}


def _verify_commitment(
    payload: bytes | bytearray,
    commitment: bytes | bytearray,
    nonce: bytes | bytearray,
) -> None:
    """Verify HMAC-SHA256 commitment. Raises ShardTamperedError on mismatch."""
    expected = bytearray(
        hmac.new(nonce, payload, hashlib.sha256).digest()  # nosec B303 — HMAC-SHA256
    )
    try:
        if not hmac.compare_digest(expected, commitment):
            raise ShardTamperedError("HMAC verification failed: shard data has been tampered with")
    finally:
        zero_buf(expected)


def reconstruct_key_fp(
    shard_a: bytes | bytearray,
    shard_b: bytes | bytearray,
    commitment: bytes | bytearray,
    nonce: bytes | bytearray,
    prefix: str,
    charset: str,
) -> bytearray:
    """Reconstruct the original API key from format-preserving shards.

    Verifies the HMAC commitment before returning.  If verification fails,
    all intermediate material is zeroed and ShardTamperedError is raised.
    """
    if isinstance(shard_a, bytearray):
        shard_a_str = shard_a.decode("utf-8")
    else:
        tmp = bytearray(shard_a)
        shard_a_str = tmp.decode("utf-8")
        tmp[:] = b"\x00" * len(tmp)

    if isinstance(shard_b, bytearray):
        shard_b_str = shard_b.decode("utf-8")
    else:
        tmp = bytearray(shard_b)
        shard_b_str = tmp.decode("utf-8")
        tmp[:] = b"\x00" * len(tmp)

    if not shard_a_str.startswith(prefix):
        raise ValueError(f"Shard-A does not start with expected prefix {prefix!r}")

    a_body = shard_a_str[len(prefix) :]
    b_body = shard_b_str

    if len(a_body) != len(b_body):
        raise ValueError(f"Shard body length mismatch: a={len(a_body)}, b={len(b_body)}")

    n = len(charset)
    char_to_idx = _CHAR_TO_IDX[charset]

    prefix_bytes = prefix.encode("utf-8")
    key = bytearray(len(prefix_bytes) + len(a_body))
    key[: len(prefix_bytes)] = prefix_bytes

    # SR-02: a tampered shard may contain chars outside charset, causing
    # KeyError mid-loop with partial key material in `key`. The try/except
    # zeroes `key` before the exception propagates — whether the failure is
    # a KeyError in the loop or an HMAC mismatch in _verify_commitment.
    try:
        for i, (a_char, b_char) in enumerate(zip(a_body, b_body, strict=True)):
            original_idx = (char_to_idx[a_char] + char_to_idx[b_char]) % n
            key[len(prefix_bytes) + i] = ord(charset[original_idx])

        _verify_commitment(key, commitment, nonce)
    except Exception:
        zero_buf(key)
        raise

    return key


def reconstruct_key(
    shard_a: bytes | bytearray,
    shard_b: bytes | bytearray,
    commitment: bytes | bytearray,
    nonce: bytes | bytearray,
) -> bytearray:
    """Reconstruct the original API key from two XOR shards (legacy).

    Verifies the HMAC commitment before returning the key. Zeros all
    intermediate material on tamper.
    """
    if len(shard_a) != len(shard_b):
        raise ValueError(f"Shard length mismatch: shard_a={len(shard_a)}, shard_b={len(shard_b)}")

    key = bytearray(a ^ b for a, b in zip(shard_a, shard_b, strict=True))

    try:
        _verify_commitment(key, commitment, nonce)
    except Exception:
        zero_buf(key)
        raise

    return key


@contextmanager
def secure_key(key_buf: bytearray) -> Generator[bytearray, None, None]:
    """Context manager that zeros key material on exit (SR-02)."""
    if not isinstance(key_buf, bytearray):  # type: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"secure_key requires a bytearray, got {type(key_buf).__name__}")
    try:
        yield key_buf
    finally:
        zero_buf(key_buf)

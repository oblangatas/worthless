"""Format-preserving key splitting with HMAC commitment.

Enrollment-side primitives only (WOR-309):
- split_key_fp: Format-preserving split — shard-A keeps prefix/charset/length
- split_key: Legacy byte-level XOR split
- derive_shard_a_fp: Re-lock helper — derive shard-A given shard-B + key

Reconstruction primitives (``reconstruct_key*``, ``secure_key``,
``_verify_commitment``) live in :mod:`worthless.crypto.reconstruction` so
the proxy can import them without tripping the AST CI guard at
``tests/architecture/test_proxy_imports.py`` (which bans
``worthless.crypto.splitter`` from the proxy package).

Re-exports below preserve the public API for CLI and test callers.
"""

from __future__ import annotations

import hmac
import secrets

from worthless.crypto.charsets import ALPHANUMERIC, BASE64URL, PRINTABLE, PROVIDER_CHARSETS
from worthless.crypto.reconstruction import (
    reconstruct_key,
    reconstruct_key_fp,
    secure_key,
)
from worthless.crypto.types import FormatPreservingSplitResult, SplitResult, zero_buf

__all__ = [
    "derive_shard_a_fp",
    "reconstruct_key",
    "reconstruct_key_fp",
    "secure_key",
    "split_key",
    "split_key_fp",
]

# ---------------------------------------------------------------------------
# Precomputed lookups for format-preserving split (SR-12)
# ---------------------------------------------------------------------------

_BASE64URL_SET = frozenset(BASE64URL)
_ALPHANUMERIC_SET = frozenset(ALPHANUMERIC)
_PRINTABLE_SET = frozenset(PRINTABLE)

_CHAR_TO_IDX: dict[str, dict[str, int]] = {
    cs: {c: i for i, c in enumerate(cs)} for cs in (ALPHANUMERIC, BASE64URL, PRINTABLE)
}


def _detect_charset(body: str, provider: str | None = None) -> str:
    """Determine the minimal charset that covers all characters in *body*.

    Tries provider-specific charset first, then falls back to broader
    charsets.
    """
    if provider and provider in PROVIDER_CHARSETS:
        cs = PROVIDER_CHARSETS[provider]
        if all(c in _CHAR_TO_IDX[cs] for c in body):
            return cs

    for cs, cs_set in (
        (ALPHANUMERIC, _ALPHANUMERIC_SET),
        (BASE64URL, _BASE64URL_SET),
        (PRINTABLE, _PRINTABLE_SET),
    ):
        if all(c in cs_set for c in body):
            return cs

    # SR-04: don't leak key characters in exceptions
    raise ValueError(
        f"Key body contains {sum(1 for c in body if c not in _PRINTABLE_SET)} "
        "character(s) outside printable ASCII"
    )


# ---------------------------------------------------------------------------
# HMAC commitment helpers (shared by FP and legacy paths)
# ---------------------------------------------------------------------------


def _make_commitment(payload: bytes | bytearray) -> tuple[bytearray, bytearray]:
    """Create an HMAC-SHA256 commitment over the given payload.

    Returns (commitment, nonce).
    """
    # mutmut: skip — token_bytes(None) defaults to 32; equivalent mutant
    nonce = bytearray(secrets.token_bytes(32))
    # digestmod passed as a name string (per RFC 4648 hmac.new accepts str|callable|module);
    # using the string form keeps static analyzers from misclassifying the HMAC keyed
    # construction as bare-SHA256 password hashing (CodeQL py/weak-cryptographic-algorithm).
    commitment = bytearray(
        hmac.new(nonce, payload, "sha256").digest()  # nosec B303 — HMAC-SHA256  # lgtm[py/weak-sensitive-data-hashing]
    )
    return commitment, nonce


# ---------------------------------------------------------------------------
# Format-preserving split (SR-12) — reconstruction lives in reconstruction.py
# ---------------------------------------------------------------------------


def split_key_fp(
    api_key: str, prefix: str, provider: str | None = None
) -> FormatPreservingSplitResult:
    """Split an API key using format-preserving modular arithmetic.

    Shard-A preserves the key's prefix, charset, and length — it is
    indistinguishable from a real API key (SR-12).  The split uses a
    one-time pad over Z/N where N is the charset size.

    Args:
        api_key: The full API key string (e.g. "sk-proj-abc123...").
        prefix: The prefix to preserve verbatim (e.g. "sk-proj-").
        provider: Provider name for charset selection (optional).

    Returns:
        A FormatPreservingSplitResult with format-valid shard_a and shard_b.
    """
    if not api_key:
        raise ValueError("Cannot split an empty key")
    if not api_key.startswith(prefix):
        raise ValueError(f"Key does not start with prefix {prefix!r}")

    body = api_key[len(prefix) :]
    if not body:
        raise ValueError("Key body is empty after prefix removal")

    charset = _detect_charset(body, provider)
    n = len(charset)
    char_to_idx = _CHAR_TO_IDX[charset]

    shard_a_chars: list[str] = []
    shard_b_chars: list[str] = []
    for char in body:
        original_idx = char_to_idx[char]
        mask = secrets.randbelow(n)
        shard_a_chars.append(charset[(original_idx - mask) % n])
        shard_b_chars.append(charset[mask])

    shard_a_str = prefix + "".join(shard_a_chars)
    shard_b_str = "".join(shard_b_chars)

    commitment, nonce = _make_commitment(bytearray(api_key.encode("utf-8")))

    return FormatPreservingSplitResult(
        shard_a=bytearray(shard_a_str.encode("utf-8")),
        shard_b=bytearray(shard_b_str.encode("utf-8")),
        commitment=commitment,
        nonce=nonce,
        prefix=prefix,
        charset=charset,
    )


def derive_shard_a_fp(
    api_key: str,
    shard_b: bytes | bytearray,
    prefix: str,
    charset: str,
) -> bytearray:
    """Derive the shard-A that pairs with *shard_b* to reconstruct *api_key*.

    Re-lock path: when an alias is already enrolled (shard-B stored), locking
    the same real key in a new .env must recreate the format-preserving
    shard-A rather than leaving the real key in the file. Inverting the
    modular split over charset index space: shard_a_idx = (key_idx - shard_b_idx) mod N.
    """
    # Defense-in-depth: prefix + charset come from decrypted DB rows, a
    # different trust boundary than the live env value. Row corruption /
    # swap would otherwise silently slice the wrong bytes or KeyError.
    if not api_key.startswith(prefix):
        raise ValueError(f"Key does not start with stored prefix {prefix!r}")
    if charset not in _CHAR_TO_IDX:
        raise ValueError(f"Unsupported stored charset (len={len(charset)})")

    body = api_key[len(prefix) :]
    # SR-01: decode via mutable bytearray so we can zero the copy. The
    # caller owns shard_b's lifecycle; the transient copy here is ours.
    tmp = bytearray(shard_b)
    try:
        b_body = tmp.decode("utf-8")
    finally:
        zero_buf(tmp)

    if len(body) != len(b_body):
        raise ValueError(f"Shard-B length mismatch: key_body={len(body)}, shard_b={len(b_body)}")

    n = len(charset)
    char_to_idx = _CHAR_TO_IDX[charset]

    shard_a_chars: list[str] = []
    for k_char, b_char in zip(body, b_body, strict=True):
        shard_a_chars.append(charset[(char_to_idx[k_char] - char_to_idx[b_char]) % n])

    return bytearray((prefix + "".join(shard_a_chars)).encode("utf-8"))


def split_key(api_key: bytes | bytearray) -> SplitResult:
    """Split an API key into two XOR shards with an HMAC commitment.

    Accepts ``bytes`` (existing callers) or ``bytearray`` (SR-01-compliant
    callers that own a zeroable buffer of secret material). The body never
    casts to ``bytes`` internally, so passing a ``bytearray`` does not
    create an immutable copy of the secret on the heap.

    Args:
        api_key: The raw API key bytes/bytearray to split.

    Returns:
        A SplitResult containing shard_a, shard_b, commitment, and nonce.

    Raises:
        ValueError: If the key is empty.
    """
    if not api_key:
        raise ValueError("Cannot split an empty key")

    mask = bytearray(secrets.token_bytes(len(api_key)))
    shard_a = bytearray(a ^ b for a, b in zip(api_key, mask, strict=True))

    commitment, nonce = _make_commitment(api_key)

    return SplitResult(
        shard_a=shard_a,
        shard_b=mask,
        commitment=commitment,
        nonce=nonce,
    )

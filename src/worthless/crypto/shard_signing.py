"""Shard-A signing — HMAC envelope for format-preserving shard-A authentication.

Phase 6 (worthless-1pua): Makes raw shard-A bytes cryptographically worthless
without the server-side signing key.

Envelope format
---------------
  signed_envelope = prefix + base64url(nonce_16 || expiry_4 || hmac_truncated_16) + shard_a_body

Where:
  - prefix        = the key's format prefix (e.g. "sk-proj-", "sk-ant-api03-")
  - nonce         = 16 cryptographically random bytes (per-enrollment, generated at lock time)
  - expiry        = 4-byte big-endian Unix timestamp (seconds); default TTL = 1 year
  - hmac_truncated = first 16 bytes of HMAC-SHA256(alias || nonce || expiry || original_shard_a,
                                                    signing_key)
  - shard_a_body  = everything in original shard_a AFTER the prefix

The 36 overhead bytes encode to exactly 48 base64url characters (no padding, since 36 % 3 == 0).
base64url charset (A-Za-z0-9-_) is a subset of all known provider key charsets — the signed
envelope is visually indistinguishable from a normal API key, just 48 characters longer.

Security properties
-------------------
- HMAC binds the envelope to: (alias, nonce, expiry, original_shard_a, signing_key)
- Raw shard_a bytes (no HMAC) are rejected immediately at proxy ingress
- Wrong alias → HMAC mismatch → rejected
- Wrong signing key → HMAC mismatch → rejected
- Tampered shard_a or overhead → HMAC mismatch → rejected
- Expired envelope → rejected on the expiry check before HMAC
- Re-lock revocation: nonces are per-alias and upserted on re-lock; envelopes issued
  before the re-lock are immediately invalid (nonce mismatch). TLS handles per-request
  replay — the nonce is NOT a per-request token.

Residual risks (documented)
---------------------------
- Signing key stored at rest in ~/.worthless/signing.key (file permissions: 0o600)
  An attacker with local file access can read it. Mitigation: mTLS + HSM in Phase 6b.
- Truncated HMAC (16 bytes / 128 bits) provides 2^64 security against forgery.
  Acceptable for this threat model; full 32 bytes would lengthen the envelope by 16 chars.
- Threat model scope: Phase 6 protects against non-filesystem exfiltration vectors
  (git history leaks, CI log leaks, env var scraping). It does NOT protect against
  machine-level compromise — an attacker with read access to the proxy host can read
  signing.key and forge envelopes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import stat
import struct
import time
from pathlib import Path

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Overhead bytes: nonce (16) + expiry (4) + truncated HMAC (16) = 36 bytes.
OVERHEAD_BYTES: int = 36

#: Overhead chars in the envelope: base64url(36 bytes) = 48 chars (no padding).
OVERHEAD_CHARS: int = 48  # ceil(36 * 4 / 3) — exact, since 36 % 3 == 0

#: Default enrollment TTL in days (1 year).
_DEFAULT_TTL_DAYS: int = 365

#: Signing key size in bytes.
_KEY_BYTES: int = 32


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ShardSigningError(ValueError):
    """Raised when shard-A envelope verification fails for any reason.

    Callers should treat all instances identically (constant-time 401 response).
    The message is intentionally generic — do not log it in a way that distinguishes
    prefix mismatch from HMAC failure (timing oracle for envelope structure).
    """


# ---------------------------------------------------------------------------
# Signing key management
# ---------------------------------------------------------------------------


def generate_signing_key() -> bytes:
    """Generate a fresh 32-byte cryptographically random signing key."""
    return secrets.token_bytes(_KEY_BYTES)


def load_or_create_signing_key(home_dir: Path) -> bytes:
    """Load the signing key from *home_dir/signing.key*, creating it if absent.

    The key is stored as 64 hex characters (lowercase).  File permissions
    are set to 0o600 (owner read/write only) atomically at creation and
    verified on every load — group/other read bits cause a hard failure.

    Args:
        home_dir: Directory containing ``signing.key``
                  (typically ``~/.worthless/``).

    Returns:
        32-byte signing key as ``bytes``.

    Raises:
        OSError: If the key file cannot be read or written.
        ValueError: If the key file has insecure permissions or is corrupt.
    """
    key_path = home_dir / "signing.key"

    if key_path.exists():
        # Reject if group or other bits are set — a world-readable signing key
        # defeats Phase 6's entire guarantee.
        mode = key_path.stat().st_mode
        unsafe_bits = (
            stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
        )
        if mode & unsafe_bits:
            raise ValueError(
                f"signing key at {key_path} has insecure permissions "
                f"({oct(stat.S_IMODE(mode))}); expected 0o600. "
                "Fix: chmod 600 ~/.worthless/signing.key"
            )
        raw = key_path.read_text().strip()
        key = bytes.fromhex(raw)
        if len(key) != _KEY_BYTES:
            raise ValueError(
                f"signing key at {key_path} is corrupt: got {len(key)} bytes, expected {_KEY_BYTES}"
            )
        return key

    # Create new key atomically at 0o600 — no TOCTOU window between write and chmod.
    key = generate_signing_key()
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (key.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)

    # If a DB already exists but the signing key was just created, all existing
    # enrollments were signed with a different (now-gone) key. Warn loudly so the
    # operator knows to re-lock every .env file.
    if (home_dir / "worthless.db").exists():
        _logger.warning(
            "Created new signing key at %s but worthless.db already exists — "
            "existing enrollments were signed with a different key and will be "
            "rejected at proxy ingress until re-locked. Run: worthless lock <your-.env>",
            key_path,
        )

    return key


# ---------------------------------------------------------------------------
# Envelope construction
# ---------------------------------------------------------------------------


def sign_shard_a(
    shard_a: bytearray,
    alias: str,
    signing_key: bytes,
    *,
    prefix: str,
    ttl_days: int = _DEFAULT_TTL_DAYS,
) -> tuple[bytearray, bytes, int]:
    """Wrap *shard_a* in an HMAC envelope.

    Args:
        shard_a:     Format-preserving shard-A (starts with *prefix*).
        alias:       Enrollment alias; bound into the HMAC (prevents cross-alias reuse).
        signing_key: 32-byte server-side secret; never leaves the host.
        prefix:      Key prefix (e.g. ``"sk-proj-"``).
        ttl_days:    Validity period in days from now (default 365).

    Returns:
        ``(signed_envelope, nonce, expires_at)`` where:
        - ``signed_envelope``: bytearray with same prefix, 48 chars longer than *shard_a*.
        - ``nonce``: 16-byte random bytes stored in the envelope (and in SQLite).
        - ``expires_at``: Unix timestamp of expiry (stored in SQLite alongside the nonce).

    Note:
        The original *shard_a* bytearray is NOT modified or zeroed by this function.
        The caller retains ownership and must zero it after use (SR-01).
    """
    if not bytes(shard_a).startswith(prefix.encode("ascii")):
        raise ValueError(f"shard_a does not start with prefix {prefix!r}")

    nonce = secrets.token_bytes(16)
    expires_at = int(time.time()) + ttl_days * 86400
    expiry_bytes = struct.pack(">I", expires_at)

    # HMAC over: alias || nonce || expiry || original_shard_a
    msg = alias.encode("utf-8") + nonce + expiry_bytes + bytes(shard_a)
    mac_full = hmac.new(signing_key, msg, hashlib.sha256).digest()
    mac_truncated = mac_full[:16]  # 128-bit truncation — see module docstring

    # Encode 36 overhead bytes → 48 base64url chars (no padding)
    overhead_raw = nonce + expiry_bytes + mac_truncated
    if len(overhead_raw) != OVERHEAD_BYTES:  # pragma: no cover
        raise AssertionError(f"overhead_raw length {len(overhead_raw)} != {OVERHEAD_BYTES}")
    overhead_b64 = base64.urlsafe_b64encode(overhead_raw).decode("ascii")
    if len(overhead_b64) != OVERHEAD_CHARS:  # pragma: no cover
        raise AssertionError(f"overhead_b64 length {len(overhead_b64)} != {OVERHEAD_CHARS}")

    # signed_envelope = prefix + overhead + shard_a_body
    shard_a_str = shard_a.decode("ascii")
    body = shard_a_str[len(prefix) :]
    signed_str = prefix + overhead_b64 + body
    return bytearray(signed_str.encode("ascii")), nonce, expires_at


# ---------------------------------------------------------------------------
# Envelope verification
# ---------------------------------------------------------------------------


def verify_and_extract(
    signed_envelope: bytearray,
    alias: str,
    signing_key: bytes,
    *,
    prefix: str,
) -> tuple[bytearray, bytes, int]:
    """Verify an HMAC envelope and extract the original shard_a.

    All failure modes raise :exc:`ShardSigningError` with a generic message.
    The caller must treat all failures identically (uniform 401 + timing floor).

    Args:
        signed_envelope: The value from the Bearer header (may be signed or raw).
        alias:           Enrollment alias from the URL path.
        signing_key:     Server-side signing key.
        prefix:          Key prefix from the DB row for this alias.

    Returns:
        ``(original_shard_a, nonce, expires_at)``

    Raises:
        ShardSigningError: On any verification failure (wrong key, wrong alias,
                           expired, tampered, unsigned/too-short).
    """
    try:
        envelope_str = signed_envelope.decode("ascii")
    except (UnicodeDecodeError, AttributeError):
        raise ShardSigningError("envelope is not ASCII") from None

    # Prefix check
    if not envelope_str.startswith(prefix):
        raise ShardSigningError("prefix mismatch")

    rest = envelope_str[len(prefix) :]

    # Length guard — must have at least 48 overhead chars + 1 body char
    if len(rest) < OVERHEAD_CHARS + 1:
        raise ShardSigningError("envelope too short to contain overhead")

    overhead_b64 = rest[:OVERHEAD_CHARS]
    body = rest[OVERHEAD_CHARS:]

    # Decode overhead
    try:
        overhead = base64.urlsafe_b64decode(overhead_b64.encode("ascii"))
    except Exception:
        raise ShardSigningError("invalid base64url in overhead") from None

    if len(overhead) != OVERHEAD_BYTES:
        raise ShardSigningError("overhead decoded to wrong length")

    nonce = overhead[:16]
    expiry_bytes = overhead[16:20]
    mac_received = overhead[20:36]

    # Expiry check BEFORE HMAC (fast-fail on obviously stale tokens)
    expires_at = struct.unpack(">I", expiry_bytes)[0]
    if expires_at < int(time.time()):
        raise ShardSigningError("envelope expired")

    # Reconstruct original shard_a = prefix + body
    original_shard_a = bytearray((prefix + body).encode("ascii"))

    # HMAC verification (constant-time compare — SR-07)
    msg = alias.encode("utf-8") + nonce + expiry_bytes + bytes(original_shard_a)
    mac_expected = hmac.new(signing_key, msg, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac_expected, mac_received):
        raise ShardSigningError("HMAC verification failed")

    return original_shard_a, bytes(nonce), expires_at

"""Cryptographic data types for the Worthless key-splitting system."""

from __future__ import annotations

from dataclasses import dataclass


def zero_buf(buf: bytearray) -> None:
    """Zero a bytearray in-place (SR-02).

    Uses ``bytearray(n)`` which maps to a single ``calloc``/``memset`` in
    CPython — no temporary ``bytes`` object allocated.  All zeroing across
    the crypto module funnels through this function so the strategy can be
    upgraded to ``ctypes.memset`` or Rust FFI in one place.
    """
    buf[:] = bytearray(len(buf))


@dataclass(frozen=True, slots=True)
class FormatPreservingSplitResult:
    """Result of format-preserving key split (SR-12).

    Shard-A preserves the original key's prefix, charset, and length.
    All byte fields use ``bytearray`` (SR-01) for secure zeroing.
    """

    shard_a: bytearray  # UTF-8 encoded: prefix + randomized body
    shard_b: bytearray  # UTF-8 encoded: body only (no prefix)
    commitment: bytearray
    nonce: bytearray
    prefix: str  # The preserved prefix (not secret — public metadata)
    charset: str  # The charset used for the split (not secret)

    @property
    def shard_a_str(self) -> str:
        """Shard-A as a string (for writing to .env)."""
        return self.shard_a.decode("utf-8")

    @property
    def shard_b_str(self) -> str:
        """Shard-B as a string."""
        return self.shard_b.decode("utf-8")

    def zero(self) -> None:
        """Zero all secret material in-place (SR-02)."""
        for buf in (self.shard_a, self.shard_b, self.commitment, self.nonce):
            zero_buf(buf)

    def __repr__(self) -> str:
        return (
            "FormatPreservingSplitResult("
            "shard_a=<redacted>, "
            "shard_b=<redacted>, "
            "commitment=<redacted>, "
            "nonce=<redacted>, "
            f"prefix={self.prefix!r}, "
            f"charset_len={len(self.charset)})"
        )


@dataclass(frozen=True, slots=True)
class SplitResult:
    """Result of splitting an API key into two XOR shards with HMAC commitment.

    All byte fields use ``bytearray`` (SR-01) so they can be zeroed after use.
    The dataclass is frozen to prevent accidental field reassignment, but the
    bytearray contents remain mutable for in-place zeroing via :meth:`zero`.

    All fields are redacted in ``__repr__`` and ``__str__`` to prevent
    accidental logging of key material (SR-04).
    """

    shard_a: bytearray
    shard_b: bytearray
    commitment: bytearray
    nonce: bytearray

    def zero(self) -> None:
        """Zero all secret material in-place (SR-02).

        Safe to call multiple times.  Works despite ``frozen=True`` because
        we mutate bytearray *contents*, not the field references.

        Commitment and nonce are not secret, but are zeroed as
        defense-in-depth — minimises residual crypto context in memory.
        """
        for buf in (self.shard_a, self.shard_b, self.commitment, self.nonce):
            zero_buf(buf)

    def __repr__(self) -> str:
        return (
            "SplitResult("
            "shard_a=<redacted>, "
            "shard_b=<redacted>, "
            "commitment=<redacted>, "
            "nonce=<redacted>)"
        )

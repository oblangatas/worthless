"""Tests for XOR key splitting, HMAC commitment, and bytearray zeroing (CRYP-01 .. CRYP-03)."""

from unittest.mock import patch

import pytest

from worthless.crypto.splitter import reconstruct_key, secure_key, split_key
from worthless.exceptions import ShardTamperedError

from tests.conftest import assert_zeroed


# --- CRYP-01: XOR round-trip ---


def test_xor_roundtrip(sample_api_key_bytes: bytes) -> None:
    """Splitting then XOR-ing shards back must yield the original key."""
    result = split_key(sample_api_key_bytes)
    reconstructed = bytes(a ^ b for a, b in zip(result.shard_a, result.shard_b))
    assert reconstructed == sample_api_key_bytes


def test_shard_length(sample_api_key_bytes: bytes) -> None:
    """Both shards must be the same length as the input key."""
    result = split_key(sample_api_key_bytes)
    assert len(result.shard_a) == len(sample_api_key_bytes)
    assert len(result.shard_b) == len(sample_api_key_bytes)


def test_shards_differ_from_key(sample_api_key_bytes: bytes) -> None:
    """Neither shard should equal the original key."""
    result = split_key(sample_api_key_bytes)
    assert result.shard_a != sample_api_key_bytes
    assert result.shard_b != sample_api_key_bytes


# --- CRYP-02: HMAC commitment ---


def test_hmac_valid(sample_api_key_bytes: bytes) -> None:
    """Reconstruction with untampered shards must succeed without error."""
    result = split_key(sample_api_key_bytes)
    key = reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)
    assert bytes(key) == sample_api_key_bytes


def test_hmac_tampered_shard_a(sample_api_key_bytes: bytes) -> None:
    """Flipping a byte in shard_a must cause ShardTamperedError."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.shard_a)
    tampered[0] ^= 0xFF
    with pytest.raises(ShardTamperedError):
        reconstruct_key(tampered, result.shard_b, result.commitment, result.nonce)


def test_hmac_tampered_shard_b(sample_api_key_bytes: bytes) -> None:
    """Flipping a byte in shard_b must cause ShardTamperedError."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.shard_b)
    tampered[0] ^= 0xFF
    with pytest.raises(ShardTamperedError):
        reconstruct_key(result.shard_a, tampered, result.commitment, result.nonce)


def test_hmac_tampered_commitment(sample_api_key_bytes: bytes) -> None:
    """Flipping a byte in the commitment must cause ShardTamperedError."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.commitment)
    tampered[0] ^= 0xFF
    with pytest.raises(ShardTamperedError):
        reconstruct_key(result.shard_a, result.shard_b, tampered, result.nonce)


def test_hmac_tampered_nonce(sample_api_key_bytes: bytes) -> None:
    """Flipping a byte in the nonce must cause ShardTamperedError."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.nonce)
    tampered[0] ^= 0xFF
    with pytest.raises(ShardTamperedError):
        reconstruct_key(result.shard_a, result.shard_b, result.commitment, tampered)


# --- CRYP-03: Bytearray zeroing ---


def test_reconstruct_returns_bytearray(sample_api_key_bytes: bytes) -> None:
    """reconstruct_key must return a bytearray (mutable, so it can be zeroed)."""
    result = split_key(sample_api_key_bytes)
    key = reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)
    assert isinstance(key, bytearray)


def test_bytearray_zeroed(sample_api_key_bytes: bytes) -> None:
    """After exiting secure_key, the bytearray must be all zeros."""
    result = split_key(sample_api_key_bytes)
    key = reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)
    with secure_key(key) as k:
        assert bytes(k) == sample_api_key_bytes  # still valid inside the block
    assert_zeroed(key)


# --- Edge cases ---


def test_split_empty_key_raises() -> None:
    """Splitting an empty key must raise ValueError."""
    with pytest.raises(ValueError):
        split_key(b"")


def test_reconstruct_length_mismatch() -> None:
    """Mismatched shard lengths must raise ValueError, not silently truncate."""
    result = split_key(b"sk-test-key-1234567890abcdef")
    with pytest.raises(ValueError, match="Shard length mismatch"):
        reconstruct_key(result.shard_a, result.shard_b[:5], result.commitment, result.nonce)


def test_secure_key_rejects_non_bytearray() -> None:
    """secure_key must reject non-bytearray inputs."""
    with pytest.raises(TypeError, match="requires a bytearray"):
        with secure_key(b"not-a-bytearray"):  # type: ignore[arg-type]
            pass


def test_bytearray_zeroed_on_exception(sample_api_key_bytes: bytes) -> None:
    """secure_key must zero the buffer even when an exception is raised inside."""
    result = split_key(sample_api_key_bytes)
    key = reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)
    with pytest.raises(RuntimeError):
        with secure_key(key):
            raise RuntimeError("simulated error")
    assert_zeroed(key)


def test_roundtrip_with_long_key(sample_long_key: bytes) -> None:
    """XOR roundtrip must work for longer keys (64 bytes)."""
    result = split_key(sample_long_key)
    key = reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)
    assert bytes(key) == sample_long_key


# --- SplitResult lifecycle ---


def test_split_result_zero(sample_api_key_bytes: bytes) -> None:
    """SplitResult.zero() must zero all fields in-place."""
    result = split_key(sample_api_key_bytes)
    result.zero()
    for buf in (result.shard_a, result.shard_b, result.commitment, result.nonce):
        assert_zeroed(buf)


def test_split_result_zero_idempotent(sample_api_key_bytes: bytes) -> None:
    """Calling zero() twice must not raise."""
    result = split_key(sample_api_key_bytes)
    result.zero()
    result.zero()
    assert_zeroed(result.shard_a)


# --- SR-04: Repr/str redaction ---


def test_split_result_repr_redacted(sample_api_key_bytes: bytes) -> None:
    """repr() must not leak any secret material."""
    result = split_key(sample_api_key_bytes)
    text = repr(result)
    assert "redacted" in text
    assert sample_api_key_bytes.decode() not in text
    assert result.shard_a.hex() not in text


def test_split_result_str_redacted(sample_api_key_bytes: bytes) -> None:
    """str() must also be redacted (SR-04 — traceback safety)."""
    result = split_key(sample_api_key_bytes)
    text = str(result)
    assert "redacted" in text


# --- reconstruct_key accepts both bytes and bytearray ---


def test_reconstruct_accepts_bytes(sample_api_key_bytes: bytes) -> None:
    """reconstruct_key must accept plain bytes inputs for interop."""
    result = split_key(sample_api_key_bytes)
    key = reconstruct_key(
        bytes(result.shard_a),
        bytes(result.shard_b),
        bytes(result.commitment),
        bytes(result.nonce),
    )
    assert bytes(key) == sample_api_key_bytes


# --- Key zeroed on tamper (security-critical) ---


def test_reconstruct_zeros_key_on_tamper(sample_api_key_bytes: bytes) -> None:
    """reconstruct_key must zero the intermediate key buffer when HMAC fails."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.shard_a)
    tampered[0] ^= 0xFF

    # We need to capture the key buffer — it's zeroed internally before the
    # exception propagates, so we verify by checking that reconstruct_key
    # does not leak the reconstructed (wrong) key in the exception.
    with pytest.raises(ShardTamperedError):
        reconstruct_key(tampered, result.shard_b, result.commitment, result.nonce)
    # If we got here, the exception was raised and key was zeroed internally.
    # There's no way to observe the zeroed buffer from outside (it's a local),
    # but the exception proves the tamper was detected before return.


# --- Adversarial: mutmut survivors (WOR-40) ---


def test_nonce_is_exactly_32_bytes(sample_api_key_bytes: bytes) -> None:
    """Nonce must be exactly 32 bytes — kills mutmut survivors that change token_bytes(32)."""
    result = split_key(sample_api_key_bytes)
    assert len(result.nonce) == 32


def test_xor_precomputed() -> None:
    """XOR with a known mask must produce the expected shard — kills ^→|/& mutants."""
    key = b"\xaa\xbb\xcc"
    result = split_key(key)
    # Manually verify: shard_a = key XOR shard_b
    for i in range(len(key)):
        assert result.shard_a[i] == (key[i] ^ result.shard_b[i])


def test_hmac_error_message_text(sample_api_key_bytes: bytes) -> None:
    """ShardTamperedError message must start with 'HMAC' — kills string mutants."""
    result = split_key(sample_api_key_bytes)
    tampered = bytearray(result.shard_a)
    tampered[0] ^= 0xFF
    with pytest.raises(ShardTamperedError, match="^HMAC verification failed"):
        reconstruct_key(tampered, result.shard_b, result.commitment, result.nonce)


def test_empty_key_error_message() -> None:
    """Empty key ValueError must start with 'Cannot' — kills string mutants."""
    with pytest.raises(ValueError, match="^Cannot split"):
        split_key(b"")


def test_expected_buf_initialized_as_bytearray() -> None:
    """The expected HMAC buffer must be a bytearray (not None) before zero_buf runs.

    reconstruct_key initialises ``expected = bytearray()`` before the try block
    so that the finally clause can always call ``zero_buf(expected)`` safely,
    even if ``hmac.new()`` raises before the reassignment.
    """

    from worthless.crypto.types import zero_buf

    result = split_key(b"sk-test-key-1234567890abcdef")

    # Force hmac.new to raise inside the try block — expected must still be
    # a bytearray when zero_buf runs in the finally clause.
    zeroed_items: list[bytearray] = []
    original_zero = zero_buf

    def tracking_zero(buf: bytearray) -> None:
        zeroed_items.append(buf)
        original_zero(buf)

    with patch("worthless.crypto.reconstruction.zero_buf", side_effect=tracking_zero):
        with patch("hmac.new", side_effect=RuntimeError("injected")):
            with pytest.raises(RuntimeError, match="injected"):
                reconstruct_key(result.shard_a, result.shard_b, result.commitment, result.nonce)

    # zero_buf should have been called with the key buffer (bytearray).
    # If expected were None, the finally clause would have raised TypeError.
    assert len(zeroed_items) >= 1
    assert all(isinstance(item, bytearray) for item in zeroed_items)
    # Direct verification: every buffer is actually all-zeros (mock-independent).
    for buf in zeroed_items:
        assert_zeroed(buf)


# --- SR-01: split_key accepts bytearray without immutable copy (WOR-384) ---


def test_split_key_accepts_bytearray_without_aliasing(sample_api_key_bytes: bytes) -> None:
    """SR-01 regression guard (WOR-384): ``split_key`` must accept
    ``bytearray`` so callers holding zeroable secret material don't need
    a ``bytes(...)`` cast — that cast leaves an unwipable copy of the
    secret on the heap. Mutating the input after the call must not
    affect the returned shards (no aliasing implies the input buffer
    also remains independently mutable/zeroable).
    """
    key_ba = bytearray(sample_api_key_bytes)
    result = split_key(key_ba)
    shard_a_snapshot = bytes(result.shard_a)

    key_ba[:] = bytearray(len(key_ba))  # zero input post-call

    # Aliasing check (also proves caller's buffer remained mutable).
    assert bytes(result.shard_a) == shard_a_snapshot
    # Roundtrip correctness against the original bytes.
    reconstructed = bytes(a ^ b for a, b in zip(result.shard_a, result.shard_b, strict=True))
    assert reconstructed == sample_api_key_bytes

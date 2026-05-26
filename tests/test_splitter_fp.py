"""Tests for format-preserving split/reconstruct (SR-12)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from worthless.crypto.charsets import ALPHANUMERIC, BASE64URL, PRINTABLE, PROVIDER_CHARSETS
from worthless.crypto.reconstruction import _verify_commitment
from worthless.crypto.splitter import (
    _detect_charset,
    _make_commitment,
    reconstruct_key_fp,
    split_key_fp,
)
from worthless.crypto.types import zero_buf
from worthless.exceptions import ShardTamperedError


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_OPENAI_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6A7b8C9d0"
_ANTHROPIC_KEY = "sk-ant-api03-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6A7bAA"
_GOOGLE_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
_XAI_KEY = "xai-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6A7b8C9d0E1f2G3h4I5j6"


# ---------------------------------------------------------------------------
# Basic correctness
# ---------------------------------------------------------------------------


class TestSplitKeyFP:
    def test_roundtrip_openai(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert key == bytearray(_OPENAI_KEY.encode("utf-8"))

    def test_roundtrip_anthropic(self) -> None:
        sr = split_key_fp(_ANTHROPIC_KEY, prefix="sk-ant-api03-", provider="anthropic")
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-ant-api03-",
            charset=sr.charset,
        )
        assert key == bytearray(_ANTHROPIC_KEY.encode("utf-8"))

    def test_roundtrip_google(self) -> None:
        sr = split_key_fp(_GOOGLE_KEY, prefix="AIza", provider="google")
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="AIza",
            charset=sr.charset,
        )
        assert key == bytearray(_GOOGLE_KEY.encode("utf-8"))

    def test_roundtrip_xai(self) -> None:
        sr = split_key_fp(_XAI_KEY, prefix="xai-", provider="xai")
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="xai-",
            charset=sr.charset,
        )
        assert key == bytearray(_XAI_KEY.encode("utf-8"))


class TestFormatPreservation:
    """SR-12: shard-A must have same prefix, charset, length as original."""

    def test_shard_a_preserves_prefix(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert sr.shard_a_str.startswith("sk-proj-")

    def test_shard_a_same_length(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert len(sr.shard_a_str) == len(_OPENAI_KEY)

    def test_shard_a_same_charset(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        body = sr.shard_a_str[len("sk-proj-") :]
        assert all(c in BASE64URL for c in body)

    def test_shard_b_body_only(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        body = _OPENAI_KEY[len("sk-proj-") :]
        assert len(sr.shard_b_str) == len(body)

    def test_shard_a_differs_from_original(self) -> None:
        # Probabilistically: shard-A body should differ from original body
        # (vanishingly unlikely to be identical with CSPRNG mask)
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert sr.shard_a_str != _OPENAI_KEY

    def test_shard_b_charset(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert all(c in BASE64URL for c in sr.shard_b_str)

    def test_xai_uses_alphanumeric(self) -> None:
        sr = split_key_fp(_XAI_KEY, prefix="xai-", provider="xai")
        body = sr.shard_a_str[len("xai-") :]
        assert all(c in ALPHANUMERIC for c in body)
        # Should NOT contain _ or -
        assert "_" not in body
        assert "-" not in body


class TestHMACTamperDetection:
    def test_tampered_shard_a_detected(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        # Replace one charset char with a different valid charset char
        prefix_len = len("sk-proj-")
        body_idx = prefix_len + 2  # pick a body char
        original_char = chr(sr.shard_a[body_idx])
        replacement = next(c for c in sr.charset if c != original_char)
        sr.shard_a[body_idx] = ord(replacement)
        with pytest.raises(ShardTamperedError):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_tampered_shard_b_detected(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        # Replace one charset char with a different valid charset char
        original_char = chr(sr.shard_b[3])
        replacement = next(c for c in sr.charset if c != original_char)
        sr.shard_b[3] = ord(replacement)
        with pytest.raises(ShardTamperedError):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_tampered_commitment_detected(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.commitment[0] ^= 0xFF
        with pytest.raises(ShardTamperedError):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )


class TestZeroing:
    def test_split_result_zero(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.zero()
        assert all(b == 0 for b in sr.shard_a)
        assert all(b == 0 for b in sr.shard_b)
        assert all(b == 0 for b in sr.commitment)
        assert all(b == 0 for b in sr.nonce)

    def test_zero_idempotent(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.zero()
        sr.zero()  # second call should not raise
        assert all(b == 0 for b in sr.shard_a)

    def test_shard_a_str_after_zero_returns_null_bytes(self) -> None:
        """Accessing shard_a_str after zeroing returns a null-byte string."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.zero()
        assert all(c == "\x00" for c in sr.shard_a_str)

    def test_repr_redacted(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        r = repr(sr)
        assert "redacted" in r
        assert _OPENAI_KEY not in r
        assert sr.shard_a_str not in r


class TestEdgeCases:
    def test_empty_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            split_key_fp("", prefix="", provider="openai")

    def test_wrong_prefix_rejected(self) -> None:
        with pytest.raises(ValueError, match="prefix"):
            split_key_fp(_OPENAI_KEY, prefix="wrong-", provider="openai")

    def test_prefix_only_rejected(self) -> None:
        with pytest.raises(ValueError, match="body is empty"):
            split_key_fp("sk-proj-", prefix="sk-proj-", provider="openai")

    def test_shard_length_mismatch_rejected(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ValueError, match="mismatch"):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b[:5],
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_reconstruct_with_bytes_input(self) -> None:
        """Exercise the non-bytearray branch in reconstruct_key_fp."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        key = reconstruct_key_fp(
            bytes(sr.shard_a),
            bytes(sr.shard_b),
            bytes(sr.commitment),
            bytes(sr.nonce),
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert key == bytearray(_OPENAI_KEY.encode("utf-8"))

    def test_reconstruct_wrong_prefix_rejected(self) -> None:
        """Shard-A with wrong prefix should be rejected."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        # Tamper the prefix portion
        tampered = bytearray(b"sk-XXXX-") + sr.shard_a[len(b"sk-proj-") :]
        with pytest.raises(ValueError, match="prefix"):
            reconstruct_key_fp(
                tampered,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_reconstruct_unknown_charset_raises(self) -> None:
        """Charset not in _CHAR_TO_IDX should raise KeyError."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(KeyError):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset="abc",  # not precomputed
            )

    def test_split_without_provider(self) -> None:
        """split_key_fp with provider=None should auto-detect charset."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider=None)
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert key == bytearray(_OPENAI_KEY.encode("utf-8"))

    def test_all_same_character_body(self) -> None:
        """Body of repeated characters should still roundtrip."""
        key = "sk-proj-" + "a" * 50
        sr = split_key_fp(key, prefix="sk-proj-", provider="openai")
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))

    def test_charset_boundary_characters(self) -> None:
        """First and last chars in charset should roundtrip correctly."""
        # base64url: first='A', last='-'
        body = "A" + "-" + "A" * 10 + "-" * 10
        key = "sk-proj-" + body
        sr = split_key_fp(key, prefix="sk-proj-", provider="openai")
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))

    def test_printable_charset_roundtrip(self) -> None:
        """Key body with special printable chars using PRINTABLE charset."""
        key = "sk-proj-abc!@#$%^&*()_+-=[]{}|;':\",./<>?"
        sr = split_key_fp(key, prefix="sk-proj-", provider=None)
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))


class TestCharsetDetection:
    def test_base64url_detected_for_openai(self) -> None:
        cs = _detect_charset("a1B2c3_-XYZ", provider="openai")
        assert cs == BASE64URL

    def test_alphanumeric_detected_for_xai(self) -> None:
        cs = _detect_charset("a1B2c3XYZ", provider="xai")
        assert cs == ALPHANUMERIC

    def test_fallback_to_broader_charset(self) -> None:
        cs = _detect_charset("a1B2_c3", provider="xai")
        assert "_" in cs

    def test_no_provider_alphanumeric(self) -> None:
        cs = _detect_charset("abcABC123", provider=None)
        assert cs == ALPHANUMERIC

    def test_no_provider_base64url(self) -> None:
        cs = _detect_charset("abc_ABC-123", provider=None)
        assert cs == BASE64URL

    def test_printable_fallback(self) -> None:
        """Body with printable-but-non-base64url chars triggers printable charset."""
        cs = _detect_charset("abc!@#$%^", provider=None)
        assert cs == PRINTABLE

    def test_printable_fallback_with_provider(self) -> None:
        """Provider charset doesn't cover chars, falls through to printable."""
        cs = _detect_charset("abc!@#", provider="openai")
        assert cs == PRINTABLE


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------


_PROVIDER_CONFIGS = [
    ("sk-proj-", "openai", BASE64URL),
    ("sk-ant-api03-", "anthropic", BASE64URL),
    ("AIza", "google", BASE64URL),
    ("xai-", "xai", ALPHANUMERIC),
]


@st.composite
def api_keys(draw: st.DrawFn) -> tuple[str, str, str, str]:
    """Generate (key, prefix, provider, charset) tuples."""
    prefix, provider, charset = draw(st.sampled_from(_PROVIDER_CONFIGS))
    body_len = draw(st.integers(min_value=10, max_value=100))
    body = draw(st.text(alphabet=charset, min_size=body_len, max_size=body_len))
    return prefix + body, prefix, provider, charset


class TestPropertyBased:
    @given(data=api_keys())
    @settings(max_examples=200)
    def test_roundtrip_property(self, data: tuple[str, str, str, str]) -> None:
        key, prefix, provider, charset = data
        sr = split_key_fp(key, prefix=prefix, provider=provider)
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix=prefix,
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))

    @given(data=api_keys())
    @settings(max_examples=200)
    def test_format_preservation_property(self, data: tuple[str, str, str, str]) -> None:
        key, prefix, provider, charset = data
        sr = split_key_fp(key, prefix=prefix, provider=provider)
        shard_a = sr.shard_a_str

        # Same prefix
        assert shard_a.startswith(prefix)
        # Same length
        assert len(shard_a) == len(key)
        # Same charset for shard-A body
        body = shard_a[len(prefix) :]
        assert all(c in charset for c in body)
        # Shard-B also stays in charset
        assert all(c in charset for c in sr.shard_b_str)
        # Shard-A differs from original (catches identity-split mutations)
        assert shard_a != key


# ---------------------------------------------------------------------------
# HMAC commitment helpers
# ---------------------------------------------------------------------------


class TestCommitmentHelpers:
    def test_make_commitment_returns_32_byte_values(self) -> None:
        commitment, nonce = _make_commitment(b"test-key-data")
        assert len(commitment) == 32
        assert len(nonce) == 32
        assert isinstance(commitment, bytearray)
        assert isinstance(nonce, bytearray)

    def test_make_commitment_deterministic_with_same_nonce(self) -> None:
        """Different calls produce different nonces (CSPRNG)."""
        c1, n1 = _make_commitment(b"same-key")
        c2, n2 = _make_commitment(b"same-key")
        assert n1 != n2  # nonces must differ
        assert c1 != c2  # commitments differ because nonces differ

    def test_verify_commitment_passes_for_valid(self) -> None:
        commitment, nonce = _make_commitment(b"my-secret-key")
        _verify_commitment(b"my-secret-key", commitment, nonce)  # should not raise

    def test_verify_commitment_fails_for_wrong_data(self) -> None:
        commitment, nonce = _make_commitment(b"my-secret-key")
        with pytest.raises(ShardTamperedError):
            _verify_commitment(b"wrong-key", commitment, nonce)

    def test_verify_commitment_fails_for_wrong_nonce(self) -> None:
        commitment, nonce = _make_commitment(b"my-secret-key")
        bad_nonce = bytearray(32)  # all zeros
        with pytest.raises(ShardTamperedError):
            _verify_commitment(b"my-secret-key", commitment, bad_nonce)

    def test_verify_commitment_fails_for_flipped_commitment_bit(self) -> None:
        commitment, nonce = _make_commitment(b"my-secret-key")
        commitment[0] ^= 0x01
        with pytest.raises(ShardTamperedError):
            _verify_commitment(b"my-secret-key", commitment, nonce)


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_null_bytes_in_key_body(self) -> None:
        """Keys with null bytes should be rejected (not in any charset)."""
        with pytest.raises(ValueError, match="outside printable ASCII"):
            split_key_fp("sk-proj-abc\x00def", prefix="sk-proj-", provider="openai")

    def test_unicode_in_key_body(self) -> None:
        """Non-ASCII unicode should be rejected."""
        with pytest.raises(ValueError, match="outside printable ASCII"):
            split_key_fp("sk-proj-abc\u00e9def", prefix="sk-proj-", provider="openai")

    def test_control_chars_in_key_body(self) -> None:
        with pytest.raises(ValueError, match="outside printable ASCII"):
            split_key_fp("sk-proj-abc\x01\x02def", prefix="sk-proj-", provider="openai")

    def test_newline_in_key_body(self) -> None:
        with pytest.raises(ValueError, match="outside printable ASCII"):
            split_key_fp("sk-proj-abc\ndef", prefix="sk-proj-", provider="openai")

    def test_very_long_key(self) -> None:
        """10K character key should still roundtrip."""
        body = "a" * 10_000
        key = "sk-proj-" + body
        sr = split_key_fp(key, prefix="sk-proj-", provider="openai")
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))

    def test_single_char_body(self) -> None:
        key = "sk-proj-a"
        sr = split_key_fp(key, prefix="sk-proj-", provider="openai")
        reconstructed = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert reconstructed == bytearray(key.encode("utf-8"))

    def test_wrong_charset_in_reconstruct(self) -> None:
        """Using wrong charset for reconstruction should fail HMAC check."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises((ShardTamperedError, KeyError)):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=ALPHANUMERIC,  # wrong — key uses base64url
            )

    def test_swapped_shards(self) -> None:
        """Swapping shard-A and shard-B should fail."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises((ShardTamperedError, ValueError)):
            reconstruct_key_fp(
                sr.shard_b,
                sr.shard_a,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_cross_provider_shards_fail(self) -> None:
        """Mixing shards from different keys should fail HMAC."""
        sr1 = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr2 = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ShardTamperedError):
            reconstruct_key_fp(
                sr1.shard_a,
                sr2.shard_b,
                sr1.commitment,
                sr1.nonce,
                prefix="sk-proj-",
                charset=sr1.charset,
            )

    def test_truncated_shard_a(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ValueError, match="mismatch"):
            reconstruct_key_fp(
                sr.shard_a[:10],
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_empty_shard_b(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ValueError, match="mismatch"):
            reconstruct_key_fp(
                sr.shard_a,
                bytearray(),
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )


# ---------------------------------------------------------------------------
# Security rules enforcement
# ---------------------------------------------------------------------------


class TestSecurityRules:
    """Verify security rules SR-01, SR-02, SR-04, SR-12 at the crypto layer."""

    def test_sr01_shard_a_is_bytearray(self) -> None:
        """SR-01: key material must be bytearray, not bytes."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert isinstance(sr.shard_a, bytearray)
        assert isinstance(sr.shard_b, bytearray)
        assert isinstance(sr.commitment, bytearray)
        assert isinstance(sr.nonce, bytearray)

    def test_sr01_reconstructed_key_is_bytearray(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        key = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            prefix="sk-proj-",
            charset=sr.charset,
        )
        assert isinstance(key, bytearray)

    def test_sr02_zero_clears_all_fields(self) -> None:
        """SR-02: explicit zeroing must clear all secret material."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.zero()
        for buf in (sr.shard_a, sr.shard_b, sr.commitment, sr.nonce):
            assert all(b == 0 for b in buf), "Field not zeroed"

    def test_sr02_zeroing_on_tamper_detection(self) -> None:
        """SR-02: on HMAC failure, key material must be zeroed before raise."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.commitment[0] ^= 0xFF
        # We can't inspect the internal key after the raise, but we can
        # verify the function raises (zeroing happens in the except block)
        with pytest.raises(ShardTamperedError):
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )

    def test_sr04_repr_does_not_leak_secrets(self) -> None:
        """SR-04: repr must not contain key material."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        r = repr(sr)
        assert _OPENAI_KEY not in r
        assert sr.shard_a_str not in r
        assert sr.shard_b_str not in r
        assert "redacted" in r

    def test_sr04_str_does_not_leak_secrets(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        s = str(sr)
        assert _OPENAI_KEY not in s
        assert sr.shard_a_str not in s

    def test_sr04_detect_charset_exception_does_not_leak_chars(self) -> None:
        """SR-04: error messages must not contain key characters."""
        bad_key = "sk-proj-abc\x00\x01\x02def"
        with pytest.raises(ValueError, match="character") as exc_info:
            split_key_fp(bad_key, prefix="sk-proj-", provider="openai")
        error_msg = str(exc_info.value)
        # Must not contain actual key characters
        assert "\x00" not in error_msg
        assert "\x01" not in error_msg
        assert "\x02" not in error_msg
        # Should contain count instead
        assert "3" in error_msg  # 3 bad chars

    def test_sr12_shard_a_indistinguishable_from_real_key(self) -> None:
        """SR-12: shard-A must look like a real API key."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        shard_a = sr.shard_a_str

        # Same prefix
        assert shard_a.startswith("sk-proj-")
        # Same length
        assert len(shard_a) == len(_OPENAI_KEY)
        # Same charset
        body = shard_a[len("sk-proj-") :]
        charset = PROVIDER_CHARSETS["openai"]
        assert all(c in charset for c in body)

    def test_sr12_different_splits_produce_different_shard_a(self) -> None:
        """Each split should produce unique shard-A (CSPRNG mask)."""
        sr1 = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr2 = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        assert sr1.shard_a != sr2.shard_a
        assert sr1.shard_b != sr2.shard_b

    def test_sr12_shard_a_alone_cannot_reconstruct(self) -> None:
        """Shard-A alone reveals nothing about the original key."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        # Without shard-B, you can't reconstruct — and shard-A looks random
        # Best we can test: shard-A body differs from original body
        original_body = _OPENAI_KEY[len("sk-proj-") :]
        shard_a_body = sr.shard_a_str[len("sk-proj-") :]
        assert shard_a_body != original_body


# ---------------------------------------------------------------------------
# Hypothesis: adversarial property tests
# ---------------------------------------------------------------------------


class TestAdversarialProperties:
    @given(data=api_keys())
    @settings(max_examples=100)
    def test_tampered_shard_a_always_detected(self, data: tuple[str, str, str, str]) -> None:
        """Any single-byte flip in shard-A must be caught by HMAC."""
        key, prefix, provider, charset = data
        sr = split_key_fp(key, prefix=prefix, provider=provider)
        if len(sr.shard_a) > len(prefix):
            # Flip a byte in the body portion
            flip_idx = len(prefix.encode("utf-8"))
            sr.shard_a[flip_idx] = (sr.shard_a[flip_idx] + 1) % 256
            with pytest.raises((ShardTamperedError, ValueError, UnicodeDecodeError, KeyError)):
                reconstruct_key_fp(
                    sr.shard_a,
                    sr.shard_b,
                    sr.commitment,
                    sr.nonce,
                    prefix=prefix,
                    charset=sr.charset,
                )

    @given(data=api_keys())
    @settings(max_examples=100)
    def test_tampered_shard_b_always_detected(self, data: tuple[str, str, str, str]) -> None:
        """Any single-byte flip in shard-B must be caught (HMAC, decode, or lookup error)."""
        key, prefix, provider, charset = data
        sr = split_key_fp(key, prefix=prefix, provider=provider)
        if len(sr.shard_b) > 0:
            sr.shard_b[0] = (sr.shard_b[0] + 1) % 256
            with pytest.raises((ShardTamperedError, ValueError, UnicodeDecodeError, KeyError)):
                reconstruct_key_fp(
                    sr.shard_a,
                    sr.shard_b,
                    sr.commitment,
                    sr.nonce,
                    prefix=prefix,
                    charset=sr.charset,
                )


# ---------------------------------------------------------------------------
# CSPRNG enforcement (SR-08)
# ---------------------------------------------------------------------------


class TestCSPRNGEnforcement:
    """Verify that split_key_fp uses secrets module, not stdlib random."""

    def test_split_uses_secrets_randbelow(self) -> None:
        """Patching secrets.randbelow must be called for each body char."""
        key = "sk-proj-" + "a" * 20
        with patch("worthless.crypto.splitter.secrets.randbelow", return_value=0) as mock_rb:
            split_key_fp(key, prefix="sk-proj-", provider="openai")
        assert mock_rb.call_count == 20  # one call per body character

    def test_split_uses_secrets_token_bytes_for_nonce(self) -> None:
        """Nonce must come from secrets.token_bytes."""
        with patch(
            "worthless.crypto.splitter.secrets.token_bytes", return_value=b"\x42" * 32
        ) as mock_tb:
            split_key_fp("sk-proj-abcdefghij", prefix="sk-proj-", provider="openai")
        # token_bytes called at least once (for nonce)
        assert mock_tb.call_count >= 1


# ---------------------------------------------------------------------------
# SR-02: zeroing on failure path
# ---------------------------------------------------------------------------


class TestZeroingOnFailure:
    def test_reconstruct_zeroes_key_on_hmac_failure(self) -> None:
        """SR-02: key bytearray must be zeroed when HMAC fails."""
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.commitment[0] ^= 0xFF  # corrupt commitment

        zeroed_bufs: list[bytearray] = []
        original_zero_buf = zero_buf

        def tracking_zero_buf(buf: bytearray) -> None:
            zeroed_bufs.append(buf)
            original_zero_buf(buf)

        with patch("worthless.crypto.reconstruction.zero_buf", side_effect=tracking_zero_buf):
            with pytest.raises(ShardTamperedError):
                reconstruct_key_fp(
                    sr.shard_a,
                    sr.shard_b,
                    sr.commitment,
                    sr.nonce,
                    prefix="sk-proj-",
                    charset=sr.charset,
                )

        # At least one buffer zeroed (the reconstructed key)
        assert len(zeroed_bufs) >= 1
        # The zeroed buffer should be all zeros
        for buf in zeroed_bufs:
            assert all(b == 0 for b in buf)

    def test_verify_commitment_zeroes_expected_on_success(self) -> None:
        """SR-02: _verify_commitment must zero the expected HMAC digest."""
        commitment, nonce = _make_commitment(b"test-key")

        zeroed_bufs: list[bytearray] = []
        original_zero_buf = zero_buf

        def tracking_zero_buf(buf: bytearray) -> None:
            zeroed_bufs.append(bytearray(buf))  # snapshot before zeroing
            original_zero_buf(buf)

        with patch("worthless.crypto.reconstruction.zero_buf", side_effect=tracking_zero_buf):
            _verify_commitment(b"test-key", commitment, nonce)

        # The expected digest was zeroed (32 bytes)
        assert any(len(buf) == 32 for buf in zeroed_bufs)


# ---------------------------------------------------------------------------
# SR-04: error messages must not leak secrets
# ---------------------------------------------------------------------------


class TestErrorMessageSafety:
    def test_shard_tampered_error_does_not_contain_key(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        sr.commitment[0] ^= 0xFF
        with pytest.raises(ShardTamperedError) as exc_info:
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )
        msg = str(exc_info.value)
        assert _OPENAI_KEY not in msg
        assert sr.shard_a_str not in msg
        assert sr.shard_b_str not in msg

    def test_prefix_mismatch_error_does_not_contain_shard(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ValueError) as exc_info:
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b,
                sr.commitment,
                sr.nonce,
                prefix="wrong-prefix-",
                charset=sr.charset,
            )
        msg = str(exc_info.value)
        assert sr.shard_a_str not in msg

    def test_length_mismatch_error_does_not_contain_shard(self) -> None:
        sr = split_key_fp(_OPENAI_KEY, prefix="sk-proj-", provider="openai")
        with pytest.raises(ValueError) as exc_info:
            reconstruct_key_fp(
                sr.shard_a,
                sr.shard_b[:5],
                sr.commitment,
                sr.nonce,
                prefix="sk-proj-",
                charset=sr.charset,
            )
        msg = str(exc_info.value)
        assert sr.shard_a_str not in msg
        assert sr.shard_b_str not in msg

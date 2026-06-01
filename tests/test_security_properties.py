"""Security property tests — Phase 6 shard-A signing + Hypothesis crypto invariants.

Phase 6 signing tests: TestShardASigning, TestEnvelopeConstruction,
TestRejectionPaths, TestSigningKeyManagement (all near the bottom of this file).

Original invariants (below):


These tests verify that security-critical properties hold across arbitrary
inputs: split/reconstruct roundtrip, shard independence, zero-after-use,
repr redaction, tamper detection, gate-before-decrypt ordering, and
upstream error sanitization.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
import time as _time
from pathlib import Path

from hypothesis import given, assume, settings as hsettings
from hypothesis import strategies as st

from worthless.crypto.shard_signing import (
    OVERHEAD_CHARS,
    ShardSigningError,
    generate_signing_key,
    load_or_create_signing_key,
    sign_shard_a,
    verify_and_extract,
)
from worthless.crypto.splitter import reconstruct_key, secure_key, split_key
from worthless.crypto.types import zero_buf
from worthless.exceptions import ShardTamperedError
from worthless.storage.repository import EncryptedShard, StoredShard

import pytest

# Root of the worthless package under src/
_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "worthless"

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# API keys: 8-128 printable ASCII bytes (real keys are 32-64 chars)
_API_KEYS = st.binary(min_size=8, max_size=128).filter(
    lambda b: b == b"".join(bytes([c]) for c in b if 32 <= c < 127)
)

# Simpler: just use text-based keys
_KEY_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=8,
    max_size=128,
).map(lambda s: s.encode())

# Binary keys — exercise non-ASCII byte paths
_KEY_BINARY = st.binary(min_size=8, max_size=128)

# Combined strategy for broader key coverage
_KEY_ANY = st.one_of(_KEY_TEXT, _KEY_BINARY)


# ---------------------------------------------------------------------------
# Split / Reconstruct roundtrip
# ---------------------------------------------------------------------------


class TestSplitReconstructRoundtrip:
    """split_key -> reconstruct_key always returns the original key."""

    @given(key=_KEY_ANY)
    def test_roundtrip_identity(self, key: bytes) -> None:
        sr = split_key(key)
        try:
            result = reconstruct_key(sr.shard_a, sr.shard_b, sr.commitment, sr.nonce)
            assert bytes(result) == key
            zero_buf(result)
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_shard_lengths_match_key(self, key: bytes) -> None:
        """Both shards have the same length as the original key."""
        sr = split_key(key)
        try:
            assert len(sr.shard_a) == len(key)
            assert len(sr.shard_b) == len(key)
        finally:
            sr.zero()


# ---------------------------------------------------------------------------
# Shard independence — XOR structure means neither shard alone reveals key,
# but this only tests non-equality (not cryptographic independence).
# ---------------------------------------------------------------------------


class TestShardNonEquality:
    """Individual shards differ from the key (necessary but not sufficient for independence).

    True cryptographic independence requires that each shard is uniformly
    random given no knowledge of the other. These tests verify the weaker
    property that neither shard equals the original key, which would indicate
    a degenerate split (e.g. one shard is all zeros).
    """

    @given(key=_KEY_ANY)
    def test_shard_a_differs_from_key(self, key: bytes) -> None:
        """shard_a alone is not the original key (except by vanishing probability)."""
        sr = split_key(key)
        try:
            assert bytes(sr.shard_a) != key
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_shard_b_differs_from_key(self, key: bytes) -> None:
        """shard_b alone is not the original key (except by vanishing probability)."""
        sr = split_key(key)
        try:
            assert bytes(sr.shard_b) != key
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_xor_reconstruction(self, key: bytes) -> None:
        """shard_a XOR shard_b = original key."""
        sr = split_key(key)
        try:
            xored = bytearray(a ^ b for a, b in zip(sr.shard_a, sr.shard_b))
            assert bytes(xored) == key
        finally:
            sr.zero()


# ---------------------------------------------------------------------------
# Zero-after-use
# ---------------------------------------------------------------------------


class TestZeroAfterUse:
    """Secret material is zeroed when .zero() is called or secure_key exits.

    Limitations:
    - Python's garbage collector may retain copies of bytes objects created
      during intermediate computations (e.g. bytes() casts, string decoding).
    - The immutable ``bytes`` type cannot be zeroed; only ``bytearray`` fields
      are cleared by .zero().
    - Compiler/interpreter optimizations may keep registers or stack copies
      beyond our control.
    - These tests verify the *bytearray* zeroing contract, not full
      memory-safe erasure. The Rust reconstruction service (roadmap) will
      provide stronger guarantees via mlock + explicit_bzero.
    """

    @given(key=_KEY_ANY)
    def test_split_result_zero_clears_all_fields(self, key: bytes) -> None:
        sr = split_key(key)
        sr.zero()
        for field in (sr.shard_a, sr.shard_b, sr.commitment, sr.nonce):
            assert all(b == 0 for b in field)

    @given(key=_KEY_ANY)
    def test_secure_key_zeros_on_exit(self, key: bytes) -> None:
        sr = split_key(key)
        try:
            result = reconstruct_key(sr.shard_a, sr.shard_b, sr.commitment, sr.nonce)
            with secure_key(result) as k:
                assert bytes(k) == key
            # After context exit, buffer is zeroed
            assert all(b == 0 for b in result)
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_secure_key_zeros_on_exception(self, key: bytes) -> None:
        """secure_key zeros even if the block raises."""
        sr = split_key(key)
        try:
            result = reconstruct_key(sr.shard_a, sr.shard_b, sr.commitment, sr.nonce)
            with pytest.raises(ValueError):
                with secure_key(result):
                    raise ValueError("deliberate")
            assert all(b == 0 for b in result)
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_stored_shard_zero(self, key: bytes) -> None:
        sr = split_key(key)
        stored = StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider="test",
        )
        sr.zero()
        stored.zero()
        for field in (stored.shard_b, stored.commitment, stored.nonce):
            assert all(b == 0 for b in field)


# ---------------------------------------------------------------------------
# Repr redaction — no secret bytes in string output
# ---------------------------------------------------------------------------


class TestReprRedaction:
    """__repr__ must never leak secret bytes."""

    @given(key=_KEY_ANY)
    def test_split_result_repr_redacted(self, key: bytes) -> None:
        sr = split_key(key)
        try:
            text = repr(sr)
            # Shard bytes (hex-encoded) must not appear
            assert sr.shard_a.hex() not in text
            assert sr.shard_b.hex() not in text
            assert "redacted" in text.lower()
        finally:
            sr.zero()

    @given(key=_KEY_ANY)
    def test_split_result_str_redacted(self, key: bytes) -> None:
        sr = split_key(key)
        try:
            text = str(sr)
            assert sr.shard_a.hex() not in text
            assert sr.shard_b.hex() not in text
            assert "redacted" in text.lower()
        finally:
            sr.zero()

    @given(shard_b=st.binary(min_size=8, max_size=64))
    def test_stored_shard_repr_no_bytes(self, shard_b: bytes) -> None:
        stored = StoredShard(
            shard_b=bytearray(shard_b),
            commitment=bytearray(b"\x00" * 32),
            nonce=bytearray(b"\x00" * 32),
            provider="test",
        )
        text = repr(stored)
        assert str(shard_b) not in text
        assert "bytes>" in text  # shows length, not content

    @given(shard_b_enc=st.binary(min_size=8, max_size=64))
    def test_encrypted_shard_repr_no_bytes(self, shard_b_enc: bytes) -> None:
        enc = EncryptedShard(
            shard_b_enc=shard_b_enc,
            commitment=b"\x00" * 32,
            nonce=b"\x00" * 32,
            provider="test",
        )
        text = repr(enc)
        assert str(shard_b_enc) not in text
        assert "bytes>" in text


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """Flipping any bit in shards, commitment, or nonce must raise ShardTamperedError."""

    @given(key=_KEY_ANY, bit_pos=st.integers(min_value=0, max_value=1023))
    def test_flipped_shard_a_bit_detected(self, key: bytes, bit_pos: int) -> None:
        sr = split_key(key)
        try:
            tampered_a = bytearray(sr.shard_a)
            idx = bit_pos % len(tampered_a)
            tampered_a[idx] ^= 1 << (bit_pos % 8)
            if tampered_a == sr.shard_a:
                return  # no-op flip (can happen if bit already matched)
            with pytest.raises(ShardTamperedError):
                reconstruct_key(tampered_a, sr.shard_b, sr.commitment, sr.nonce)
        finally:
            sr.zero()

    @given(key=_KEY_ANY, bit_pos=st.integers(min_value=0, max_value=1023))
    def test_flipped_shard_b_bit_detected(self, key: bytes, bit_pos: int) -> None:
        sr = split_key(key)
        try:
            tampered_b = bytearray(sr.shard_b)
            idx = bit_pos % len(tampered_b)
            tampered_b[idx] ^= 1 << (bit_pos % 8)
            if tampered_b == sr.shard_b:
                return
            with pytest.raises(ShardTamperedError):
                reconstruct_key(sr.shard_a, tampered_b, sr.commitment, sr.nonce)
        finally:
            sr.zero()

    @given(key=_KEY_ANY, byte_idx=st.integers(min_value=0, max_value=31))
    def test_flipped_commitment_bit_detected(self, key: bytes, byte_idx: int) -> None:
        sr = split_key(key)
        try:
            tampered_commit = bytearray(sr.commitment)
            tampered_commit[byte_idx] ^= 0xFF
            with pytest.raises(ShardTamperedError):
                reconstruct_key(sr.shard_a, sr.shard_b, tampered_commit, sr.nonce)
        finally:
            sr.zero()

    @given(key=_KEY_ANY, byte_idx=st.integers(min_value=0, max_value=31))
    def test_flipped_nonce_bit_detected(self, key: bytes, byte_idx: int) -> None:
        """Tampering with the nonce invalidates the HMAC commitment."""
        sr = split_key(key)
        try:
            tampered_nonce = bytearray(sr.nonce)
            tampered_nonce[byte_idx] ^= 0xFF
            with pytest.raises(ShardTamperedError):
                reconstruct_key(sr.shard_a, sr.shard_b, sr.commitment, tampered_nonce)
        finally:
            sr.zero()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Boundary conditions for crypto primitives."""

    def test_empty_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            split_key(b"")

    def test_secure_key_rejects_bytes(self) -> None:
        with pytest.raises(TypeError, match="bytearray"):
            with secure_key(b"not mutable"):  # type: ignore[arg-type]
                pass

    def test_shard_length_mismatch_rejected(self) -> None:
        with pytest.raises(ValueError, match="mismatch"):
            reconstruct_key(
                bytearray(b"short"),
                bytearray(b"longer_shard"),
                bytearray(b"\x00" * 32),
                bytearray(b"\x00" * 32),
            )


# ---------------------------------------------------------------------------
# SR-03: Gate before decrypt — rules engine evaluates BEFORE Fernet decryption
# ---------------------------------------------------------------------------


class TestGateBeforeDecrypt:
    """SR-03: Rules engine evaluates BEFORE any Fernet decryption.

    The proxy handler must call rules_engine.evaluate() before
    repo.decrypt_shard() to ensure denied requests never touch
    decrypted key material.
    """

    def test_evaluate_precedes_decrypt_in_proxy_handler(self) -> None:
        """Static analysis: rules_engine.evaluate appears before repo.decrypt_shard in source."""
        from worthless.proxy.app import create_app

        source = inspect.getsource(create_app)
        gate_pos = source.find("rules_engine.evaluate")
        decrypt_pos = source.find("repo.decrypt_shard")
        assert gate_pos != -1, "rules_engine.evaluate not found in proxy handler"
        assert decrypt_pos != -1, "repo.decrypt_shard not found in proxy handler"
        assert gate_pos < decrypt_pos, (
            f"gate (pos {gate_pos}) must appear before decrypt (pos {decrypt_pos}) in source"
        )

    def test_fetch_encrypted_returns_encrypted_type(self) -> None:
        """fetch_encrypted returns EncryptedShard with shard_b_enc (not decrypted shard_b).

        This proves the gate can inspect the provider field without
        ever touching plaintext key material.
        """
        enc = EncryptedShard(
            shard_b_enc=b"ciphertext-blob",
            commitment=b"\x00" * 32,
            nonce=b"\x00" * 32,
            provider="openai",
        )
        # EncryptedShard exposes shard_b_enc (ciphertext), NOT shard_b (plaintext)
        assert hasattr(enc, "shard_b_enc")
        assert not hasattr(enc, "shard_b")
        assert enc.provider == "openai"

    def test_fetch_encrypted_source_has_no_decrypt_calls(self) -> None:
        """fetch_encrypted AST must not contain any method calls with 'decrypt' in the name."""
        from worthless.storage.repository import ShardRepository

        source = textwrap.dedent(inspect.getsource(ShardRepository.fetch_encrypted))
        tree = ast.parse(source)
        decrypt_calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and "decrypt" in node.attr.lower():
                decrypt_calls.append(node.attr)
            elif isinstance(node, ast.Name) and "decrypt" in node.id.lower():
                decrypt_calls.append(node.id)
        assert not decrypt_calls, (
            f"fetch_encrypted must not call decrypt methods, found: {decrypt_calls}"
        )

    @hsettings(deadline=None)
    @given(allow=st.booleans())
    def test_gate_deny_prevents_decrypt(self, allow: bool) -> None:
        """When gate denies, decrypt_shard must not be called.

        Verifies the control flow structure: the denial return statement
        appears before the decrypt_shard call in the source.
        """
        from worthless.proxy.app import create_app

        source = inspect.getsource(create_app)

        # Find the gate evaluation
        gate_idx = source.find("rules_engine.evaluate")
        assert gate_idx != -1

        # Find the denial check that follows
        denial_check_idx = source.find("if denial is not None:", gate_idx)
        assert denial_check_idx != -1, "denial check must follow evaluate call"

        # Find the return statement inside the denial block
        # (must come before decrypt_shard)
        denial_return_idx = source.find("return Response(", denial_check_idx)
        decrypt_idx = source.find("repo.decrypt_shard", gate_idx)
        assert denial_return_idx != -1, "denial block must have a return"
        assert decrypt_idx != -1, "decrypt_shard must exist in handler"
        assert denial_return_idx < decrypt_idx, "denial return must come before decrypt_shard call"

        if not allow:
            # When denied, the handler returns at denial_return_idx
            # which is before decrypt_idx — decrypt is never reached
            assert denial_return_idx < decrypt_idx


# ---------------------------------------------------------------------------
# SR-05: Sanitized errors must not leak upstream provider messages
# ---------------------------------------------------------------------------

# Strategy for error messages: printable ASCII to avoid Hypothesis shrinking
# issues with full-unicode text strategies combined with alphabet-restricted ones.
_ERROR_MSG = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=8,
    max_size=256,
)

_ERROR_TYPE = st.from_regex(r"[a-z][a-z_]{0,30}", fullmatch=True)


class TestSanitizeNeverLeaksMessage:
    """SR-05: Sanitized errors must not leak upstream provider messages."""

    @hsettings(deadline=None)
    @given(
        message=_ERROR_MSG,
        provider=st.sampled_from(["openai", "anthropic"]),
        error_type=_ERROR_TYPE,
        status_code=st.integers(min_value=400, max_value=599),
    )
    def test_original_message_never_in_output(
        self,
        message: str,
        provider: str,
        error_type: str,
        status_code: int,
    ) -> None:
        """Original upstream error message must not appear in sanitized output."""
        from worthless.proxy.app import _sanitize_upstream_error

        # Skip if the message happens to be our generic replacement
        assume(message != "upstream provider error")
        # Skip very short messages that could coincidentally match JSON keys
        assume(len(message.strip()) >= 8)

        if provider == "anthropic":
            body = json.dumps(
                {"type": "error", "error": {"type": error_type, "message": message}}
            ).encode()
        else:
            body = json.dumps({"error": {"message": message, "type": error_type}}).encode()

        sanitized = _sanitize_upstream_error(status_code, body, provider)

        assert message.encode() not in sanitized, (
            f"Original message {message!r} leaked into sanitized output"
        )
        assert b"upstream provider error" in sanitized

    @hsettings(deadline=None)
    @given(body=st.binary(min_size=1, max_size=4096))
    def test_arbitrary_binary_never_leaks(self, body: bytes) -> None:
        """Even garbage input produces safe generic output."""
        from worthless.proxy.app import _sanitize_upstream_error

        sanitized = _sanitize_upstream_error(500, body, "openai")

        # Any 8+ byte substring of input must not appear in output
        # (unless it coincides with the generic replacement text)
        generic = b"upstream provider error"
        for i in range(len(body) - 7):
            chunk = body[i : i + 8]
            if chunk in generic:
                continue
            assert chunk not in sanitized, (
                f"Input chunk {chunk!r} at offset {i} leaked into sanitized output"
            )

    @hsettings(deadline=None)
    @given(
        status_code=st.integers(min_value=400, max_value=599),
        provider=st.sampled_from(["openai", "anthropic"]),
    )
    def test_sanitized_output_is_valid_json(self, status_code: int, provider: str) -> None:
        """Sanitized output must always be valid JSON regardless of input."""
        from worthless.proxy.app import _sanitize_upstream_error

        # Feed completely invalid input
        sanitized = _sanitize_upstream_error(status_code, b"\xff\xfe\x00", provider)
        parsed = json.loads(sanitized)
        assert isinstance(parsed, dict)

    @hsettings(deadline=None)
    @given(
        message=_ERROR_MSG,
        provider=st.sampled_from(["openai", "anthropic"]),
    )
    def test_error_type_preserved_but_message_replaced(self, message: str, provider: str) -> None:
        """The error type field passes through but the message is always generic."""
        from worthless.proxy.app import _sanitize_upstream_error

        assume(message != "upstream provider error")

        custom_type = "rate_limit_error"
        if provider == "anthropic":
            body = json.dumps(
                {"type": "error", "error": {"type": custom_type, "message": message}}
            ).encode()
        else:
            body = json.dumps({"error": {"message": message, "type": custom_type}}).encode()

        sanitized = _sanitize_upstream_error(400, body, provider)
        parsed = json.loads(sanitized)

        if provider == "anthropic":
            assert parsed["error"]["type"] == custom_type
            assert parsed["error"]["message"] == "upstream provider error"
        else:
            assert parsed["error"]["type"] == custom_type
            assert parsed["error"]["message"] == "upstream provider error"


# ---------------------------------------------------------------------------
# SR-07: Constant-time comparison — hmac.compare_digest enforced
# ---------------------------------------------------------------------------


def _collect_all_python_files() -> list[Path]:
    """Collect all .py files under _SRC_ROOT."""
    return sorted(_SRC_ROOT.rglob("*.py"))


def _operand_has_suspect_name(
    operand: ast.expr,
    suspect_names: frozenset[str],
) -> str | None:
    """Return the suspect name if the operand is a bare name or attribute in the set.

    Checks both ``ast.Name`` (e.g. ``digest == x``) and ``ast.Attribute``
    (e.g. ``self.commitment == other``, ``obj.digest == value``).

    Returns the matched name string or ``None``.
    """
    if isinstance(operand, ast.Name) and operand.id in suspect_names:
        return operand.id
    if isinstance(operand, ast.Attribute) and operand.attr in suspect_names:
        return operand.attr
    return None


class TestSR07ConstantTimeCompare:
    """SR-07: All digest/hash comparisons must use hmac.compare_digest.

    Files that import hmac must use hmac.compare_digest for comparisons,
    never == or != on digest values. This prevents timing side-channel attacks.

    Limitation: detection relies on a heuristic name set (_SUSPECT_NAMES).
    Code that stores digests in variables with non-suspect names (e.g.
    ``computed_hmac``, ``stored_hmac``) will bypass detection. When adding
    new digest-handling code, either use a name from the suspect set or
    extend _SUSPECT_NAMES accordingly.
    """

    _SUSPECT_NAMES: frozenset[str] = frozenset(
        {"digest", "commitment", "expected", "mac", "expected_commitment"}
    )

    def _find_hmac_files(self) -> list[Path]:
        """Find all source files that import or use the hmac module."""
        hmac_files: list[Path] = []
        for py_file in _collect_all_python_files():
            source = py_file.read_text()
            if "import hmac" in source or "from hmac" in source:
                hmac_files.append(py_file)
        return hmac_files

    def test_hmac_files_exist(self) -> None:
        """At least one file uses hmac — test is not vacuously true."""
        hmac_files = self._find_hmac_files()
        assert hmac_files, (
            f"No files under {_SRC_ROOT} import hmac — "
            f"SR-07 test is vacuously true and needs updating"
        )

    def test_hmac_comparison_uses_compare_digest(self) -> None:
        """Files that compare HMAC digests in Python must use hmac.compare_digest.

        Only flags files that both compute a digest AND compare it against
        another value using == or != in Python code. Files that compute
        digests for storage, lookup, or return (without in-Python comparison)
        are not flagged -- the comparison happens in SQL or downstream.
        """
        for py_file in self._find_hmac_files():
            source = py_file.read_text()
            tree = ast.parse(source)

            calls_digest = False
            uses_compare_digest = False
            compares_digest_with_eq = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr in ("digest", "hexdigest"):
                        calls_digest = True
                    if (
                        isinstance(func, ast.Attribute)
                        and func.attr == "compare_digest"
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "hmac"
                    ):
                        uses_compare_digest = True
                # Check if digest results are compared with == or !=
                if isinstance(node, ast.Compare):
                    for op in node.ops:
                        if isinstance(op, ast.Eq | ast.NotEq):
                            all_operands = [node.left, *node.comparators]
                            for operand in all_operands:
                                if _operand_has_suspect_name(operand, self._SUSPECT_NAMES):
                                    compares_digest_with_eq = True

            if not calls_digest:
                continue
            # Only enforce compare_digest if the file actually compares
            # digest values with == or != in Python, OR uses compare_digest
            # already (to avoid removing existing correct usage)
            if not compares_digest_with_eq and not uses_compare_digest:
                continue

            rel = py_file.relative_to(_SRC_ROOT)
            assert uses_compare_digest, (
                f"{rel} computes HMAC digests and compares them with ==/!= — "
                f"use hmac.compare_digest instead (SR-07 violation)"
            )

    def test_no_equality_compare_on_digest_variables(self) -> None:
        """AST scan: files using hmac must not use == or != on variables
        named 'digest', 'commitment', 'expected', or 'mac'.

        This is a heuristic -- it catches the most common patterns of
        insecure digest comparison. See the class docstring for known
        limitations around variable renaming.
        """
        for py_file in self._find_hmac_files():
            source = py_file.read_text()
            tree = ast.parse(source)
            rel = py_file.relative_to(_SRC_ROOT)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                # Check if any comparator uses == or != with suspect variable names
                for op in node.ops:
                    if not isinstance(op, ast.Eq | ast.NotEq):
                        continue
                    # Check left side and comparators for suspect names
                    all_operands = [node.left, *node.comparators]
                    for operand in all_operands:
                        matched = _operand_has_suspect_name(operand, self._SUSPECT_NAMES)
                        if matched:
                            pytest.fail(
                                f"{rel}:{node.lineno} compares '{matched}' with "
                                f"{'==' if isinstance(op, ast.Eq) else '!='} — "
                                f"use hmac.compare_digest instead (SR-07 violation)"
                            )


# ---------------------------------------------------------------------------
# SR-08: CSPRNG only — secrets module required, random module forbidden
# ---------------------------------------------------------------------------


class TestSR08CSPRNGOnly:
    """SR-08: All randomness must come from the secrets module (CSPRNG).

    The stdlib random module (Mersenne Twister) is NOT cryptographically
    secure. This test enforces that src/worthless/ never imports it, and
    that files generating random bytes use secrets.token_bytes or similar.
    """

    all_files = _collect_all_python_files()

    @pytest.mark.parametrize(
        "py_file",
        all_files,
        ids=[str(f.relative_to(_SRC_ROOT)) for f in all_files],
    )
    def test_no_random_module_import(self, py_file: Path) -> None:
        """AST scan: no source file imports the random module.

        Catches:
          - ``import random``
          - ``from random import ...``
        Does NOT catch dynamic imports — the Ruff TID251 rule covers those.
        """
        source = py_file.read_text()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "random" and not alias.name.startswith("random."), (
                        f"{py_file.relative_to(_SRC_ROOT)}:{node.lineno} imports 'random' — "
                        f"use secrets module instead (SR-08: CSPRNG only)"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module == "random" or node.module.startswith("random.")):
                    pytest.fail(
                        f"{py_file.relative_to(_SRC_ROOT)}:{node.lineno} imports from "
                        f"'{node.module}' — use secrets module instead (SR-08: CSPRNG only)"
                    )

    def test_crypto_files_use_secrets(self) -> None:
        """Files generating random bytes must use the secrets module.

        Checks that crypto/ files (where randomness is most critical)
        import and use secrets.token_bytes, secrets.token_hex, or
        secrets.token_urlsafe.
        """
        crypto_dir = _SRC_ROOT / "crypto"
        if not crypto_dir.is_dir():
            pytest.skip("crypto/ directory not found")

        secrets_functions = {"token_bytes", "token_hex", "token_urlsafe"}
        crypto_files_with_randomness: list[Path] = []

        for py_file in sorted(crypto_dir.rglob("*.py")):
            source = py_file.read_text()
            if "secrets" not in source:
                continue

            tree = ast.parse(source)
            uses_secrets_func = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in secrets_functions:
                    if isinstance(node.value, ast.Name) and node.value.id == "secrets":
                        uses_secrets_func = True
                        break
                elif isinstance(node, ast.ImportFrom) and node.module == "secrets":
                    for alias in node.names:
                        if alias.name in secrets_functions:
                            uses_secrets_func = True
                            break

            if uses_secrets_func:
                crypto_files_with_randomness.append(py_file)

        assert crypto_files_with_randomness, (
            "No crypto/ files use secrets.token_bytes/token_hex/token_urlsafe — "
            "randomness source is unknown (SR-08 violation)"
        )


# ---------------------------------------------------------------------------
# Phase 6 — Shard-A signing (worthless-1pua)
#
# Design:
#   envelope = prefix + base64url(nonce_16 || expiry_4 || hmac_truncated_16) + shard_a_body
#   - 36 overhead bytes → 48 base64url chars (no padding; 36 % 3 == 0)
#   - base64url charset (A-Za-z0-9-_) is a subset of all provider key charsets
#   - Envelope is 48 chars longer than raw shard_a — verified harmless (providers
#     return 401 not 400 for variable-length keys with correct prefix)
#   - signing_key lives in ~/.worthless/signing.key; 32 random bytes; never leaves host
#   - Nonce is per-enrollment (16 bytes); valid until expiry (default 1 year)
#   - SQLite signing_nonces(nonce_hex, alias, expires_at) stores valid nonces
# ---------------------------------------------------------------------------


class TestPhase6EnvelopeConstruction:
    """Envelope format: correct prefix, correct charset, 48 chars longer."""

    def test_signed_shard_a_has_same_prefix_as_original(self):
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "A" * 60).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(shard_a, "openai-test", key, prefix=prefix)
        assert envelope.decode().startswith(prefix)

    def test_signed_shard_a_is_exactly_48_chars_longer(self):
        assert OVERHEAD_CHARS == 48  # 36 bytes → 48 base64url chars
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "B" * 60).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix)
        assert len(envelope) == len(shard_a) + OVERHEAD_CHARS

    def test_overhead_uses_only_base64url_charset(self):
        """Overhead bytes encoded as base64url — subset of all provider key charsets."""
        import string

        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "C" * 60).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix)
        valid = set(string.ascii_letters + string.digits + "-_")
        overhead_section = envelope.decode()[len(prefix) : len(prefix) + OVERHEAD_CHARS]
        assert all(c in valid for c in overhead_section)

    def test_anthropic_prefix_preserved(self):
        prefix = "sk-ant-api03-"
        shard_a = bytearray(("sk-ant-api03-" + "D" * 80).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(shard_a, "ant-test", key, prefix=prefix)
        assert envelope.decode().startswith(prefix)

    def test_nonce_is_16_bytes(self):
        shard_a = bytearray(("sk-proj-" + "E" * 60).encode())
        key = generate_signing_key()
        _, nonce, _ = sign_shard_a(shard_a, "alias", key, prefix="sk-proj-")
        assert len(nonce) == 16

    def test_nonce_space_is_128_bits(self):
        """128-bit nonce → birthday attack requires 2^64 attempts."""
        shard_a = bytearray(("sk-proj-" + "F" * 60).encode())
        key = generate_signing_key()
        _, nonce, _ = sign_shard_a(shard_a, "alias", key, prefix="sk-proj-")
        assert len(nonce) * 8 >= 128

    def test_two_enrollments_produce_different_nonces(self):
        shard_a1 = bytearray(("sk-proj-" + "G" * 60).encode())
        shard_a2 = bytearray(("sk-proj-" + "G" * 60).encode())
        key = generate_signing_key()
        _, nonce1, _ = sign_shard_a(shard_a1, "alias1", key, prefix="sk-proj-")
        _, nonce2, _ = sign_shard_a(shard_a2, "alias2", key, prefix="sk-proj-")
        assert nonce1 != nonce2

    def test_expiry_is_in_the_future(self):
        shard_a = bytearray(("sk-proj-" + "H" * 60).encode())
        key = generate_signing_key()
        _, _, expires_at = sign_shard_a(shard_a, "alias", key, prefix="sk-proj-", ttl_days=1)
        assert expires_at > int(_time.time())

    def test_ttl_days_controls_expiry(self):
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "I" * 60).encode())
        _, _, exp_30 = sign_shard_a(bytearray(shard_a), "a", key, prefix="sk-proj-", ttl_days=30)
        _, _, exp_365 = sign_shard_a(bytearray(shard_a), "a", key, prefix="sk-proj-", ttl_days=365)
        assert exp_365 > exp_30 + 300 * 86400


class TestPhase6Roundtrip:
    """sign → verify → extract recovers byte-identical original shard_a."""

    def test_roundtrip_openai_key(self):
        prefix = "sk-proj-"
        original = bytearray(("sk-proj-" + "J" * 60).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(bytearray(original), "alias", key, prefix=prefix)
        recovered, _, _ = verify_and_extract(envelope, "alias", key, prefix=prefix)
        assert bytes(recovered) == bytes(original)

    def test_roundtrip_anthropic_key(self):
        prefix = "sk-ant-api03-"
        original = bytearray(("sk-ant-api03-" + "K" * 80).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(bytearray(original), "ant", key, prefix=prefix)
        recovered, _, _ = verify_and_extract(envelope, "ant", key, prefix=prefix)
        assert bytes(recovered) == bytes(original)

    def test_recovery_is_byte_identical(self):
        prefix = "sk-proj-"
        original = bytearray(("sk-proj-" + "L" * 124).encode())
        key = generate_signing_key()
        envelope, _, _ = sign_shard_a(bytearray(original), "alias", key, prefix=prefix)
        recovered, _, _ = verify_and_extract(envelope, "alias", key, prefix=prefix)
        assert recovered == original


class TestPhase6RejectionPaths:
    """Rejection: wrong key, wrong alias, expired, tampered, unsigned."""

    def test_raw_unsigned_shard_a_is_rejected(self):
        prefix = "sk-proj-"
        raw = bytearray(("sk-proj-" + "M" * 60).encode())
        key = generate_signing_key()
        with pytest.raises(ShardSigningError):
            verify_and_extract(raw, "alias", key, prefix=prefix)

    def test_wrong_signing_key_is_rejected(self):
        prefix = "sk-proj-"
        key1 = generate_signing_key()
        key2 = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "N" * 60).encode())
        envelope, _, _ = sign_shard_a(shard_a, "alias", key1, prefix=prefix)
        with pytest.raises(ShardSigningError):
            verify_and_extract(envelope, "alias", key2, prefix=prefix)

    def test_wrong_alias_is_rejected(self):
        """HMAC binds to alias; presenting under different alias fails."""
        prefix = "sk-proj-"
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "O" * 60).encode())
        envelope, _, _ = sign_shard_a(shard_a, "openai-abc123", key, prefix=prefix)
        with pytest.raises(ShardSigningError):
            verify_and_extract(envelope, "openai-different", key, prefix=prefix)

    def test_expired_envelope_is_rejected(self):
        prefix = "sk-proj-"
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "P" * 60).encode())
        # Sign with a negative TTL so the envelope is genuinely expired AND the
        # HMAC covers the past expiry. This exercises the expiry check on a VALID
        # envelope, not a tampered one (mutating expiry post-sign would break the
        # MAC and could pass for the wrong reason).
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix, ttl_days=-1)
        with pytest.raises(ShardSigningError, match="expired"):
            verify_and_extract(envelope, "alias", key, prefix=prefix)

    def test_tampered_body_is_rejected(self):
        prefix = "sk-proj-"
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "Q" * 60).encode())
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix)
        # Flip one char in the body (after prefix + overhead)
        idx = len(prefix) + OVERHEAD_CHARS + 1
        b = bytearray(envelope)
        b[idx] = ord("Z") if chr(b[idx]) != "Z" else ord("A")
        with pytest.raises(ShardSigningError):
            verify_and_extract(bytearray(b), "alias", key, prefix=prefix)

    def test_tampered_overhead_is_rejected(self):
        prefix = "sk-proj-"
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "R" * 60).encode())
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix)
        # Flip one char deep in the overhead section
        idx = len(prefix) + 10
        b = bytearray(envelope)
        b[idx] = ord("Z") if chr(b[idx]) != "Z" else ord("A")
        with pytest.raises(ShardSigningError):
            verify_and_extract(bytearray(b), "alias", key, prefix=prefix)

    def test_prefix_mismatch_is_rejected(self):
        prefix = "sk-proj-"
        key = generate_signing_key()
        shard_a = bytearray(("sk-proj-" + "S" * 60).encode())
        envelope, _, _ = sign_shard_a(shard_a, "alias", key, prefix=prefix)
        with pytest.raises(ShardSigningError, match="prefix"):
            verify_and_extract(envelope, "alias", key, prefix="sk-ant-api03-")

    def test_envelope_too_short_is_rejected(self):
        key = generate_signing_key()
        with pytest.raises(ShardSigningError):
            verify_and_extract(bytearray(b"sk-proj-short"), "alias", key, prefix="sk-proj-")


class TestPhase6SigningKeyManagement:
    """Signing key: 32 bytes, restricted permissions, idempotent creation."""

    def test_generate_signing_key_is_32_bytes(self):
        assert len(generate_signing_key()) == 32

    def test_two_generated_keys_differ(self):
        assert generate_signing_key() != generate_signing_key()

    def test_load_or_create_creates_key_file(self, tmp_path):
        key = load_or_create_signing_key(tmp_path)
        assert (tmp_path / "signing.key").exists()
        assert len(key) == 32

    def test_load_or_create_is_idempotent(self, tmp_path):
        key1 = load_or_create_signing_key(tmp_path)
        key2 = load_or_create_signing_key(tmp_path)
        assert key1 == key2

    def test_signing_key_file_has_restricted_permissions(self, tmp_path):
        import stat as stat_mod

        load_or_create_signing_key(tmp_path)
        mode = (tmp_path / "signing.key").stat().st_mode
        assert not (mode & stat_mod.S_IRGRP)
        assert not (mode & stat_mod.S_IROTH)

    def test_world_readable_signing_key_raises_on_load(self, tmp_path):
        """load_or_create_signing_key rejects a key file with group/other read bits."""
        key = generate_signing_key()
        key_path = tmp_path / "signing.key"
        key_path.write_text(key.hex() + "\n")
        key_path.chmod(0o644)  # world-readable — should be rejected
        with pytest.raises(ValueError, match="insecure permissions"):
            load_or_create_signing_key(tmp_path)

    def test_corrupt_short_signing_key_raises_on_load(self, tmp_path):
        """load_or_create_signing_key rejects a truncated key file (wrong byte count)."""
        import os

        # Write only 16 bytes as hex (half the required 32)
        key_path = tmp_path / "signing.key"
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, b"aa" * 16 + b"\n")  # 16 bytes hex-encoded
        finally:
            os.close(fd)
        with pytest.raises(ValueError, match="corrupt"):
            load_or_create_signing_key(tmp_path)


class TestPhase6NoncePersistence:
    """Nonce is stored in SQLite — re-lock revokes old envelopes, survives restart."""

    def test_shard_a_replay_is_rejected_after_relock(self, tmp_path):
        """After re-lock the old signed envelope's nonce is stale — proxy rejects it.

        Directly tests the revocation contract: is_valid_signing_nonce returns
        False for the old nonce once a new one is upserted.
        """
        import asyncio
        from cryptography.fernet import Fernet
        from worthless.storage.repository import ShardRepository

        db_path = str(tmp_path / "test.db")
        fernet_key = Fernet.generate_key()
        signing_key = generate_signing_key()
        alias = "test-alias-replay"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "X" * 60).encode())

        async def _run() -> None:
            repo = ShardRepository(db_path, fernet_key)
            await repo.initialize()

            # Lock 1: sign and store nonce_1
            old_envelope, nonce_1, expires_1 = sign_shard_a(
                shard_a, alias, signing_key, prefix=prefix
            )
            await repo.store_signing_nonce(alias, nonce_1, expires_1)
            assert await repo.is_valid_signing_nonce(alias, nonce_1)

            # Re-lock: upsert nonce_2 — this invalidates nonce_1
            _, nonce_2, expires_2 = sign_shard_a(shard_a, alias, signing_key, prefix=prefix)
            await repo.store_signing_nonce(alias, nonce_2, expires_2)

            # Old envelope HMAC still verifies, but nonce is now stale
            _, old_nonce, _ = verify_and_extract(
                bytearray(old_envelope), alias, signing_key, prefix=prefix
            )
            assert not await repo.is_valid_signing_nonce(alias, old_nonce)
            # New nonce still valid
            assert await repo.is_valid_signing_nonce(alias, nonce_2)

        asyncio.run(_run())

    def test_nonce_replay_rejected_after_server_restart(self, tmp_path):
        """Nonce persisted to SQLite: a fresh ShardRepository instance honours it.

        Proves the nonce is NOT held in memory — a fresh repo on the same DB
        file rejects old nonces and accepts the current one, even without any
        in-process state from the original repo instance.
        """
        import asyncio
        from cryptography.fernet import Fernet
        from worthless.storage.repository import ShardRepository

        db_path = str(tmp_path / "test.db")
        fernet_key = Fernet.generate_key()
        signing_key = generate_signing_key()
        alias = "test-alias-restart"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "Y" * 60).encode())

        async def _run() -> None:
            # repo1 = first server instance
            repo1 = ShardRepository(db_path, fernet_key)
            await repo1.initialize()

            _, nonce_1, expires_1 = sign_shard_a(shard_a, alias, signing_key, prefix=prefix)
            await repo1.store_signing_nonce(alias, nonce_1, expires_1)

            # Re-lock: upsert nonce_2
            _, nonce_2, expires_2 = sign_shard_a(shard_a, alias, signing_key, prefix=prefix)
            await repo1.store_signing_nonce(alias, nonce_2, expires_2)

            # repo2 = fresh server instance — same SQLite file, no shared memory
            repo2 = ShardRepository(db_path, fernet_key)
            await repo2.initialize()

            # Old nonce rejected by fresh instance (proves SQLite, not in-memory)
            assert not await repo2.is_valid_signing_nonce(alias, nonce_1)
            # Current nonce accepted
            assert await repo2.is_valid_signing_nonce(alias, nonce_2)

        asyncio.run(_run())


class TestPhase6KeyRotation:
    """Rotating the signing key invalidates all outstanding envelopes."""

    def test_old_key_envelope_rejected_after_signing_key_rotation(self):
        """ATTACK: attacker holds a valid signed envelope but the signing key was rotated.

        After key rotation every previously issued envelope fails verify_and_extract
        because the HMAC was computed with the old key.
        """
        alias = "test-alias-rotation"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "Z" * 60).encode())

        key_a = generate_signing_key()
        key_b = generate_signing_key()
        assert key_a != key_b  # sanity: two independent keys

        # Sign with key_a (the "old" signing key before rotation)
        old_envelope, _, _ = sign_shard_a(shard_a, alias, key_a, prefix=prefix)

        # After rotation, the proxy uses key_b — old envelope must be rejected
        with pytest.raises(ShardSigningError):
            verify_and_extract(bytearray(old_envelope), alias, key_b, prefix=prefix)


class TestPhase6KeyCreationWarning:
    """Warning emitted when a new signing key is created alongside an existing DB."""

    def test_warning_logged_when_key_created_with_existing_db(self, tmp_path, caplog):
        """load_or_create_signing_key warns when worthless.db exists but signing.key does not.

        This state means existing enrollments were signed with a now-deleted key —
        the operator must re-lock every .env file or requests will be rejected.
        """
        import logging

        # Simulate existing DB (enrollments present) without a signing key
        (tmp_path / "worthless.db").write_bytes(b"")

        with caplog.at_level(logging.WARNING, logger="worthless.crypto.shard_signing"):
            load_or_create_signing_key(tmp_path)

        assert any("existing enrollments" in r.message for r in caplog.records), (
            "Expected a WARNING about existing enrollments when signing key is created "
            f"alongside worthless.db. Got: {[r.message for r in caplog.records]}"
        )

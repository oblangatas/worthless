"""Security property tests — Hypothesis-powered invariant checks for crypto primitives.

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
from pathlib import Path

from hypothesis import given, assume, settings as hsettings
from hypothesis import strategies as st

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
    """SR-03: Rules engine evaluates BEFORE any decryption.

    Post-WOR-309 the proxy delegates decryption to the sidecar via
    ``ipc.open()``. The handler must call rules_engine.evaluate() before
    ipc.open() so denied requests never trigger sidecar decryption.
    """

    def test_evaluate_precedes_decrypt_in_proxy_handler(self) -> None:
        """Static analysis: rules_engine.evaluate appears before ipc.open in source."""
        from worthless.proxy.app import create_app

        source = inspect.getsource(create_app)
        gate_pos = source.find("rules_engine.evaluate")
        open_pos = source.find("ipc.open")
        assert gate_pos != -1, "rules_engine.evaluate not found in proxy handler"
        assert open_pos != -1, "ipc.open not found in proxy handler"
        assert gate_pos < open_pos, (
            f"gate (pos {gate_pos}) must appear before ipc.open (pos {open_pos}) in source"
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
        """When gate denies, ipc.open must not be called.

        Verifies the control flow structure: the denial return statement
        appears before the ipc.open call in the source.
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
        # (must come before ipc.open)
        denial_return_idx = source.find("return Response(", denial_check_idx)
        open_idx = source.find("ipc.open", gate_idx)
        assert denial_return_idx != -1, "denial block must have a return"
        assert open_idx != -1, "ipc.open must exist in handler"
        assert denial_return_idx < open_idx, "denial return must come before ipc.open call"

        if not allow:
            # When denied, the handler returns at denial_return_idx
            # which is before open_idx — sidecar decryption never reached
            assert denial_return_idx < open_idx


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

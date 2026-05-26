"""Fernet-backed sidecar crypto backend (v1.1).

Reconstructs a Fernet key from two equal-length XOR shares, then exposes
``seal`` / ``open`` / ``attest`` per ``engineering/ipc-contract.md`` \u00a7Ops.

Security notes:
    * The reconstructed key lives on the instance but is never serialised
      (``__repr__`` is redacted).
    * ``open`` / ``attest`` never leak ciphertext, plaintext, share bytes,
      or underlying exception messages; callers get a fixed safe string.
    * ``context`` is advisory in v1.1 (Fernet has no AAD binding);
      v2.0 backends are expected to bind it cryptographically.
"""

from __future__ import annotations

import hmac
import logging
from hashlib import sha256
from typing import ClassVar

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from worthless.sidecar.backends.base import Backend, BackendError

__all__ = ["FernetBackend"]

_LOG = logging.getLogger(__name__)

_ATTEST_SALT = b"worthless-attest-v1"
_ATTEST_INFO = b"attest"
_ATTEST_SECRET_LEN = 32


class FernetBackend(Backend):
    """Fernet backend reconstructed from two XOR shares."""

    # ``mac`` is the WOR-465 A3a verb — raw HMAC-SHA256 over (key, value).
    # See backends/base.py docstring for why caps gates dispatch.
    caps: ClassVar[tuple[str, ...]] = ("seal", "open", "attest", "mac")

    __slots__ = ("_fernet", "_attest_secret", "_raw_key")

    def __init__(self, shares: tuple[bytes, bytes]) -> None:
        share_a, share_b = shares
        if len(share_a) != len(share_b):
            raise ValueError(
                f"FernetBackend: shares must be equal length; got {len(share_a)} and {len(share_b)}"
            )

        key = bytes(a ^ b for a, b in zip(share_a, share_b, strict=True))

        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError):
            # Do NOT chain the underlying exception — its message may echo
            # key bytes. Use `from None` to suppress the cause entirely.
            raise ValueError("FernetBackend: reconstructed key is not a valid Fernet key") from None

        # Retain the reconstructed key for the ``mac`` verb. ShardRepository's
        # legacy in-process ``_compute_decoy_hash`` keys HMAC-SHA256 with the
        # 44-byte urlsafe-b64 form of the Fernet key — exactly what ``key`` is
        # here — so ``mac(value)`` produces byte-identical output across the
        # WORTHLESS_FERNET_IPC_ONLY flag flip. Storing the key on the instance
        # does not widen the attack surface beyond what Fernet already keeps
        # internally; ``__repr__`` is redacted.
        self._raw_key = key

        # Derive a dedicated attest secret so ``attest`` output cannot be
        # used to recover or probe the Fernet key directly.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_ATTEST_SECRET_LEN,
            salt=_ATTEST_SALT,
            info=_ATTEST_INFO,
        )
        self._attest_secret = hkdf.derive(key)

    # ------------------------------------------------------------------ repr
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "<FernetBackend key_id=<redacted>>"

    # ------------------------------------------------------------------ ops
    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        if context is not None:
            _LOG.debug(
                "FernetBackend.seal: context provided but not cryptographically bound (v1.1)"
            )
        return self._fernet.encrypt(plaintext)

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        # ``key_id`` is accepted for contract compatibility with future
        # multi-key backends; v1.1 has a single key and ignores it.
        if context is not None:
            _LOG.debug(
                "FernetBackend.open: context provided but not cryptographically bound (v1.1)"
            )
        if key_id is not None:
            _LOG.debug("FernetBackend.open: key_id accepted but ignored in v1.1")

        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken:
            raise BackendError("BACKEND: decryption failed") from None
        except (TypeError, ValueError):
            # Malformed input (non-bytes, wrong shape) — same safe message.
            raise BackendError("BACKEND: decryption failed") from None

    async def mac(self, value: bytes) -> bytes:
        """Return raw HMAC-SHA256(self._raw_key, value).

        Distinct from :meth:`attest`: ``attest`` keys an HKDF-derived
        subkey and length-prefixes (nonce, purpose) — domain separation
        across cross-purpose replays. ``mac`` is the unwrapped tag with
        the Fernet key as the MAC key, matching the bytes produced by
        ``hmac.new(fernet_key, value, sha256).digest()`` in
        ``ShardRepository._compute_decoy_hash``. Byte-identity across
        the WORTHLESS_FERNET_IPC_ONLY flag flip is the load-bearing
        property — see ``tests/ipc/test_mac_verb.py``.
        """
        return hmac.new(self._raw_key, value, sha256).digest()

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        purpose_bytes = purpose.encode("utf-8") if purpose is not None else b""
        # Length-prefix each component so distinct (nonce, purpose) pairs map
        # to distinct MAC inputs. Without this, variable-length ``nonce``
        # concatenated with free-form ``purpose`` produces collisions across
        # purposes — e.g. ``attest(b"abc", "de")`` and ``attest(b"abcde", "")``
        # would hash the same bytes, letting an attacker forge a
        # ``decrypt``-purpose attestation from a ``liveness`` one once a
        # verifier exists. Fix: Q-prefix (8 bytes BE) each component.
        message = (
            len(nonce).to_bytes(8, "big")
            + nonce
            + len(purpose_bytes).to_bytes(8, "big")
            + purpose_bytes
        )
        mac = hmac.new(self._attest_secret, message, sha256)
        return mac.digest()

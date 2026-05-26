"""Abstract backend interface for the sidecar.

The sidecar server speaks only to :class:`Backend`; concrete backends
(Fernet today, KMS/MPC later) are swappable without touching server code.

See ``engineering/ipc-contract.md`` \u00a7Ops for the wire-level semantics of
``seal`` / ``open`` / ``attest`` / ``mac`` that every backend implementation
must honour.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

#: Wire-level length of HMAC-SHA256 output. Re-exported here because both
#: ``mac`` and ``attest`` produce this length and callers (e.g. bootstrap
#: attestation validation) need the constant alongside the verbs.
HMAC_SHA256_LEN: int = 32


class BackendError(Exception):
    """Raised by backend implementations on crypto / key failures.

    The error message is deliberately fixed and information-free: backends
    MUST NOT echo ciphertext, plaintext, key material, or the underlying
    exception text. Callers that need diagnostics should rely on structured
    logging inside the backend, not on exception contents.
    """


class Backend(ABC):
    """Abstract crypto backend for the sidecar.

    v1.1 implementation: :class:`worthless.sidecar.backends.fernet.FernetBackend`.
    v2.0 will add KMS and MPC backends; the sidecar server talks only to
    this interface so backends are swappable without touching server code.

    All methods are async to allow future backends to do I/O (KMS calls,
    MPC rounds). The Fernet backend implements them synchronously under
    the hood but keeps the async signature.

    Subclasses MUST declare :attr:`caps` listing the verbs they support.
    The sidecar server derives both the wire-level handshake advertisement
    AND the dispatch allowlist from this tuple, so a backend that does not
    advertise a verb cannot have that verb dispatched against it \u2014 even
    if the method exists on the class. This defends against future v2.0
    backends silently accepting verbs they have not implemented (WOR-465 A3a
    defense-in-depth).
    """

    #: Verbs this backend implements. Empty default forces subclasses to
    #: declare explicitly; the server uses this for handshake advertisement
    #: and dispatch validation.
    caps: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        """Encrypt ``plaintext``; return opaque ciphertext bytes."""

    @abstractmethod
    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        """Decrypt ``ciphertext``; return plaintext."""

    @abstractmethod
    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        """Return opaque evidence binding ``nonce`` to backend identity."""

    async def mac(self, value: bytes) -> bytes:
        """Return raw HMAC-SHA256 over ``(key, value)``.

        Default implementation raises :class:`NotImplementedError`. Subclasses
        that include ``"mac"`` in :attr:`caps` MUST override. The server
        guards by ``caps`` so this default is unreachable on a well-formed
        sidecar build; raising here is the regression backstop.
        """
        raise NotImplementedError("backend does not implement mac()")

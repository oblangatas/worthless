"""In-process fake :class:`IPCSupervisor` for proxy unit tests.

Production code at ``src/worthless/proxy/app.py:180-189`` reads
``app.state.ipc_supervisor`` if pre-set; otherwise it builds a real one
and eager-connects. By pre-setting our fake before ``_lifespan`` runs,
the proxy uses the fake transparently — no real sidecar spawn, no
``asyncio.open_unix_connection``, no socket plumbing.

The fake mirrors :class:`worthless.proxy.ipc_supervisor.IPCSupervisor`'s
public surface exactly:

* async ``connect()``
* async ``aclose()``
* ``acquire()`` async context manager (yields a tiny client double)
* async ``open(ciphertext, *, key_id) -> bytearray``
* property ``backend_caps``
* default-plaintext + configurable-failure knobs for tests

Mirrors the ``_BrokenIPCClient`` pattern from ``tests/ipc/conftest.py:143-182``
but at the *supervisor* level — Phase 5 needs to inject at
``app.state.ipc_supervisor``, not at the client layer.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from worthless.proxy.ipc_supervisor import IPCUnavailable

__all__ = [
    "DEFAULT_FAKE_PLAINTEXT",
    "FakeIPCClient",
    "FakeIPCSupervisor",
]

#: Default plaintext returned by ``open()`` when the test does not pin a
#: per-key value. Distinct, recognisable byte string so a test that gets
#: it back unexpectedly can grep-find the source. Length matches a typical
#: 44-byte Fernet key shard so callers downstream that XOR with shard-A
#: don't trip length checks.
DEFAULT_FAKE_PLAINTEXT: bytes = b"FAKE-PLAINTEXT-SHARD-B-padded-to-44-bytes-XX"


class FakeIPCClient:
    """Minimal IPCClient stand-in yielded by ``FakeIPCSupervisor.acquire()``.

    The supervisor's ``open()`` shortcuts past ``acquire()`` so this class
    exists only for the rare test that exercises ``async with sup.acquire()
    as client: await client.open(...)`` directly.
    """

    def __init__(self, supervisor: FakeIPCSupervisor) -> None:
        self._supervisor = supervisor

    @property
    def backend_caps(self) -> tuple[str, ...]:
        return tuple(sorted(self._supervisor.backend_caps))

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        # The supervisor's surface is the canonical entrypoint; defer to it
        # so configured plaintext + failure knobs apply uniformly.
        key_id_str = key_id.decode("utf-8") if key_id else ""
        # Return immutable bytes (matches real IPCClient.open signature);
        # the supervisor wraps it into a bytearray on the way out.
        result = await self._supervisor._do_open(ciphertext, key_id_str)
        return bytes(result)

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        # Not part of the proxy hot path, but provided for surface parity.
        return b"FAKE-CIPHERTEXT"

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        return b"FAKE-EVIDENCE"

    async def aclose(self) -> None:
        return None


class FakeIPCSupervisor:
    """In-process fake of :class:`IPCSupervisor`.

    Tests construct this, configure knobs (``fail_open_with``, plaintexts
    keyed by ``key_id``), then assign to ``app.state.ipc_supervisor``
    *before* the ASGI lifespan runs.

    Default behaviour: ``open()`` returns :data:`DEFAULT_FAKE_PLAINTEXT` as a
    fresh ``bytearray`` for any key_id. Tests that need cryptographically
    correct plaintext (so reconstruction succeeds) override via
    :meth:`set_plaintext`.
    """

    def __init__(
        self,
        *,
        backend_caps: frozenset[str] | tuple[str, ...] = frozenset({"open", "seal", "attest"}),
        default_plaintext: bytes = DEFAULT_FAKE_PLAINTEXT,
    ) -> None:
        self._backend_caps: frozenset[str] = (
            backend_caps if isinstance(backend_caps, frozenset) else frozenset(backend_caps)
        )
        self._default_plaintext = bytes(default_plaintext)
        self._plaintexts: dict[str, bytes] = {}
        self._fail_open_with: type[BaseException] | None = None
        self._fail_open_message: str = "fake sidecar configured to fail"
        self._fail_connect_with: type[BaseException] | None = None
        self._fail_connect_message: str = "fake sidecar configured to fail connect"
        self._connected = False
        self._closed = False
        self.connect_calls = 0
        self.aclose_calls = 0
        self.open_calls = 0

    # ------------------------------------------------------------------
    # Public IPCSupervisor surface
    # ------------------------------------------------------------------

    @property
    def backend_caps(self) -> frozenset[str]:
        return self._backend_caps

    async def connect(self) -> None:
        self.connect_calls += 1
        if self._closed:
            raise RuntimeError("supervisor is closed")
        if self._fail_connect_with is not None:
            raise self._fail_connect_with(self._fail_connect_message)
        self._connected = True

    async def aclose(self) -> None:
        self.aclose_calls += 1
        self._closed = True
        self._connected = False

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[FakeIPCClient]:
        if self._closed:
            raise IPCUnavailable("fake supervisor is closed")
        # Acquiring a client when not connected mirrors real-supervisor
        # transparent reconnect — auto-connect for test ergonomics, but
        # honour configured connect failure if any.
        if not self._connected:
            await self.connect()
        yield FakeIPCClient(self)

    async def open(self, ciphertext: bytes, *, key_id: str) -> bytearray:
        """Decrypt over the fake. Returns a *fresh* bytearray (SR-01)."""
        self.open_calls += 1
        plaintext = await self._do_open(ciphertext, key_id)
        # Always hand the caller a fresh bytearray so they can zero it
        # without touching shared state — matches real supervisor contract.
        return bytearray(plaintext)

    # ------------------------------------------------------------------
    # Test configuration knobs
    # ------------------------------------------------------------------

    def set_plaintext(self, key_id: str, plaintext: bytes) -> None:
        """Pin a specific plaintext for a given ``key_id``.

        Tests that need reconstruction to succeed (i.e. XOR(shard_a,
        shard_b) reproduces the original API key) call this with the real
        shard_b bytes for their alias.
        """
        self._plaintexts[key_id] = bytes(plaintext)

    def fail_open_with(
        self,
        exc_class: type[BaseException] = IPCUnavailable,
        message: str = "fake sidecar configured to fail",
    ) -> None:
        """Configure ``open()`` to raise ``exc_class(message)`` next call."""
        self._fail_open_with = exc_class
        self._fail_open_message = message

    def fail_connect_with(
        self,
        exc_class: type[BaseException] = IPCUnavailable,
        message: str = "fake sidecar configured to fail connect",
    ) -> None:
        """Configure ``connect()`` to raise ``exc_class(message)`` next call."""
        self._fail_connect_with = exc_class
        self._fail_connect_message = message

    def clear_failures(self) -> None:
        """Reset all configured failure modes."""
        self._fail_open_with = None
        self._fail_connect_with = None

    # ------------------------------------------------------------------
    # Internal hook used by both ``open()`` and ``FakeIPCClient.open()``
    # ------------------------------------------------------------------

    async def _do_open(self, ciphertext: bytes, key_id: str) -> bytes:
        if self._closed:
            raise IPCUnavailable("fake supervisor is closed")
        if self._fail_open_with is not None:
            raise self._fail_open_with(self._fail_open_message)
        # Configured per-key plaintext wins over the default.
        return self._plaintexts.get(key_id, self._default_plaintext)

    # Surface parity helpers: the real supervisor exposes these as plain
    # attributes; some tests inspect them. Provide read-only access.
    @property
    def is_connected(self) -> bool:
        return self._connected and not self._closed

    @property
    def is_closed(self) -> bool:
        return self._closed

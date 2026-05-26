"""Tests for ShardRepository's IPC-backed crypto path (WOR-465 A3b 2/3).

When ShardRepository is constructed with an IPCClient instead of a raw
key, it MUST:

* route ``store`` / ``store_enrolled`` encryption through ``ipc.seal``
* route ``decrypt_shard`` (now async) through ``ipc.open``
* route ``_compute_decoy_hash`` (now async) through ``ipc.mac`` and
  hex-encode the resulting bytes so byte-identity with the legacy
  ``hmac.new(fernet_key, value, sha256).hexdigest()`` path is preserved

Load-bearing invariant: ``decoy_hash`` bytes MUST be byte-identical
across the WORTHLESS_FERNET_IPC_ONLY flag flip. Otherwise every
existing customer's stored decoy_hash row invalidates at the moment
the flag is enabled.

Bare-metal path (constructor with bytes/bytearray) is unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import secrets
from hashlib import sha256
from typing import Any

import pytest

from worthless.sidecar.backends.fernet import FernetBackend
from worthless.storage.repository import ShardRepository


# ---------------------------------------------------------------------------
# Helpers: build shares from a known 44-byte Fernet key so the byte-identity
# test can compute the expected HMAC against the SAME key the FernetBackend
# is reconstructing.
# ---------------------------------------------------------------------------


def _shares_for(fernet_key_44b: bytes) -> tuple[bytes, bytes]:
    share_a = b"\x5a" * len(fernet_key_44b)
    share_b = bytes(a ^ k for a, k in zip(share_a, fernet_key_44b, strict=True))
    return share_a, share_b


def _fresh_fernet_key_44b() -> bytes:
    return base64.urlsafe_b64encode(secrets.token_bytes(32))


# ---------------------------------------------------------------------------
# Fake IPC client — records seal/open/mac calls and routes them to a real
# FernetBackend so byte-equivalence tests work without spinning up a
# sidecar process.
# ---------------------------------------------------------------------------


class _BackendBackedIPCClient:
    """Drop-in for IPCClient. Wraps a real FernetBackend so output bytes
    match what the sidecar would produce against the same key.

    Implements only the async methods ShardRepository's IPC path uses:
    ``seal``, ``open``, ``mac``. Records every call so tests can assert
    on routing.
    """

    def __init__(self, backend: FernetBackend) -> None:
        self._backend = backend
        self.seal_calls: list[bytes] = []
        self.open_calls: list[bytes] = []
        self.mac_calls: list[bytes] = []

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        self.seal_calls.append(bytes(plaintext))
        return await self._backend.seal(plaintext, context)

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        self.open_calls.append(bytes(ciphertext))
        return await self._backend.open(ciphertext, context, key_id)

    async def mac(self, value: bytes) -> bytes:
        self.mac_calls.append(bytes(value))
        return await self._backend.mac(value)


@pytest.fixture
def fernet_key_44b() -> bytes:
    return _fresh_fernet_key_44b()


@pytest.fixture
def backend_backed_client(fernet_key_44b: bytes) -> _BackendBackedIPCClient:
    shares = _shares_for(fernet_key_44b)
    backend = FernetBackend(shares=shares)
    return _BackendBackedIPCClient(backend)


# ---------------------------------------------------------------------------
# Constructor contract
# ---------------------------------------------------------------------------


def test_repository_accepts_ipcclient(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
) -> None:
    """ShardRepository(db_path, IPCClient) MUST construct without error.

    Today's constructor accepts bytes|bytearray only and would
    ``bytearray(IPCClient)`` which raises TypeError. This pins the new
    contract: IPCClient is a valid second argument.
    """
    repo = ShardRepository(tmp_db_path, backend_backed_client)
    assert repo is not None


def test_constructor_rejects_unknown_type(tmp_db_path: str) -> None:
    """Anything not bytes / bytearray / IPCClient-like MUST raise TypeError.

    Defends against a future caller passing a str (e.g., the b64-encoded
    key as a string) and silently producing garbage HMACs.
    """
    with pytest.raises(TypeError):
        ShardRepository(tmp_db_path, "not-a-key-and-not-an-ipc-client")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Routing: seal / open go through the IPC client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seal_routes_through_ipc_when_constructed_with_client(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
    sample_split_result: Any,
) -> None:
    """``repo.store`` MUST call ``ipc.seal`` exactly once with the plaintext."""
    from tests.conftest import stored_shard_from_split

    repo = ShardRepository(tmp_db_path, backend_backed_client)
    await repo.initialize()
    shard = stored_shard_from_split(sample_split_result)

    await repo.store("alias-seal", shard)

    assert len(backend_backed_client.seal_calls) == 1, (
        f"expected exactly 1 seal call, got {len(backend_backed_client.seal_calls)}"
    )
    assert backend_backed_client.seal_calls[0] == bytes(shard.shard_b), (
        "seal must be called with the plaintext shard_b"
    )


@pytest.mark.asyncio
async def test_open_routes_through_ipc_when_constructed_with_client(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
    sample_split_result: Any,
) -> None:
    """``repo.retrieve`` (decrypt) MUST call ``ipc.open`` exactly once."""
    from tests.conftest import stored_shard_from_split

    repo = ShardRepository(tmp_db_path, backend_backed_client)
    await repo.initialize()
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("alias-open", shard)

    backend_backed_client.open_calls.clear()  # ignore any open from initialize/store
    result = await repo.retrieve("alias-open")

    assert result is not None
    assert result.shard_b == shard.shard_b
    assert len(backend_backed_client.open_calls) == 1, (
        f"expected exactly 1 open call, got {len(backend_backed_client.open_calls)}"
    )


# ---------------------------------------------------------------------------
# decrypt_shard becomes async
# ---------------------------------------------------------------------------


def test_decrypt_shard_is_async() -> None:
    """``ShardRepository.decrypt_shard`` MUST be a coroutine function.

    A3b 2/3 cascades async up so callers (lock.py:262, unlock.py:179)
    can await the IPC roundtrip. This is the contract pin — the actual
    cascade changes live in those caller files.
    """
    assert asyncio.iscoroutinefunction(ShardRepository.decrypt_shard), (
        "decrypt_shard must be `async def` after WOR-465 A3b 2/3"
    )


# ---------------------------------------------------------------------------
# LOAD-BEARING: decoy_hash byte-identity across the flag flip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_decoy_hash_byte_identical_across_flag_flip(
    tmp_db_path: str,
    fernet_key_44b: bytes,
) -> None:
    """``_compute_decoy_hash`` MUST produce byte-identical hex strings
    whether the repo holds the raw key or routes through ``ipc.mac``.

    This is the single most important test for the WOR-465 A3b flag
    flip. If the bytes change, every customer's stored decoy_hash row
    invalidates at the moment they enable the flag, silently breaking
    every decoy match in their enrollment table.

    Method: compute decoy_hash for the same value via two paths:

    1. Today's path — raw key in ShardRepository, in-process
       ``hmac.new(fernet_key, value, sha256).hexdigest()``.
    2. New path — IPCClient backed by FernetBackend(shares) where the
       shares XOR to the same fernet_key. The sidecar's ``mac`` verb
       returns 32 raw bytes; the repo MUST hex-encode them.

    Both paths MUST yield the same hex string.
    """
    # Today's path
    repo_raw = ShardRepository(tmp_db_path, fernet_key_44b)
    expected_hex = await repo_raw._compute_decoy_hash("sk-secret-decoy-value")

    # New path
    shares = _shares_for(fernet_key_44b)
    backend = FernetBackend(shares=shares)
    ipc = _BackendBackedIPCClient(backend)
    repo_ipc = ShardRepository(tmp_db_path, ipc)
    actual_hex = await repo_ipc._compute_decoy_hash("sk-secret-decoy-value")

    assert actual_hex == expected_hex, (
        "decoy_hash bytes MUST be byte-identical across the IPC flag flip "
        f"— legacy={expected_hex!r}, ipc={actual_hex!r}. Mismatching here "
        "means every stored decoy_hash row will silently invalidate when "
        "WORTHLESS_FERNET_IPC_ONLY=1 is enabled."
    )

    # Cross-check: the expected hex matches the textbook HMAC-SHA256
    # so a future refactor of the legacy path can't drift either.
    textbook = hmac.new(fernet_key_44b, b"sk-secret-decoy-value", sha256).hexdigest()
    assert expected_hex == textbook, (
        "legacy _compute_decoy_hash must equal "
        "hmac.new(fernet_key, value.encode(), sha256).hexdigest() — "
        "if this drifts, the byte-identity guarantee is broken on the "
        "legacy side, not the IPC side."
    )


def test_compute_decoy_hash_is_async() -> None:
    """``_compute_decoy_hash`` MUST become a coroutine function.

    Cascade: ``set_decoy_hash`` / ``is_known_decoy`` already async
    and now ``await`` it. Pins the contract.
    """
    assert asyncio.iscoroutinefunction(ShardRepository._compute_decoy_hash), (
        "_compute_decoy_hash must be `async def` after WOR-465 A3b 2/3"
    )


# ---------------------------------------------------------------------------
# close() is a no-op when constructed with an IPCClient (no key bytes to zero)
# ---------------------------------------------------------------------------


def test_close_is_noop_under_ipc_path(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
) -> None:
    """``repo.close()`` MUST NOT raise when no raw key is held.

    The legacy path zeroes the bytearray and nulls the Fernet handle.
    The IPC path holds neither — close should silently succeed so
    existing ``try/finally: repo.close()`` patterns at call sites
    keep working.
    """
    repo = ShardRepository(tmp_db_path, backend_backed_client)
    repo.close()  # must not raise
    repo.close()  # idempotent


# ---------------------------------------------------------------------------
# Adversarial: constructor type validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [None, 42, 3.14, [1, 2, 3], {"k": "v"}, object()])
def test_constructor_rejects_None_and_other_garbage(tmp_db_path: str, bad: Any) -> None:
    """``None`` / ints / floats / lists / dicts / arbitrary objects
    MUST raise TypeError.

    Defends against a caller passing whatever sloppy thing they have
    rather than a key or an IPCClient. The duck-typed IPCClient check
    (``hasattr seal/open/mac``) MUST NOT accidentally match on common
    junk types.
    """
    with pytest.raises(TypeError):
        ShardRepository(tmp_db_path, bad)


# ---------------------------------------------------------------------------
# Adversarial: empty-bytes mac value
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_decoy_hash_empty_string_via_ipc(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
) -> None:
    """``_compute_decoy_hash("")`` MUST return a valid 64-char hex string.

    ``hmac.new(key, b"", sha256).digest()`` is well-defined; the IPC
    path must produce byte-identical output. Edge case for empty-string
    decoy values that could plausibly show up in malformed enrollments.
    """
    repo = ShardRepository(tmp_db_path, backend_backed_client)
    result = await repo._compute_decoy_hash("")

    assert isinstance(result, str)
    assert len(result) == 64, f"hex of HMAC-SHA256 must be 64 chars, got {len(result)}"
    # Recompute via the underlying backend; bytes must match.
    expected = (await backend_backed_client.mac(b"")).hex()
    assert result == expected


# ---------------------------------------------------------------------------
# Concurrency: serialized round-trips through one IPC client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_decoy_hash_through_one_ipc_client_is_consistent(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
) -> None:
    """N concurrent ``_compute_decoy_hash`` calls on one repo MUST each
    return the correct hex for their input — no cross-talk, no torn reads.

    The real ``IPCClient`` serializes IO through an ``asyncio.Lock``;
    the test fixture mirrors the async surface. This test pins that
    ``await asyncio.gather(*[_compute_decoy_hash(v_i) ...])`` returns
    results in stable per-input correspondence rather than racing
    request/response pairs.
    """
    repo = ShardRepository(tmp_db_path, backend_backed_client)
    inputs = [f"value-{i}-{secrets.token_hex(4)}" for i in range(16)]

    results = await asyncio.gather(*(repo._compute_decoy_hash(v) for v in inputs))

    # Each result must equal a fresh single-shot computation for the
    # corresponding input — proves no cross-talk.
    for v, observed in zip(inputs, results, strict=True):
        expected = await repo._compute_decoy_hash(v)
        assert observed == expected, (
            f"concurrency cross-talk: input {v!r} expected {expected!r} got {observed!r}"
        )


# ---------------------------------------------------------------------------
# Chaos: sidecar dies mid-decrypt — error propagates cleanly
# ---------------------------------------------------------------------------


class _DyingIPCClient:
    """Drop-in IPC client whose ``open`` raises after the first call.

    Simulates a sidecar that disconnects between request and reply.
    """

    def __init__(self, exc_factory) -> None:
        self._exc_factory = exc_factory
        self.open_calls = 0

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        return b"fake-ciphertext"

    async def open(
        self, ciphertext: bytes, context: bytes | None = None, key_id: bytes | None = None
    ) -> bytes:
        self.open_calls += 1
        raise self._exc_factory()

    async def mac(self, value: bytes) -> bytes:
        return b"\x00" * 32

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        # Future-proof: if ShardRepository ever probes ``attest`` at
        # construction time, this no-op keeps the fixture compatible.
        return b"\x00" * 32


@pytest.mark.asyncio
async def test_decrypt_shard_propagates_ipc_error_when_sidecar_dies(
    tmp_db_path: str,
) -> None:
    """``decrypt_shard`` MUST propagate ``IPCError`` (or subclass) when
    the sidecar fails mid-op — NEVER fall back to in-process decryption.

    Falling back would defeat the WOR-465 invariant. The exception type
    must survive the ShardRepository wrapper so the caller can map it
    to HTTP 503 / WRTLS-114.
    """
    from worthless.ipc.client import IPCProtocolError
    from worthless.storage.models import EncryptedShard

    client = _DyingIPCClient(lambda: IPCProtocolError("sidecar gone"))
    repo = ShardRepository(tmp_db_path, client)

    fake_enc = EncryptedShard(
        shard_b_enc=b"opaque-ciphertext-bytes",
        commitment=b"\x00" * 32,
        nonce=b"\x00" * 12,
        provider="openai",
        prefix=None,
        charset=None,
        base_url=None,
    )

    with pytest.raises(IPCProtocolError):
        await repo.decrypt_shard(fake_enc)


# ---------------------------------------------------------------------------
# Chaos: close() while an op is mid-flight on the same repo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_while_decoy_hash_in_flight_does_not_corrupt(
    tmp_db_path: str,
    backend_backed_client: _BackendBackedIPCClient,
) -> None:
    """Calling ``repo.close()`` while a ``_compute_decoy_hash`` is awaiting
    the IPC roundtrip MUST NOT corrupt the in-flight call.

    Under IPC mode, ``close()`` is a no-op (no key bytes to zero) so the
    in-flight HMAC MUST complete and return the correct value. Under
    legacy mode, close() nulls the Fernet handle but a check-then-use
    race could surface a confusing error — we pin the cleaner IPC-mode
    contract here.
    """
    repo = ShardRepository(tmp_db_path, backend_backed_client)

    async def _slow_path() -> str:
        # Tiny sleep so close() lands while we are mid-roundtrip.
        await asyncio.sleep(0)
        return await repo._compute_decoy_hash("racing-decoy")

    async def _closer() -> None:
        await asyncio.sleep(0)
        repo.close()

    hash_result, _ = await asyncio.gather(_slow_path(), _closer())
    expected = (await backend_backed_client.mac(b"racing-decoy")).hex()
    assert hash_result == expected, (
        "close() racing with in-flight _compute_decoy_hash must not corrupt "
        "the result on the IPC path"
    )


class TestCloseClearsIPC:
    """ShardRepository.close() must drop its IPCClient reference so the
    object cannot accidentally be reused after teardown and so the GC can
    reclaim the client immediately."""

    def test_close_clears_ipc(
        self,
        tmp_db_path: str,
        backend_backed_client: _BackendBackedIPCClient,
    ) -> None:
        """After close(), self._ipc must be None even if the repo was
        constructed with an IPCClient."""
        repo = ShardRepository(tmp_db_path, backend_backed_client)
        assert repo._ipc is not None, "precondition: IPCClient mode active"
        repo.close()
        assert repo._ipc is None

    def test_close_is_idempotent(
        self,
        tmp_db_path: str,
        backend_backed_client: _BackendBackedIPCClient,
    ) -> None:
        """close() called twice must not raise — the cleanup is best-effort
        and must tolerate already-closed state."""
        repo = ShardRepository(tmp_db_path, backend_backed_client)
        repo.close()
        repo.close()
        assert repo._ipc is None


class TestCloseAdversarial:
    """Use-after-close and concurrent-close probes. ShardRepository.close()
    is part of SR-02 (key zeroing) and is called from teardown paths in
    error_boundary. The contract: methods called after close() must fail
    cleanly (not segfault, not silently succeed against zeroed state), and
    concurrent close() calls from teardown races must not crash."""

    @pytest.mark.asyncio
    async def test_method_call_after_close_fails_cleanly_in_ipc_mode(
        self,
        tmp_db_path: str,
        backend_backed_client: _BackendBackedIPCClient,
    ) -> None:
        """After close() in IPC mode, self._ipc is None. A subsequent
        decrypt/seal call must raise a Python exception (not segfault,
        not return stale data). The exact exception type isn't pinned —
        the contract is "fails fast and observably." """
        repo = ShardRepository(tmp_db_path, backend_backed_client)
        await repo.initialize()
        repo.close()

        with pytest.raises(Exception):
            await repo._seal(b"plaintext-after-close")

    def test_concurrent_close_from_two_threads_does_not_raise(
        self,
        tmp_db_path: str,
        backend_backed_client: _BackendBackedIPCClient,
    ) -> None:
        """close() called from two threads simultaneously must not
        double-free, double-zero, or raise. This mirrors a teardown race
        where error_boundary and a finally-block both reach close()."""
        import threading

        repo = ShardRepository(tmp_db_path, backend_backed_client)
        errors: list[BaseException] = []

        def _close() -> None:
            try:
                repo.close()
            except BaseException as exc:  # noqa: BLE001 — capture for assertion
                errors.append(exc)

        t1 = threading.Thread(target=_close)
        t2 = threading.Thread(target=_close)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
        assert not t1.is_alive() and not t2.is_alive(), "close() deadlocked"
        assert errors == [], f"concurrent close raised: {errors}"
        assert repo._ipc is None

    @pytest.mark.asyncio
    async def test_method_call_after_close_fails_cleanly_in_fernet_mode(
        self,
        tmp_db_path: str,
        fernet_key_44b: bytes,
    ) -> None:
        """The IPC-mode after-close test exercises self._ipc=None; this is
        the legacy Fernet-mode counterpart. After close(), self._fernet is
        None and self._fernet_key_bytes is zeroed — a subsequent seal/open
        must fail observably, not silently encrypt against zeroed key
        bytes (which would produce a recoverable-looking ciphertext that
        nothing else in the system can decrypt)."""
        repo = ShardRepository(tmp_db_path, fernet_key_44b)
        await repo.initialize()
        repo.close()

        with pytest.raises(Exception):
            await repo._seal(b"plaintext-after-close")

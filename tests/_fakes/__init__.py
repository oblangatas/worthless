"""Test doubles for WOR-309 proxy/sidecar test surface.

The fakes here mirror the public surface of production classes so tests
can inject them as ``app.state.ipc_supervisor`` (or wherever the seam is)
without spinning up a real subprocess sidecar.

Constraints:
* Honour SR-01 — return :class:`bytearray` for plaintext (never bytes).
* Match :class:`worthless.proxy.ipc_supervisor.IPCSupervisor` public surface
  exactly so production code can't tell the difference at runtime.
"""

from __future__ import annotations

from typing import Any

from cryptography.fernet import Fernet


WOR309_SUBPROCESS_FOLLOWUP = (
    "WOR-309 follow-up: spawning a real proxy/daemon subprocess now "
    "requires a real sidecar at WORTHLESS_SIDECAR_SOCKET. Re-enable once "
    "the harness can launch a sidecar fixture and inject the socket path "
    "into the spawned process's environment."
)


def pin_shard_b(app: Any, alias: str, shard_b: bytes | bytearray) -> None:
    """Pin a per-alias plaintext into the autouse FakeIPCSupervisor.

    The autouse fixture pre-attaches a FakeIPCSupervisor to ``app.state``
    so ``ipc.open(key_id=alias)`` resolves without a real sidecar. Tests
    that store a shard via the storage repo must mirror its bytes here so
    the proxy's reconstruction yields the real shard-B (otherwise the
    fake returns its default plaintext and the proxy 401s).

    Safe no-op when the supervisor is the real production class.
    """
    fake = getattr(app.state, "ipc_supervisor", None)
    if fake is not None and hasattr(fake, "set_plaintext"):
        fake.set_plaintext(alias, bytes(shard_b))


def bind_real_fernet(app: Any, fernet_key: bytes | bytearray) -> None:
    """Bind the autouse FakeIPCSupervisor's ``open()`` to a real Fernet decrypt.

    The autouse fixture pre-attaches a :class:`FakeIPCSupervisor` to
    ``app.state.ipc_supervisor`` whose default ``open()`` returns
    :data:`DEFAULT_FAKE_PLAINTEXT` for any ``key_id``. Tests whose
    repo seals real shard-B ciphertext via legacy in-process Fernet
    need the IPC supervisor's ``open()`` to return the real plaintext
    so XOR(shard-A, shard-B) reconstructs the original key and the
    commitment check passes.

    This helper rebinds ``open()`` to a closure that decrypts whatever
    ciphertext shows up using the test's Fernet key. Crypto result is
    byte-identical to the production sidecar roundtrip; the test process
    already held the Fernet key via :class:`ShardRepository(fernet_key=...)`,
    so this widens nothing.

    Use this when the test stores shards via the legacy-mode repo and
    needs the proxy auth path to reconstruct them through IPC. Prefer
    :func:`pin_shard_b` when the test knows the alias → plaintext map
    up front and only needs one or two aliases pinned.

    Safe no-op when the supervisor is the real production class.
    """
    fake = getattr(app.state, "ipc_supervisor", None)
    if fake is None or not hasattr(fake, "set_plaintext"):
        return
    fernet = Fernet(bytes(fernet_key))

    async def _real_open(ciphertext: bytes, *, key_id: str) -> bytearray:
        return bytearray(fernet.decrypt(ciphertext))

    fake.open = _real_open  # type: ignore[method-assign]

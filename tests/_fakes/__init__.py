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

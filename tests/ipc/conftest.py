"""Shared IPC test fixtures (sockets, shares, running sidecar, client).

Extracted from ``test_roundtrip.py`` so failure-matrix and future IPC
tests can reuse them without duplication. Pytest autodiscovers every
fixture in this file for any test in ``tests/ipc/``.

See ``engineering/ipc-contract.md`` for the surfaces these fixtures exercise.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Generator
from pathlib import Path
from typing import Any

import msgpack
import pytest
import pytest_asyncio

from worthless.ipc.client import IPCClient, IPCProtocolError
from worthless.ipc.framing import encode_frame, read_frame
from worthless.sidecar.backends.base import Backend
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

# AF_UNIX sun_path is 104 bytes on macOS (108 on Linux). Use the tighter
# limit with a byte of headroom for the terminating NUL.
_SUN_PATH_MAX = 104


@pytest.fixture
def sidecar_socket_path() -> Generator[Path, None, None]:
    """Return a short, xdist-safe AF_UNIX socket path.

    Uses ``tempfile.mkdtemp`` directly under ``/tmp`` (not pytest's
    ``tmp_path_factory``) so we stay under macOS's 104-byte ``sun_path``
    limit even under xdist. Pytest's tmp dir on macOS resolves to a
    ~90-char prefix under ``/private/var/folders/...`` — add any worker
    suffix + ``s.sock`` basename and we blow the limit.

    ``mkdtemp`` is atomic per-worker so there is no race to guard.
    """
    base = Path(tempfile.mkdtemp(prefix="w-", dir="/tmp"))
    sock_path = base / "s.sock"
    if len(str(sock_path)) >= _SUN_PATH_MAX:
        pytest.skip(
            f"tmp path too long for AF_UNIX (len={len(str(sock_path))} >= {_SUN_PATH_MAX}): "
            f"{sock_path}"
        )
    try:
        yield sock_path
    finally:
        # Server unlinks the socket on close; remove the parent dir too.
        try:
            if sock_path.exists():
                sock_path.unlink()
            base.rmdir()
        except OSError:
            pass


@pytest.fixture
def fernet_shares() -> tuple[bytes, bytes]:
    """Two 44-byte shares whose XOR yields a valid urlsafe-b64 Fernet key."""
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))  # 44 bytes
    share_a = secrets.token_bytes(len(key))
    share_b = bytes(a ^ k for a, k in zip(share_a, key, strict=True))
    return share_a, share_b


@pytest.fixture
def fernet_backend(fernet_shares: tuple[bytes, bytes]) -> FernetBackend:
    """Instantiated FernetBackend ready for sealing/opening."""
    return FernetBackend(shares=fernet_shares)


@pytest_asyncio.fixture
async def running_sidecar(sidecar_socket_path: Path, fernet_backend: FernetBackend):
    """Start a sidecar bound to ``sidecar_socket_path``; tear down cleanly."""
    server = await start_sidecar(
        socket_path=sidecar_socket_path,
        backend=fernet_backend,
        allowed_uids=[os.getuid()],
    )
    try:
        yield server
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass


@pytest_asyncio.fixture
async def ipc_client(running_sidecar, sidecar_socket_path: Path) -> AsyncIterator[IPCClient]:
    """Yield a connected IPCClient against the running sidecar."""
    async with IPCClient(sidecar_socket_path) as client:
        yield client


class StallingBackend(Backend):
    """Backend that blocks forever on ``seal`` so client timeouts trip.

    ``open`` and ``attest`` delegate to a real Fernet so the handshake and
    any non-seal paths still work — only the operation under test stalls.
    """

    # Match the surface tests assert against. ``mac`` is omitted: stalling
    # tests only exercise seal/open/attest, and per the WOR-465 A3a
    # caps-driven dispatch the server simply won't route ``mac`` here.
    caps = ("seal", "open", "attest")

    def __init__(self, inner: FernetBackend) -> None:
        self._inner = inner

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        await asyncio.sleep(60)
        return b""  # unreachable

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        return await self._inner.open(ciphertext, context, key_id)

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        return await self._inner.attest(nonce, purpose)


# ---------------------------------------------------------------------------
# WOR-309 Phase 0 fixtures: broken_ipc_client, fake_sidecar, subprocess_sidecar
# ---------------------------------------------------------------------------


class _BrokenIPCClient:
    """Stand-in for IPCClient where every public op raises IPCProtocolError.

    Used to prove the proxy returns 503 with no plaintext leak when the
    sidecar is unreachable. ``IPCProtocolError`` is the no-fallback signal
    the proxy maps to HTTP 503 (see ``IPCClient`` docstring §invariants).
    A future ``IPCUnavailable`` alias may be added; until then the protocol
    error class is the canonical "transport down" exception.
    """

    backend_caps: tuple[str, ...] = ()

    async def __aenter__(self) -> _BrokenIPCClient:
        raise IPCProtocolError("sidecar unavailable: connect refused")

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes:
        raise IPCProtocolError("sidecar unavailable: seal denied")

    async def open(
        self,
        ciphertext: bytes,
        context: bytes | None = None,
        key_id: bytes | None = None,
    ) -> bytes:
        raise IPCProtocolError("sidecar unavailable: open denied")

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        raise IPCProtocolError("sidecar unavailable: attest denied")


@pytest.fixture
def broken_ipc_client() -> _BrokenIPCClient:
    """A drop-in IPC client double whose every call raises IPCProtocolError."""
    return _BrokenIPCClient()


@dataclasses.dataclass
class FakeSidecarHandle:
    """Control surface for the in-process fake sidecar.

    Tests mutate these knobs to drive specific protocol scenarios:

    * ``protocol_version`` — version returned in the HELLO reply (drives
      version-mismatch tests). Defaults to the client's ``_PROTOCOL_VERSION``
      (=1) so happy-path tests work without configuration.
    * ``sleep_before_response`` — seconds the fake stalls before replying
      to any non-HELLO op (drives the 2 s timeout test).
    * ``caps`` — backend caps tuple advertised in HELLO (drives caps
      re-check on reconnect, security restoration C3).
    * ``drop_after_n_requests`` — close the connection (force EOF) after
      N successful round-trips (drives reconnect tests). ``None`` = never.

    Tests acquire it from the ``fake_sidecar`` fixture as
    ``(socket_path, handle) = fake_sidecar``.
    """

    protocol_version: int = 1
    sleep_before_response: float = 0.0
    caps: tuple[str, ...] = ("seal", "open", "attest")
    drop_after_n_requests: int | None = None
    echo_ciphertext: bool = False
    requests_seen: int = 0
    server: asyncio.base_events.Server | None = None


async def _fake_sidecar_handler(
    handle: FakeSidecarHandle,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Speak the wire protocol per src/worthless/ipc/client.py:197-236.

    Performs one HELLO handshake (configurable version + caps) and then
    echoes simple ``op``-shaped responses. Phase 0: skeleton only — Phase 1
    test bodies will assert against this loop's behaviour.
    """
    try:
        envelope = await read_frame(reader)
        # HELLO reply with configurable version/caps.
        reply = {
            "v": handle.protocol_version,
            "id": envelope.get("id"),
            "kind": "resp",
            "op": "hello",
            "body": {
                "version": handle.protocol_version,
                "backend_caps": list(handle.caps),
            },
        }
        writer.write(encode_frame(reply))
        await writer.drain()

        while True:
            envelope = await read_frame(reader)
            if handle.sleep_before_response > 0:
                await asyncio.sleep(handle.sleep_before_response)
            handle.requests_seen += 1
            op = envelope.get("op", "")
            body: dict[str, Any] = {}
            req_body = envelope.get("body") or {}
            if op == "seal":
                if handle.echo_ciphertext:
                    pt = req_body.get("plaintext", b"")
                    body = {"ciphertext": bytes(pt) if isinstance(pt, bytes | bytearray) else b""}
                else:
                    body = {"ciphertext": b"FAKE-CT"}
            elif op == "open":
                if handle.echo_ciphertext:
                    ct = req_body.get("ciphertext", b"")
                    body = {"plaintext": bytes(ct) if isinstance(ct, bytes | bytearray) else b""}
                else:
                    body = {"plaintext": b"FAKE-PT"}
            elif op == "attest":
                body = {"evidence": b"FAKE-EV"}
            reply = {
                "v": 1,
                "id": envelope.get("id"),
                "kind": "resp",
                "op": op,
                "body": body,
            }
            writer.write(encode_frame(reply))
            await writer.drain()
            if (
                handle.drop_after_n_requests is not None
                and handle.requests_seen >= handle.drop_after_n_requests
            ):
                writer.close()
                return
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
        return
    finally:
        try:
            writer.close()
        except Exception:
            pass


@pytest_asyncio.fixture
async def fake_sidecar(
    sidecar_socket_path: Path,
) -> AsyncIterator[tuple[Path, FakeSidecarHandle]]:
    """In-process fake sidecar that speaks the framed-msgpack protocol.

    Yields ``(socket_path, handle)``. Tests configure ``handle.*`` BEFORE
    making any IPC call. The fake uses the real ``encode_frame`` / ``read_frame``
    so framing bugs surface as integration failures, not mock leaks.

    Real ``asyncio.start_unix_server`` is used per the task constraint —
    we do NOT mock ``asyncio.open_unix_connection``.
    """
    handle = FakeSidecarHandle()

    async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _fake_sidecar_handler(handle, reader, writer)

    server = await asyncio.start_unix_server(_on_connect, path=str(sidecar_socket_path))
    handle.server = server
    try:
        yield sidecar_socket_path, handle
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass


@pytest.fixture
def subprocess_sidecar(
    sidecar_socket_path: Path,
    fernet_shares: tuple[bytes, bytes],
    tmp_path: Path,
) -> Generator[tuple[Path, int], None, None]:
    """Spawn a real ``python -m worthless.sidecar`` over a tmp UDS.

    Yields ``(socket_path, pid)``. Marked ``integration`` — slow, opens a
    real subprocess. Tests using this fixture must declare
    ``@pytest.mark.integration``.

    Teardown SIGKILLs the child and removes the socket. Required env per
    ``src/worthless/sidecar/__main__.py`` §Environment.
    """
    share_a_path = tmp_path / "share_a.bin"
    share_b_path = tmp_path / "share_b.bin"
    share_a_path.write_bytes(fernet_shares[0])
    share_b_path.write_bytes(fernet_shares[1])

    env = {
        **os.environ,
        "WORTHLESS_SIDECAR_SOCKET": str(sidecar_socket_path),
        "WORTHLESS_SIDECAR_SHARE_A": str(share_a_path),
        "WORTHLESS_SIDECAR_SHARE_B": str(share_b_path),
        "WORTHLESS_SIDECAR_ALLOWED_UID": str(os.getuid()),
        "WORTHLESS_LOG_LEVEL": "WARNING",
    }
    proc = subprocess.Popen(  # noqa: S603 — args are static, no shell
        [sys.executable, "-m", "worthless.sidecar"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for the sidecar to print its ready line OR the socket to appear.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if sidecar_socket_path.exists():
            break
        if proc.poll() is not None:
            proc.wait(timeout=2)
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            pytest.fail(f"sidecar exited rc={proc.returncode}: {stderr}")
        time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail(f"sidecar did not bind {sidecar_socket_path} within 5s")

    try:
        yield sidecar_socket_path, proc.pid
    finally:
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
        if sidecar_socket_path.exists():
            try:
                sidecar_socket_path.unlink()
            except OSError:
                pass


# Re-export msgpack so test files that need to construct adversarial frames
# don't have to repeat the import. Kept here to honour the "no mid-file
# imports" project rule — tests do ``from tests.ipc.conftest import msgpack``
# (or just rely on the fake_sidecar fixture and never construct frames).
__all__ = [
    "FakeSidecarHandle",
    "broken_ipc_client",
    "fake_sidecar",
    "msgpack",
    "subprocess_sidecar",
]

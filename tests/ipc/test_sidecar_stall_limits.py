"""An allowed peer can't pin sidecar memory by stalling half-sent frames (WOR-1076).

Before this fix the sidecar waited forever for a frame's body and held any
number of connections. A peer that passed the peer-uid check could open N
connections, declare a 1 MiB frame on each, send all but one byte, and pin
about N MiB until the sidecar ran out of fds or was OOM-killed.

Every test here drives a real sidecar over a real AF_UNIX socket:

* a peer that stalls mid-frame, before or after the hello, is closed once
  the frame deadline passes;
* a connection that sits idle between requests is NOT closed: the proxy
  keeps one connection open for its whole life;
* connections beyond the cap are refused before the sidecar reads a byte
  from them, so they add no memory, and a closed connection frees its slot.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
import tracemalloc
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from worthless.ipc.client import IPCClient, IPCProtocolError
from worthless.ipc.framing import MAX_FRAME_SIZE, FrameTimeoutError, encode_frame, read_frame
from tests.ipc.conftest import StallingBackend
from worthless.sidecar.backends.base import Backend
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

# WOR-582: every test here spawns a real sidecar; running them in the
# parallel xdist pass crashes a worker on py3.13 (asyncio server + forked
# worker). Route the whole module to the serial real_ipc pass.
pytestmark = pytest.mark.real_ipc

_FRAME_TIMEOUT_S = 0.5

# The deadline plus slack for a loaded CI host. Before the fix the sidecar
# never closes these connections, so any finite wait fails it.
_CLOSE_WITHIN_S = _FRAME_TIMEOUT_S + 3.0

_HELLO = encode_frame(
    {"v": 1, "id": 1, "kind": "req", "op": "hello", "body": {"client_versions": [1]}}
)

# A header declaring the largest frame the contract allows, then every body
# byte but the last: the most memory one stalled frame can pin.
_STALLED_FRAME = MAX_FRAME_SIZE.to_bytes(4, "big") + b"\xa5" * (MAX_FRAME_SIZE - 1)


StartSidecar = Callable[..., Awaitable[asyncio.AbstractServer]]


@pytest_asyncio.fixture
async def start(
    sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> AsyncIterator[StartSidecar]:
    """Start a sidecar with the given limits; stop it, stalled handlers included, at teardown."""
    servers: list[asyncio.AbstractServer] = []

    async def _start(backend: Backend | None = None, **limits: Any) -> asyncio.AbstractServer:
        server = await start_sidecar(
            sidecar_socket_path, backend or fernet_backend, [os.getuid()], **limits
        )
        servers.append(server)
        return server

    yield _start
    for server in servers:
        server.close()
        # Before the fix stalled handlers never end; cancel them so teardown can't hang.
        tasks = _handlers(server)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def _handlers(server: asyncio.AbstractServer) -> set[asyncio.Task[None]]:
    return set(server._worthless_handler_tasks)  # type: ignore[attr-defined]


async def _closed_by_sidecar(reader: asyncio.StreamReader) -> bool:
    """True if the sidecar closes the connection within the deadline plus slack."""
    try:
        data = await asyncio.wait_for(reader.read(1), timeout=_CLOSE_WITHIN_S)
    except ConnectionResetError:
        return True
    except asyncio.TimeoutError:
        return False
    return data == b""


async def _shake_hands(sock: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_unix_connection(str(sock), limit=MAX_FRAME_SIZE)
    writer.write(_HELLO)
    await writer.drain()
    reply = await asyncio.wait_for(read_frame(reader), timeout=5.0)
    assert reply.get("kind") == "resp", f"handshake failed: {reply!r}"
    return reader, writer


# ---------------------------------------------------------------------------
# Frame deadline
# ---------------------------------------------------------------------------


async def test_stalled_half_frame_after_hello_is_closed_within_deadline(
    start: StartSidecar, sidecar_socket_path: Path
) -> None:
    """The attack in WOR-1076: hello, then a 1 MiB frame short one byte, then silence."""
    server = await start(frame_timeout_s=_FRAME_TIMEOUT_S)
    reader, writer = await _shake_hands(sidecar_socket_path)
    stalled = _handlers(server)
    t0 = time.monotonic()
    writer.write(_STALLED_FRAME)
    await writer.drain()

    closed = await _closed_by_sidecar(reader)
    elapsed = time.monotonic() - t0

    assert closed, "sidecar kept a half-sent frame open past its deadline"
    # The deadline, not something else, closed it: the clock starts when
    # the header arrives, which is after t0.
    assert elapsed >= _FRAME_TIMEOUT_S * 0.9, f"closed after {elapsed:.3f}s, before the deadline"
    writer.close()
    # The handler is gone, so the partial frame's buffer is released.
    _, still_running = await asyncio.wait(stalled, timeout=2.0)
    assert not still_running, "stalled handler is still running"


@pytest.mark.parametrize(
    "sent",
    [
        pytest.param(b"", id="nothing"),
        pytest.param(_HELLO[:3], id="part-of-header"),
        pytest.param(_STALLED_FRAME, id="1MiB-hello-short-one-byte"),
    ],
)
async def test_stalled_hello_is_closed_within_deadline(
    start: StartSidecar, sidecar_socket_path: Path, sent: bytes
) -> None:
    """Every client sends its hello as soon as it connects, so the hello's clock starts then."""
    await start(frame_timeout_s=_FRAME_TIMEOUT_S)
    reader, writer = await asyncio.open_unix_connection(str(sidecar_socket_path))
    if sent:
        writer.write(sent)
        await writer.drain()

    assert await _closed_by_sidecar(reader), (
        "sidecar kept a connection that never finished its hello"
    )
    writer.close()


async def test_idle_connection_between_requests_stays_open(
    start: StartSidecar, sidecar_socket_path: Path
) -> None:
    """The proxy holds one connection for its whole life and may send nothing for hours.

    Only a frame that has started is on the clock. A connection idle for
    several deadlines must still serve its next request.
    """
    await start(frame_timeout_s=_FRAME_TIMEOUT_S)
    async with IPCClient(sidecar_socket_path) as client:
        await asyncio.sleep(_FRAME_TIMEOUT_S * 3)
        ciphertext = await client.seal(b"still here")
        assert await client.open(ciphertext) == b"still here"


# ---------------------------------------------------------------------------
# Connection cap
# ---------------------------------------------------------------------------


def _attack(sock: Path) -> tuple[socket.socket, bool]:
    """Connect, send a 1 MiB frame short one byte, and report whether the sidecar refused us.

    Blocking socket on a worker thread: ``sendall`` reads straight from the
    shared payload, so the attacker adds nothing to the Python heap that
    tracemalloc measures. The socket is returned open so whatever the
    sidecar buffered for it is still held when memory is read.
    """
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(2.0)
    conn.connect(str(sock))
    try:
        conn.sendall(_STALLED_FRAME)
        refused = conn.recv(1) == b""
    except (BrokenPipeError, ConnectionResetError):
        refused = True
    except TimeoutError:
        refused = False
    return conn, refused


async def test_connections_beyond_cap_are_refused_without_memory_growth(
    start: StartSidecar, sidecar_socket_path: Path
) -> None:
    cap = 4
    extra = 8
    await start(max_connections=cap, frame_timeout_s=30.0)
    attackers: list[socket.socket] = []
    async with AsyncExitStack() as stack:
        held = [await stack.enter_async_context(IPCClient(sidecar_socket_path)) for _ in range(cap)]
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            results = await asyncio.gather(
                *(asyncio.to_thread(_attack, sidecar_socket_path) for _ in range(extra))
            )
            grown = tracemalloc.get_traced_memory()[0] - baseline
            attackers = [conn for conn, _ in results]

            # Accepting them would buffer ~1 MiB each (~8 MiB here). Refused
            # before the first read, they buffer nothing.
            assert grown < MAX_FRAME_SIZE, (
                f"sidecar memory grew {grown} bytes for refused connections"
            )
            refused = sum(1 for _, was_refused in results if was_refused)
            assert refused == extra, (
                f"only {refused} of {extra} connections over the cap were refused"
            )
            # The connections under the cap still work.
            assert await held[0].open(await held[0].seal(b"ok")) == b"ok"
        finally:
            tracemalloc.stop()
            for conn in attackers:
                conn.close()


async def test_closed_connection_frees_its_slot(
    start: StartSidecar, sidecar_socket_path: Path
) -> None:
    server = await start(max_connections=2)
    async with IPCClient(sidecar_socket_path) as first, IPCClient(sidecar_socket_path):
        with pytest.raises(IPCProtocolError):
            async with IPCClient(sidecar_socket_path):
                pass
        await first.aclose()
        _, still_open = await asyncio.wait(
            _handlers(server), timeout=2.0, return_when=asyncio.FIRST_COMPLETED
        )
        assert len(still_open) == 1, "closed connection kept its slot"
        async with IPCClient(sidecar_socket_path) as late:
            assert await late.open(await late.seal(b"late")) == b"late"


async def test_start_sidecar_rejects_nonsense_limits(
    start: StartSidecar, sidecar_socket_path: Path
) -> None:
    with pytest.raises(ValueError, match="max_connections"):
        await start(max_connections=0)
    with pytest.raises(ValueError, match="frame_timeout_s"):
        await start(frame_timeout_s=0)
    assert not sidecar_socket_path.exists(), "a refused config must not leave a bound socket"


# ---------------------------------------------------------------------------
# read_frame(body_timeout=...) (unit)
# ---------------------------------------------------------------------------


async def test_read_frame_body_timeout_trips_on_a_stalled_body() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data((10).to_bytes(4, "big") + b"abc")
    with pytest.raises(FrameTimeoutError):
        await read_frame(reader, body_timeout=0.05)


async def test_read_frame_body_timeout_does_not_bound_the_wait_for_a_header() -> None:
    reader = asyncio.StreamReader()
    pending = asyncio.ensure_future(read_frame(reader, body_timeout=0.05))
    await asyncio.sleep(0.2)
    assert not pending.done(), "an idle stream between frames must not time out"
    reader.feed_data(encode_frame({"v": 1}))
    assert await asyncio.wait_for(pending, timeout=1.0) == {"v": 1}


async def test_client_reports_a_reset_connection_as_a_protocol_error(
    start: StartSidecar, sidecar_socket_path: Path, fernet_backend: FernetBackend
) -> None:
    """On Linux a peer the sidecar refuses or aborts reads a reset, not EOF.

    The client's contract is that a lost connection is an ``IPCProtocolError``,
    which the proxy turns into a 503 and the CLI into a clear error. The
    stalling backend never replies, so the reset lands while the client reads.
    """
    await start(backend=StallingBackend(fernet_backend))
    async with IPCClient(sidecar_socket_path) as client:
        sealing = asyncio.create_task(client.seal(b"x"))
        await asyncio.sleep(0.1)  # the request is written; the client is waiting to read
        client._reader.set_exception(ConnectionResetError(104, "Connection reset by peer"))  # type: ignore[union-attr]  # noqa: SLF001
        with pytest.raises(IPCProtocolError, match="connection lost"):
            await sealing

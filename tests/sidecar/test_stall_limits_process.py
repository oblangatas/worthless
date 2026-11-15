"""The real sidecar process enforces WOR-1076's limits at their documented values.

``tests/ipc/test_sidecar_stall_limits.py`` drives ``start_sidecar`` in-process
with a 0.5 s deadline and a small cap. These tests start ``python -m
worthless.sidecar`` the way ``worthless up`` and the Docker image do, with
nothing overridden, so they fail if the entrypoint stops applying the limits
or a default drifts from the 10 s and 32 connections the CHANGELOG promises.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Iterator
from contextlib import AsyncExitStack
from pathlib import Path

import psutil
import pytest

from tests.sidecar.test_shutdown import _spawn_sidecar, _terminate, _wait_for_ready
from worthless.ipc.client import IPCClient, IPCProtocolError
from worthless.ipc.framing import MAX_FRAME_SIZE, encode_frame, read_frame

# Serial real_ipc pass, with its 120 s budget: one test waits out the real deadline.
pytestmark = [pytest.mark.real_ipc, pytest.mark.xdist_group("real_sidecar")]

# The CHANGELOG's numbers, not the code's constants: changing those must fail here.
_DEADLINE_S = 10.0
_CAP = 32

_HELLO = encode_frame(
    {"v": 1, "id": 1, "kind": "req", "op": "hello", "body": {"client_versions": [1]}}
)
_STALLED_FRAME = MAX_FRAME_SIZE.to_bytes(4, "big") + b"\xa5" * (MAX_FRAME_SIZE - 1)


@pytest.fixture
def sidecar(sidecar_env: tuple[Path, dict[str, str]]) -> Iterator[tuple[Path, psutil.Process]]:
    """A real ``python -m worthless.sidecar`` with its production defaults."""
    sock, env = sidecar_env
    proc = _spawn_sidecar(env)
    try:
        _wait_for_ready(proc)
        yield sock, psutil.Process(proc.pid)
    finally:
        _terminate(proc)


async def test_stalled_frame_is_dropped_at_the_10s_deadline_and_its_memory_freed(
    sidecar: tuple[Path, psutil.Process],
) -> None:
    """The attack in WOR-1076 against the real process: hello, 1 MiB short one byte, silence."""
    sock, child = sidecar
    async with IPCClient(sock) as held:  # the proxy's long-lived connection
        reader, writer = await asyncio.open_unix_connection(str(sock))
        writer.write(_HELLO)
        await writer.drain()
        assert (await asyncio.wait_for(read_frame(reader), timeout=5.0))["kind"] == "resp"
        await asyncio.sleep(0.5)
        before = child.memory_info().rss

        t0 = time.monotonic()
        writer.write(_STALLED_FRAME)
        await writer.drain()
        await asyncio.sleep(1.0)
        pinned = child.memory_info().rss - before
        try:
            data: bytes | None = await asyncio.wait_for(reader.read(1), _DEADLINE_S + 5.0)
        except ConnectionResetError:
            data = b""
        except asyncio.TimeoutError:
            data = None
        elapsed = time.monotonic() - t0
        writer.close()
        await asyncio.sleep(1.0)
        kept = child.memory_info().rss - before

        assert await held.open(await held.seal(b"still served")) == b"still served"

    assert data == b"", f"sidecar kept a half-sent frame open for {elapsed:.1f}s"
    assert elapsed >= _DEADLINE_S * 0.95, f"closed after {elapsed:.2f}s, before the deadline"
    assert pinned >= MAX_FRAME_SIZE // 2, f"sidecar grew only {pinned} bytes for the stalled frame"
    # macOS's allocator keeps freed large blocks (a CHANGELOG limit); the Docker
    # image runs on Linux, where glibc hands the frame's buffer back.
    if sys.platform == "linux":
        assert kept < pinned // 2, f"sidecar still {kept} bytes larger after dropping the frame"


async def test_connection_over_32_is_refused_and_a_closed_one_frees_its_slot(
    sidecar: tuple[Path, psutil.Process],
) -> None:
    sock, _ = sidecar
    async with AsyncExitStack() as stack:
        held = [await stack.enter_async_context(IPCClient(sock)) for _ in range(_CAP)]
        with pytest.raises(IPCProtocolError):
            async with IPCClient(sock):
                pass

        await held[0].aclose()
        # The slot comes back once the sidecar's handler sees the close.
        for _ in range(20):
            try:
                async with IPCClient(sock) as late:
                    assert await late.open(await late.seal(b"late")) == b"late"
                break
            except IPCProtocolError:
                await asyncio.sleep(0.1)
        else:
            pytest.fail("a closed connection never gave its slot back")

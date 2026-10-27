"""WOR-1075: a frame can't run up the real sidecar's memory.

Each shape reaches ``read_frame`` right after the peer-uid check, before any
envelope validation:

* GHSA-j8c6-9vc5-hj6x: msgpack preallocates every array at the length its
  header declares, before reading a single item. 1023 nested headers that
  each declare 65535 items are 5 KB on the wire and peaked the sidecar at
  ~513 MiB on msgpack 1.2.2/1.2.3 (~80 MiB on 1.2.4). ``MAX_CONTAINER_LEN``
  bounds it on every msgpack version.
* CVE-2026-114613: a map with a non-string key leaked the whole frame on
  every rejection, ~1 MiB per connection on msgpack 1.2.2. Fixed in 1.2.3.
* A valid hello padded with ~1 MiB of empty lists: ~60 bytes of Python
  objects per byte on every msgpack version, kept for as long as the
  connection stays open. ``MAX_CONTAINERS`` bounds it.

The sidecar runs ``start_sidecar`` in a child process on a real AF_UNIX
socket, so its RSS is measured alone, not mixed with pytest's.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path

import msgpack
import pytest

from worthless.ipc.framing import (
    MAX_CONTAINER_LEN,
    MalformedFrameError,
    read_frame,
)

# Spawns a real sidecar process; serial lane (WOR-582).
pytestmark = [
    pytest.mark.real_ipc,
    pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX sidecar"),
]

_MiB = 1024 * 1024

# Prints "ready", then answers each line on stdin with "<rss> <peak rss>" in
# bytes. The backend is never reached: every frame here fails in read_frame.
_SIDECAR = """
import asyncio, os, resource, sys, threading, traceback
from pathlib import Path

import psutil

from worthless.sidecar.backends.base import Backend
from worthless.sidecar.server import start_sidecar


def peak_rss():
    if sys.platform == "darwin":
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # bytes, this process
    # Linux: VmHWM counts this process since exec. ru_maxrss there also
    # carries the parent's peak across vfork+exec, i.e. pytest's.
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("no VmHWM in /proc/self/status")


class Unreachable(Backend):
    caps = ("seal", "open", "attest")

    async def seal(self, plaintext, context=None):
        raise AssertionError("malformed frames never reach the backend")

    async def open(self, ciphertext, context=None, key_id=None):
        raise AssertionError("malformed frames never reach the backend")

    async def attest(self, nonce, purpose=None):
        raise AssertionError("malformed frames never reach the backend")


def report_memory():
    # Exits on stdin EOF or on any error, so the sidecar never outlives the test.
    try:
        me = psutil.Process()
        for _ in sys.stdin:
            print(me.memory_info().rss, peak_rss(), flush=True)
    except BaseException:
        traceback.print_exc()
    os._exit(0)


async def main():
    server = await start_sidecar(Path(sys.argv[1]), Unreachable(), [os.getuid()])
    print("ready", flush=True)
    threading.Thread(target=report_memory, daemon=True).start()
    async with server:
        await server.serve_forever()


asyncio.run(main())
"""


class _Sidecar:
    def __init__(self, child: subprocess.Popen[str], socket_path: Path) -> None:
        self._child = child
        self.socket_path = socket_path

    def memory(self) -> tuple[int, int]:
        """Return the sidecar's current and peak RSS in bytes."""
        assert self._child.stdin is not None
        assert self._child.stdout is not None
        self._child.stdin.write("\n")
        self._child.stdin.flush()
        line = self._child.stdout.readline()
        if not line:
            raise RuntimeError(f"sidecar stopped answering (exit {self._child.wait(timeout=10)})")
        rss, peak = line.split()
        return int(rss), int(peak)

    def open(self, body: bytes) -> tuple[socket.socket, dict[str, object]]:
        """Send one handshake frame on a new connection; return the still-open
        connection and the sidecar's reply."""
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(20)
            conn.connect(str(self.socket_path))
            conn.sendall(len(body).to_bytes(4, "big") + body)
            with conn.makefile("rb") as stream:
                reply = stream.read(int.from_bytes(stream.read(4), "big"))
        except BaseException:
            conn.close()
            raise
        return conn, msgpack.unpackb(reply, raw=False)

    def send(self, body: bytes) -> dict[str, object]:
        """Send one handshake frame on a fresh connection; return the reply."""
        conn, reply = self.open(body)
        conn.close()
        # PROTO: the frame got past peer-uid auth and was refused.
        assert reply["code"] == "PROTO", reply
        return reply


@pytest.fixture
def sidecar(sidecar_socket_path: Path) -> Generator[_Sidecar, None, None]:
    with subprocess.Popen(
        [sys.executable, "-c", _SIDECAR, str(sidecar_socket_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as child:
        try:
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "ready", (
                f"sidecar did not start (exit {child.poll()})"
            )
            yield _Sidecar(child, sidecar_socket_path)
        finally:
            child.kill()


def _assert_decoder_rejects(body: bytes) -> None:
    """The sidecar's PROTO reply could also come from handshake validation;
    this pins it to read_frame's decoder, the path being measured."""

    async def decode() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(len(body).to_bytes(4, "big") + body)
        reader.feed_eof()
        await read_frame(reader)

    with pytest.raises(MalformedFrameError, match="invalid msgpack payload"):
        asyncio.run(decode())


def _nested_array_headers(declared: int) -> bytes:
    # array32 headers, each declaring ``declared`` items and holding none.
    # 1023 is as deep as msgpack's C decoder nests.
    return (b"\xdd" + declared.to_bytes(4, "big")) * 1023


@pytest.mark.parametrize(
    "declared",
    [0xFFFF, MAX_CONTAINER_LEN],
    ids=["advisory-shape", "at-the-cap"],
)
def test_tiny_frame_of_nested_array_headers_cannot_balloon_sidecar_memory(
    sidecar: _Sidecar, declared: int
) -> None:
    body = _nested_array_headers(declared)
    sidecar.send(msgpack.packb([1]))  # warm the rejection path
    rss_before, _ = sidecar.memory()

    for _ in range(3):
        sidecar.send(body)

    _, peak_after = sidecar.memory()
    # Peak against the pre-attack RSS, not the earlier peak, so a startup
    # high-water mark can't hide the attack. Was ~513 MiB on msgpack 1.2.2.
    peak_growth = peak_after - rss_before
    assert peak_growth < 32 * _MiB, (
        f"a {len(body):,}-byte frame took sidecar RSS {peak_growth / _MiB:.1f} MiB above "
        f"its {rss_before / _MiB:.1f} MiB baseline (msgpack {msgpack.version})"
    )
    _assert_decoder_rejects(body)


def _hello_padded_with_empty_lists() -> bytes:
    # A valid hello with one unused key holding a tree of 31-entry lists
    # that ends in ~920k empty ones: just under MAX_FRAME_SIZE.
    def tree(depth: int) -> bytes:
        if depth == 0:
            return b"\x90"
        return b"\xdc" + (31).to_bytes(2, "big") + tree(depth - 1) * 31

    hello = msgpack.packb(
        {"v": 1, "id": 1, "kind": "req", "op": "hello", "body": {"client_versions": [1]}}
    )
    assert hello[0] == 0x85  # fixmap of 5; widen it to 6 for the "pad" key
    return b"\x86" + hello[1:] + msgpack.packb("pad") + tree(4)


def test_valid_hello_padded_with_empty_lists_cannot_hold_sidecar_memory(
    sidecar: _Sidecar,
) -> None:
    body = _hello_padded_with_empty_lists()
    sidecar.send(msgpack.packb([1]))  # warm the rejection path
    rss_before, _ = sidecar.memory()

    # Kept open: an accepted hello stays referenced for the connection's life.
    conns = [sidecar.open(body) for _ in range(4)]
    try:
        _, peak_after = sidecar.memory()
    finally:
        for conn, _ in conns:
            conn.close()

    # Was +57 MiB per open connection: the hello passed every check.
    peak_growth = peak_after - rss_before
    assert peak_growth < 32 * _MiB, (
        f"{len(conns)} connections each sending a {len(body):,}-byte hello took sidecar RSS "
        f"{peak_growth / _MiB:.1f} MiB above its {rss_before / _MiB:.1f} MiB baseline "
        f"(msgpack {msgpack.version})"
    )
    assert [reply["code"] for _, reply in conns] == ["PROTO"] * len(conns)
    _assert_decoder_rejects(body)


@pytest.mark.skipif(
    msgpack.version < (1, 2, 3),
    reason="CVE-2026-114613 leaks in msgpack < 1.2.3; PR #745 moves the lock and floor past it",
)
def test_non_string_map_keys_do_not_leak_sidecar_memory(sidecar: _Sidecar) -> None:
    # One int key (strict_map_key rejects it) holding ~900 KB.
    body = msgpack.packb({1: b"A" * 900_000}, use_bin_type=True)
    for _ in range(10):  # let allocator pools and stream buffers settle
        sidecar.send(body)
    rss_before, _ = sidecar.memory()

    connections = 200
    for _ in range(connections):
        sidecar.send(body)

    rss_after, _ = sidecar.memory()
    sent = connections * len(body)
    growth = rss_after - rss_before
    # A leak keeps every frame (~172 MiB here); a non-leaking decoder ~1 MiB.
    assert growth < sent // 4, (
        f"sidecar RSS grew {growth / _MiB:.1f} MiB after {connections} malformed "
        f"handshakes carrying {sent / _MiB:.1f} MiB (msgpack {msgpack.version})"
    )
    _assert_decoder_rejects(body)

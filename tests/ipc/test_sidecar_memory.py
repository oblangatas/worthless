"""WOR-1075: a frame can't run up the real sidecar's memory.

Each shape reaches ``read_frame`` right after the peer-uid check, before any
envelope validation:

* GHSA-j8c6-9vc5-hj6x: msgpack preallocates every array at the length its
  header declares, before reading a single item. 1023 nested headers that
  each declare 65535 items are 5 KB on the wire and peaked the sidecar at
  ~513 MiB on msgpack 1.2.2/1.2.3 (~80 MiB on 1.2.4). ``MAX_CONTAINER_LEN``
  bounds it on every msgpack version.
* CVE-2026-114613: a map with a non-string key leaked the whole frame on
  every rejection, ~1 MiB per connection on msgpack 1.2.2. Fixed in 1.2.3;
  Worthless requires 1.2.4.
* A valid hello padded with ~1 MiB of empty lists: ~60 bytes of Python
  objects per byte on every msgpack version, kept for as long as the
  connection stays open. ``MAX_CONTAINERS`` bounds it.
* A hello refused for a ~1 MiB string with one emoji in it: the reason the
  sidecar logged held its ``repr``, ~16 bytes per byte received, and on macOS
  that memory piled up across closed connections.
* A request that crashes the handler, such as a seal whose reply is over
  ``MAX_FRAME_SIZE``: the handler task kept the exception in a reference cycle,
  so every crashed connection's frame stayed alive until a GC pass.
* A peer that closes without reading the reply: asyncio keeps the write's
  BrokenPipeError on the StreamReader, and once the handler re-raised it, its
  traceback held the handler's frame, the frame received included. Another
  cycle only a GC pass freed.

The sidecar runs ``start_sidecar`` in a child process on a real AF_UNIX
socket, so its RSS is measured alone, not mixed with pytest's.
"""

from __future__ import annotations

import asyncio
import functools
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
from worthless.sidecar.server import _validate_handshake, _validate_request_envelope

# Spawns a real sidecar process; serial lane (WOR-582).
pytestmark = [
    pytest.mark.real_ipc,
    pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX sidecar"),
]

_MiB = 1024 * 1024
_LIMIT = 32 * _MiB  # what any one test's frames may add to the sidecar's RSS

_HELLO: dict[str, object] = {
    "v": 1,
    "id": 1,
    "kind": "req",
    "op": "hello",
    "body": {"client_versions": [1]},
}
# ~1 MiB of control characters plus one emoji: CPython stores it at 4 bytes a
# character, and repr() spells each control character as 4 of them.
_HUGE_STR = "\x00" * 1_000_000 + "\U0001f600"

# Prints "ready", then answers each line on stdin with "<rss> <peak rss>" in
# bytes. Only seal reaches the backend.
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


class Stub(Backend):
    caps = ("seal", "open", "attest")

    async def seal(self, plaintext, context=None):
        # Like Fernet's, the ciphertext is longer than the plaintext, so a
        # seal near MAX_FRAME_SIZE gets a reply too large to send.
        return plaintext * 2

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
    server = await start_sidecar(Path(sys.argv[1]), Stub(), [os.getuid()])
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

    def send_unread(self, body: bytes) -> None:
        """Send one frame on a fresh connection and close without reading the
        reply, so the sidecar's reply write fails."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(20)
            conn.connect(str(self.socket_path))
            conn.sendall(len(body).to_bytes(4, "big") + body)

    def request(self, body: bytes) -> dict[str, object]:
        """Shake hands, then send one request frame; return its reply."""
        conn, hello_reply = self.open(msgpack.packb(_HELLO))
        with conn, conn.makefile("rb") as stream:
            assert hello_reply["kind"] == "resp", hello_reply
            conn.sendall(len(body).to_bytes(4, "big") + body)
            reply = stream.read(int.from_bytes(stream.read(4), "big"))
        return msgpack.unpackb(reply, raw=False)


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
    assert peak_growth < _LIMIT, (
        f"a {len(body):,}-byte frame took sidecar RSS {peak_growth / _MiB:.1f} MiB above "
        f"its {rss_before / _MiB:.1f} MiB baseline (msgpack {msgpack.version})"
    )
    _assert_decoder_rejects(body)


def _hello_padded_with_empty_lists() -> bytes:
    # A valid hello with one unused key holding a tree of 31-entry lists
    # that ends in ~920k empty ones: just under MAX_FRAME_SIZE.
    pad: list[object] = []
    for _ in range(4):
        pad = [pad] * 31
    return msgpack.packb({**_HELLO, "pad": pad})


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

    # Was +67 MiB per open connection: the hello passed every check.
    peak_growth = peak_after - rss_before
    assert peak_growth < _LIMIT, (
        f"{len(conns)} connections each sending a {len(body):,}-byte hello took sidecar RSS "
        f"{peak_growth / _MiB:.1f} MiB above its {rss_before / _MiB:.1f} MiB baseline "
        f"(msgpack {msgpack.version})"
    )
    assert [reply["code"] for _, reply in conns] == ["PROTO"] * len(conns)
    _assert_decoder_rejects(body)


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


_VALIDATORS = {
    "hello": _validate_handshake,
    "req": functools.partial(_validate_request_envelope, valid_ops=frozenset({"seal"})),
}


@pytest.mark.parametrize(
    ("validator", "envelope"),
    [
        *(
            pytest.param(name, {**_HELLO, field: _HUGE_STR}, id=f"{name}-{field}")
            for name in _VALIDATORS
            for field in ("v", "kind", "op")
        ),
        pytest.param(
            "hello", {**_HELLO, "body": {"client_versions": [_HUGE_STR]}}, id="hello-versions"
        ),
        # Unhashable: used to raise TypeError into the handler's crash path.
        pytest.param("req", {**_HELLO, "op": [_HUGE_STR]}, id="req-op-list"),
    ],
)
def test_rejection_reasons_never_copy_peer_values(
    validator: str, envelope: dict[str, object]
) -> None:
    ok, reason = _VALIDATORS[validator](envelope)
    assert not ok
    assert len(reason) < 200, f"{len(reason):,}-char reason: {reason[:80]!r}..."


def test_refused_hellos_with_huge_strings_do_not_pile_up_in_sidecar_memory(
    sidecar: _Sidecar,
) -> None:
    hello = {**_HELLO, "body": {"client_versions": [_HUGE_STR]}}
    body = msgpack.packb(hello, use_bin_type=True)
    for _ in range(4):  # let allocator pools and stream buffers settle
        sidecar.send(body)
    rss_before, _ = sidecar.memory()

    connections = 32
    for _ in range(connections):
        sidecar.send(body)

    _, peak_after = sidecar.memory()
    # Was +145 to +270 MiB on macOS: each refusal built a ~16 MiB repr of the
    # string. The peak bounds what's left over too.
    peak_growth = peak_after - rss_before
    assert peak_growth < _LIMIT, (
        f"{connections} refused {len(body):,}-byte hellos took sidecar RSS "
        f"{peak_growth / _MiB:.1f} MiB above its {rss_before / _MiB:.1f} MiB baseline"
    )


def test_requests_that_crash_the_handler_do_not_pile_up_in_sidecar_memory(
    sidecar: _Sidecar,
) -> None:
    # The stub doubles it, so the reply is ~2 MB: encode_frame raises and the
    # handler takes its internal-error path.
    body = msgpack.packb(
        {"v": 1, "id": 2, "kind": "req", "op": "seal", "body": {"plaintext": b"\x00" * 1_000_000}}
    )
    for _ in range(4):  # let allocator pools and stream buffers settle
        sidecar.request(body)
    rss_before, _ = sidecar.memory()

    connections = 32
    replies = [sidecar.request(body) for _ in range(connections)]

    _, peak_after = sidecar.memory()
    # Was +91 MiB on macOS with the real Fernet backend: each crashed task kept
    # its exception, whose traceback held the frame, the plaintext and the
    # reply, in a cycle only the GC could free.
    peak_growth = peak_after - rss_before
    assert peak_growth < _LIMIT, (
        f"{connections} seal requests that crashed the handler took sidecar RSS "
        f"{peak_growth / _MiB:.1f} MiB above its {rss_before / _MiB:.1f} MiB baseline"
    )
    assert {reply["message"] for reply in replies} == {"PROTO: internal error"}


@pytest.mark.parametrize(
    "envelope",
    [
        pytest.param({**_HELLO, "body": {"client_versions": [_HUGE_STR]}}, id="refused-hello"),
        pytest.param({**_HELLO, "pad": _HUGE_STR}, id="accepted-hello"),
    ],
)
def test_peers_that_close_without_reading_the_reply_do_not_pile_up_in_sidecar_memory(
    sidecar: _Sidecar, envelope: dict[str, object]
) -> None:
    body = msgpack.packb(envelope, use_bin_type=True)
    for _ in range(4):  # let allocator pools and stream buffers settle
        sidecar.send_unread(body)
    sidecar.send(msgpack.packb([1]))  # a full round trip: the sidecar caught up
    rss_before, _ = sidecar.memory()

    connections = 32
    for _ in range(connections):
        sidecar.send_unread(body)
    sidecar.send(msgpack.packb([1]))

    _, peak_after = sidecar.memory()
    # Was +122 MiB on Linux for refused hellos: each failed reply write kept
    # its BrokenPipeError on the reader, whose traceback kept the handler's
    # frame and the decoded hello.
    peak_growth = peak_after - rss_before
    assert peak_growth < _LIMIT, (
        f"{connections} peers that closed without reading took sidecar RSS "
        f"{peak_growth / _MiB:.1f} MiB above its {rss_before / _MiB:.1f} MiB baseline"
    )

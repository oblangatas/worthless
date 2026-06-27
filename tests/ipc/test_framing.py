"""Tests for ``worthless.ipc.framing`` — length-prefix + msgpack codec.

Contract: engineering/ipc-contract.md §Frame.
"""

from __future__ import annotations

import asyncio

import msgpack
import pytest

from worthless.ipc.framing import (
    MAX_FRAME_SIZE,
    FrameTooLargeError,
    FrameTruncatedError,
    MalformedFrameError,
    encode_frame,
    read_frame,
)


def _envelope(**overrides: object) -> dict[str, object]:
    """Build a canonical envelope; override any field via kwargs."""
    env: dict[str, object] = {
        "v": 1,
        "id": 1,
        "kind": "req",
        "op": "hello",
        "body": {},
    }
    env.update(overrides)
    return env


def _feed(reader: asyncio.StreamReader, data: bytes) -> None:
    reader.feed_data(data)
    reader.feed_eof()


# ---------------------------------------------------------------------------
# encode_frame — sync
# ---------------------------------------------------------------------------


class TestEncodeFrame:
    def test_length_prefix_is_big_endian(self) -> None:
        frame = encode_frame(_envelope(body={"client_versions": [1]}))
        declared = int.from_bytes(frame[:4], "big")
        assert declared == len(frame) - 4
        assert declared > 0

    def test_payload_is_valid_msgpack_of_envelope(self) -> None:
        env = _envelope(body={"client_versions": [1]})
        frame = encode_frame(env)
        decoded = msgpack.unpackb(frame[4:], raw=False)
        assert decoded == env

    def test_bytes_in_body_preserved_as_bytes(self) -> None:
        # Critical for seal/open: plaintext/ciphertext are bytes, must NOT
        # be coerced to str. use_bin_type=True is the magic flag.
        env = _envelope(op="seal", body={"plaintext": b"\x00\x01secret"})
        frame = encode_frame(env)
        decoded = msgpack.unpackb(frame[4:], raw=False)
        assert decoded["body"]["plaintext"] == b"\x00\x01secret"
        assert isinstance(decoded["body"]["plaintext"], bytes)

    def test_oversized_payload_rejected(self) -> None:
        huge = _envelope(body={"blob": b"x" * (MAX_FRAME_SIZE + 1024)})
        with pytest.raises(FrameTooLargeError):
            encode_frame(huge)


# ---------------------------------------------------------------------------
# read_frame — async
# ---------------------------------------------------------------------------


class TestReadFrame:
    async def test_roundtrip_small_envelope(self) -> None:
        env = _envelope(body={"foo": "bar"})
        reader = asyncio.StreamReader()
        _feed(reader, encode_frame(env))
        assert await read_frame(reader) == env

    async def test_roundtrip_bytes_body(self) -> None:
        env = _envelope(op="seal", body={"plaintext": b"\xde\xad\xbe\xef"})
        reader = asyncio.StreamReader()
        _feed(reader, encode_frame(env))
        decoded = await read_frame(reader)
        assert decoded["body"]["plaintext"] == b"\xde\xad\xbe\xef"

    async def test_truncated_header_raises(self) -> None:
        reader = asyncio.StreamReader()
        _feed(reader, b"\x00\x00")  # 2 of 4 header bytes
        with pytest.raises(FrameTruncatedError):
            await read_frame(reader)

    async def test_truncated_body_raises(self) -> None:
        reader = asyncio.StreamReader()
        # Header claims 100 bytes, only provide 10
        _feed(reader, (100).to_bytes(4, "big") + b"x" * 10)
        with pytest.raises(FrameTruncatedError):
            await read_frame(reader)

    async def test_oversized_length_prefix_rejected(self) -> None:
        reader = asyncio.StreamReader()
        _feed(reader, (MAX_FRAME_SIZE + 1).to_bytes(4, "big"))
        with pytest.raises(FrameTooLargeError):
            await read_frame(reader)

    async def test_malformed_msgpack_rejected(self) -> None:
        reader = asyncio.StreamReader()
        garbage = b"\xc1\xc1\xc1\xc1"  # 0xc1 is "never used" per msgpack spec
        _feed(reader, len(garbage).to_bytes(4, "big") + garbage)
        with pytest.raises(MalformedFrameError):
            await read_frame(reader)

    async def test_non_dict_payload_rejected(self) -> None:
        # Valid msgpack, but it's a list, not a dict — envelope must be dict.
        payload = msgpack.packb([1, 2, 3], use_bin_type=True)
        reader = asyncio.StreamReader()
        _feed(reader, len(payload).to_bytes(4, "big") + payload)
        with pytest.raises(MalformedFrameError):
            await read_frame(reader)

    async def test_zero_length_frame_rejected(self) -> None:
        reader = asyncio.StreamReader()
        _feed(reader, (0).to_bytes(4, "big"))
        with pytest.raises(MalformedFrameError):
            await read_frame(reader)

    async def test_two_frames_back_to_back(self) -> None:
        # Stream framing must consume exactly one frame, leaving the next intact.
        env1 = _envelope(id=1)
        env2 = _envelope(id=2)
        reader = asyncio.StreamReader()
        reader.feed_data(encode_frame(env1) + encode_frame(env2))
        reader.feed_eof()
        assert await read_frame(reader) == env1
        assert await read_frame(reader) == env2

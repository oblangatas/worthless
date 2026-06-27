"""Tests for enroll_stub.py (WOR-74)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from worthless.cli.enroll_stub import enroll_stub
from worthless.storage.repository import ShardRepository
from worthless.crypto.splitter import reconstruct_key

from tests.helpers import fake_anthropic_key, fake_openai_key

_TEST_KEY = fake_openai_key()
_TEST_KEY_2 = fake_anthropic_key()


async def _retrieve(db_path: str, fernet_key: bytes, alias: str):
    """Helper: init repo and retrieve a stored shard."""
    r = ShardRepository(db_path, fernet_key)
    await r.initialize()
    return await r.retrieve(alias)


class TestEnrollStub:
    """Core enroll_stub behaviour."""

    def test_returns_shard_a_bytearray(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """enroll_stub returns shard_a as bytearray (SR-01: zeroable)."""
        shard_a = asyncio.run(
            enroll_stub("test-alias", _TEST_KEY, "openai", tmp_db_path, fernet_key)
        )
        assert isinstance(shard_a, bytearray)
        assert len(shard_a) > 0

    def test_shard_b_stored_in_db(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """enroll_stub stores shard_b in the database."""
        asyncio.run(enroll_stub("test-alias", _TEST_KEY, "openai", tmp_db_path, fernet_key))

        stored = asyncio.run(_retrieve(tmp_db_path, fernet_key, "test-alias"))
        assert stored is not None
        assert stored.provider == "openai"
        assert len(stored.shard_b) > 0
        assert len(stored.commitment) > 0
        assert len(stored.nonce) > 0

    def test_reconstruct_roundtrip(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """shard_a + shard_b from DB reconstruct the original key."""
        shard_a = asyncio.run(enroll_stub("rt-alias", _TEST_KEY, "openai", tmp_db_path, fernet_key))
        assert shard_a is not None

        stored = asyncio.run(_retrieve(tmp_db_path, fernet_key, "rt-alias"))
        key_buf = reconstruct_key(
            bytearray(shard_a), stored.shard_b, stored.commitment, stored.nonce
        )
        assert key_buf.decode() == _TEST_KEY

    def test_writes_shard_a_file_when_dir_given(
        self, tmp_db_path: str, fernet_key: bytes, tmp_path: Path
    ) -> None:
        """When shard_a_dir is provided, enroll_stub writes the file."""
        shard_a_dir = tmp_path / "shard_a"
        shard_a = asyncio.run(
            enroll_stub(
                "file-alias",
                _TEST_KEY,
                "openai",
                tmp_db_path,
                fernet_key,
                shard_a_dir=str(shard_a_dir),
            )
        )
        shard_a_path = shard_a_dir / "file-alias"
        assert shard_a_path.exists()
        assert shard_a_path.read_bytes() == shard_a

    def test_no_shard_a_file_without_dir(
        self, tmp_db_path: str, fernet_key: bytes, tmp_path: Path
    ) -> None:
        """Without shard_a_dir, no file is written."""
        shard_a_dir = tmp_path / "shard_a"
        asyncio.run(enroll_stub("no-file", _TEST_KEY, "openai", tmp_db_path, fernet_key))
        assert not shard_a_dir.exists()

    def test_creates_shard_a_dir_if_missing(
        self, tmp_db_path: str, fernet_key: bytes, tmp_path: Path
    ) -> None:
        """shard_a_dir is created if it doesn't exist."""
        nested = tmp_path / "deep" / "nested" / "shard_a"
        asyncio.run(
            enroll_stub(
                "nested-alias",
                _TEST_KEY,
                "openai",
                tmp_db_path,
                fernet_key,
                shard_a_dir=str(nested),
            )
        )
        assert nested.exists()
        assert (nested / "nested-alias").exists()

    def test_duplicate_alias_raises(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """Enrolling the same alias twice raises IntegrityError."""
        import sqlite3

        asyncio.run(enroll_stub("dup-alias", _TEST_KEY, "openai", tmp_db_path, fernet_key))
        with pytest.raises(sqlite3.IntegrityError):
            asyncio.run(enroll_stub("dup-alias", _TEST_KEY, "openai", tmp_db_path, fernet_key))


# ------------------------------------------------------------------
# WOR-74: Multi-key enrollment
# ------------------------------------------------------------------


class TestEnrollStubMultipleKeys:
    """WOR-74: enroll_stub handles multi-key enrollment."""

    def test_enroll_two_keys_both_stored(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """Enrolling two different keys results in both being stored and retrievable."""
        shard_a_1 = asyncio.run(
            enroll_stub("key-openai", _TEST_KEY, "openai", tmp_db_path, fernet_key)
        )
        shard_a_2 = asyncio.run(
            enroll_stub("key-anthropic", _TEST_KEY_2, "anthropic", tmp_db_path, fernet_key)
        )

        assert isinstance(shard_a_1, bytearray)
        assert isinstance(shard_a_2, bytearray)

        # Both are retrievable
        stored_1 = asyncio.run(_retrieve(tmp_db_path, fernet_key, "key-openai"))
        stored_2 = asyncio.run(_retrieve(tmp_db_path, fernet_key, "key-anthropic"))

        assert stored_1 is not None
        assert stored_2 is not None
        assert stored_1.provider == "openai"
        assert stored_2.provider == "anthropic"

    def test_multi_key_reconstruct_roundtrip(self, tmp_db_path: str, fernet_key: bytes) -> None:
        """Both enrolled keys reconstruct correctly to their original values."""
        shard_a_1 = asyncio.run(
            enroll_stub("rt-openai", _TEST_KEY, "openai", tmp_db_path, fernet_key)
        )
        shard_a_2 = asyncio.run(
            enroll_stub("rt-anthropic", _TEST_KEY_2, "anthropic", tmp_db_path, fernet_key)
        )

        stored_1 = asyncio.run(_retrieve(tmp_db_path, fernet_key, "rt-openai"))
        stored_2 = asyncio.run(_retrieve(tmp_db_path, fernet_key, "rt-anthropic"))

        key_1 = reconstruct_key(
            bytearray(shard_a_1), stored_1.shard_b, stored_1.commitment, stored_1.nonce
        )
        key_2 = reconstruct_key(
            bytearray(shard_a_2), stored_2.shard_b, stored_2.commitment, stored_2.nonce
        )

        assert key_1.decode() == _TEST_KEY
        assert key_2.decode() == _TEST_KEY_2

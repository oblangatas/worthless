"""RED tests for worthless-3sd: Fernet key must be bytearray, not str.

These tests define the contracts for the fix:
- ProxySettings.fernet_key must be bytearray (currently str -> FAIL)
- _read_fernet_key() must return bytearray (currently str -> FAIL)
- ShardRepository must accept bytearray key and have a close() that zeros it
  (close() doesn't exist yet -> AttributeError -> FAIL)
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from worthless.proxy.config import ProxySettings, _read_fernet_key
from worthless.storage.repository import ShardRepository

from tests.conftest import stored_shard_from_split


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all WORTHLESS_* env vars so each test starts clean."""
    for key in list(os.environ):
        if key.startswith("WORTHLESS_"):
            monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# ProxySettings.fernet_key type contract
# ---------------------------------------------------------------------------


class TestFernetKeyTypeContract:
    """ProxySettings.fernet_key must be bytearray, not str."""

    def test_fernet_key_type_is_bytearray(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After fix, fernet_key field must be bytearray."""
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "test-key-material")
        s = ProxySettings()
        assert isinstance(s.fernet_key, bytearray), (
            f"Expected bytearray, got {type(s.fernet_key).__name__}"
        )

    def test_fernet_key_empty_is_bytearray(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Even empty fernet_key should be bytearray (empty), not empty str."""
        # Class-attr injection — bulletproof against the py3.10 xdist race.
        monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(lambda: bytearray()))
        s = ProxySettings()
        assert isinstance(s.fernet_key, bytearray), (
            f"Expected bytearray, got {type(s.fernet_key).__name__}"
        )


# ---------------------------------------------------------------------------
# _read_fernet_key() return type contract
# ---------------------------------------------------------------------------


class TestReadFernetKeyReturnsBytearray:
    """_read_fernet_key() must return bytearray."""

    def test_read_fernet_key_from_env_returns_bytearray(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-key-value")
        result = _read_fernet_key()
        assert isinstance(result, bytearray), f"Expected bytearray, got {type(result).__name__}"

    def test_read_fernet_key_from_fd_returns_bytearray(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "99")
        with (
            patch("worthless.proxy.config.os.read", return_value=b"fd-key-value"),
            patch("worthless.proxy.config.os.close"),
        ):
            result = _read_fernet_key()
        assert isinstance(result, bytearray), f"Expected bytearray, got {type(result).__name__}"

    def test_read_fernet_key_empty_returns_bytearray(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No key found -> empty bytearray, not empty str.

        Uses real filesystem state (empty HOME) instead of patching the
        keystore — sidesteps the py3.10 xdist patch-state race.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        result = _read_fernet_key()
        assert isinstance(result, bytearray), f"Expected bytearray, got {type(result).__name__}"


# ---------------------------------------------------------------------------
# ShardRepository.close() zeroing contract
# ---------------------------------------------------------------------------


class TestRepositoryZeroing:
    """ShardRepository must have a close() method that zeros key material."""

    def test_repository_close_zeros_fernet_key_bytes(self, tmp_db_path: str) -> None:
        """After close(), the internal key bytearray must be all zeros."""
        key = Fernet.generate_key()
        key_ba = bytearray(key)
        repo = ShardRepository(tmp_db_path, key_ba)

        # Verify the key material is non-zero before close
        assert any(b != 0 for b in repo._fernet_key_bytes), "Key should be non-zero before close"

        repo.close()

        # After close, key material must be zeroed
        assert all(b == 0 for b in repo._fernet_key_bytes), "Key material not zeroed after close()"

    def test_repository_close_exists(self, tmp_db_path: str) -> None:
        """ShardRepository must have a close() method."""
        key = Fernet.generate_key()
        repo = ShardRepository(tmp_db_path, bytearray(key))
        assert hasattr(repo, "close"), "ShardRepository missing close() method"
        assert callable(repo.close), "ShardRepository.close is not callable"


# ---------------------------------------------------------------------------
# ShardRepository accepts bytearray key (roundtrip)
# ---------------------------------------------------------------------------


class TestRepositoryBytearray:
    """ShardRepository must work with bytearray keys."""

    @pytest.mark.asyncio
    async def test_compute_decoy_hash_raises_after_close(self, tmp_db_path: str) -> None:
        """After close(), _compute_decoy_hash must raise RuntimeError
        instead of silently producing wrong HMACs with zeroed key."""
        key = Fernet.generate_key()
        repo = ShardRepository(tmp_db_path, bytearray(key))
        repo.close()

        with pytest.raises(RuntimeError, match="closed"):
            await repo._compute_decoy_hash("test")

    @pytest.mark.asyncio
    async def test_repository_accepts_bytearray_key(
        self, tmp_db_path: str, sample_split_result
    ) -> None:
        """Create repo with bytearray key, store and retrieve a shard."""
        key = Fernet.generate_key()
        repo = ShardRepository(tmp_db_path, bytearray(key))
        await repo.initialize()

        shard = stored_shard_from_split(sample_split_result)
        await repo.store("ba-test", shard)

        result = await repo.retrieve("ba-test")
        assert result is not None
        assert bytes(result.shard_b) == bytes(shard.shard_b)

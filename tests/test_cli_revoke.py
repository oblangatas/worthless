"""Tests for ``worthless revoke`` CLI command."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import aiosqlite
import pytest
from click.testing import Result
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from worthless.crypto.splitter import split_key
from tests.conftest import make_repo, stored_shard_from_split
from tests.helpers import fake_openai_key

runner = CliRunner()


@pytest.fixture(autouse=True)
def _patch_delete_fernet_key(request):
    """Suppress real keychain calls in all tests except TestRevokeKeychainCleanup.

    My changes make delete_fernet_key fire on every last-enrollment revoke.
    Tests that don't specifically assert on keychain behaviour should not hit
    the real OS keyring — that causes macOS Keychain dialogs during local runs.
    """
    if "TestRevokeKeychainCleanup" in request.node.nodeid:
        yield
        return
    with patch("worthless.cli.commands.revoke.delete_fernet_key"):
        yield


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _invoke_revoke(alias: str, home: WorthlessHome) -> Result:
    """Invoke ``worthless revoke --alias=<alias>`` with home overridden."""
    with patch("worthless.cli.commands.revoke.get_home", return_value=home):
        return runner.invoke(app, ["revoke", "--alias", alias])


def _enrollments_for(home: WorthlessHome, alias: str) -> list:
    repo = make_repo(home)
    asyncio.run(repo.initialize())
    return asyncio.run(repo.list_enrollments(alias))


def _shard_exists(home: WorthlessHome, alias: str) -> bool:
    repo = make_repo(home)
    asyncio.run(repo.initialize())
    result = asyncio.run(repo.fetch_encrypted(alias))
    return result is not None


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


class TestRevokeExistingKey:
    """Revoke an enrolled key -- happy path."""

    def test_exits_zero(self, home_with_key: WorthlessHome) -> None:
        result = _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert result.exit_code == 0, result.output

    def test_no_shard_a_file_still_succeeds(self, home_with_key: WorthlessHome) -> None:
        """Revoke succeeds even when no shard_a file exists on disk (SR-09)."""
        shard_a = home_with_key.shard_a_dir / "openai-a1b2c3d4"
        assert not shard_a.exists(), "SR-09: shard_a files should not exist"
        _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert not shard_a.exists()

    def test_db_shard_deleted(self, home_with_key: WorthlessHome) -> None:
        assert _shard_exists(home_with_key, "openai-a1b2c3d4")
        _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert not _shard_exists(home_with_key, "openai-a1b2c3d4")

    def test_enrollments_deleted(self, home_with_key: WorthlessHome) -> None:
        assert len(_enrollments_for(home_with_key, "openai-a1b2c3d4")) > 0
        _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert len(_enrollments_for(home_with_key, "openai-a1b2c3d4")) == 0

    def test_prints_confirmation(self, home_with_key: WorthlessHome) -> None:
        result = _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert "revoked" in result.output.lower() or "removed" in result.output.lower()


class TestRevokeNonExistent:
    """Revoke an alias that doesn't exist -- idempotent, prints warning."""

    def test_exits_zero(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("no-such-alias", home_dir)
        assert result.exit_code == 0, result.output

    def test_prints_warning(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("no-such-alias", home_dir)
        assert "not found" in result.output.lower() or "nothing" in result.output.lower()


class TestShardAZeroedBeforeDeletion:
    """Shard-A file zeroing when a legacy file exists on disk."""

    def test_legacy_file_zeroed_before_delete(self, home_with_key: WorthlessHome) -> None:
        """If a legacy shard_a file exists, revoke should zero and delete it."""
        shard_a = home_with_key.shard_a_dir / "openai-a1b2c3d4"
        # Simulate a legacy shard_a file left from pre-SR-09
        shard_a.write_bytes(b"legacy-shard-data-here")
        original_size = shard_a.stat().st_size
        assert original_size > 0

        # Capture what's written before the unlink
        written_data: list[bytes] = []
        real_open = os.open
        real_write = os.write

        def spy_open(path, flags, *args, **kwargs):
            return real_open(path, flags, *args, **kwargs)

        def spy_write(fd, data):
            written_data.append(bytes(data))
            return real_write(fd, data)

        with patch("worthless.cli.commands.revoke.os.open", side_effect=spy_open):
            with patch("worthless.cli.commands.revoke.os.write", side_effect=spy_write):
                _invoke_revoke("openai-a1b2c3d4", home_with_key)

        # At least one write should be all zeros (the zeroing pass)
        assert any(all(b == 0 for b in data) and len(data) > 0 for data in written_data), (
            f"Expected a zero-fill write, got: {[d.hex()[:20] for d in written_data]}"
        )
        assert not shard_a.exists()

    def test_no_file_no_zeroing(
        self, home_with_key: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no shard_a file exists (SR-09 default), revoke succeeds without zeroing."""
        import os as _os

        shard_a = home_with_key.shard_a_dir / "openai-a1b2c3d4"
        assert not shard_a.exists()

        writes: list[bytes] = []
        _real_write = _os.write

        def _spy_write(fd, data):
            writes.append(bytes(data))
            return _real_write(fd, data)

        monkeypatch.setattr(_os, "write", _spy_write)

        result = _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert result.exit_code == 0
        # No zero-fill writes should have occurred (no file to zero)
        zero_writes = [d for d in writes if all(b == 0 for b in d) and len(d) > 0]
        assert zero_writes == [], "Zeroing should not occur when no shard_a file exists"


class TestRevokeCleanupSpendLog:
    """Revoke should also clean up spend_log entries for the alias."""

    def test_spend_log_cleaned(self, home_with_key: WorthlessHome) -> None:
        # Insert a spend_log entry
        async def _insert_spend():
            async with aiosqlite.connect(str(home_with_key.db_path)) as db:
                await db.execute(
                    "INSERT INTO spend_log (key_alias, tokens, provider) VALUES (?, ?, ?)",
                    ("openai-a1b2c3d4", 100, "openai"),
                )
                await db.commit()

        async def _count_spend():
            async with aiosqlite.connect(str(home_with_key.db_path)) as db:
                cur = await db.execute(
                    "SELECT COUNT(*) FROM spend_log WHERE key_alias = ?",
                    ("openai-a1b2c3d4",),
                )
                row = await cur.fetchone()
                return row[0]

        asyncio.run(_insert_spend())
        assert asyncio.run(_count_spend()) == 1

        _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert asyncio.run(_count_spend()) == 0


class TestRevokePathTraversal:
    """Alias must be validated to prevent path traversal attacks."""

    def test_path_traversal_rejected(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("../../etc/passwd", home_dir)
        assert result.exit_code == 1

    def test_dotdot_rejected(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("../fernet.key", home_dir)
        assert result.exit_code == 1

    def test_slash_rejected(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("foo/bar", home_dir)
        assert result.exit_code == 1

    def test_valid_alias_accepted(self, home_dir: WorthlessHome) -> None:
        result = _invoke_revoke("openai-abc123", home_dir)
        assert result.exit_code == 0  # not found, but no validation error


class TestRevokeDebugMode:
    """--debug should surface full tracebacks instead of sanitized messages."""

    def test_debug_mode_shows_traceback(self) -> None:
        with patch(
            "worthless.cli.commands.revoke._revoke_key",
            side_effect=RuntimeError("internal boom"),
        ):
            result = runner.invoke(app, ["--debug", "revoke", "--alias", "test-key"])
        assert result.exit_code != 0
        # In debug mode the full traceback should be visible.
        # CliRunner mixes stderr into stdout by default.
        output = result.output or ""
        assert "Traceback" in output or "internal boom" in output, (
            f"Expected traceback in debug output, got:\n{output}"
        )


class TestRevokeKeychainCleanup:
    """Master Fernet key removed from keychain only after the last enrollment."""

    def test_last_revoke_deletes_fernet_key(self, home_with_key: WorthlessHome) -> None:
        """Revoking the only enrolled alias triggers delete_fernet_key."""
        with patch("worthless.cli.commands.revoke.delete_fernet_key") as mock_delete:
            result = _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert result.exit_code == 0, result.output
        mock_delete.assert_called_once_with(home_with_key.base_dir)

    def test_non_last_revoke_keeps_fernet_key(self, home_with_key: WorthlessHome) -> None:
        """Revoking one of several aliases must NOT delete the master key."""
        # Enroll a second alias so revoking the first is not the last.
        repo = make_repo(home_with_key)
        asyncio.run(repo.initialize())
        key2 = fake_openai_key()
        sr2 = split_key(key2.encode())
        try:
            asyncio.run(
                repo.store_enrolled(
                    "openai-second",
                    stored_shard_from_split(sr2, provider="openai"),
                    var_name="OPENAI_API_KEY",
                    env_path=None,
                )
            )
        finally:
            sr2.zero()

        with patch("worthless.cli.commands.revoke.delete_fernet_key") as mock_delete:
            result = _invoke_revoke("openai-a1b2c3d4", home_with_key)
        assert result.exit_code == 0, result.output
        mock_delete.assert_not_called()

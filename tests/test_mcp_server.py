"""Tests for the Worthless MCP server tools."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from worthless.mcp.server import (  # noqa: E402
    worthless_lock,
    worthless_scan,
    worthless_spend,
    worthless_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env_file(tmp_path: Path, content: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    return env_file


def _make_home(tmp_path: Path) -> Path:
    """Create a minimal WorthlessHome directory."""
    from cryptography.fernet import Fernet

    home = tmp_path / ".worthless"
    home.mkdir(mode=0o700)
    (home / "shard_a").mkdir(mode=0o700)
    key = Fernet.generate_key()
    (home / "fernet.key").write_bytes(key)
    return home


# ---------------------------------------------------------------------------
# worthless_status
# ---------------------------------------------------------------------------


class TestWorthlessStatus:
    @pytest.mark.asyncio
    async def test_status_no_home(self, tmp_path: Path) -> None:
        """Status returns empty when worthless is not initialized."""
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(tmp_path / "nonexistent")}):
            result = json.loads(await worthless_status())
        assert result["keys"] == []
        assert result["proxy"]["healthy"] is False

    @pytest.mark.asyncio
    async def test_status_with_home(self, tmp_path: Path) -> None:
        """Status returns empty keys list when initialized but no keys enrolled."""
        home = _make_home(tmp_path)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())
        assert result["keys"] == []
        assert result["proxy"]["healthy"] is False


# ---------------------------------------------------------------------------
# worthless_scan
# ---------------------------------------------------------------------------


class TestWorthlessScan:
    @pytest.mark.asyncio
    async def test_scan_clean_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scanning a file with no keys returns empty findings."""
        monkeypatch.chdir(tmp_path)
        env_file = _make_env_file(tmp_path, "FOO=bar\nBAZ=123\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))
        assert result["findings"] == []
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_scan_detects_key(self, tmp_path: Path) -> None:
        """Scanning a file with a real-looking key returns findings."""
        # Use a high-entropy string that matches provider patterns
        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={fake_key}\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))
        assert result["summary"]["total"] >= 1
        assert result["summary"]["unprotected"] >= 1

    @pytest.mark.asyncio
    async def test_scan_no_paths_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scanning with no paths scans .env in cwd."""
        monkeypatch.chdir(tmp_path)
        _make_env_file(tmp_path, "FOO=bar\n")
        result = json.loads(await worthless_scan())
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_scan_envelope_has_skipped_and_scan_incomplete(self, tmp_path: Path) -> None:
        """c5kc: MCP scan envelope always carries ``skipped`` + ``scan_incomplete``
        so the calling agent can tell ``no findings`` (clean) apart from
        ``no findings because I couldn't read everything`` (partial)."""
        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))

        # Additive fields must be present even on a clean scan.
        assert "skipped" in result
        assert "scan_incomplete" in result
        assert result["skipped"] == []
        assert result["scan_incomplete"] is False

    @pytest.mark.asyncio
    async def test_scan_offloaded_to_worker_thread(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """c5kc / CodeRabbit follow-up: scan_files is synchronous and runs for
        up to 30 s; calling it inline would block the FastMCP event loop and
        starve other concurrent MCP tools. This test pins that the MCP tool
        actually offloads to a worker thread.

        If a future refactor accidentally re-inlines the call (drops
        ``await asyncio.to_thread(...)``), this test fails because
        ``scan_files`` would then run on the main event-loop thread.
        """
        import threading

        main_thread_id = threading.get_ident()
        called_from: dict[str, int] = {}

        def tracking_scan_files(*args, **kwargs):
            called_from["thread"] = threading.get_ident()
            return []

        # Patch the symbol where the MCP tool imports it from.
        import worthless.cli.scanner as scanner_mod

        monkeypatch.setattr(scanner_mod, "scan_files", tracking_scan_files)

        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        await worthless_scan(paths=[str(env_file)])

        assert "thread" in called_from, "scan_files was never called"
        assert called_from["thread"] != main_thread_id, (
            "scan_files ran on the event-loop thread — would block other MCP tools. "
            "Wrap the call in `await asyncio.to_thread(scan_files, ...)`."
        )

    @pytest.mark.asyncio
    async def test_scan_truncated_file_marks_scan_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """c5kc: an oversize file scans its prefix and surfaces ``truncated``
        in the envelope so the agent doesn't read ``0 findings`` as clean."""
        import worthless.cli.scanner as scanner_mod

        # Tiny cap so we don't have to write 5 MB to disk in CI.
        monkeypatch.setattr(scanner_mod, "MAX_SCAN_FILE_BYTES", 256)

        env_file = tmp_path / ".env"
        env_file.write_bytes(b"# placeholder\n" + b"x" * 1024)

        result = json.loads(await worthless_scan(paths=[str(env_file)]))

        assert result["scan_incomplete"] is True
        assert any(s["reason"] == "truncated" for s in result["skipped"])
        # Skip notice path + reason only — never any bytes of file content.
        for s in result["skipped"]:
            assert set(s.keys()) == {"file", "reason"}


# ---------------------------------------------------------------------------
# worthless_lock
# ---------------------------------------------------------------------------


class TestWorthlessLock:
    @pytest.mark.asyncio
    async def test_lock_no_keys(self, tmp_path: Path) -> None:
        """Locking a file with no API keys returns 0 protected."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 0

    @pytest.mark.asyncio
    async def test_lock_protects_key(self, tmp_path: Path) -> None:
        """Locking a file with an API key should protect it."""
        home = _make_home(tmp_path)
        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={fake_key}\n")
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 1
        # Original key should no longer be in the file
        assert fake_key not in env_file.read_text()
        # dqzj: a clean lock reconciles to a consistent state — no false orphan.
        assert result["state_consistent"] is True
        assert "orphan_shards" not in result

    @pytest.mark.asyncio
    async def test_lock_surfaces_orphan_shard(self, tmp_path: Path) -> None:
        """dqzj: a shards row with no enrollment is surfaced, not silently 'ok'.

        The MCP lock runs off the main thread (no interrupt rollback). If the DB
        carries an orphan shard (a half-written/legacy mixed state), the result
        must flag it and point at `doctor` rather than returning a bare success.
        """
        import aiosqlite

        from worthless.storage.schema import init_db

        home = _make_home(tmp_path)
        db_path = str(home / "worthless.db")
        await init_db(db_path)
        # An orphan: a shard with NO enrollment row (no shard-A, useless, but junk).
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
                "VALUES (?, ?, ?, ?, ?)",
                ("orphan-alias", b"b", b"c", b"n", "openai"),
            )
            await db.commit()

        env_file = _make_env_file(tmp_path, "FOO=bar\n")  # no keys → protected_count 0
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))

        assert result["protected_count"] == 0
        assert result["state_consistent"] is False
        assert result["orphan_shards"] == ["orphan-alias"]
        assert "doctor" in result["hint"]


# ---------------------------------------------------------------------------
# worthless_spend
# ---------------------------------------------------------------------------


class TestWorthlessSpend:
    @pytest.mark.asyncio
    async def test_spend_empty(self, tmp_path: Path) -> None:
        """Spend returns empty list when no spend data exists."""
        home = _make_home(tmp_path)
        # Initialize the DB schema
        from worthless.storage.schema import init_db

        await init_db(str(home / "worthless.db"))

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend())
        assert result["spend"] == []

    @pytest.mark.asyncio
    async def test_spend_with_data(self, tmp_path: Path) -> None:
        """Spend aggregates rows from spend_log table."""
        home = _make_home(tmp_path)
        from worthless.storage.schema import init_db

        db_path = str(home / "worthless.db")
        await init_db(db_path)

        # Insert test spend data directly
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc123", 100, "gpt-4", "openai"),
            )
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc123", 200, "gpt-4", "openai"),
            )
            await db.commit()

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend())
        assert len(result["spend"]) == 1
        assert result["spend"][0]["alias"] == "openai-abc123"
        assert result["spend"][0]["total_tokens"] == 300
        assert result["spend"][0]["request_count"] == 2

    @pytest.mark.asyncio
    async def test_spend_filter_by_alias(self, tmp_path: Path) -> None:
        """Spend filters by alias when provided."""
        home = _make_home(tmp_path)
        from worthless.storage.schema import init_db

        db_path = str(home / "worthless.db")
        await init_db(db_path)

        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc", 100, "gpt-4", "openai"),
            )
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("anthropic-xyz", 500, "claude-3", "anthropic"),
            )
            await db.commit()

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend(alias="openai-abc"))
        assert len(result["spend"]) == 1
        assert result["spend"][0]["alias"] == "openai-abc"

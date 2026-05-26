"""Tests for encrypted shard storage (STOR-01, STOR-02)."""

from __future__ import annotations

import aiosqlite
import pytest

from worthless.storage.repository import EncryptedShard, ShardRepository, StoredShard
from worthless.storage.schema import SCHEMA, migrate_db

from tests.conftest import stored_shard_from_split


# ------------------------------------------------------------------
# Roundtrip: store then retrieve
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shard_roundtrip(repo: ShardRepository, sample_split_result) -> None:
    """Store a shard and retrieve it; shard_b must match original."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("alias1", shard)

    result = await repo.retrieve("alias1")
    assert result is not None
    assert result.shard_b == shard.shard_b
    assert result.commitment == shard.commitment
    assert result.nonce == shard.nonce
    assert result.provider == "openai"


# ------------------------------------------------------------------
# Encryption at rest
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shard_encrypted_at_rest(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """Raw SQLite column must NOT contain plaintext shard_b."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("alias1", shard)

    # Read raw column directly
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT shard_b_enc FROM shards WHERE key_alias = 'alias1'")
        row = await cursor.fetchone()
        assert row is not None
        raw_enc = row[0]
        assert raw_enc != shard.shard_b, "shard_b stored in plaintext!"


# ------------------------------------------------------------------
# Metadata persistence
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metadata_persistence(
    tmp_db_path: str,
    fernet_key: bytes,
) -> None:
    """Metadata survives close and reopen of repository."""
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    await repo.set_metadata("enrolled_at", "2026-03-16")

    # Create a new repository instance (simulates reopen)
    repo2 = ShardRepository(tmp_db_path, fernet_key)
    await repo2.initialize()
    value = await repo2.get_metadata("enrolled_at")
    assert value == "2026-03-16"


# ------------------------------------------------------------------
# Duplicate alias
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_duplicate_alias_raises(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Storing the same alias twice raises IntegrityError."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("dup", shard)

    with pytest.raises(aiosqlite.IntegrityError):
        await repo.store("dup", shard)


# ------------------------------------------------------------------
# Non-existent alias
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retrieve_nonexistent_returns_none(repo: ShardRepository) -> None:
    """Retrieving an unknown alias returns None."""
    assert await repo.retrieve("no-such-alias") is None


# ------------------------------------------------------------------
# List enrolled keys
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_enrolled_keys(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """list_keys returns all enrolled aliases."""
    shard_a = stored_shard_from_split(sample_split_result, provider="openai")
    shard_b = stored_shard_from_split(sample_split_result, provider="anthropic")
    await repo.store("key-a", shard_a)
    await repo.store("key-b", shard_b)

    keys = await repo.list_keys()
    assert sorted(keys) == ["key-a", "key-b"]


# ------------------------------------------------------------------
# fetch_encrypted + decrypt_shard split (CRYP-05)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_encrypted_returns_encrypted_shard(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """fetch_encrypted returns an EncryptedShard with raw encrypted bytes."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("enc1", shard)

    enc = await repo.fetch_encrypted("enc1")
    assert enc is not None
    assert isinstance(enc, EncryptedShard)
    # The encrypted blob must differ from the plaintext shard_b
    assert enc.shard_b_enc != bytes(shard.shard_b)
    assert enc.provider == "openai"


@pytest.mark.asyncio
async def test_fetch_encrypted_returns_none_for_unknown(
    repo: ShardRepository,
) -> None:
    """fetch_encrypted returns None for an unknown alias."""
    assert await repo.fetch_encrypted("no-such") is None


@pytest.mark.asyncio
async def test_decrypt_shard_returns_bytearray_stored_shard(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """decrypt_shard takes EncryptedShard and returns StoredShard with bytearray fields."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("dec1", shard)

    enc = await repo.fetch_encrypted("dec1")
    assert enc is not None

    result = await repo.decrypt_shard(enc)
    assert isinstance(result, StoredShard)
    assert isinstance(result.shard_b, bytearray)
    assert isinstance(result.commitment, bytearray)
    assert isinstance(result.nonce, bytearray)
    assert result.provider == "openai"
    # Content must match original
    assert bytes(result.shard_b) == bytes(shard.shard_b)
    assert bytes(result.commitment) == bytes(shard.commitment)
    assert bytes(result.nonce) == bytes(shard.nonce)


@pytest.mark.asyncio
async def test_retrieve_backward_compat_with_bytearray(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """retrieve() still works and returns StoredShard with bytearray fields."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("compat1", shard)

    result = await repo.retrieve("compat1")
    assert result is not None
    assert isinstance(result.shard_b, bytearray)
    assert isinstance(result.commitment, bytearray)
    assert isinstance(result.nonce, bytearray)
    assert bytes(result.shard_b) == bytes(shard.shard_b)


# ------------------------------------------------------------------
# spend_log index (H-6/H-7)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spend_log_index_exists(tmp_db_path: str) -> None:
    """idx_spend_log_alias index must exist after init_db."""
    from worthless.storage.schema import init_db

    await init_db(tmp_db_path)

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("PRAGMA index_list(spend_log)")
        indexes = await cursor.fetchall()
        index_names = [row[1] for row in indexes]
        assert "idx_spend_log_alias" in index_names


# ---------------------------------------------------------------------------
# WOR-183: Schema migration for rules engine columns
# ---------------------------------------------------------------------------


def test_assert_safe_db_path_rejects_quotes_and_control_chars() -> None:
    """``_migrate_base_url_column`` inlines ``db_path`` into the SQL of
    ``VACUUM INTO '<path>'`` because SQLite's VACUUM INTO does not accept
    parameterised paths. The ``_assert_safe_db_path`` validator makes
    that inlining provably safe by refusing any path that could escape
    the surrounding ``'…'`` quotes or terminate the statement early.

    Threat model: ``db_path`` is operator-controlled (``WORTHLESS_HOME``
    env var). This is operator-self-pwn / config-error hardening, not
    anti-injection from an external attacker. But it's still a real
    footgun — a user with a quote in their HOME path would have crashed
    migration mid-transaction without this guard.

    Pinning the validator behaviour also closes Semgrep findings
    ``sqlalchemy-execute-raw-query`` and ``formatted-sql-query`` on
    ``schema.py:100`` against drift back to a bare interpolation.
    """
    from worthless.storage.schema import _assert_safe_db_path

    # Safe paths pass through silently. Path strings are not real fs paths
    # — the validator is pure string analysis, doesn't touch the filesystem.
    safe_paths = [
        "/var/lib/worthless/shards.db",  # noqa: S108
        "/Users/alice/.worthless/shards.db",
        # Windows path with backslashes — backslash is intentionally
        # allowed (legal in SQLite literals; not in _UNSAFE_DB_PATH_CHARS).
        # Don't "fix" this entry to forward slashes.
        "C:\\Users\\Bob\\worthless\\shards.db",
        "/path/with-dashes_and.dots/shards.db",
    ]
    for path in safe_paths:
        _assert_safe_db_path(path)  # must not raise

    # Unsafe characters all raise.
    bad_paths = [
        "/var/has'quote/shards.db",  # noqa: S108 — single quote escapes the SQL literal
        "/var/has\x00null/shards.db",  # noqa: S108 — NUL truncates the path
        "/var/has\nnewline/shards.db",  # noqa: S108 — newline corrupts SQL multi-statement
        "/var/has\rreturn/shards.db",  # noqa: S108
        "/var/has\ttab/shards.db",  # noqa: S108
    ]
    for path in bad_paths:
        with pytest.raises(ValueError, match="unsafe character"):
            _assert_safe_db_path(path)


@pytest.mark.asyncio
async def test_migrate_base_url_column_refuses_unsafe_db_path() -> None:
    """End-to-end: the migration that uses VACUUM INTO refuses a quote-
    bearing db_path before any SQL fires. Without this guard the f-string
    SQL would syntax-error mid-transaction.

    Uses an in-memory SQLite — no SCHEMA setup needed, the validator runs
    BEFORE any DB read on the migration path. A bare connection is enough
    to reach the validator, and dropping the schema setup keeps test
    intent narrow ("validator rejects bad path", not "migration e2e").
    """
    # Pass an unsafe path. Validator must reject before any SQL fires.
    unsafe_db = "/var/has'quote/shards.db"  # noqa: S108 — string analysis only
    from worthless.storage.schema import _migrate_base_url_column

    async with aiosqlite.connect(":memory:") as db:
        with pytest.raises(ValueError, match="unsafe character"):
            await _migrate_base_url_column(db, unsafe_db, shard_columns=set())


@pytest.mark.asyncio
async def test_migrate_adds_rules_columns(tmp_path) -> None:
    """Migration adds token_budget_*, time_window to enrollment_config."""
    db_path = str(tmp_path / "old_rules.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(enrollment_config)")
        columns = {row[1] for row in await cursor.fetchall()}

    expected_new = {
        "token_budget_daily",
        "token_budget_weekly",
        "token_budget_monthly",
        "time_window",
    }
    assert expected_new.issubset(columns), f"Missing columns: {expected_new - columns}"


@pytest.mark.asyncio
async def test_migrate_rules_columns_idempotent(tmp_path) -> None:
    """Running migration twice doesn't error."""
    db_path = str(tmp_path / "idempotent.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)
    await migrate_db(db_path)  # Second run should not raise


@pytest.mark.asyncio
async def test_migrate_rules_columns_default_null(tmp_path) -> None:
    """New rules columns default to NULL for existing enrollments."""
    db_path = str(tmp_path / "defaults.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute(
            "INSERT INTO enrollment_config (key_alias, spend_cap) VALUES (?, ?)",
            ("existing-key", 1000.0),
        )
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT token_budget_daily, token_budget_weekly, "
            "token_budget_monthly, time_window FROM enrollment_config WHERE key_alias = ?",
            ("existing-key",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert all(v is None for v in row), f"Expected all NULL, got {row}"


@pytest.mark.asyncio
async def test_spend_log_index_exists_after_migrate(tmp_path) -> None:
    """Migration creates idx_spend_log_alias_created index."""
    db_path = str(tmp_path / "index.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND name='idx_spend_log_alias_created'"
        ) as cur:
            row = await cur.fetchone()
    assert row is not None, "idx_spend_log_alias_created index not found"


# ---------------------------------------------------------------------------
# WOR-207: prefix/charset columns for format-preserving split
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_adds_prefix_charset_columns(tmp_path) -> None:
    """Migration adds prefix and charset columns to shards table."""
    db_path = str(tmp_path / "old_no_fp.db")

    # Create DB with current schema (no prefix/charset)
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}

    assert "prefix" in columns, "prefix column not added"
    assert "charset" in columns, "charset column not added"


@pytest.mark.asyncio
async def test_store_enrolled_with_prefix_charset(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """store_enrolled persists prefix and charset fields."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "fp-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/.env",  # noqa: S108
        prefix="sk-proj-",
        charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    )

    enc = await repo.fetch_encrypted("fp-alias")
    assert enc is not None
    assert enc.prefix == "sk-proj-"
    assert enc.charset == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


@pytest.mark.asyncio
async def test_fetch_encrypted_returns_prefix_charset(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """fetch_encrypted includes prefix and charset in returned EncryptedShard."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "fp-fetch",
        shard,
        var_name="ANTHROPIC_API_KEY",
        env_path="/tmp/.env",  # noqa: S108
        prefix="sk-ant-api03-",
        charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    )

    enc = await repo.fetch_encrypted("fp-fetch")
    assert enc is not None
    assert enc.prefix == "sk-ant-api03-"
    assert enc.charset is not None
    assert len(enc.charset) == 64  # base64url


@pytest.mark.asyncio
async def test_store_without_prefix_charset_defaults_none(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Existing store() without prefix/charset stores None (backward compat)."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store("legacy-alias", shard)

    enc = await repo.fetch_encrypted("legacy-alias")
    assert enc is not None
    assert enc.prefix is None
    assert enc.charset is None


# ---------------------------------------------------------------------------
# list_aliases_with_provider (WOR-207)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_aliases_with_routing_empty(repo: ShardRepository) -> None:
    """list_aliases_with_routing returns empty list when no enrollments exist."""
    result = await repo.list_aliases_with_routing()
    assert result == []


@pytest.mark.asyncio
async def test_list_aliases_with_routing_returns_four_tuples(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """list_aliases_with_routing returns (alias, var_name, base_url, protocol)."""
    shard_a = stored_shard_from_split(sample_split_result, provider="openai")
    shard_b = stored_shard_from_split(sample_split_result, provider="anthropic")
    await repo.store_enrolled(
        "key-oai",
        shard_a,
        var_name="OPENAI_API_KEY",
        env_path=None,
        base_url="https://api.openai.com/v1",
    )
    await repo.store_enrolled(
        "key-anth",
        shard_b,
        var_name="ANTHROPIC_API_KEY",
        env_path=None,
        base_url="https://api.anthropic.com/v1",
    )

    result = await repo.list_aliases_with_routing()
    by_alias = {row[0]: row for row in result}
    assert by_alias["key-oai"] == (
        "key-oai",
        "OPENAI_API_KEY",
        "https://api.openai.com/v1",
        "openai",
    )
    assert by_alias["key-anth"] == (
        "key-anth",
        "ANTHROPIC_API_KEY",
        "https://api.anthropic.com/v1",
        "anthropic",
    )


@pytest.mark.asyncio
async def test_list_aliases_with_routing_after_delete(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Deleted alias should not appear in list_aliases_with_routing."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "delete-me",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=None,
        base_url="https://api.openai.com/v1",
    )
    await repo.delete("delete-me")

    result = await repo.list_aliases_with_routing()
    aliases = [row[0] for row in result]
    assert "delete-me" not in aliases


@pytest.mark.asyncio
async def test_list_aliases_with_routing_legacy_row_has_null_base_url(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """A pre-8rqs row stored without base_url surfaces as ``None`` in routing —
    the proxy (Phase 6) refuses to use it; the user must re-lock. This pins
    that flow at the data-layer boundary."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "legacy",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=None,
        # base_url omitted — simulates a row enrolled before this PR.
    )

    result = await repo.list_aliases_with_routing()
    by_alias = {row[0]: row for row in result}
    assert by_alias["legacy"][2] is None, (
        f"legacy row should have NULL base_url, got {by_alias['legacy']!r}"
    )


# ---------------------------------------------------------------------------
# worthless-8rqs Phase 4: base_url roundtrip on store / fetch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_enrolled_with_base_url_roundtrips(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """store_enrolled(base_url=...) is read back by fetch_encrypted."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "or-alias",
        shard,
        var_name="OPENROUTER_API_KEY",
        env_path=None,
        base_url="https://openrouter.ai/api/v1",
    )

    enc = await repo.fetch_encrypted("or-alias")
    assert enc is not None
    assert enc.base_url == "https://openrouter.ai/api/v1"


@pytest.mark.asyncio
async def test_store_enrolled_without_base_url_returns_none(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Omitting base_url leaves the column NULL → field reads as None."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "no-url",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=None,
    )

    enc = await repo.fetch_encrypted("no-url")
    assert enc is not None
    assert enc.base_url is None


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_adds_decoy_hash_column(tmp_path) -> None:
    """Migration adds decoy_hash to an existing DB without the column."""
    db_path = str(tmp_path / "old.db")

    # Create a DB with the old schema (no decoy_hash)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS shards ("
            "key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL, "
            "commitment BLOB NOT NULL, nonce BLOB NOT NULL, "
            "provider TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key_alias TEXT NOT NULL REFERENCES shards(key_alias), "
            "var_name TEXT NOT NULL, env_path TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.commit()

    # Run migration
    await migrate_db(db_path)

    # Verify column was added
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(enrollments)")
        columns = {row[1] for row in await cursor.fetchall()}
        assert "decoy_hash" in columns


# ------------------------------------------------------------------
# worthless-8rqs Phase 3: per-enrollment base_url column
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_db_has_base_url_column(tmp_path) -> None:
    """A DB initialised from current SCHEMA includes ``base_url`` in shards."""
    db_path = str(tmp_path / "fresh.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}

    assert "base_url" in columns, (
        "fresh DB missing shards.base_url — required for per-enrollment routing (8rqs)"
    )


@pytest.mark.asyncio
async def test_migrate_adds_base_url_column(tmp_path) -> None:
    """Migration adds ``base_url`` to a pre-8rqs DB without the column."""
    db_path = str(tmp_path / "pre_8rqs.db")

    # Create a DB with the schema as it existed BEFORE 8rqs (no base_url).
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS shards ("
            "key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL, "
            "commitment BLOB NOT NULL, nonce BLOB NOT NULL, "
            "provider TEXT NOT NULL, prefix TEXT, charset TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key_alias TEXT NOT NULL REFERENCES shards(key_alias), "
            "var_name TEXT NOT NULL, env_path TEXT, "
            "decoy_hash TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}
        assert "base_url" in columns


@pytest.mark.asyncio
async def test_migrate_base_url_idempotent(tmp_path) -> None:
    """Running migrate twice must not raise (post-8rqs DBs already have the column)."""
    db_path = str(tmp_path / "double_migrate.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    # First run: column already there, no-op.
    await migrate_db(db_path)
    # Second run: also no-op.
    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = [row[1] for row in await cursor.fetchall()]
        # Column appears exactly once (no duplicate-add).
        assert columns.count("base_url") == 1


@pytest.mark.asyncio
async def test_migrate_creates_backup_before_altering(tmp_path) -> None:
    """When migration ACTUALLY runs ALTER (column was missing), it must
    leave a ``.bak.<timestamp>`` file alongside the DB so the user has a
    rollback option if anything subsequent goes wrong.

    Brutus's scoping decision: no backfill (would mis-route legacy rows),
    but DO take the backup — ALTER itself is safe but the migration window
    is the right time for a defensive snapshot.
    """
    db_path = tmp_path / "to_migrate.db"

    # Create pre-8rqs DB.
    async with aiosqlite.connect(str(db_path)) as db:
        await db.execute(
            "CREATE TABLE IF NOT EXISTS shards ("
            "key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL, "
            "commitment BLOB NOT NULL, nonce BLOB NOT NULL, "
            "provider TEXT NOT NULL, prefix TEXT, charset TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key_alias TEXT NOT NULL REFERENCES shards(key_alias), "
            "var_name TEXT NOT NULL, env_path TEXT, decoy_hash TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.commit()

    await migrate_db(str(db_path))

    backups = list(tmp_path.glob("to_migrate.db.bak.*"))
    assert len(backups) >= 1, (
        f"no pre-migration backup created in {tmp_path}; existing files: {list(tmp_path.iterdir())}"
    )


@pytest.mark.asyncio
async def test_migrate_no_backup_when_already_migrated(tmp_path) -> None:
    """If the DB already has base_url (post-8rqs), migrate must NOT spam
    the directory with a fresh backup on every startup."""
    db_path = tmp_path / "already.db"
    async with aiosqlite.connect(str(db_path)) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    # Fresh DB has the column → migrate is a no-op for shards.base_url.
    await migrate_db(str(db_path))

    backups = list(tmp_path.glob("already.db.bak.*"))
    assert len(backups) == 0, (
        f"backup file created on no-op migration; got: {[p.name for p in backups]}"
    )

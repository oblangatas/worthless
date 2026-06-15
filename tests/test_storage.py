"""Tests for encrypted shard storage (STOR-01, STOR-02)."""

from __future__ import annotations

import aiosqlite
import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

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
async def test_migrate_adds_original_mode_column(tmp_path) -> None:
    """WOR-715: migration adds enrollments.original_mode to a pre-715 DB.

    Simulates an install done before this ticket: enrollments WITHOUT
    original_mode. After migrate_db the column exists and legacy rows
    backfill NULL (= "mode unknown, leave file mode as-is" at uninstall).
    """
    db_path = str(tmp_path / "pre_wor715.db")

    # Old enrollments schema: everything the current schema has EXCEPT
    # original_mode, so the migration's only job here is to add it.
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(
            """
            CREATE TABLE shards (
                key_alias   TEXT PRIMARY KEY,
                shard_b_enc BLOB NOT NULL,
                commitment  BLOB NOT NULL,
                nonce       BLOB NOT NULL,
                provider    TEXT NOT NULL
            );
            CREATE TABLE enrollments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key_alias  TEXT NOT NULL,
                var_name   TEXT NOT NULL,
                env_path   TEXT,
                decoy_hash TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(key_alias, var_name, env_path)
            );
            """
        )
        await db.execute(
            "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
            "VALUES (?, ?, ?, ?, ?)",
            ("legacy-key", b"b", b"c", b"n", "openai"),
        )
        await db.execute(
            "INSERT INTO enrollments (key_alias, var_name, env_path) VALUES (?, ?, ?)",
            ("legacy-key", "OPENAI_API_KEY", "/home/alice/proj/.env"),
        )
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(enrollments)")
        columns = {row[1] for row in await cursor.fetchall()}
        assert "original_mode" in columns, "migration did not add enrollments.original_mode"

        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", ("legacy-key",)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] is None, f"legacy row should backfill NULL, got {row[0]!r}"


@pytest.mark.asyncio
async def test_migrate_original_mode_idempotent(tmp_path) -> None:
    """WOR-715: running the original_mode migration twice doesn't error."""
    db_path = str(tmp_path / "original_mode_idempotent.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)
    await migrate_db(db_path)  # second run must not raise


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
async def test_store_enrolled_persists_original_mode(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """WOR-715: store_enrolled(original_mode=...) persists it on the enrollment row."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "mode-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/proj/.env",  # noqa: S108
        original_mode=0o644,
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", ("mode-alias",)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == 0o644


@pytest.mark.asyncio
async def test_store_enrolled_without_original_mode_is_null(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """WOR-715: omitting original_mode stores NULL (= leave file mode as-is)."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "no-mode-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/proj2/.env",  # noqa: S108
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", ("no-mode-alias",)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] is None


@pytest.mark.asyncio
async def test_store_enrolled_masks_file_type_bits(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """WOR-715: a raw st_mode (S_IFREG|0o644) is stored as permission bits only.

    Guards the phase-3 capture: a naive ``env_path.stat().st_mode`` yields
    ``0o100644``; the storage boundary must mask it to ``0o644`` so readers
    and ``f"{mode:o}"`` see permission bits, not the file-type bits.
    """
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "masked-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/proj3/.env",  # noqa: S108
        original_mode=0o100644,  # S_IFREG | 0o644 — the raw stat().st_mode
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", ("masked-alias",)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == 0o644, f"expected masked 0o644, got {row[0]:o}"


@pytest.mark.asyncio
async def test_add_enrollment_persists_original_mode(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """WOR-715: the add_enrollment path (re-lock / extra location) also persists
    the masked original_mode — lock.py uses this path, not only store_enrolled.
    """
    shard = stored_shard_from_split(sample_split_result)
    # First location creates the shard + its enrollment.
    await repo.store_enrolled(
        "multi-loc-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/loc-a/.env",  # noqa: S108
        original_mode=0o644,
    )
    # Second location enrolls via add_enrollment (no new shard).
    await repo.add_enrollment(
        "multi-loc-alias",
        var_name="OPENAI_API_KEY",
        env_path="/tmp/loc-b/.env",  # noqa: S108
        original_mode=0o100600,  # raw st_mode; masks to 0o600
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ? AND env_path = ?",
            ("multi-loc-alias", "/tmp/loc-b/.env"),  # noqa: S108
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == 0o600, f"expected masked 0o600, got {row[0]:o}"


@given(st.integers(min_value=0, max_value=0o177777))
@example(0o100644)  # S_IFREG | rw-r--r--   (the raw stat().st_mode of a normal .env)
@example(0o120777)  # S_IFLNK | rwxrwxrwx   (a symlink's st_mode)
@example(0o102755)  # S_IFREG | setgid | rwxr-xr-x
@example(0o101644)  # S_IFREG | sticky | rw-r--r--
def test_perm_bits_strips_all_but_permission_bits(raw_mode: int) -> None:
    """WOR-715 property: _perm_bits keeps ONLY the 0o777 permission bits.

    No file-type (S_IFREG/S_IFLNK) or special (setuid/setgid/sticky) bit may
    ever be persisted as original_mode — a refactor to ``& 0o7777`` (special
    bits) or no mask (type bits) is caught here, not in production.
    """
    from worthless.storage.repository import _perm_bits

    result = _perm_bits(raw_mode)
    assert result is not None
    assert result == raw_mode & 0o777  # low 9 permission bits preserved
    assert result & ~0o777 == 0  # nothing above 0o777 survives
    assert 0 <= result <= 0o777


def test_perm_bits_none_passthrough() -> None:
    """WOR-715: _perm_bits(None) stays None — 'mode unknown, leave file as-is'."""
    from worthless.storage.repository import _perm_bits

    assert _perm_bits(None) is None


@pytest.mark.asyncio
async def test_store_enrolled_relock_preserves_first_original_mode(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
) -> None:
    """WOR-715: re-enrolling the same (alias, var, path) keeps the FIRST mode.

    The true pre-lock mode is only knowable at the very first lock; a re-lock
    would stat the already-tightened 0o600. ``INSERT OR IGNORE`` must keep the
    original 0o644 — a future switch to UPSERT would silently record 0o600 as
    the 'original', defeating the whole feature.
    """
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "relock-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/relock/.env",  # noqa: S108
        original_mode=0o644,
    )
    # Re-enroll the SAME tuple as if re-locking the now-0o600 file.
    await repo.store_enrolled(
        "relock-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/relock/.env",  # noqa: S108
        original_mode=0o600,
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", ("relock-alias",)
        )
        rows = await cursor.fetchall()
    assert len(rows) == 1, f"expected exactly 1 enrollment row, got {rows}"
    assert rows[0][0] == 0o644, (
        f"re-lock must preserve the first-captured 0o644, got {oct(rows[0][0])} — "
        "INSERT OR IGNORE was likely changed to an UPSERT"
    )


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.integers(min_value=0, max_value=0o777))
@example(0o644)
@example(0o600)
@example(0o755)
@pytest.mark.asyncio
async def test_store_enrolled_original_mode_roundtrip_property(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
    mode: int,
) -> None:
    """WOR-715 / Wave 4: masked mode written by store_enrolled round-trips to DB."""
    shard = stored_shard_from_split(sample_split_result)
    alias = f"prop-{mode:o}"
    await repo.store_enrolled(
        alias,
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/prop/.env",  # noqa: S108
        original_mode=mode,
    )
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == mode


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.integers(min_value=0, max_value=0o777))
@example(0o644)
@example(0o755)
@pytest.mark.asyncio
async def test_add_enrollment_original_mode_roundtrip_property(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
    mode: int,
) -> None:
    """WOR-715 / Wave 4: add_enrollment path masks and persists original_mode."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "add-prop-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/add-prop-a/.env",  # noqa: S108
        original_mode=0o644,
    )
    env_b = f"/tmp/add-prop-b-{mode:o}/.env"  # noqa: S108
    await repo.add_enrollment(
        "add-prop-alias",
        var_name="OPENAI_API_KEY",
        env_path=env_b,
        original_mode=mode,
    )
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ? AND env_path = ?",
            ("add-prop-alias", env_b),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == mode


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.integers(min_value=0, max_value=0o177777))
@example(0o100644)
@example(0o120777)
@pytest.mark.asyncio
async def test_store_enrolled_masks_raw_st_mode_property(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_split_result,
    raw_mode: int,
) -> None:
    """WOR-715 Tier 1: raw stat().st_mode (type/special bits) masks to 0o777 in DB."""
    shard = stored_shard_from_split(sample_split_result)
    alias = f"raw-{raw_mode:o}"
    await repo.store_enrolled(
        alias,
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/raw/.env",  # noqa: S108
        original_mode=raw_mode,
    )
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT original_mode FROM enrollments WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == (raw_mode & 0o777)


@pytest.mark.asyncio
async def test_list_enrollments_surfaces_original_mode(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """WOR-435 plumbing: original_mode is readable via list_enrollments.

    It's write-only on the WOR-715 branch (no SELECT surfaces it). The
    uninstaller enumerates locked .env files and needs each one's original
    mode to restore permissions, so the read path must carry it.
    """
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "mode-read-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/read/.env",  # noqa: S108
        original_mode=0o644,
    )

    records = await repo.list_enrollments("mode-read-alias")
    assert len(records) == 1
    assert records[0].original_mode == 0o644


@pytest.mark.asyncio
async def test_get_enrollment_surfaces_original_mode(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """WOR-435 plumbing: get_enrollment also carries original_mode."""
    shard = stored_shard_from_split(sample_split_result)
    await repo.store_enrolled(
        "mode-get-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path="/tmp/get/.env",  # noqa: S108
        original_mode=0o600,
    )

    rec = await repo.get_enrollment("mode-get-alias", env_path="/tmp/get/.env")  # noqa: S108
    assert rec is not None
    assert rec.original_mode == 0o600


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


# ------------------------------------------------------------------
# WOR-705: per-key ceiling override — migration + setter
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_adds_ceiling_override(tmp_path) -> None:
    """An OLD-shape enrollment_config (no ceiling_override) gains the column.

    Builds a full-SCHEMA DB, then DROPs ceiling_override to simulate a
    pre-WOR-705 database — so the ALTER path is genuinely exercised, not
    satisfied trivially by the current SCHEMA.
    """
    db_path = str(tmp_path / "old_ceiling.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute("ALTER TABLE enrollment_config DROP COLUMN ceiling_override")
        await db.commit()
        cursor = await db.execute("PRAGMA table_info(enrollment_config)")
        before = {row[1] for row in await cursor.fetchall()}
    assert "ceiling_override" not in before, "setup: column should be absent pre-migration"

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(enrollment_config)")
        after = {row[1] for row in await cursor.fetchall()}
    assert "ceiling_override" in after, "migration did not add ceiling_override"


@pytest.mark.asyncio
async def test_migrate_ceiling_override_idempotent(tmp_path) -> None:
    """Migrating twice (column already present) does not error."""
    db_path = str(tmp_path / "ceiling_idempotent.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()
    await migrate_db(db_path)
    await migrate_db(db_path)  # second run must not raise


@pytest.mark.asyncio
async def test_set_ceiling_override_persists(tmp_db_path: str, fernet_key: bytes) -> None:
    """set_ceiling_override writes a valid override that reads back."""
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute("INSERT INTO enrollment_config (key_alias) VALUES ('k1')")
        await db.commit()

    ok = await repo.set_ceiling_override("k1", 200_000)
    assert ok is True

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT ceiling_override FROM enrollment_config WHERE key_alias = 'k1'"
        )
        (val,) = await cursor.fetchone()
    assert val == 200_000


@pytest.mark.asyncio
async def test_set_ceiling_override_missing_alias_returns_false(
    tmp_db_path: str, fernet_key: bytes
) -> None:
    """No enrollment_config row → setter reports no update (False)."""
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    ok = await repo.set_ceiling_override("nope", 200_000)
    assert ok is False


@pytest.mark.asyncio
async def test_set_ceiling_override_rejects_below_global(
    tmp_db_path: str, fernet_key: bytes
) -> None:
    """Raise-only: an override below the global ceiling is rejected."""
    from worthless.proxy.config import GLOBAL_CEILING_TOKENS

    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    with pytest.raises(ValueError):
        await repo.set_ceiling_override("k1", GLOBAL_CEILING_TOKENS - 1)


@pytest.mark.asyncio
async def test_set_ceiling_override_rejects_nonpositive_and_bool(
    tmp_db_path: str, fernet_key: bytes
) -> None:
    """Zero, negative, and bool (an int subclass) are all rejected."""
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    for bad in (0, -5):
        with pytest.raises(ValueError):
            await repo.set_ceiling_override("k1", bad)
    with pytest.raises(ValueError):
        await repo.set_ceiling_override("k1", True)  # bool is an int subclass


# ---------------------------------------------------------------------------
# WOR-651 / WOR-621 F4: OpenClaw rollback columns (shape-only, no key at rest)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_db_has_oc_rollback_columns(tmp_path) -> None:
    """A DB built from current SCHEMA includes the two OC rollback columns."""
    db_path = str(tmp_path / "fresh_oc.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}

    # G5-C: oc_original_base_url was dropped — the URL lives inside
    # oc_original_api_key_json (the MAC-bound source of truth).
    assert "oc_original_base_url" not in columns, "G5-C: oc_original_base_url must be gone"
    assert "oc_original_api_key_json" in columns, "oc_original_api_key_json not in SCHEMA"


@pytest.mark.asyncio
async def test_migrate_adds_oc_rollback_columns(tmp_path) -> None:
    """Migration adds both OC rollback columns to an old DB lacking them."""
    db_path = str(tmp_path / "old_no_oc.db")

    # Old shards table without the OC rollback columns. (enrollments is
    # included because earlier migrations — decoy_hash — touch it.)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS shards ("
            "key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL, "
            "commitment BLOB NOT NULL, nonce BLOB NOT NULL, "
            "provider TEXT NOT NULL, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key_alias TEXT NOT NULL REFERENCES shards(key_alias), "
            "var_name TEXT NOT NULL, env_path TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}

    # G5-C: migration no longer adds oc_original_base_url; an existing
    # old DB carrying that column will have it dropped (SQLite ≥3.35);
    # an old DB without it stays without it.
    assert "oc_original_base_url" not in columns, (
        "G5-C: migration must not add oc_original_base_url"
    )
    assert "oc_original_api_key_json" in columns, "oc_original_api_key_json not added by migrate"


@pytest.mark.asyncio
async def test_migrate_oc_rollback_columns_idempotent(tmp_path) -> None:
    """Running migrate twice on a fresh-schema DB doesn't error (idempotent)."""
    db_path = str(tmp_path / "oc_idempotent.db")

    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    await migrate_db(db_path)
    await migrate_db(db_path)  # Second run must not raise on duplicate columns.

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        columns = {row[1] for row in await cursor.fetchall()}
    # G5-C: oc_original_base_url was dropped from the schema.
    assert "oc_original_base_url" not in columns
    assert "oc_original_api_key_json" in columns


@pytest.mark.asyncio
async def test_upsert_locked_shard_oc_rollback_roundtrips(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """upsert_locked_shard persists OC rollback fields; fetch_encrypted reads them back."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.upsert_locked_shard(
        "oc-roundtrip",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-roundtrip/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("plaintext"),
    )

    enc = await repo.fetch_encrypted("oc-roundtrip")
    assert enc is not None
    # G5-C: oc_original_base_url is gone; the URL is inside the
    # oc_original_api_key_json record (see test_lock_capture_oc_rollback).
    assert enc.oc_original_api_key_json == '{"kind":"plaintext"}'


@pytest.mark.asyncio
async def test_upsert_locked_shard_without_oc_rollback_defaults_none(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Omitting the OC rollback params leaves the columns NULL (backward-compat)."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.upsert_locked_shard(
        "oc-omit",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-omit/v1",
    )

    enc = await repo.fetch_encrypted("oc-omit")
    assert enc is not None
    # G5-C: oc_original_base_url is gone from the row entirely.
    assert enc.oc_original_api_key_json is None


@pytest.mark.asyncio
async def test_store_enrolled_oc_rollback_roundtrips(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """store_enrolled threads OC rollback fields through to fetch_encrypted."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    ref = {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "oc-enrolled",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=None,
        base_url="https://api.openai.com/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("secretref", ref),
    )

    enc = await repo.fetch_encrypted("oc-enrolled")
    assert enc is not None
    # G5-C: oc_original_base_url is gone — apiKey record carries the shape.
    import json as _json

    decoded = _json.loads(enc.oc_original_api_key_json)
    assert decoded == {"kind": "secretref", "ref": ref}


def test_build_oc_rollback_apikey_record_plaintext_has_no_key() -> None:
    """plaintext record is shape-only — equals {"kind":"plaintext"}, no key bytes."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    out = build_oc_rollback_apikey_record("plaintext")
    assert out == '{"kind":"plaintext"}'
    assert "sk-" not in out
    assert "ref" not in out


def test_build_oc_rollback_apikey_record_secretref_roundtrips() -> None:
    """secretref record carries only the non-secret pointer, never a key."""
    import json as _json

    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    ref = {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}
    out = build_oc_rollback_apikey_record("secretref", ref)
    decoded = _json.loads(out)
    assert decoded == {"kind": "secretref", "ref": ref}
    assert "sk-" not in out


def test_build_oc_rollback_apikey_record_unknown_kind_raises() -> None:
    """An unknown kind is rejected — no silent fallthrough."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    with pytest.raises(ValueError):
        build_oc_rollback_apikey_record("ciphertext")


@pytest.mark.asyncio
async def test_oc_rollback_no_key_at_rest(
    repo: ShardRepository,
    tmp_db_path: str,
    sample_api_key_bytes: bytes,
    sample_split_result,
) -> None:
    """AC8: NEITHER the real client-held shard-A NOR the original plaintext
    API key ever appears in the stored shards row, and a plaintext OC rollback
    record carries no key bytes.

    NON-VACUOUS: unlike the prior version (which generated a throwaway random
    token the storage layer never saw, so the absence assertion was true by
    construction), this stores the ACTUAL ``sample_split_result`` material and
    checks for the REAL ``sample_split_result.shard_a`` bytes and the REAL
    source key (``sample_api_key_bytes``, the input that was split). If the
    storage layer ever persisted shard-A — or echoed the source key — into any
    column, this test would FAIL.
    """
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    # The real client-held shard-A from the same split that produced shard_b.
    # The client keeps this; the server must never store it.
    shard_a_bytes = bytes(sample_split_result.shard_a)

    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.upsert_locked_shard(
        "no-key-at-rest",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/no-key-at-rest/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("plaintext"),
    )

    # Read the ENTIRE raw row back and serialize every column.
    async with aiosqlite.connect(tmp_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM shards WHERE key_alias = 'no-key-at-rest'")
        row = await cursor.fetchone()
    assert row is not None

    serialized = b"".join(
        v if isinstance(v, bytes | bytearray) else str(v).encode() for v in tuple(row)
    )
    # Both the real shard-A AND the original plaintext key are absent — these
    # are values the storage layer actually handled (shard-A's XOR sibling
    # shard_b WAS stored), so the assertions have teeth.
    assert shard_a_bytes not in serialized, "shard-A leaked into the stored row!"
    assert bytes(sample_api_key_bytes) not in serialized, (
        "original plaintext API key leaked into the stored row!"
    )

    oc_json = row["oc_original_api_key_json"]
    assert oc_json == '{"kind":"plaintext"}'
    assert "sk-" not in oc_json


@pytest.mark.asyncio
async def test_upsert_locked_shard_overwrites_existing_oc_rollback_record(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """A second upsert of the SAME alias with DIFFERENT oc_original_* values
    overwrites the row — proving ON CONFLICT DO UPDATE SET oc_original_* =
    excluded.* fires (previously only the first-insert path was covered)."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.upsert_locked_shard(
        "oc-overwrite",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-overwrite/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("plaintext"),
    )

    # Second upsert: same alias, DIFFERENT oc rollback record.
    ref = {"source": "env", "provider": "anthropic", "id": "ANTHROPIC_API_KEY"}
    await repo.upsert_locked_shard(
        "oc-overwrite",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-overwrite/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("secretref", ref),
    )

    enc = await repo.fetch_encrypted("oc-overwrite")
    assert enc is not None
    # G5-C: oc_original_base_url is gone; the shape record carries the truth.
    import json as _json

    assert _json.loads(enc.oc_original_api_key_json) == {"kind": "secretref", "ref": ref}


@pytest.mark.asyncio
async def test_upsert_relock_omitting_oc_params_nulls_record(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """Re-locking the same alias while OMITTING the oc params silently NULLs
    the previously-stored rollback record (excluded.* defaults to None).

    This PINS the CURRENT behavior. F2 (unlock) will decide whether this
    silent null-out is desired or whether re-lock should preserve the prior
    rollback record; if F2 changes it, this test is the canary."""
    from worthless.openclaw.integration import build_oc_rollback_apikey_record

    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.upsert_locked_shard(
        "oc-relock",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-relock/v1",
        oc_original_api_key_json=build_oc_rollback_apikey_record("plaintext"),
    )

    # Re-lock the SAME alias, omitting the oc params (they default to None).
    await repo.upsert_locked_shard(
        "oc-relock",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-relock/v1",
    )

    enc = await repo.fetch_encrypted("oc-relock")
    assert enc is not None
    # G5-C: oc_original_base_url is gone from the row entirely.
    assert enc.oc_original_api_key_json is None


@pytest.mark.asyncio
async def test_store_enrolled_without_oc_rollback_defaults_none(
    repo: ShardRepository,
    sample_split_result,
) -> None:
    """store_enrolled without the oc params leaves both columns None."""
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    await repo.store_enrolled(
        "enrolled-no-oc",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=None,
        base_url="https://api.openai.com/v1",
    )

    enc = await repo.fetch_encrypted("enrolled-no-oc")
    assert enc is not None
    # G5-C: oc_original_base_url is gone from the row entirely.
    assert enc.oc_original_api_key_json is None


@pytest.mark.asyncio
async def test_fetch_encrypted_legacy_row_predating_oc_columns_returns_none_fields(
    tmp_path,
    fernet_key: bytes,
) -> None:
    """A row stored in a DB that predates the oc_original_* columns reads back
    with those fields as None after migration — graceful, not a KeyError."""
    db_path = str(tmp_path / "legacy_no_oc.db")

    # Build a minimal OLD-schema DB: shards WITHOUT oc_original_* (and without
    # shard_a_enc), plus enrollments so earlier migrations have their target.
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS shards ("
            "key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL, "
            "commitment BLOB NOT NULL, nonce BLOB NOT NULL, "
            "provider TEXT NOT NULL, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key_alias TEXT NOT NULL REFERENCES shards(key_alias), "
            "var_name TEXT NOT NULL, env_path TEXT, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        await db.execute(
            "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
            "VALUES (?, ?, ?, ?, ?)",
            ("legacy-oc", b"enc-b", b"commit", b"nonce", "openai"),
        )
        await db.commit()

    # Migration adds the new columns (oc_original_*, shard_a_enc, base_url, ...).
    await migrate_db(db_path)

    repo = ShardRepository(db_path, fernet_key)
    enc = await repo.fetch_encrypted("legacy-oc")
    assert enc is not None
    # G5-C: oc_original_base_url is gone from the row entirely.
    assert enc.oc_original_api_key_json is None


def test_encrypted_shard_repr_omits_oc_fields() -> None:
    """SR-04 regression lock: repr() of an EncryptedShard with a non-None
    oc_original_api_key_json must NOT leak the JSON into the string form.
    (G5-C: oc_original_base_url is gone, so this now only covers the JSON.)"""
    sensitive_json = '{"kind":"secretref","ref":{"id":"OPENAI_API_KEY"}}'
    enc = EncryptedShard(
        shard_b_enc=b"x" * 16,
        commitment=b"c" * 8,
        nonce=b"n" * 12,
        provider="openai",
        oc_original_api_key_json=sensitive_json,
    )

    text = repr(enc)
    assert sensitive_json not in text
    # Sanity: it is still a useful repr.
    assert "EncryptedShard(" in text


@pytest.mark.asyncio
async def test_fetch_encrypted_against_hand_inserted_raw_row(
    repo: ShardRepository,
    tmp_db_path: str,
) -> None:
    """Hand-INSERT a shards row via raw SQL with a known
    oc_original_api_key_json, then read it via fetch_encrypted. Pins the
    SELECT column list independent of the write path (upsert/store_enrolled).
    G5-C: oc_original_base_url is no longer a column."""
    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "INSERT INTO shards "
            "(key_alias, shard_b_enc, commitment, nonce, provider, "
            "oc_original_api_key_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "hand-row",
                b"enc-b",
                b"commit",
                b"nonce",
                "openai",
                '{"kind":"plaintext"}',
            ),
        )
        await db.commit()

    enc = await repo.fetch_encrypted("hand-row")
    assert enc is not None
    assert enc.oc_original_api_key_json == '{"kind":"plaintext"}'

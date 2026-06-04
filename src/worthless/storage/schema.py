"""SQLite schema and initialisation for encrypted shard storage."""

from __future__ import annotations

import time

import aiosqlite

# Characters that would break out of a single-quoted SQL literal or are
# otherwise illegal in a SQLite path argument. ``VACUUM INTO`` does not
# accept parameterised paths (``VACUUM INTO ?`` is a syntax error in
# SQLite), so the backup path MUST be inlined into the SQL string. This
# guard makes the inlining safe by refusing any path that could escape
# the surrounding ``'…'`` quotes or terminate the statement early.
#
# Threat model: ``db_path`` is operator-controlled (``WORTHLESS_DB_PATH``
# env var or composed from ``WORTHLESS_HOME``); not network-reachable.
# This is operator-self-pwn / config-error hardening, not an
# anti-injection defense against an external attacker.
_UNSAFE_DB_PATH_CHARS = frozenset("'\x00\r\n\t")


def _assert_safe_db_path(db_path: str) -> None:
    """Refuse db paths that would corrupt the migration ``VACUUM INTO`` SQL.

    See ``_UNSAFE_DB_PATH_CHARS`` for the rationale and threat-model
    framing. Any control char or single quote in the path raises
    ``ValueError`` before the f-string interpolation happens, making
    the subsequent inlined SQL provably safe.
    """
    bad = _UNSAFE_DB_PATH_CHARS.intersection(db_path)
    if bad:
        raise ValueError(
            f"db_path {db_path!r} contains unsafe character(s) {sorted(bad)!r}; "
            "set WORTHLESS_HOME / WORTHLESS_DB_PATH to a path without quotes "
            "or control characters"
        )


SCHEMA = """\
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS shards (
    key_alias   TEXT PRIMARY KEY,
    shard_b_enc BLOB NOT NULL,
    commitment  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    provider    TEXT NOT NULL,
    prefix      TEXT,
    charset     TEXT,
    base_url    TEXT,
    shard_a_enc BLOB,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spend_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_alias  TEXT NOT NULL,
    tokens     INTEGER NOT NULL,
    model      TEXT,
    provider   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS enrollment_config (
    key_alias            TEXT PRIMARY KEY,
    spend_cap            REAL,
    rate_limit_rps       REAL NOT NULL DEFAULT 100.0,
    token_budget_daily   INTEGER,
    token_budget_weekly  INTEGER,
    token_budget_monthly INTEGER,
    time_window          TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS enrollments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_alias  TEXT NOT NULL REFERENCES shards(key_alias) ON DELETE CASCADE,
    var_name   TEXT NOT NULL,
    env_path   TEXT,
    decoy_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(key_alias, var_name, env_path)
);

CREATE TABLE IF NOT EXISTS pending_charges (
    handle     TEXT PRIMARY KEY,
    key_alias  TEXT NOT NULL,
    estimate   INTEGER NOT NULL,
    provider   TEXT NOT NULL,
    model      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_spend_log_alias ON spend_log (key_alias);
CREATE INDEX IF NOT EXISTS idx_spend_log_alias_created ON spend_log (key_alias, created_at);
CREATE INDEX IF NOT EXISTS idx_enrollments_alias ON enrollments (key_alias);
CREATE INDEX IF NOT EXISTS idx_enrollments_decoy_hash
    ON enrollments (decoy_hash) WHERE decoy_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollments_null_path
    ON enrollments (key_alias, var_name) WHERE env_path IS NULL;
CREATE INDEX IF NOT EXISTS idx_pending_charges_alias ON pending_charges (key_alias);
CREATE INDEX IF NOT EXISTS idx_pending_charges_created ON pending_charges (created_at);
"""


async def _migrate_shard_format_columns(db: aiosqlite.Connection, shard_columns: set[str]) -> None:
    """WOR-207: prefix/charset columns for format-preserving split."""
    _SHARD_MIGRATIONS = {
        "prefix": "ALTER TABLE shards ADD COLUMN prefix TEXT",
        "charset": "ALTER TABLE shards ADD COLUMN charset TEXT",
    }
    for col_name, stmt in _SHARD_MIGRATIONS.items():
        if col_name not in shard_columns:
            try:
                await db.execute(stmt)
            except Exception as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
    await db.commit()


async def _migrate_base_url_column(
    db: aiosqlite.Connection, db_path: str, shard_columns: set[str]
) -> None:
    """worthless-8rqs: add ``shards.base_url`` (nullable, no backfill).

    Backfilling NULL → per-provider default could silently mis-route legacy
    OpenAI-protocol rows that pointed at OpenRouter via the old env-var
    workaround. Phase-6 readers raise a "predates upstream URL storage"
    error on NULL, forcing explicit re-lock for affected aliases.
    """
    if "base_url" in shard_columns:
        return
    # Defensive snapshot via SQLite's VACUUM INTO — clean copy that respects
    # WAL state. Only runs the first time we add the column. ``VACUUM INTO``
    # cannot use a parameterised path (SQLite syntax limitation), so the
    # path is inlined; ``_assert_safe_db_path`` proves the inlining is safe
    # by refusing any path with quotes or control chars.
    _assert_safe_db_path(db_path)
    backup_path = f"{db_path}.bak.{int(time.time())}"
    # SQLite VACUUM INTO has no parameter form; path is inlined. Validator
    # above proves the inlining is safe (rejects ', NUL, CR, LF, TAB).
    # The nosemgrep annotation MUST be on the line immediately above the
    # flagged call — not 2-3 lines up — or Semgrep's parser ignores it
    # and the rule fires on the next CI scan (PR #127 had this regress
    # twice). Inline form keeps the annotation locked to the call site.
    # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query
    await db.execute(f"VACUUM INTO '{backup_path}'")  # noqa: S608
    try:
        await db.execute("ALTER TABLE shards ADD COLUMN base_url TEXT")
        await db.commit()
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


async def _migrate_shard_a_enc_column(db: aiosqlite.Connection, shard_columns: set[str]) -> None:
    """worthless-16x2: add ``shards.shard_a_enc`` (nullable, no backfill).

    Pre-16x2 rows have NULL here — the proxy falls back to the legacy
    header-based shard-A path for those aliases.  After the operator
    re-locks an alias the column is populated and the stable-token path
    takes over automatically.
    """
    if "shard_a_enc" in shard_columns:
        return
    try:
        await db.execute("ALTER TABLE shards ADD COLUMN shard_a_enc BLOB")
        await db.commit()
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


async def init_db(db_path: str) -> None:
    """Create tables and enable WAL journal mode."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.executescript(SCHEMA)
        await db.execute("PRAGMA journal_mode=WAL")
        await db.commit()


async def _prune_old_spend_log(db: aiosqlite.Connection) -> None:
    """WOR-182: prune spend_log entries older than 90 days."""
    try:
        await db.execute("DELETE FROM spend_log WHERE created_at < datetime('now', '-90 days')")
        await db.commit()
    except Exception:  # noqa: S110 — spend_log may not exist in pre-schema DBs  # nosec B110
        pass


async def _migrate_decoy_hash_column(db: aiosqlite.Connection) -> None:
    """WOR-31: add decoy_hash column to enrollments.

    The early-return-on-column-exists guard used to skip BOTH the ALTER
    and the CREATE INDEX. If a previous migration crashed AFTER ALTER
    but BEFORE the index commit, subsequent runs would see the column
    and exit — never converging on the missing index. Now: ALTER is
    column-conditional (skipped if present), CREATE INDEX is always
    attempted (idempotent via IF NOT EXISTS).
    """
    cursor = await db.execute("PRAGMA table_info(enrollments)")
    columns = {row[1] for row in await cursor.fetchall()}
    try:
        if "decoy_hash" not in columns:
            await db.execute("ALTER TABLE enrollments ADD COLUMN decoy_hash TEXT")
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_enrollments_decoy_hash "
            "ON enrollments (decoy_hash) WHERE decoy_hash IS NOT NULL"
        )
        await db.commit()
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


async def _migrate_pending_charges(db: aiosqlite.Connection) -> None:
    """Create the write-ahead pre-charge ledger table + indexes (WOR-659).

    Pure-additive and idempotent. Committed independently so it lands even on
    very old DBs that trip the enrollment_config early-return in migrate_db.
    """
    await db.executescript(
        "CREATE TABLE IF NOT EXISTS pending_charges ("
        " handle TEXT PRIMARY KEY, key_alias TEXT NOT NULL,"
        " estimate INTEGER NOT NULL, provider TEXT NOT NULL, model TEXT,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now')));"
        "CREATE INDEX IF NOT EXISTS idx_pending_charges_alias"
        " ON pending_charges (key_alias);"
        "CREATE INDEX IF NOT EXISTS idx_pending_charges_created"
        " ON pending_charges (created_at);"
    )
    # Add the settle-metadata columns to a pre-existing (initial-shape) table.
    cur = await db.execute("PRAGMA table_info(pending_charges)")
    cols = {row[1] for row in await cur.fetchall()}
    if "provider" not in cols:
        await db.execute(
            "ALTER TABLE pending_charges ADD COLUMN provider TEXT NOT NULL DEFAULT 'openai'"
        )
    if "model" not in cols:
        await db.execute("ALTER TABLE pending_charges ADD COLUMN model TEXT")
    await db.commit()


async def migrate_db(db_path: str) -> None:
    """Apply forward-only migrations for existing databases."""
    async with aiosqlite.connect(db_path) as db:
        await _migrate_pending_charges(db)

        await _prune_old_spend_log(db)
        await _migrate_decoy_hash_column(db)

        cursor = await db.execute("PRAGMA table_info(shards)")
        shard_columns = {row[1] for row in await cursor.fetchall()}
        await _migrate_shard_format_columns(db, shard_columns)
        await _migrate_base_url_column(db, db_path, shard_columns)
        await _migrate_shard_a_enc_column(db, shard_columns)

        # WOR-183: Add rules engine columns to enrollment_config
        # Guard: table may not exist in very old DBs
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='enrollment_config'"
        )
        if await cursor.fetchone() is None:
            return
        cursor = await db.execute("PRAGMA table_info(enrollment_config)")
        config_columns = {row[1] for row in await cursor.fetchall()}
        # Hardcoded migration statements — not dynamic SQL
        _ALTER = "ALTER TABLE enrollment_config ADD COLUMN"
        _CONFIG_MIGRATIONS = {
            "token_budget_daily": _ALTER + " token_budget_daily INTEGER",
            "token_budget_weekly": _ALTER + " token_budget_weekly INTEGER",
            "token_budget_monthly": _ALTER + " token_budget_monthly INTEGER",
            "time_window": _ALTER + " time_window TEXT",
        }
        for col_name, stmt in _CONFIG_MIGRATIONS.items():
            if col_name not in config_columns:
                try:
                    await db.execute(stmt)
                except Exception as exc:
                    if "duplicate column" not in str(exc).lower():
                        raise
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_spend_log_alias_created "
            "ON spend_log (key_alias, created_at)"
        )
        await db.commit()

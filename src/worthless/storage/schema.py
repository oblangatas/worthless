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
    -- WOR-651/F4: shape-only OpenClaw rollback record so unlock (F2) can
    -- restore the original provider entry WITHOUT ever storing the real key.
    -- The full key-redacted original entry (including its baseUrl) lives in
    -- ``oc_original_api_key_json`` and is MAC-bound via ``oc_rollback_mac``.
    -- A prior ``oc_original_base_url`` column was dropped in G5-C: it
    -- duplicated data already present in the MAC-bound JSON and was NOT
    -- MAC-bound itself — a footgun. Stage A of unlock parses the URL from
    -- the JSON record (the source of truth), never from a fast column.
    oc_original_api_key_json TEXT,
    -- WOR-621 F2 G2 (decision 4): HMAC-SHA256 tag (hex) over
    -- ``oc_original_api_key_json``, keyed by the fernet-derived MAC subkey
    -- (same subkey the ``decoy_hash`` column uses). Unlock recomputes and
    -- constant-time-compares; a DB-write attacker who flips the JSON (e.g.
    -- secretref→plaintext) leaves a stale tag here, so unlock refuses the
    -- row → entry stays on the proxy, plaintext is never synthesized from a
    -- tampered record.
    oc_rollback_mac          TEXT,
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
    ceiling_override     INTEGER,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS enrollments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_alias  TEXT NOT NULL REFERENCES shards(key_alias) ON DELETE CASCADE,
    var_name   TEXT NOT NULL,
    env_path   TEXT,
    decoy_hash TEXT,
    original_mode INTEGER,
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


async def _add_columns_if_missing(
    db: aiosqlite.Connection,
    migrations: dict[str, str],
    existing_columns: set[str],
) -> None:
    """Run ``ALTER TABLE ... ADD COLUMN`` statements for each missing column.

    Each entry in ``migrations`` is ``{col_name: full_ALTER_statement}``.
    Columns already present in ``existing_columns`` are skipped. A racing
    "duplicate column" error (two callers initialising the DB at once) is
    swallowed; any other error propagates. Caller is responsible for the
    enclosing ``db.commit()`` -- this helper does NOT commit so the caller
    can batch multiple migrations into one transaction.

    Extracts the pattern that ``_migrate_shard_format_columns`` and
    ``_migrate_oc_rollback_columns`` both used to inline -- consolidating
    drops cognitive complexity on the latter back under the SonarCloud
    ceiling (PR #276 CodeRabbit nit).
    """
    for col_name, stmt in migrations.items():
        if col_name in existing_columns:
            continue
        try:
            await db.execute(stmt)
        except Exception as exc:
            if "duplicate column" not in str(exc).lower():
                raise


async def _migrate_shard_format_columns(db: aiosqlite.Connection, shard_columns: set[str]) -> None:
    """WOR-207: prefix/charset columns for format-preserving split."""
    await _add_columns_if_missing(
        db,
        {
            "prefix": "ALTER TABLE shards ADD COLUMN prefix TEXT",
            "charset": "ALTER TABLE shards ADD COLUMN charset TEXT",
        },
        shard_columns,
    )
    await db.commit()


async def _migrate_oc_rollback_columns(db: aiosqlite.Connection, shard_columns: set[str]) -> None:
    """WOR-651/F4 + WOR-621 F2 G2 + G5-C: OpenClaw rollback columns on ``shards``.

    ``oc_original_api_key_json`` holds the full key-redacted original entry
    (including its baseUrl) — shape-only / non-secret. ``oc_rollback_mac``
    (G2) binds that JSON to a fernet-keyed HMAC so a DB-write attacker
    can't flip the record (e.g. secretref→plaintext) without the next
    unlock noticing.

    G5-C drop: a prior ``oc_original_base_url`` column duplicated data
    already in the MAC-bound JSON AND was NOT MAC-bound itself (a DB-write
    attacker could flip it silently). Forward-only ALTER TABLE DROP COLUMN
    removes it from any DB carrying it. SQLite ≥3.35 (March 2021). The
    column is also removed from the SCHEMA DDL above so a fresh DB never
    creates it. Stage A of unlock has always parsed the URL from the JSON
    record (the source of truth), so the drop is byte-stable on restore.

    Mirrors :func:`_migrate_shard_format_columns`: duplicate-column-tolerant
    ALTERs, nullable, no backfill.
    """
    _oc_migrations = {
        "oc_original_api_key_json": ("ALTER TABLE shards ADD COLUMN oc_original_api_key_json TEXT"),
        "oc_rollback_mac": "ALTER TABLE shards ADD COLUMN oc_rollback_mac TEXT",
    }
    await _add_columns_if_missing(db, _oc_migrations, shard_columns)
    # G5-C: drop the dead duplicate column if present on an existing DB.
    # SQLite ≥3.35 supports ALTER TABLE … DROP COLUMN; on older runtimes
    # this raises and the column is left in place (the column being dead
    # data already, leaving it costs nothing).
    if "oc_original_base_url" in shard_columns:
        try:
            await db.execute("ALTER TABLE shards DROP COLUMN oc_original_base_url")
        except Exception as exc:
            msg = str(exc).lower()
            # Pre-3.35 SQLite reports "near 'DROP': syntax error" — accept
            # the column lingering rather than failing init.
            if "syntax error" not in msg and "no such column" not in msg:
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


async def _migrate_original_mode_column(db: aiosqlite.Connection) -> None:
    """WOR-715: add enrollments.original_mode (nullable, no backfill).

    Stores the .env's pre-lock POSIX mode so uninstall can restore the
    original permissions, not just the contents. ``safe_rewrite`` rewrites
    every locked .env onto a fresh tmpfile created 0o600 + an explicit
    ``fchmod(0o600)`` with no ``copymode`` from the original, so a once-0o644
    .env becomes 0o600 on lock. Without this column uninstall would silently
    leave it at 0o600. NULL = "mode unknown (pre-715 install), leave as-is".
    """
    cursor = await db.execute("PRAGMA table_info(enrollments)")
    columns = {row[1] for row in await cursor.fetchall()}
    if "original_mode" not in columns:
        try:
            await db.execute("ALTER TABLE enrollments ADD COLUMN original_mode INTEGER")
            await db.commit()
        except Exception as exc:
            if "duplicate column" not in str(exc).lower():
                raise


async def migrate_db(db_path: str) -> None:
    """Apply forward-only migrations for existing databases."""
    async with aiosqlite.connect(db_path) as db:
        await _migrate_pending_charges(db)

        await _prune_old_spend_log(db)
        await _migrate_decoy_hash_column(db)
        await _migrate_original_mode_column(db)

        cursor = await db.execute("PRAGMA table_info(shards)")
        shard_columns = {row[1] for row in await cursor.fetchall()}
        await _migrate_shard_format_columns(db, shard_columns)
        await _migrate_oc_rollback_columns(db, shard_columns)
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
            # WOR-705: per-key fail-closed ceiling override (raise-only).
            "ceiling_override": _ALTER + " ceiling_override INTEGER",
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

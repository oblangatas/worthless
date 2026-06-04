"""Schema tests for the ``pending_charges`` ledger table (write-ahead pre-charge).

The spend cap's durable HOLD lives in ``pending_charges``: a request reserves its
estimated cost here BEFORE spending, then settles to the actual amount after. The
durability is the whole point — a hold must survive a crash so the cap reads it
back on the next boot. These tests pin that the table + its indexes exist on a
freshly-created DB (via ``SCHEMA``) and on a legacy DB upgraded through
``migrate_db``.
"""

from __future__ import annotations

import aiosqlite
import pytest

from worthless.storage.schema import SCHEMA, migrate_db


async def _names(db: aiosqlite.Connection, kind: str) -> set[str]:
    cur = await db.execute("SELECT name FROM sqlite_master WHERE type=?", (kind,))
    return {row[0] for row in await cur.fetchall()}


@pytest.mark.asyncio
async def test_schema_creates_pending_charges_table_and_indexes(tmp_path) -> None:
    """A fresh DB built from SCHEMA has the table + both indexes."""
    db_path = str(tmp_path / "fresh.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()
        tables = await _names(db, "table")
        indexes = await _names(db, "index")
    assert "pending_charges" in tables
    assert "idx_pending_charges_alias" in indexes
    assert "idx_pending_charges_created" in indexes


@pytest.mark.asyncio
async def test_pending_charges_has_expected_columns(tmp_path) -> None:
    """Columns: handle (PK) + key_alias + estimate + created_at."""
    db_path = str(tmp_path / "cols.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        cur = await db.execute("PRAGMA table_info(pending_charges)")
        cols = {row[1]: row for row in await cur.fetchall()}
    assert set(cols) == {"handle", "key_alias", "estimate", "provider", "model", "created_at"}
    # PRAGMA table_info column index 5 is the primary-key flag.
    assert cols["handle"][5] == 1


@pytest.mark.asyncio
async def test_migrate_db_adds_pending_charges_to_legacy_db(tmp_path) -> None:
    """A legacy DB lacking the table gets it (and its indexes) via migrate_db.

    Simulates a pre-pre-charge database by building the full schema then dropping
    the table — crash-orphan recovery on existing installs depends on this.
    """
    db_path = str(tmp_path / "legacy.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.execute("DROP TABLE IF EXISTS pending_charges")
        await db.execute("DROP INDEX IF EXISTS idx_pending_charges_alias")
        await db.execute("DROP INDEX IF EXISTS idx_pending_charges_created")
        await db.commit()

    await migrate_db(db_path)

    async with aiosqlite.connect(db_path) as db:
        tables = await _names(db, "table")
        indexes = await _names(db, "index")
    assert "pending_charges" in tables
    assert "idx_pending_charges_alias" in indexes
    assert "idx_pending_charges_created" in indexes

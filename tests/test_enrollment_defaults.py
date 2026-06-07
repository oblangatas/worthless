"""Tests for WOR-168: default spend cap on enrollment."""

from __future__ import annotations

import aiosqlite
import pytest

from worthless.defaults import DEFAULT_SPEND_CAP_TOKENS
from worthless.proxy.rules import SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard


def _make_shard() -> StoredShard:
    """Minimal shard for enrollment tests — no real key material needed."""
    return StoredShard(
        shard_b=bytearray(b"\x01" * 32),
        commitment=bytearray(b"\x02" * 32),
        nonce=bytearray(b"\x03" * 16),
        provider="openai",
    )


@pytest.mark.asyncio
async def test_new_enrollment_gets_default_spend_cap(repo: ShardRepository, tmp_db_path: str):
    """store_enrolled() should create an enrollment_config row with DEFAULT_SPEND_CAP_TOKENS."""
    await repo.store_enrolled("openai-abc123", _make_shard(), var_name="OPENAI_API_KEY")

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", ("openai-abc123",)
        )
        row = await cursor.fetchone()

    assert row is not None, "enrollment_config row should be created"
    assert row[0] == DEFAULT_SPEND_CAP_TOKENS


@pytest.mark.asyncio
async def test_custom_spend_cap_honored(repo: ShardRepository, tmp_db_path: str):
    """store_enrolled(spend_cap=5000) should store 5000, not the default."""
    await repo.store_enrolled(
        "openai-custom", _make_shard(), var_name="OPENAI_API_KEY", spend_cap=5000
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", ("openai-custom",)
        )
        row = await cursor.fetchone()

    assert row is not None
    assert row[0] == 5000


@pytest.mark.asyncio
async def test_explicit_none_means_unlimited(repo: ShardRepository, tmp_db_path: str):
    """store_enrolled(spend_cap=None) should store NULL (no cap)."""
    await repo.store_enrolled(
        "openai-unlim", _make_shard(), var_name="OPENAI_API_KEY", spend_cap=None
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", ("openai-unlim",)
        )
        row = await cursor.fetchone()

    assert row is not None
    assert row[0] is None


@pytest.mark.asyncio
async def test_re_enrollment_does_not_overwrite_config(repo: ShardRepository, tmp_db_path: str):
    """Second store_enrolled for the same alias should keep the original spend cap."""
    await repo.store_enrolled("openai-re", _make_shard(), var_name="OPENAI_API_KEY", spend_cap=5000)
    await repo.store_enrolled(
        "openai-re", _make_shard(), var_name="OPENAI_KEY_2", env_path="/app/.env.local"
    )

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", ("openai-re",)
        )
        row = await cursor.fetchone()

    assert row is not None
    assert row[0] == 5000


@pytest.mark.asyncio
async def test_spend_cap_rule_enforces_default(repo: ShardRepository, tmp_db_path: str):
    """After enrollment with default cap, SpendCapRule should deny when tokens exceed it."""
    await repo.store_enrolled("openai-enforce", _make_shard(), var_name="OPENAI_API_KEY")

    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            ("openai-enforce", DEFAULT_SPEND_CAP_TOKENS + 1, "gpt-4", "openai"),
        )
        await db.commit()

    async with aiosqlite.connect(tmp_db_path) as db:
        rule = SpendCapRule(db=db)
        result = await rule.evaluate("openai-enforce", object())
        assert result.denial is not None, "SpendCapRule should deny when tokens exceed default cap"
        assert result.denial.status_code == 402


@pytest.mark.asyncio
async def test_spend_cap_rule_allows_under_default(repo: ShardRepository, tmp_db_path: str):
    """After enrollment with default cap, requests under cap should pass."""
    await repo.store_enrolled("openai-ok", _make_shard(), var_name="OPENAI_API_KEY")

    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            ("openai-ok", 1000, "gpt-4", "openai"),
        )
        await db.commit()

    async with aiosqlite.connect(tmp_db_path) as db:
        rule = SpendCapRule(db=db)
        # Small valid request — 1000 spent + tiny estimate well under 1B default.
        result = await rule.evaluate("openai-ok", object(), body=b'{"max_tokens": 50}')
        assert result.denial is None

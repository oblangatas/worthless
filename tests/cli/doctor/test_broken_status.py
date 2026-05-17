"""WOR-464: broken_status check.

An enrollment is BROKEN when its shard_a file is missing on disk.
Repair: surgical delete of the dangling enrollment + shard rows.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import broken_status
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository, StoredShard


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def repo(fake_home):
    return ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))


@pytest.fixture
def ctx(fake_home, repo):
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


def _seed_enrollment(repo: ShardRepository, alias: str) -> None:
    """Helper: insert a shard + enrollment row for ``alias``."""
    shard = StoredShard(
        shard_b=bytearray(b"\x00" * 32),
        commitment=bytearray(b"\x00" * 32),
        nonce=bytearray(b"\x00" * 12),
        provider="openai",
    )
    asyncio.run(repo.initialize())
    asyncio.run(
        repo.store_enrolled(
            alias,
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/fake/.env",
        )
    )


def test_no_findings_when_shard_a_present(ctx, fake_home, repo) -> None:
    """Enrollment + matching shard_a file → ok."""
    _seed_enrollment(repo, "my-key")
    (fake_home.shard_a_dir / "my-key").write_bytes(b"\x01" * 32)

    result = broken_status.run(ctx)
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_detects_missing_shard_a(ctx, fake_home, repo) -> None:
    """Enrollment without shard_a file → warn finding."""
    _seed_enrollment(repo, "my-key")
    # No shard_a file written.

    result = broken_status.run(ctx)
    assert result["status"] == "warn"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["key_alias"] == "my-key"
    assert result["findings"][0]["inferred_status"] == "BROKEN"


def test_fix_deletes_broken_enrollment(ctx, fake_home, repo) -> None:
    """``fix=True`` removes the dangling enrollment row."""
    _seed_enrollment(repo, "my-key")
    ctx.fix = True

    result = broken_status.run(ctx)
    remaining = asyncio.run(repo.list_enrollments())
    assert not any(e.key_alias == "my-key" for e in remaining)
    assert result["status"] == "ok"


def test_dry_run_does_not_delete(ctx, fake_home, repo) -> None:
    """``dry_run=True`` keeps the row, returns warn."""
    _seed_enrollment(repo, "my-key")
    ctx.fix = True
    ctx.dry_run = True

    result = broken_status.run(ctx)
    remaining = asyncio.run(repo.list_enrollments())
    assert any(e.key_alias == "my-key" for e in remaining)
    assert result["status"] == "warn"
    assert result["fixed"] == []


def test_fixable_true(ctx) -> None:
    """broken_status declares fixable=True."""
    result = broken_status.run(ctx)
    assert result["fixable"] is True

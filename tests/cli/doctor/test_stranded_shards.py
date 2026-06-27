"""WOR-464: stranded shard-A files check."""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import stranded_shards
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def ctx(fake_home):
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


def test_no_stranded_when_empty(ctx) -> None:
    """Empty shard_a dir → ok with no findings."""
    result = stranded_shards.run(ctx)
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_detects_stranded_shard(ctx, fake_home) -> None:
    """File in shard_a/ with no matching DB row → finding."""
    stranded = fake_home.shard_a_dir / "ghost-alias"
    stranded.write_bytes(b"\x00" * 32)

    result = stranded_shards.run(ctx)
    assert result["status"] == "warn"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["shard_path"] == str(stranded)


def test_fix_unlinks_stranded(ctx, fake_home) -> None:
    """``fix=True`` removes the stranded file."""
    stranded = fake_home.shard_a_dir / "ghost-alias"
    stranded.write_bytes(b"\x00" * 32)

    ctx.fix = True
    result = stranded_shards.run(ctx)
    assert not stranded.exists()
    assert result["status"] == "ok"
    assert len(result["fixed"]) == 1


def test_dry_run_does_not_unlink(ctx, fake_home) -> None:
    """``fix=True, dry_run=True`` lists but does not delete."""
    stranded = fake_home.shard_a_dir / "ghost-alias"
    stranded.write_bytes(b"\x00" * 32)

    ctx.fix = True
    ctx.dry_run = True
    result = stranded_shards.run(ctx)
    assert stranded.exists()
    assert result["fixed"] == []
    assert result["status"] == "warn"


def test_fixable_is_true(ctx) -> None:
    """stranded_shards declares fixable=True."""
    result = stranded_shards.run(ctx)
    assert result["fixable"] is True

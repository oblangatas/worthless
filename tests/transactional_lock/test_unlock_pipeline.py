"""Transactional-unlock invariants for ``worthless unlock`` across N keys.

Mirrors ``test_lock_pipeline.py``: either every alias is reconstructed
AND ``.env`` is fully rewritten with plaintext + BASE_URLs removed,
or the ``.env`` is byte-identical to the locked state AND the DB
still contains every shard/enrollment.

WOR-343 regression suite.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_key

runner = CliRunner()


@pytest.fixture()
def three_key_env(tmp_path: Path) -> Path:
    env = tmp_path / ".env"
    oa1 = fake_key("sk-" + "proj-", seed="unlock-pipeline-openai-1")
    oa2 = fake_key("sk-" + "proj-", seed="unlock-pipeline-openai-2")
    an1 = fake_anthropic_key()
    env.write_text(f"OPENAI_API_KEY_A={oa1}\nOPENAI_API_KEY_B={oa2}\nANTHROPIC_API_KEY={an1}\n")
    return env


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _env_glob_siblings(env_path: Path) -> list[str]:
    return sorted(p.name for p in env_path.parent.glob(".env*"))


def _lock(env_path: Path, home: WorthlessHome) -> None:
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_path)],
        env={"WORTHLESS_HOME": str(home.base_dir)},
    )
    assert result.exit_code == 0, result.output


def _tamper_first_shard(home: WorthlessHome) -> None:
    """Corrupt one row's commitment so HMAC verify will fail in pass-1."""
    conn = sqlite3.connect(str(home.db_path))
    try:
        # Per CodeRabbit nitpick: explicit ORDER BY so the chosen shard is
        # deterministic across SQLite implementations / page-layout changes.
        # Without ORDER BY, "LIMIT 1" picks any row — works today but flakes
        # on a different SQLite build or after a schema-rewriting migration.
        conn.execute(
            "UPDATE shards SET commitment = randomblob(32) "
            "WHERE key_alias = (SELECT key_alias FROM shards "
            "ORDER BY key_alias LIMIT 1)"
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. Happy path: 3 keys round-trip cleanly
# ---------------------------------------------------------------------------


class TestBatchUnlockHappyPath:
    def test_round_trip_byte_identical(self, home_dir: WorthlessHome, three_key_env: Path) -> None:
        original_sha = _sha256_of(three_key_env)
        _lock(three_key_env, home_dir)
        assert _sha256_of(three_key_env) != original_sha

        result = runner.invoke(
            app,
            ["unlock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert _sha256_of(three_key_env) == original_sha

        repo = _repo(home_dir)
        assert asyncio.run(repo.list_enrollments()) == []


# ---------------------------------------------------------------------------
# 2. All-or-nothing: tamper one shard → .env byte-identical
# ---------------------------------------------------------------------------


class TestBatchUnlockAllOrNothingEnvIdentical:
    def test_tamper_leaves_env_byte_identical(
        self, home_dir: WorthlessHome, three_key_env: Path
    ) -> None:
        _lock(three_key_env, home_dir)
        locked_sha = _sha256_of(three_key_env)

        _tamper_first_shard(home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, "Tampered shard must cause unlock to fail; got success."
        assert _sha256_of(three_key_env) == locked_sha, (
            ".env was mutated despite a tampered-shard refusal."
        )


# ---------------------------------------------------------------------------
# 3. All-or-nothing: tamper → DB rows intact (no partial deletion)
# ---------------------------------------------------------------------------


class TestBatchUnlockAllOrNothingDbIntact:
    def test_tamper_leaves_db_rows_intact(
        self, home_dir: WorthlessHome, three_key_env: Path
    ) -> None:
        _lock(three_key_env, home_dir)
        repo = _repo(home_dir)
        before = len(asyncio.run(repo.list_enrollments()))
        assert before == 3

        _tamper_first_shard(home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0

        after = len(asyncio.run(repo.list_enrollments()))
        assert after == before, f"DB partially deleted on failed unlock: {before} → {after}"

        conn = sqlite3.connect(str(home_dir.db_path))
        try:
            shard_rows = conn.execute("SELECT count(*) FROM shards").fetchone()[0]
        finally:
            conn.close()
        assert shard_rows == 3, f"Expected 3 shards, found {shard_rows}"


# ---------------------------------------------------------------------------
# 4. No ghost-tmp / staging artifacts on refusal
# ---------------------------------------------------------------------------


class TestBatchUnlockTamperLeavesNoGhostTmp:
    def test_no_ghost_siblings_after_refused_unlock(
        self, home_dir: WorthlessHome, three_key_env: Path
    ) -> None:
        _lock(three_key_env, home_dir)
        _tamper_first_shard(home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0

        siblings = _env_glob_siblings(three_key_env)
        assert siblings == [".env"], (
            f"Ghost tmp/staging artifacts remain after refused unlock: {siblings!r}"
        )


# ---------------------------------------------------------------------------
# 5. Missing .env: refuse pass-3 rather than silently purge DB rows
# ---------------------------------------------------------------------------


class TestBatchUnlockRefusesWhenEnvMissing:
    def test_missing_env_keeps_db_rows(self, home_dir: WorthlessHome, three_key_env: Path) -> None:
        # Lock as normal, then yank the .env out from under unlock.
        _lock(three_key_env, home_dir)
        repo = _repo(home_dir)
        before = len(asyncio.run(repo.list_enrollments()))
        assert before == 3
        three_key_env.unlink()

        result = runner.invoke(
            app,
            ["unlock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        # Refuse rather than silently purge DB rows + zero plaintext.
        assert result.exit_code != 0, (
            f"unlock against missing .env must refuse, not silently purge. Output: {result.output}"
        )
        after = len(asyncio.run(repo.list_enrollments()))
        assert after == before, (
            f"DB rows were deleted despite missing .env: {before} → {after} "
            f"(silent data loss — keys can never be recovered)."
        )

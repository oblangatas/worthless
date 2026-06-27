"""Transactional-lock invariants for ``worthless lock`` across N keys.

Either every key is enrolled in the DB AND ``.env`` is fully rewritten,
or the DB has zero new rows AND ``.env`` is byte-identical to pre-lock.
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
from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def three_key_env(tmp_path: Path) -> Path:
    """Create a ``.env`` with 3 unprotected provider keys.

    Two distinct openai keys (different seeds → different aliases) plus
    one anthropic key. Aliases will differ because ``_make_alias``
    hashes the key value.
    """
    env = tmp_path / ".env"
    oa1 = fake_key("sk-" + "proj-", seed="three-key-env-openai-1")
    oa2 = fake_key("sk-" + "proj-", seed="three-key-env-openai-2")
    an1 = fake_anthropic_key()
    env.write_text(f"OPENAI_API_KEY_A={oa1}\nOPENAI_API_KEY_B={oa2}\nANTHROPIC_API_KEY={an1}\n")
    return env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _env_glob_siblings(env_path: Path) -> list[str]:
    """Names of every ``.env*`` entry in *env_path*'s parent dir."""
    return sorted(p.name for p in env_path.parent.glob(".env*"))


# ---------------------------------------------------------------------------
# 1. Exactly one safe_rewrite call for an N-key lock
# ---------------------------------------------------------------------------


class TestBatchLockSingleSafeRewriteCall:
    def test_batch_lock_single_safe_rewrite_call(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Locking 3 keys must issue exactly ONE ``safe_rewrite`` call."""
        import worthless.cli.dotenv_rewriter as rw

        call_count = 0
        real_safe_rewrite = rw.safe_rewrite

        def _counting(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return real_safe_rewrite(*args, **kwargs)

        monkeypatch.setattr(rw, "safe_rewrite", _counting)

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert call_count == 1, (
            f"Expected exactly 1 safe_rewrite call for atomic 3-key lock, got {call_count}."
        )


# ---------------------------------------------------------------------------
# 2. Happy path: all enrolled + all rewritten
# ---------------------------------------------------------------------------


class TestBatchLockHappyPath:
    def test_batch_lock_happy_path_all_enrolled(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
    ) -> None:
        """3 fresh keys → 3 DB rows, 3 shard-A values, BASE_URLs added, exit 0."""
        original_keys = {}
        for line in three_key_env.read_text().splitlines():
            k, v = line.split("=", 1)
            original_keys[k] = v

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # DB: all 3 aliases enrolled
        repo = _repo(home_dir)
        enrollments = asyncio.run(repo.list_enrollments())
        var_names = {e.var_name for e in enrollments}
        assert var_names == {
            "OPENAI_API_KEY_A",
            "OPENAI_API_KEY_B",
            "ANTHROPIC_API_KEY",
        }

        # .env: each original key replaced with shard-A
        from dotenv import dotenv_values

        parsed = dotenv_values(three_key_env)
        for var in ("OPENAI_API_KEY_A", "OPENAI_API_KEY_B", "ANTHROPIC_API_KEY"):
            assert parsed[var] != original_keys[var], f"{var} not rewritten"
            assert parsed[var] is not None
            assert len(parsed[var]) == len(original_keys[var])

        # At least one OPENAI_BASE_URL and one ANTHROPIC_BASE_URL must exist
        content = three_key_env.read_text()
        assert "OPENAI_BASE_URL=" in content
        assert "ANTHROPIC_BASE_URL=" in content


def _inject_verify_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the verify hook for one that unconditionally refuses the rewrite."""
    import worthless.cli.commands.lock as lock_mod

    def _bad_hook_builder(*_args, **_kwargs):
        def _hook():
            raise UnsafeRewriteRefused(UnsafeReason.VERIFY_FAILED)

        return _hook

    monkeypatch.setattr(lock_mod, "_build_verify_hook", _bad_hook_builder)


# ---------------------------------------------------------------------------
# 3. All-or-nothing: .env byte-identical on failure
# ---------------------------------------------------------------------------


class TestBatchLockAllOrNothingEnvIdentical:
    def test_batch_lock_all_or_nothing_env_identical(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify failure → ``.env`` sha256 equals pre-lock sha256."""
        pre_sha = _sha256_of(three_key_env)
        _inject_verify_failure(monkeypatch)

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, result.output

        post_sha = _sha256_of(three_key_env)
        assert post_sha == pre_sha, ".env was mutated despite a VERIFY_FAILED refusal."


# ---------------------------------------------------------------------------
# 4. All-or-nothing: DB rolled back on failure
# ---------------------------------------------------------------------------


class TestBatchLockAllOrNothingDbRolledBack:
    def test_batch_lock_all_or_nothing_db_rolled_back(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify failure → zero enrollments, zero shards for every alias."""
        _inject_verify_failure(monkeypatch)

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, result.output

        repo = _repo(home_dir)
        enrollments = asyncio.run(repo.list_enrollments())
        assert enrollments == [], (
            f"DB still has {len(enrollments)} enrollment(s) after a failed lock."
        )

        # Defensive: raw shards table should be empty too.
        if home_dir.db_path.exists():
            conn = sqlite3.connect(str(home_dir.db_path))
            try:
                rows = conn.execute("SELECT key_alias FROM shards").fetchall()
            finally:
                conn.close()
            assert rows == [], f"shards table has orphan rows after a failed lock: {rows!r}"


class TestVerifyHookAbortNoStaleOriginalMode:
    """Wave 4 / chaos-engineer T1: verify-hook abort must not leave original_mode rows."""

    def test_verify_hook_abort_leaves_no_original_mode_rows(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pass-2 verify failure → compensating unwind removes enrollment + original_mode."""
        _inject_verify_failure(monkeypatch)

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, result.output

        con = sqlite3.connect(str(home_dir.db_path))
        try:
            mode_rows = con.execute("SELECT original_mode FROM enrollments").fetchall()
            enroll_rows = con.execute("SELECT 1 FROM enrollments").fetchall()
        finally:
            con.close()
        assert enroll_rows == [], f"enrollment rows survived verify abort: {enroll_rows!r}"
        assert mode_rows == [], (
            "original_mode must not survive verify-hook abort — "
            f"would landmine a future restore; got {mode_rows!r}"
        )


# ---------------------------------------------------------------------------
# 5. No ghost-tmp / staging artifacts + .env byte-identical on refusal
# ---------------------------------------------------------------------------


class TestBatchLockRewriteRefusedLeavesNoGhostTmp:
    def test_batch_lock_rewrite_refused_leaves_no_ghost_tmp(
        self,
        home_dir: WorthlessHome,
        three_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify failure → only ``.env`` remains AND it is byte-identical.

        Two invariants:
        1. No ``.env.tmp-*`` / ``.env.staging-*`` litter in the parent dir.
        2. ``.env`` sha256 matches pre-lock.
        """
        pre_sha = _sha256_of(three_key_env)
        _inject_verify_failure(monkeypatch)

        result = runner.invoke(
            app,
            ["lock", "--env", str(three_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, result.output

        siblings = _env_glob_siblings(three_key_env)
        assert siblings == [".env"], (
            f"Ghost tmp/staging artifacts remain after refused lock: {siblings!r}."
        )

        post_sha = _sha256_of(three_key_env)
        assert post_sha == pre_sha, ".env mutated despite refusal."

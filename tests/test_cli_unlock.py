"""Tests for the unlock CLI command."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import WorthlessError

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_openai_key

runner = CliRunner()

_TEST_KEY = fake_openai_key()
_TEST_KEY_2 = fake_anthropic_key()


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    """Create a .env with a known OpenAI key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")
    return env


@pytest.fixture()
def multi_env_file(tmp_path: Path) -> Path:
    """Create a .env with two API keys."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={_TEST_KEY}\nANTHROPIC_API_KEY={_TEST_KEY_2}\n")
    return env


def _lock(env_file: Path, home: WorthlessHome) -> None:
    """Helper: lock the env file."""
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home.base_dir)},
    )
    assert result.exit_code == 0, result.output


class TestUnlockCommand:
    """Tests for `worthless unlock`."""

    def test_round_trip_lock_unlock(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Lock then unlock should restore identical .env content."""
        original = env_file.read_text()
        _lock(env_file, home_dir)

        # .env should be different after lock
        assert env_file.read_text() != original

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert env_file.read_text() == original

    def test_unlock_specific_alias(self, home_dir: WorthlessHome, multi_env_file: Path) -> None:
        """Unlock with --alias should only unlock that specific key."""
        _lock(multi_env_file, home_dir)

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 2

        # Unlock just one
        alias = aliases[0]
        result = runner.invoke(
            app,
            ["unlock", "--alias", alias, "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # Only one alias should remain in DB
        remaining = asyncio.run(repo.list_keys())
        assert len(remaining) == 1

    def test_unlock_all_aliases(self, home_dir: WorthlessHome, multi_env_file: Path) -> None:
        """Unlock without --alias should unlock all enrolled keys."""
        original = multi_env_file.read_text()
        _lock(multi_env_file, home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert multi_env_file.read_text() == original

        # DB should be empty
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == []

    def test_unlock_missing_alias_errors(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Unlock with nonexistent alias should exit with error."""
        result = runner.invoke(
            app,
            ["unlock", "--alias", "nonexistent-key", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1

    def test_unlock_missing_env_reports_no_keys(
        self, home_dir: WorthlessHome, env_file: Path, tmp_path: Path
    ) -> None:
        """Unlock with missing .env finds no enrolled keys for that path."""
        _lock(env_file, home_dir)

        missing_env = tmp_path / "does-not-exist.env"

        result = runner.invoke(
            app,
            ["unlock", "--env", str(missing_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        # No enrollments match the missing .env path → "no enrolled keys"
        assert result.exit_code == 0
        assert "no enrolled" in result.output.lower()

    def test_shards_cleaned_up_after_unlock(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After unlock, DB entries should be removed."""
        _lock(env_file, home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        # No DB entries
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == []


class TestUnlockFromDB:
    """Unlock reads var_name from DB enrollment."""

    def test_unlock_reads_var_name_from_db(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Unlock should read var_name from enrollments table."""
        original = env_file.read_text()
        _lock(env_file, home_dir)

        # Verify enrollment exists in DB
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        enrollment = asyncio.run(repo.get_enrollment(aliases[0]))
        assert enrollment is not None
        assert enrollment.var_name == "OPENAI_API_KEY"

        # Unlock should work from DB enrollment
        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert env_file.read_text() == original

    def test_unlock_cleans_up_enrollment_in_db(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """After unlock, enrollment records should be deleted from DB."""
        _lock(env_file, home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        repo = _repo(home_dir)
        enrollments = asyncio.run(repo.list_enrollments())
        assert enrollments == []


class TestShardAInEnv:
    """After lock, shard-A is the .env value (format-preserving). Unlock reads it back."""

    def test_shard_a_preserved_in_env(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Lock stores shard-A in .env; unlock reads it back for reconstruction."""
        original = env_file.read_text()
        _lock(env_file, home_dir)

        from dotenv import dotenv_values

        parsed = dotenv_values(env_file)
        shard_a = parsed["OPENAI_API_KEY"]
        # Shard-A must differ from original
        assert shard_a != _TEST_KEY
        # Shard-A preserves prefix
        assert shard_a.startswith("sk-proj-")

        # Unlock reconstructs original
        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        assert env_file.read_text() == original

    def test_unlock_removes_base_url(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Unlock should remove the BASE_URL line that lock added."""
        _lock(env_file, home_dir)

        content = env_file.read_text()
        assert "OPENAI_BASE_URL=" in content

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        content_after = env_file.read_text()
        assert "OPENAI_BASE_URL=" not in content_after


class TestEnrollUnlockNullEnvPath:
    """Direct enroll (env_path=NULL) followed by unlock should clean up completely."""

    def test_enroll_then_unlock_prints_key(self, home_dir: WorthlessHome) -> None:
        """After enroll (env_path=NULL), unlock prints key to stdout."""
        from worthless.cli.commands.lock import _make_alias

        alias = _make_alias("openai", _TEST_KEY)

        # Enroll via CLI
        result = runner.invoke(
            app,
            ["enroll", "--alias", alias, "--key", _TEST_KEY, "--provider", "openai"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        # Unlock — no .env, so it fails (shard-A is not on disk anymore)
        # Direct-enrolled keys with format-preserving split have no shard-A on disk
        # and no .env — they need a different recovery path
        result = runner.invoke(
            app,
            ["unlock", "--alias", alias],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        # This will error because there's no .env to read shard_a from
        assert result.exit_code == 1


class TestUnlockMultiEnrollment:
    """Multi-enrollment unlock: same key enrolled from multiple .env files."""

    @pytest.fixture()
    def two_env_files(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create two .env files (in distinct subdirs) with the same key.

        The safe-rewrite gate requires the literal basename ``.env`` - so
        distinct fixtures live under ``a/`` and ``b/`` rather than as
        ``a.env``/``b.env`` at tmp_path root.
        """
        dir_a = tmp_path / "a"
        dir_a.mkdir()
        env_a = dir_a / ".env"
        env_a.write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")
        dir_b = tmp_path / "b"
        dir_b.mkdir()
        env_b = dir_b / ".env"
        env_b.write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")
        return env_a, env_b

    def _lock_both(self, env_a: Path, env_b: Path, home: WorthlessHome) -> str:
        """Lock same key via two env files, return the alias."""
        _lock(env_a, home)
        _lock(env_b, home)
        repo = _repo(home)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1  # same key -> same alias
        return aliases[0]

    def test_unlock_multi_enrollment_with_env_flag_succeeds(
        self, home_dir: WorthlessHome, two_env_files: tuple[Path, Path]
    ) -> None:
        """Unlock with --env restores one file, leaves other enrollment intact."""
        env_a, env_b = two_env_files
        original_a = env_a.read_text()
        alias = self._lock_both(env_a, env_b, home_dir)

        result = runner.invoke(
            app,
            ["unlock", "--alias", alias, "--env", str(env_a)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # env_a restored
        assert env_a.read_text() == original_a

        # env_b still enrolled (enrollment remains in DB)
        # Note: env_b may still have original key if re-lock guard
        # didn't rewrite it (same alias already in DB)

        # One enrollment remains in DB
        repo = _repo(home_dir)
        remaining = asyncio.run(repo.list_enrollments(alias))
        assert len(remaining) == 1


class TestUnlockErrorBranches:
    """Error branch coverage for unlock failure paths."""

    def test_unlock_db_retrieve_failure_exits_clean(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exception during repo.fetch_encrypted -> exit_code=1 with WRTLS."""
        _lock(env_file, home_dir)

        async def _boom(self, _alias):
            raise Exception("DB corrupt")

        monkeypatch.setattr(
            "worthless.storage.repository.ShardRepository.fetch_encrypted",
            _boom,
        )

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1

        result = runner.invoke(
            app,
            ["unlock", "--alias", aliases[0], "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output

    def test_unlock_no_shard_b_in_db_exits_clean(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """No shard_b in DB for alias -> WRTLS error."""
        result = runner.invoke(
            app,
            ["unlock", "--alias", "nonexistent-alias", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output


class TestUnlockNoAliases:
    """unlock with no enrolled keys prints warning."""

    def test_unlock_empty_home_warns(self, home_dir: WorthlessHome) -> None:
        """unlock on empty home prints 'No enrolled keys found.'

        No `--env` flag — exercises the default-CWD path. Pnn2 makes
        the HF4 discriminator implicit-default-safe: if the user did
        not name a path, we don't surface the shard-shape hard error
        even when the CWD has a `.env` belonging to a different
        project.
        """
        result = runner.invoke(
            app,
            ["unlock"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert "no enrolled" in result.output.lower()

    def test_unlock_default_env_with_unrelated_shards_does_not_error(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pnn2 contract: ``worthless unlock`` (no flag) from a directory
        whose `.env` happens to contain shard-shape values from an
        unrelated project must NOT raise HF4's hard error.

        Scenario: user has projects /work/a/.env (locked by worthless)
        and /work/b/.env (someone else's, not enrolled here). Running
        ``unlock`` from /work/b should warn and exit 0, not crash with
        "no enrollment found for shard-shape value(s)..."
        """
        # Simulate /work/b/.env in CWD with shard-shape (but unenrolled)
        # values via a real fake OpenAI key.
        proj = tmp_path / "unrelated-project"
        proj.mkdir()
        (proj / ".env").write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")
        monkeypatch.chdir(proj)

        result = runner.invoke(
            app,
            ["unlock"],  # no --env
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, (
            f"implicit-default unlock must not surface HF4 hard error "
            f"on a CWD .env the user did not name:\n{result.output}"
        )
        assert "no enrolled" in result.output.lower()
        assert "no enrollment found" not in result.output.lower(), (
            "HF4 discriminator should NOT fire on implicit default"
        )

    def test_unlock_explicit_env_with_unrelated_shards_still_errors(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
    ) -> None:
        """Pnn2 keeps HF4's loud failure on explicit ``--env``: if the
        user named the path, they meant it. Shard-shape values without
        DB rows still surface as a hard error with a re-lock hint.
        """
        env = tmp_path / "orphaned.env"
        env.write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, (
            f"explicit --env to an orphaned shard-shape .env must still "
            f"hard-fail (HF4 contract):\n{result.output}"
        )
        # HF4's error hint must be present.
        assert (
            "no enrollment found" in result.output.lower()
            or "unrecognised shards" in result.output.lower()
        ), f"missing HF4 hint:\n{result.output}"


class TestUnlockScopedToEnv:
    """CR-2: unlock without --alias should only unlock keys enrolled in the target .env."""

    def test_unlock_only_restores_keys_in_target_env(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Lock keys in two different .env files. Unlock one. Other stays locked."""
        dir_a = tmp_path / "a"
        dir_a.mkdir()
        env_a = dir_a / ".env"
        dir_b = tmp_path / "b"
        dir_b.mkdir()
        env_b = dir_b / ".env"
        env_a.write_text(f"OPENAI_API_KEY={_TEST_KEY}\n")
        env_b.write_text(f"ANTHROPIC_API_KEY={_TEST_KEY_2}\n")

        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        # Lock both
        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0
        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 0

        # Unlock only env_a (no --alias, should scope to env_a)
        r3 = runner.invoke(app, ["unlock", "--env", str(env_a)], env=env_vars)
        assert r3.exit_code == 0

        # env_a should have original key restored
        assert _TEST_KEY in env_a.read_text()

        # env_b should still be locked (NOT restored)
        assert _TEST_KEY_2 not in env_b.read_text(), (
            "unlock --env a/.env should NOT have touched b/.env"
        )

        # DB should still have the anthropic key enrolled
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1, f"Expected 1 remaining key, got {aliases}"


# ------------------------------------------------------------------
# WOR-74: Multi-key unlock scenarios
# ------------------------------------------------------------------


class TestResolveEnrollment:
    """Unit tests for _resolve_enrollment helper."""

    def test_resolve_with_env_path(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """_resolve_enrollment with env_path returns matching enrollment."""
        from worthless.cli.commands.unlock import _resolve_enrollment

        _lock(env_file, home_dir)
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())

        async def _run():
            await repo.initialize()
            return await _resolve_enrollment(aliases[0], repo, env_file)

        enrollment = asyncio.run(_run())
        assert enrollment is not None
        assert enrollment.var_name == "OPENAI_API_KEY"

    def test_resolve_without_env_returns_single(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """_resolve_enrollment without env_path returns the sole enrollment."""
        from worthless.cli.commands.unlock import _resolve_enrollment

        _lock(env_file, home_dir)
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())

        async def _run():
            await repo.initialize()
            return await _resolve_enrollment(aliases[0], repo, env_path=None)

        enrollment = asyncio.run(_run())
        assert enrollment is not None

    def test_resolve_nonexistent_alias_returns_none(self, home_dir: WorthlessHome) -> None:
        """_resolve_enrollment for unknown alias returns None."""
        from worthless.cli.commands.unlock import _resolve_enrollment

        repo = _repo(home_dir)

        async def _run():
            await repo.initialize()
            return await _resolve_enrollment("nonexistent", repo, env_path=None)

        assert asyncio.run(_run()) is None


class TestLoadShardA:
    """Unit tests for _load_shard_a helper."""

    def test_load_from_env_file(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """_load_shard_a reads shard-A from .env for format-preserving keys."""
        from worthless.cli.commands.unlock import _load_shard_a

        _lock(env_file, home_dir)
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        alias = aliases[0]

        encrypted = asyncio.run(repo.fetch_encrypted(alias))
        assert encrypted is not None
        assert encrypted.prefix is not None

        shard_a = _load_shard_a(encrypted, env_file, "OPENAI_API_KEY", home_dir, alias)
        assert isinstance(shard_a, bytearray)
        assert len(shard_a) > 0

    def test_load_missing_var_raises(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """_load_shard_a raises when var_name not in .env."""
        from worthless.cli.commands.unlock import _load_shard_a

        _lock(env_file, home_dir)
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        encrypted = asyncio.run(repo.fetch_encrypted(aliases[0]))

        with pytest.raises(WorthlessError, match="not found"):
            _load_shard_a(encrypted, env_file, "NONEXISTENT_VAR", home_dir, aliases[0])

    def test_load_no_env_path_raises(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """_load_shard_a raises when env_path is None for FP keys."""
        from worthless.cli.commands.unlock import _load_shard_a

        _lock(env_file, home_dir)
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        encrypted = asyncio.run(repo.fetch_encrypted(aliases[0]))

        with pytest.raises(WorthlessError, match="shard-A"):
            _load_shard_a(encrypted, None, "OPENAI_API_KEY", home_dir, aliases[0])


class TestUnlockMultipleKeys:
    """WOR-74: unlock handles multiple enrolled keys, each reconstructs correctly."""

    def test_unlock_multiple_keys_each_reconstructs(
        self, home_dir: WorthlessHome, multi_env_file: Path
    ) -> None:
        """Lock two different keys, unlock all, verify both original values restored."""
        original = multi_env_file.read_text()
        _lock(multi_env_file, home_dir)

        # Verify both keys are enrolled
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 2, f"Expected 2 enrolled keys, got {len(aliases)}"

        # Unlock all
        result = runner.invoke(
            app,
            ["unlock", "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # Both original keys restored
        restored = multi_env_file.read_text()
        assert _TEST_KEY in restored, "OpenAI key not restored after unlock"
        assert _TEST_KEY_2 in restored, "Anthropic key not restored after unlock"
        assert restored == original

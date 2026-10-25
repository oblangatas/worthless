"""Tests for the unlock CLI command."""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner, Result

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import WorthlessError
from worthless.cli.providers import user_registry_path

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_key, fake_openai_key, fake_openrouter_key

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


def _lock(env_file: Path, home: WorthlessHome, *args: str, check: bool = True) -> Result:
    """Helper: lock the env file; *check* asserts it succeeded."""
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file), *args],
        env={"WORTHLESS_HOME": str(home.base_dir)},
    )
    if check:
        assert result.exit_code == 0, result.output
    return result


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


def _unlock(env: Path, home: WorthlessHome, *args: str, check: bool = True) -> Result:
    result = runner.invoke(
        app,
        ["unlock", "--env", str(env), *args],
        env={"WORTHLESS_HOME": str(home.base_dir)},
    )
    if check:
        assert result.exit_code == 0, result.output
    return result


def _said(result: Result, phrase: str) -> bool:
    """*phrase* is in the output however Rich wrapped it (WOR-1022)."""
    return phrase in " ".join(result.output.split())


def _alias_for(home: WorthlessHome, var_name: str) -> str:
    enrollments = asyncio.run(_repo(home).list_enrollments())
    return next(e.key_alias for e in enrollments if e.var_name == var_name)


_GATEWAY_URL = "https://gateway.example.com/v1"


def _register_gateway(
    home: WorthlessHome, url: str = _GATEWAY_URL, name: str = "corp-gateway"
) -> None:
    """Lock refuses a user's own upstream URL until it is registered."""
    result = runner.invoke(
        app,
        ["providers", "register", "--name", name, "--url", url, "--protocol", "openai"],
        env={"WORTHLESS_HOME": str(home.base_dir)},
    )
    assert result.exit_code == 0, result.output


def _edit_enrollments(home: WorthlessHome, set_clause: str, params: tuple = ()) -> None:
    with contextlib.closing(sqlite3.connect(home.db_path)) as conn:
        conn.execute(f"UPDATE enrollments SET {set_clause}", params)  # noqa: S608 — test literal
        conn.commit()


def _saved_record(home: WorthlessHome) -> tuple[str, str]:
    with contextlib.closing(sqlite3.connect(home.db_path)) as conn:
        return conn.execute(
            "SELECT base_url_restore_json, base_url_restore_mac FROM enrollments"
        ).fetchone()


def _as_enrolled_before_wor_1013(home: WorthlessHome) -> None:
    """Drop lock's BASE_URL record, as on an enrollment an older version made."""
    _edit_enrollments(home, "base_url_restore_json = NULL, base_url_restore_mac = NULL")


class TestUnlockRemovesTheBaseUrlLockWrote:
    """Unlock drops the ``*_BASE_URL`` line lock wrote for a key, and no other (WOR-981)."""

    @pytest.mark.parametrize(
        ("preamble", "var_name", "key", "base_url_var"),
        [
            ("", "OPENROUTER_API_KEY", fake_openrouter_key(), "OPENROUTER_BASE_URL"),
            # An openai-protocol key under a var not named after the protocol.
            ("", "GROQ_API_KEY", fake_key("sk-", seed="unlock-groq-var-name"), "GROQ_BASE_URL"),
            # WOR-981's red case: unlock deleted the user's own OPENAI_BASE_URL.
            (
                "OPENAI_BASE_URL=https://api.openai.com/v1\n",
                "OPENROUTER_API_KEY",
                fake_openrouter_key(),
                "OPENROUTER_BASE_URL",
            ),
        ],
        ids=["openrouter", "groq-var-name", "users-own-openai-base-url"],
    )
    def test_round_trip_is_byte_identical(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        preamble: str,
        var_name: str,
        key: str,
        base_url_var: str,
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(f"{preamble}{var_name}={key}\n")
        original = env.read_bytes()
        _lock(env, home_dir)
        assert base_url_var in dotenv_values(env)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_line_named_by_an_older_lock_stops_routing_the_proxy(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Before v0.3.3 lock named the line after the protocol, not the key's var.

        The OpenRouter key is the only key here, so the app that read OPENAI_BASE_URL
        for it gets OpenRouter's address back (WOR-1013 old-row rule), not OpenAI's.
        """
        env = tmp_path / ".env"
        env.write_text(f"OPENROUTER_API_KEY={fake_openrouter_key()}\n")
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)
        env.write_text(env.read_text().replace("OPENROUTER_BASE_URL=", "OPENAI_BASE_URL="))

        _unlock(env, home_dir)
        assert "127.0.0.1" not in env.read_text()
        assert dotenv_values(env)["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"

    def test_line_is_removed_after_the_proxy_port_changed(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(f"OPENROUTER_API_KEY={fake_openrouter_key()}\n")
        original = env.read_bytes()
        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir), "WORTHLESS_PORT": "9911"},
        )
        assert result.exit_code == 0, result.output
        assert ":9911/" in (dotenv_values(env)["OPENROUTER_BASE_URL"] or "")

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_unlocking_one_key_keeps_the_other_keys_base_url(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={_TEST_KEY}\nOPENROUTER_API_KEY={fake_openrouter_key()}\n")
        original = env.read_bytes()
        _lock(env, home_dir)
        locked = dotenv_values(env)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "OPENROUTER_API_KEY"))
        after = dotenv_values(env)
        assert "OPENROUTER_BASE_URL" not in after
        # OPENAI_API_KEY is still locked: its shard-A must keep going to the proxy.
        assert after["OPENAI_API_KEY"] == locked["OPENAI_API_KEY"]
        assert after["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_unlocking_a_key_keeps_a_shared_base_url_another_key_owns(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Both vars map to OPENAI_BASE_URL; lock points it at OPENAI_API_KEY's alias."""
        env = tmp_path / ".env"
        other_key = fake_key("sk-proj-", seed="unlock-shared-slot")
        env.write_text(f"MY_OPENAI_KEY={other_key}\nOPENAI_API_KEY={_TEST_KEY}\n")
        _lock(env, home_dir)
        locked = dotenv_values(env)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "MY_OPENAI_KEY"))
        after = dotenv_values(env)
        assert after["MY_OPENAI_KEY"] == other_key
        assert after["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]

    def test_line_is_found_when_dotenv_keeps_a_bom_in_the_first_key(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """python-dotenv before 1.2.3 parses a BOM file's first key as '\\ufeffKEY'.

        Unlock reads the .env through one snapshot that strips the BOM before
        python-dotenv sees it, so the line is found on any version.
        """
        env = tmp_path / ".env"
        env.write_bytes(
            b"\xef\xbb\xbfOPENAI_BASE_URL=https://api.openai.com/v1\n"
            + f"OPENAI_API_KEY={_TEST_KEY}\n".encode()
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)  # the fallback path, not the record

        _unlock(env, home_dir)
        # Found despite the BOM. An OpenAI key's old row loses it: OpenAI's address
        # is the SDK default anyway, and sk- also names other vendors' keys. Bytes,
        # not dotenv_values: python-dotenv before 1.2.3 would misname the first key.
        assert env.read_bytes() == b"\xef\xbb\xbf" + f"OPENAI_API_KEY={_TEST_KEY}\n".encode()

    def test_a_saved_value_the_rewriter_refuses_is_removed_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        """Lock never saves one, but unlock must not depend on that (WOR-1013)."""
        from worthless.cli.commands.unlock import _batch_restore_env, _PlannedRestore
        from worthless.storage.models import BaseUrlRestore

        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=http://127.0.0.1:8787/openai-deadbeef/v1\n"
            "OPENAI_API_KEY=sk-proj-shard-a-placeholder-value-0123456789\n"
        )
        planned = _PlannedRestore(
            alias="openai-deadbeef",
            provider="openai",
            enrollment=None,
            var_name="OPENAI_API_KEY",
            env_path=env,
            key_buf=bytearray(_TEST_KEY.encode()),
            base_url_restore=BaseUrlRestore("OPENAI_BASE_URL", "https://gw.example.com/it's"),
        )
        _batch_restore_env(env, [planned])
        assert env.read_text() == f"OPENAI_API_KEY={_TEST_KEY}\n"

    def test_non_utf8_env_gets_the_rewriters_refusal_not_a_decode_error(
        self, tmp_path: Path
    ) -> None:
        from worthless.cli.commands.unlock import _batch_restore_env, _PlannedRestore

        env = tmp_path / ".env"
        env.write_bytes(b"OPENAI_API_KEY=sk-\xe9\xe9\xe9\n")
        planned = _PlannedRestore(
            alias="openai-deadbeef",
            provider="openai",
            enrollment=None,
            var_name="OPENAI_API_KEY",
            env_path=env,
            key_buf=bytearray(_TEST_KEY.encode()),
        )
        with pytest.raises(WorthlessError):
            _batch_restore_env(env, [planned])

    @pytest.mark.parametrize(
        ("var_name", "key", "base_url_var", "upstream"),
        [
            ("OPENAI_API_KEY", _TEST_KEY, "OPENAI_BASE_URL", "https://api.openai.com/v1"),
            (
                "OPENROUTER_API_KEY",
                fake_openrouter_key(),
                "OPENROUTER_BASE_URL",
                "https://openrouter.ai/api/v1",
            ),
        ],
        ids=["openai", "openrouter"],
    )
    def test_keys_only_lock_keeps_the_users_own_base_url(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        var_name: str,
        key: str,
        base_url_var: str,
        upstream: str,
    ) -> None:
        """--keys-only never writes the line, so unlock has none of its own to drop."""
        env = tmp_path / ".env"
        env.write_text(f"{base_url_var}={upstream}\n{var_name}={key}\n")
        original = env.read_bytes()
        _lock(env, home_dir, "--keys-only")
        assert dotenv_values(env)[base_url_var] == upstream

        _unlock(env, home_dir)
        assert env.read_bytes() == original


class TestUnlockPutsBackTheBaseUrlYouHad:
    """A ``*_BASE_URL`` line you had before lock comes back on unlock (WOR-1013)."""

    @pytest.mark.parametrize(
        "content",
        [
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY={key}\n",
            "OPENROUTER_API_KEY={key}\nOPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n",
            'export OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"  # mine\n'
            "OPENROUTER_API_KEY={key}\n",
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\r\nOPENROUTER_API_KEY={key}\r\n",
            # Empty: lock routes the key to the registry default and still takes the line.
            "OPENROUTER_BASE_URL=\nOPENROUTER_API_KEY={key}\n",
        ],
        ids=["before-key", "after-key", "quoted-export-comment", "crlf", "empty"],
    )
    def test_round_trip_is_byte_identical(
        self, home_dir: WorthlessHome, tmp_path: Path, content: str
    ) -> None:
        env = tmp_path / ".env"
        env.write_bytes(content.format(key=fake_openrouter_key()).encode())
        original = env.read_bytes()
        _lock(env, home_dir)
        alias = _alias_for(home_dir, "OPENROUTER_API_KEY")
        assert f"/{alias}/v1" in (dotenv_values(env)["OPENROUTER_BASE_URL"] or "")

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    @pytest.mark.parametrize(
        "preamble",
        [
            f"OPENAI_BASE_URL={_GATEWAY_URL}\n",
            # Put back as written, not as python-dotenv expands it.
            "GATEWAY=https://gateway.example.com\nOPENAI_BASE_URL=${GATEWAY}/v1\n",
        ],
        ids=["gateway", "interpolated"],
    )
    def test_your_gateway_url_is_put_back(
        self, home_dir: WorthlessHome, tmp_path: Path, preamble: str
    ) -> None:
        _register_gateway(home_dir)
        env = tmp_path / ".env"
        env.write_bytes(f"{preamble}OPENAI_API_KEY={_TEST_KEY}\n".encode())
        original = env.read_bytes()
        _lock(env, home_dir)
        assert dotenv_values(env)["OPENAI_BASE_URL"] != _GATEWAY_URL

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_unlocking_one_key_puts_back_only_its_line(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\nOPENAI_API_KEY={_TEST_KEY}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        locked = dotenv_values(env)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "OPENROUTER_API_KEY"))
        after = dotenv_values(env)
        assert after["OPENROUTER_BASE_URL"] == "https://openrouter.ai/api/v1"
        assert after["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_a_shared_line_you_had_comes_back(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Both vars map to OPENAI_BASE_URL; only OPENAI_API_KEY's lock wrote it."""
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://api.openai.com/v1\n"
            f"MY_OPENAI_KEY={fake_key('sk-proj-', seed='unlock-shared-own-line')}\n"
            f"OPENAI_API_KEY={_TEST_KEY}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        locked = dotenv_values(env)

        # OPENAI_API_KEY stays locked, so the line keeps routing it to the proxy.
        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "MY_OPENAI_KEY"))
        assert dotenv_values(env)["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_your_first_line_comes_back_in_a_bom_file(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Lock and unlock parse with the BOM stripped, so even python-dotenv before
        1.2.3 (which kept it in the first key's name) sees the line."""
        env = tmp_path / ".env"
        env.write_bytes(
            b"\xef\xbb\xbfOPENAI_BASE_URL=https://api.openai.com/v1\n"
            + f"OPENAI_API_KEY={_TEST_KEY}\n".encode()
        )
        original = env.read_bytes()
        _lock(env, home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_a_record_from_an_earlier_lock_is_refused(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A record saved from a DB backup can't bring back a value this lock never saw."""
        _register_gateway(home_dir)
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(f"OPENROUTER_BASE_URL={_GATEWAY_URL}\nOPENROUTER_API_KEY={key}\n")
        _lock(env, home_dir)
        saved = _saved_record(home_dir)
        _unlock(env, home_dir)

        env.write_text(f"OPENROUTER_API_KEY={key}\n")  # this lock adds the line
        _lock(env, home_dir)
        _edit_enrollments(home_dir, "base_url_restore_json = ?, base_url_restore_mac = ?", saved)

        result = _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"
        assert _said(result, "changed in the Worthless database")

    @pytest.mark.parametrize(
        ("url", "line"),
        [
            ("https://gateway.example.com/v1/o'neil", "https://gateway.example.com/v1/o'neil"),
            ("https://gateway.example.com/v1 ", '"https://gateway.example.com/v1 "'),
        ],
        ids=["embedded-quote", "quoted-trailing-space"],
    )
    def test_a_value_unlock_cannot_write_back_is_removed_not_a_crash(
        self, home_dir: WorthlessHome, tmp_path: Path, url: str, line: str
    ) -> None:
        """The rewriter refuses these values, so unlock removes the line instead."""
        _register_gateway(home_dir, url, name="quoted-gw")
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_BASE_URL={line}\nOPENAI_API_KEY={_TEST_KEY}\n")
        assert _said(_lock(env, home_dir), "can't save this value")

        _unlock(env, home_dir)
        assert env.read_text() == f"OPENAI_API_KEY={_TEST_KEY}\n"

    @pytest.mark.parametrize(
        "users_line",
        ["OPENAI_BASE_URL=https://api.openai.com/v1\n", ""],
        ids=["your-line", "lock-added-it"],
    )
    def test_one_key_under_two_names_leaves_no_proxy_line(
        self, home_dir: WorthlessHome, tmp_path: Path, users_line: str
    ) -> None:
        """Whichever of the key's rows unlock reads, the line lock wrote is put back or removed.

        Which variable gets the key back is WOR-1018; the line must never be left
        routing an alias whose rows unlock deletes.
        """
        env = tmp_path / ".env"
        env.write_text(f"{users_line}MY_OPENAI_KEY={_TEST_KEY}\nOPENAI_API_KEY={_TEST_KEY}\n")
        _lock(env, home_dir)
        alias = _alias_for(home_dir, "OPENAI_API_KEY")

        _unlock(env, home_dir)
        after = dotenv_values(env)
        assert f"/{alias}/" not in env.read_text()
        assert after.get("OPENAI_BASE_URL") == ("https://api.openai.com/v1" if users_line else None)

    def test_a_line_referring_to_another_locked_line_is_put_back_as_its_value(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Restored as written, ${OPENAI_BASE_URL} would expand to the proxy line of a
        key that is still locked, and send the real OpenRouter key there."""
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://api.openai.com/v1\n"
            "OPENROUTER_BASE_URL=${OPENAI_BASE_URL}\n"
            f"OPENAI_API_KEY={_TEST_KEY}\nOPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "OPENROUTER_API_KEY"))
        assert dotenv_values(env)["OPENROUTER_BASE_URL"] == "https://api.openai.com/v1"

        _unlock(env, home_dir)
        assert dotenv_values(env)["OPENROUTER_BASE_URL"] == "https://api.openai.com/v1"

    def test_a_line_referring_to_another_locked_line_through_a_plain_var_is_put_back_as_its_value(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """${ROUTER}, where ROUTER=${OPENAI_BASE_URL}, reaches the locked line too
        (merge-ready security review)."""
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://api.openai.com/v1\n"
            "ROUTER=${OPENAI_BASE_URL}\n"
            "OPENROUTER_BASE_URL=${ROUTER}\n"
            f"OPENAI_API_KEY={_TEST_KEY}\nOPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "OPENROUTER_API_KEY"))
        assert dotenv_values(env)["OPENROUTER_BASE_URL"] == "https://api.openai.com/v1"

    @pytest.mark.parametrize("other_key", [False, True], ids=["alone", "next-to-an-openai-key"])
    def test_your_line_that_refers_to_a_line_lock_wrote_is_left_alone(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, other_key
    ) -> None:
        """While locked, ${OPENROUTER_BASE_URL} expands to the proxy, but lock never
        wrote OPENAI_BASE_URL: unlock must not rewrite or remove it (merge-ready brutus)."""
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            "OPENAI_BASE_URL=${OPENROUTER_BASE_URL}\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
            + (f"BACKUP_OPENAI_API_KEY={_TEST_KEY}\n" if other_key else "")
        )
        original = env.read_bytes()
        _lock(env, home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_a_line_that_refers_to_a_key_is_saved_as_written_never_expanded(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """The expanded form would put the real key into the DB record (CodeRabbit)."""
        env = tmp_path / ".env"
        _register_gateway(home_dir, f"https://gw.example.com/{_TEST_KEY}/v1", name="key-in-path")
        env.write_text(
            "OPENAI_API_KEY=" + _TEST_KEY + "\n"
            "OPENAI_BASE_URL=https://gw.example.com/${OPENAI_API_KEY}/v1\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        record_json, _mac = _saved_record(home_dir)
        if _TEST_KEY in record_json:
            pytest.fail("the saved BASE_URL record holds the key")  # never echo it

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_lock_never_saves_a_line_that_spells_out_a_key(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A key typed literally into the URL stays out of the record too (karen)."""
        env = tmp_path / ".env"
        _register_gateway(home_dir, f"https://gw.example.com/{_TEST_KEY}/v1", name="literal-key")
        env.write_text(
            f"OPENAI_API_KEY={_TEST_KEY}\nOPENAI_BASE_URL=https://gw.example.com/{_TEST_KEY}/v1\n"
        )
        locked = _lock(env, home_dir)
        record_json, _mac = _saved_record(home_dir)
        if _TEST_KEY in record_json:
            pytest.fail("the saved BASE_URL record holds the key")  # never echo it
        assert _said(locked, "it holds one of your keys")

        _unlock(env, home_dir)
        assert "OPENAI_BASE_URL" not in dotenv_values(env)

    def test_lock_never_saves_an_expanded_value_that_holds_a_key(self) -> None:
        """Whatever the reason lock falls back to the expanded form, a key never
        reaches the record (CodeRabbit on #738)."""
        from worthless.cli.commands.lock import _value_to_put_back
        from worthless.cli.dotenv_rewriter import EnvSnapshot

        snapshot = EnvSnapshot(
            parsed={
                "OPENAI_API_KEY": _TEST_KEY,
                "OPENAI_BASE_URL": f"https://gw.example.com/{_TEST_KEY}/v1",
            },
            raw={},  # the line as written could not be saved
            sha256=b"",
        )
        saved = _value_to_put_back(
            "OPENAI_BASE_URL", snapshot, {"OPENAI_BASE_URL"}, {"OPENAI_API_KEY"}
        )
        assert saved is None

    def test_a_line_that_defaults_to_itself_comes_back_as_written(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """${OPENROUTER_BASE_URL:-...} reads the shell, never the line lock rewrites."""
        monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_unlock_says_so_when_your_line_is_gone(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Deleting the proxy line after lock means unlock can't put yours back silently."""
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            f"OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY={key}\n"
        )
        _lock(env, home_dir)
        env.write_text(f"OPENROUTER_API_KEY={dotenv_values(env)['OPENROUTER_API_KEY']}\n")

        result = _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"
        assert "OPENROUTER_BASE_URL" in result.output
        assert "https://openrouter.ai" not in result.output  # names the line, never its value

    def test_unlock_never_macs_a_real_key(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real key back in the .env (a killed lock, a paste) fails the commitment
        check first; it must not reach the MAC (SR-01/SR-02, and the sidecar in IPC mode)."""
        from worthless.storage.repository import ShardRepository

        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            f"OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY={key}\n"
        )
        _lock(env, home_dir)
        env.write_text(env.read_text().replace(dotenv_values(env)["OPENROUTER_API_KEY"] or "", key))

        seen: list[str] = []
        real_mac = ShardRepository._compute_decoy_hash

        async def spy(self: ShardRepository, value: str) -> str:
            seen.append(value)
            return await real_mac(self, value)

        monkeypatch.setattr(ShardRepository, "_compute_decoy_hash", spy)
        result = _unlock(env, home_dir, check=False)
        assert result.exit_code != 0
        assert not any(key in value for value in seen)

    def test_lock_stops_when_the_env_changes_under_it(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pass-1 and the saved values describe one snapshot; the rewrite refuses a newer file."""
        import worthless.cli.commands.lock as lock_mod

        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        real_pass1 = lock_mod._pass1_db_writes

        async def pass1_then_edit(*args: object, **kwargs: object) -> None:
            await real_pass1(*args, **kwargs)  # type: ignore[arg-type]
            env.write_text(env.read_text().replace("openrouter.ai", "unregistered.example"))

        monkeypatch.setattr(lock_mod, "_pass1_db_writes", pass1_then_edit)
        result = _lock(env, home_dir, check=False)
        assert result.exit_code != 0, result.output
        assert _said(result, "file changed while worthless was writing it")
        assert "unregistered.example" in env.read_text()  # lock wrote nothing

    def test_lock_stops_when_the_env_changes_before_its_keys_are_scanned(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The snapshot comes first, so a key edited before the scan can't be locked
        from one file and rewritten into another (CodeRabbit on #738)."""
        import worthless.cli.commands.lock as lock_mod

        env = tmp_path / ".env"
        env.write_text(f"OPENROUTER_API_KEY={fake_openrouter_key()}\n")
        edited = f"OPENROUTER_API_KEY={fake_key('sk-or-v1-', seed='edited-before-scan')}\n"
        real_scan = lock_mod.scan_env_keys

        def edit_then_scan(path: Path):  # noqa: ANN202 — mirrors scan_env_keys
            env.write_text(edited)
            return real_scan(path)

        monkeypatch.setattr(lock_mod, "scan_env_keys", edit_then_scan)
        result = _lock(env, home_dir, check=False)
        assert result.exit_code != 0, result.output
        assert env.read_text() == edited  # lock wrote nothing over the edit

    def test_lock_stops_before_the_env_when_a_record_is_not_saved(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A key rotated in place, the old one kept under another name.

        The superseded-alias cleanup deletes the new MY_OPENAI_KEY row before
        its record is written; lock must stop instead of leaving a shard-A that
        no row can open.
        """
        old_key = fake_key("sk-proj-", seed="unlock-rotated-old")
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={old_key}\n")
        _lock(env, home_dir, "--keys-only")
        env.write_text(
            "OPENAI_BASE_URL=https://api.openai.com/v1\n"
            f"MY_OPENAI_KEY={old_key}\nOPENAI_API_KEY={_TEST_KEY}\n"
        )
        before = env.read_bytes()

        result = _lock(env, home_dir, check=False)
        assert result.exit_code != 0, result.output
        assert "unchanged" in result.output
        assert env.read_bytes() == before

    def test_a_line_you_changed_after_lock_is_kept(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)
        proxy_url = dotenv_values(env)["OPENROUTER_BASE_URL"] or ""
        env.write_text(env.read_text().replace(proxy_url, "https://eu.openrouter.ai/api/v1"))

        _unlock(env, home_dir)
        assert dotenv_values(env)["OPENROUTER_BASE_URL"] == "https://eu.openrouter.ai/api/v1"

    def test_a_key_locked_by_an_older_version_gets_your_line_back(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """No record: unlock writes back the upstream the key used while locked, which
        lock took from your own line (release-owner decision for #738)."""
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        result = _unlock(env, home_dir)
        assert env.read_bytes() == original
        # Never silent: the note names the file (uninstall walks several) and the
        # host it wrote, so a surprising destination shows (WOR-1023).
        assert _said(
            result,
            "to an address at https://openrouter.ai, the upstream this key used while locked",
        )
        assert _said(result, "older version")
        assert str(env) in "".join(result.output.split())

    def test_a_key_locked_by_an_older_version_keeps_a_working_line_lock_added(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Lock added the line, so the stored upstream is the provider's own: a correct
        extra line, never the SDK's api.openai.com default."""
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(f"OPENROUTER_API_KEY={key}\n")
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert dotenv_values(env) == {
            "OPENROUTER_API_KEY": key,
            "OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1",
        }

    def test_an_old_row_never_points_a_protocol_line_at_another_vendor(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """OPENROUTER_KEY reaches OPENAI_BASE_URL only through the protocol's name, and
        OPENAI_KEY reads that line too: OpenRouter's address there would send the real
        OpenAI key to OpenRouter (brutus on #738)."""
        env = tmp_path / ".env"
        env.write_text(f"OPENROUTER_KEY={fake_openrouter_key()}\nOPENAI_KEY={_TEST_KEY}\n")
        _lock(env, home_dir)
        assert dotenv_values(env)["OPENAI_BASE_URL"].endswith(
            f"/{_alias_for(home_dir, 'OPENROUTER_KEY')}/v1"
        )
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert "OPENAI_BASE_URL" not in dotenv_values(env)

    @pytest.mark.parametrize(
        ("content", "line"),
        [
            # 1. A DeepSeek key starts with sk-, so old locks stored OpenAI's address.
            (f"DEEPSEEK_API_KEY={fake_key('sk-', seed='deepseek-old-row')}\n", "DEEPSEEK_BASE_URL"),
            # 2. The OpenAI SDK reads OPENAI_BASE_URL for OPENAI_KEY's key too.
            (
                f"OPENAI_API_KEY={fake_openrouter_key()}\nOPENAI_KEY={_TEST_KEY}\n",
                "OPENAI_BASE_URL",
            ),
            # 3. The Anthropic SDK reads ANTHROPIC_BASE_URL, whatever key it holds.
            (f"ANTHROPIC_API_KEY={fake_openrouter_key()}\n", "ANTHROPIC_BASE_URL"),
            # An OpenAI SDK reads OPENAI_BASE_URL: never an Anthropic address there.
            (f"OPENAI_API_KEY={_TEST_KEY_2}\n", "OPENAI_BASE_URL"),
        ],
        ids=[
            "sk-key-of-another-vendor",
            "another-key-reads-the-line",
            "anthropic-line",
            "cross-protocol-line",
        ],
    )
    def test_an_old_row_writes_no_address_another_vendor_or_client_would_misuse(
        self, home_dir: WorthlessHome, tmp_path: Path, content: str, line: str
    ) -> None:
        """Brutus round 4 on #738: the line is removed, as main does."""
        env = tmp_path / ".env"
        env.write_text(content)
        _lock(env, home_dir)
        assert line in dotenv_values(env)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert line not in dotenv_values(env)

    def test_an_old_row_writes_no_address_a_key_never_locked_would_follow(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A plain OpenAI key added after lock also reads OPENAI_BASE_URL (Bugbot)."""
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENAI_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)
        with env.open("a") as f:
            f.write(f"OPENAI_KEY={_TEST_KEY}\n")

        _unlock(env, home_dir)
        assert "OPENAI_BASE_URL" not in dotenv_values(env)

    def test_an_old_row_under_two_names_still_gets_its_line_back(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Both names hold the same OpenRouter key, so sharing the line is safe (Bugbot)."""
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            "OPENAI_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENAI_API_KEY={key}\nMY_OPENROUTER={key}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert dotenv_values(env)["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"

    def test_an_old_row_writes_no_anthropic_address_into_any_line(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """CLAUDE_BASE_URL too: an app passing it to Anthropic(base_url=...) would call
        /v1/v1/messages (brutus round 5)."""
        env = tmp_path / ".env"
        env.write_text(f"CLAUDE_API_KEY={_TEST_KEY_2}\n")
        original = env.read_bytes()
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_an_old_row_checks_the_protocol_line_of_a_key_under_its_own_name(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """MY_OPENAI_API_KEY's own line is MY_OPENAI_BASE_URL, but its OpenAI SDK reads
        OPENAI_BASE_URL too, so OpenRouter's address can't go there."""
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENAI_API_KEY={fake_openrouter_key()}\nMY_OPENAI_API_KEY={_TEST_KEY}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert "OPENAI_BASE_URL" not in dotenv_values(env)

    def test_an_old_row_never_writes_a_gateway_of_another_protocol_into_its_line(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A providers.toml edited by hand can give a gateway a protocol whose SDK
        doesn't read OPENAI_BASE_URL (karen: pins the protocol-line check)."""
        _register_gateway(home_dir)
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_BASE_URL={_GATEWAY_URL}\nOPENAI_API_KEY={_TEST_KEY}\n")
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)
        registry = user_registry_path()
        registry.write_text(registry.read_text().replace('"openai"', '"gemini"'))

        _unlock(env, home_dir)
        assert env.read_text() == f"OPENAI_API_KEY={_TEST_KEY}\n"

    def test_an_old_row_whose_stored_address_is_another_vendors_loses_the_line(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A bundled address goes back only for the vendor the key's own prefix names."""
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            f"OPENROUTER_BASE_URL=https://api.groq.com/openai/v1\nOPENROUTER_API_KEY={key}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"

    def test_an_old_row_gets_your_registered_gateway_back(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """A gateway you registered came from your own line, so it goes back."""
        _register_gateway(home_dir)
        env = tmp_path / ".env"
        env.write_text(
            f"OPENROUTER_BASE_URL={_GATEWAY_URL}\nOPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_an_old_row_never_writes_back_a_private_or_cleartext_gateway(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Registered or not, a stored http or private address fails lock's SSRF check."""
        _register_gateway(home_dir, "http://10.0.0.5/v1", name="private-gw")
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(f"OPENROUTER_BASE_URL=http://10.0.0.5/v1\nOPENROUTER_API_KEY={key}\n")
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"

    def test_unlock_stops_when_the_env_changes_under_it(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unlock judges the lines on one snapshot, and its rewrite refuses a newer file."""
        import worthless.cli.commands.unlock as unlock_mod

        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)
        real_snapshot = unlock_mod.read_env_snapshot

        def snapshot_then_edit(path: Path):  # noqa: ANN202 — mirrors read_env_snapshot
            taken = real_snapshot(path)
            with env.open("a") as f:
                f.write("EDITED_DURING_UNLOCK=1\n")
            return taken

        monkeypatch.setattr(unlock_mod, "read_env_snapshot", snapshot_then_edit)
        result = _unlock(env, home_dir, check=False)
        assert result.exit_code != 0, result.output
        assert "EDITED_DURING_UNLOCK=1" in env.read_text()
        assert "127.0.0.1" in env.read_text()  # nothing was restored over the edit

    def test_an_old_anthropic_row_gets_no_line_its_sdk_would_misread(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """The registry keeps /v1 on Anthropic's URL for the proxy; the Anthropic SDK adds
        its own, so writing it back would turn every call into /v1/v1/messages."""
        env = tmp_path / ".env"
        env.write_text(f"ANTHROPIC_API_KEY={_TEST_KEY_2}\n")
        original = env.read_bytes()
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_an_old_row_gets_openrouter_back_in_openai_base_url_named_after_its_key(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """OpenRouter's documented setup: its key in OPENAI_API_KEY, its address in
        OPENAI_BASE_URL. The line is named after this key, so it comes back."""
        env = tmp_path / ".env"
        env.write_text(
            "OPENAI_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENAI_API_KEY={fake_openrouter_key()}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    @pytest.mark.parametrize(
        "stored",
        # Ollama's bundled URL is registered, but lock's SSRF check refuses loopback.
        [
            "https://unregistered.example/v1",
            "http://localhost:11434/v1",
            # Registered, but python-dotenv (or a shell) would expand another key into it.
            "https://gw.example.com/${OPENAI_API_KEY}/v1",
            "https://gw.example.com/$OPENAI_API_KEY/v1",
            # Registered, but the rewriter can't write a quote back (WOR-1027).
            "https://gw.example.com/o'neil/v1",
        ],
        ids=[
            "unregistered",
            "registered-but-loopback",
            "registered-with-reference",
            "registered-with-bare-dollar",
            "registered-but-unwritable",
        ],
    )
    def test_an_old_row_whose_stored_upstream_lock_would_refuse_loses_the_line(
        self, home_dir: WorthlessHome, tmp_path: Path, stored: str
    ) -> None:
        if "$" in stored or "'" in stored:
            _register_gateway(home_dir, stored, name="reference-gw")
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            f"OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY={key}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)
        with contextlib.closing(sqlite3.connect(home_dir.db_path)) as conn:
            conn.execute("UPDATE shards SET base_url = ?", (stored,))
            conn.commit()

        result = _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"
        assert _said(result, "Removed OPENROUTER_BASE_URL")

    def test_a_tampered_record_is_not_written_into_the_env(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Without the Fernet key, a DB edit can't choose where the real key goes next."""
        env = tmp_path / ".env"
        key = fake_openrouter_key()
        env.write_text(
            f"OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY={key}\n"
        )
        _lock(env, home_dir)
        _edit_enrollments(
            home_dir,
            "base_url_restore_json ="
            " replace(base_url_restore_json, 'openrouter.ai', 'evil.example')",
        )

        result = _unlock(env, home_dir)
        assert env.read_text() == f"OPENROUTER_API_KEY={key}\n"
        assert _said(result, "changed in the Worthless database")


class TestOlderRowsOnlyTouchLinesThatRouteThem:
    """Rows from before WOR-1013 still act on a line only while it routes their alias."""

    def test_your_own_other_base_url_is_kept(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            f"OPENAI_BASE_URL=https://api.openai.com/v1\nOPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        _lock(env, home_dir)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        after = dotenv_values(env)
        assert after["OPENAI_BASE_URL"] == "https://api.openai.com/v1"
        assert after["OPENROUTER_BASE_URL"] == "https://openrouter.ai/api/v1"  # lock added it

    def test_keys_only_keeps_your_line(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
            f"OPENROUTER_API_KEY={fake_openrouter_key()}\n"
        )
        original = env.read_bytes()
        _lock(env, home_dir, "--keys-only")
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir)
        assert env.read_bytes() == original

    def test_a_still_locked_key_keeps_its_line(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={_TEST_KEY}\nOPENROUTER_API_KEY={fake_openrouter_key()}\n")
        _lock(env, home_dir)
        locked = dotenv_values(env)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "OPENROUTER_API_KEY"))
        assert dotenv_values(env)["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]

    def test_a_shared_line_another_key_owns_is_kept(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        env = tmp_path / ".env"
        env.write_text(
            f"MY_OPENAI_KEY={fake_key('sk-proj-', seed='unlock-old-row-shared')}\n"
            f"OPENAI_API_KEY={_TEST_KEY}\n"
        )
        _lock(env, home_dir)
        locked = dotenv_values(env)
        _as_enrolled_before_wor_1013(home_dir)

        _unlock(env, home_dir, "--alias", _alias_for(home_dir, "MY_OPENAI_KEY"))
        assert dotenv_values(env)["OPENAI_BASE_URL"] == locked["OPENAI_BASE_URL"]


class TestEnrollUnlockNullEnvPath:
    """Direct enroll (env_path=NULL) followed by unlock should clean up completely."""

    def test_enroll_then_unlock_prints_key(self, home_dir: WorthlessHome) -> None:
        """After enroll (env_path=NULL), unlock prints key to stdout."""
        from worthless.cli.commands.lock import _make_alias

        alias = _make_alias("openai", _TEST_KEY)

        # Enroll via CLI
        result = runner.invoke(
            app,
            ["enroll", "--alias", alias, "--key-stdin", "--provider", "openai"],
            input=f"{_TEST_KEY}\n",
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

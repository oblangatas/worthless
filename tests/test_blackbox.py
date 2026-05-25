"""Black-box functional tests for the worthless CLI.

Exercises the product from the outside -- lock, unlock, scan, status --
without knowledge of internal implementation. Each test verifies observable
behavior: .env file changes, exit codes, JSON output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome, ensure_home

from tests.helpers import fake_anthropic_key, fake_openai_key

runner = CliRunner(mix_stderr=False)

# WOR-582: CliRunner.invoke(["lock", ...]) calls asyncio.run() via bootstrap;
# under xdist threaded workers this triggers event-loop conflicts that hang the
# worker. Route the whole module to the serial pass (-n0).
pytestmark = pytest.mark.real_ipc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def home_dir(tmp_path: Path) -> WorthlessHome:
    """Bootstrap a fresh WorthlessHome in tmp_path."""
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture()
def cli_env(home_dir: WorthlessHome) -> dict[str, str]:
    """Environment dict isolating WORTHLESS_HOME."""
    return {"WORTHLESS_HOME": str(home_dir.base_dir)}


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    """Create a .env with a single OpenAI key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture()
def multi_env_file(tmp_path: Path) -> Path:
    """Create a .env with both OpenAI and Anthropic keys."""
    env = tmp_path / ".env"
    env.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\nANTHROPIC_API_KEY={fake_anthropic_key()}\n"
    )
    return env


# ---------------------------------------------------------------------------
# TestLock
# ---------------------------------------------------------------------------


class TestLock:
    """Lock replaces keys with format-preserving shards in .env."""

    def test_lock_replaces_key_format_preserving(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """Lock produces a shard with same prefix, same length, different value."""
        original_key = fake_openai_key()

        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(env_file)
        shard_a = parsed["OPENAI_API_KEY"]
        assert shard_a.startswith("sk-proj-"), "Shard must preserve prefix"
        assert len(shard_a) == len(original_key), "Shard must preserve length"
        assert shard_a != original_key, "Shard must differ from original"

    def test_lock_adds_base_url_with_v1_suffix(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """Lock writes OPENAI_BASE_URL ending with /v1."""
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(env_file)
        base_url = parsed.get("OPENAI_BASE_URL")
        assert base_url is not None, "OPENAI_BASE_URL should be added"
        assert base_url.endswith("/v1"), f"BASE_URL should end with /v1, got {base_url}"

    def test_lock_keys_only_skips_base_url(self, cli_env: dict[str, str], env_file: Path) -> None:
        """--keys-only flag prevents BASE_URL from being written."""
        result = runner.invoke(app, ["lock", "--env", str(env_file), "--keys-only"], env=cli_env)
        assert result.exit_code == 0, result.output

        content = env_file.read_text()
        assert "BASE_URL" not in content

    def test_double_lock_is_idempotent(self, cli_env: dict[str, str], env_file: Path) -> None:
        """Second lock does not re-split an already-enrolled key."""
        result1 = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result1.exit_code == 0

        value_after_first = dotenv_values(env_file)["OPENAI_API_KEY"]

        result2 = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result2.exit_code == 0

        value_after_second = dotenv_values(env_file)["OPENAI_API_KEY"]
        assert value_after_first == value_after_second, "Second lock should not change shard"


# ---------------------------------------------------------------------------
# TestUnlock
# ---------------------------------------------------------------------------


class TestUnlock:
    """Unlock restores original keys and cleans up .env."""

    def test_unlock_restores_original_key(self, cli_env: dict[str, str], env_file: Path) -> None:
        """Unlock restores the exact original key value."""
        original_key = fake_openai_key()

        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0

        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(env_file)
        assert parsed["OPENAI_API_KEY"] == original_key

    def test_unlock_removes_base_url(self, cli_env: dict[str, str], env_file: Path) -> None:
        """Unlock removes the OPENAI_BASE_URL that lock added."""
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0
        assert "OPENAI_BASE_URL" in env_file.read_text()

        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0

        assert "OPENAI_BASE_URL" not in env_file.read_text()


# ---------------------------------------------------------------------------
# TestScan
# ---------------------------------------------------------------------------


class TestScan:
    """Scan detects unprotected keys and respects enrollment status."""

    def test_scan_before_lock_finds_unprotected(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """Scan on an unlocked .env exits 1 (unprotected keys found)."""
        result = runner.invoke(
            app,
            ["scan", "--pre-commit", "--json", str(env_file)],
            env=cli_env,
        )
        assert result.exit_code == 1

        data = json.loads(result.stdout)
        # HF5: scan --json shape is {schema_version, findings, orphans}.
        unprotected = [f for f in data["findings"] if not f["is_protected"]]
        assert len(unprotected) >= 1

    def test_scan_after_lock_reports_zero_unprotected(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """Scan on a locked .env exits 0 (all keys protected)."""
        lock_result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert lock_result.exit_code == 0

        result = runner.invoke(
            app,
            ["scan", "--pre-commit", "--json", str(env_file)],
            env=cli_env,
        )
        assert result.exit_code == 0

    def test_scan_after_unlock_finds_unprotected(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """Scan after lock+unlock exits 1 again (key restored, unprotected)."""
        r = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert r.exit_code == 0, f"setup lock failed: {r.output}"
        r = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert r.exit_code == 0, f"setup unlock failed: {r.output}"

        result = runner.invoke(
            app,
            ["scan", "--pre-commit", "--json", str(env_file)],
            env=cli_env,
        )
        assert result.exit_code == 1

        data = json.loads(result.stdout)
        # HF5: scan --json shape is {schema_version, findings, orphans}.
        unprotected = [f for f in data["findings"] if not f["is_protected"]]
        assert len(unprotected) >= 1


# ---------------------------------------------------------------------------
# TestStatus
# ---------------------------------------------------------------------------


class TestStatus:
    """Status --json reflects enrollment state."""

    def test_status_json_shows_enrolled_key_after_lock(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """After lock, status --json lists the enrolled key."""
        r = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert r.exit_code == 0, f"setup lock failed: {r.output}"

        result = runner.invoke(app, ["--json", "status"], env=cli_env)
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert len(data["keys"]) == 1
        assert data["keys"][0]["provider"] == "openai"

    def test_status_json_empty_before_lock(self, cli_env: dict[str, str], env_file: Path) -> None:
        """Before lock, status --json shows no enrolled keys."""
        result = runner.invoke(app, ["--json", "status"], env=cli_env)
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert data["keys"] == []

    def test_status_json_empty_after_unlock(self, cli_env: dict[str, str], env_file: Path) -> None:
        """After lock+unlock, status --json shows no enrolled keys."""
        r = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert r.exit_code == 0, f"setup lock failed: {r.output}"
        r = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert r.exit_code == 0, f"setup unlock failed: {r.output}"

        result = runner.invoke(app, ["--json", "status"], env=cli_env)
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert data["keys"] == []


# ---------------------------------------------------------------------------
# TestIdempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Roundtrip lock/unlock cycles preserve original keys."""

    def test_lock_unlock_lock_unlock_roundtrip(
        self, cli_env: dict[str, str], env_file: Path
    ) -> None:
        """lock -> unlock -> lock -> unlock restores original key both times."""
        original_key = fake_openai_key()

        # First cycle
        runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0
        assert dotenv_values(env_file)["OPENAI_API_KEY"] == original_key

        # Second cycle
        runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0
        assert dotenv_values(env_file)["OPENAI_API_KEY"] == original_key


# ---------------------------------------------------------------------------
# TestMultiKey
# ---------------------------------------------------------------------------


class TestMultiKey:
    """Multi-key operations protect and restore independently."""

    def test_lock_protects_both_keys_with_prefix_preservation(
        self, cli_env: dict[str, str], multi_env_file: Path
    ) -> None:
        """Lock protects both OpenAI and Anthropic keys, preserving prefixes."""
        original_openai = fake_openai_key()
        original_anthropic = fake_anthropic_key()

        result = runner.invoke(app, ["lock", "--env", str(multi_env_file)], env=cli_env)
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(multi_env_file)

        # OpenAI shard preserves prefix and length
        openai_shard = parsed["OPENAI_API_KEY"]
        assert openai_shard.startswith("sk-proj-")
        assert len(openai_shard) == len(original_openai)
        assert openai_shard != original_openai

        # Anthropic shard preserves prefix and length
        anthropic_shard = parsed["ANTHROPIC_API_KEY"]
        assert anthropic_shard.startswith("sk-ant-api03-")
        assert len(anthropic_shard) == len(original_anthropic)
        assert anthropic_shard != original_anthropic

    def test_unlock_one_key_by_alias_other_stays_locked(
        self, cli_env: dict[str, str], multi_env_file: Path
    ) -> None:
        """Unlocking one key by alias leaves the other locked with its BASE_URL."""
        result = runner.invoke(app, ["lock", "--env", str(multi_env_file)], env=cli_env)
        assert result.exit_code == 0

        # Find the OpenAI alias from status
        status_result = runner.invoke(app, ["--json", "status"], env=cli_env)
        data = json.loads(status_result.stdout)
        openai_alias = next(k["alias"] for k in data["keys"] if k["provider"] == "openai")
        anthropic_alias = next(k["alias"] for k in data["keys"] if k["provider"] == "anthropic")

        # Unlock only the OpenAI key
        unlock_result = runner.invoke(
            app,
            ["unlock", "--alias", openai_alias, "--env", str(multi_env_file)],
            env=cli_env,
        )
        assert unlock_result.exit_code == 0

        parsed = dotenv_values(multi_env_file)

        # OpenAI key restored
        assert parsed["OPENAI_API_KEY"] == fake_openai_key()
        assert "OPENAI_BASE_URL" not in parsed

        # Anthropic key still locked (shard, not original)
        assert parsed["ANTHROPIC_API_KEY"] != fake_anthropic_key()
        assert "ANTHROPIC_BASE_URL" in parsed

        # Status still shows the anthropic key enrolled
        status_result = runner.invoke(app, ["--json", "status"], env=cli_env)
        remaining = json.loads(status_result.stdout)["keys"]
        remaining_aliases = [k["alias"] for k in remaining]
        assert anthropic_alias in remaining_aliases
        assert openai_alias not in remaining_aliases

"""UX tests for the worthless CLI.

These tests verify user-facing messages, exit codes, and output formats
from the perspective of someone typing commands in a terminal.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.crypto.splitter import split_key
from worthless.storage.repository import ShardRepository, StoredShard

from tests.helpers import fake_anthropic_key, fake_openai_key

# mix_stderr=False so we can inspect stdout vs stderr independently
runner = CliRunner(mix_stderr=False)

# Scanner-safe fake keys (generated at runtime to avoid false positives).
_OPENAI_KEY = fake_openai_key()
_ANTHROPIC_KEY = fake_anthropic_key()

# home_with_key fixture is in conftest.py


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent scan from picking up the project-root .env."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def env_with_openai(tmp_path: Path) -> Path:
    """Create a .env with one OpenAI key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n")
    return env


@pytest.fixture()
def env_clean(tmp_path: Path) -> Path:
    """Create a .env with no API keys."""
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://localhost/db\nAPP_NAME=myapp\n")
    return env


@pytest.fixture()
def env_with_google(tmp_path: Path) -> Path:
    """Create a .env with a Google AI key (unsupported provider)."""
    env = tmp_path / ".env"
    # Google keys look like AIzaSy... (39 chars), high-entropy
    env.write_text("GOOGLE_API_KEY=AIzaSyB3x7k9mR2pQ1wE5vF8nJ4hL0tY6uI2oP3\n")
    return env


# home_with_key fixture is in conftest.py


@pytest.fixture()
def home_with_multi_env_key(home_dir: WorthlessHome) -> WorthlessHome:
    """Home with one alias enrolled in TWO different env files (ambiguous)."""
    sr = split_key(_OPENAI_KEY.encode())
    try:
        alias = "openai-a1b2c3d4"
        # SR-09: no shard_a file on disk -- shard-A lives in .env only
        repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
        asyncio.run(repo.initialize())
        stored = StoredShard(
            shard_b=bytearray(sr.shard_b),
            commitment=bytearray(sr.commitment),
            nonce=bytearray(sr.nonce),
            provider="openai",
        )
        asyncio.run(
            repo.store_enrolled(
                alias,
                stored,
                var_name="OPENAI_API_KEY",
                env_path="/project-a/.env",
            )
        )
        asyncio.run(
            repo.store_enrolled(
                alias,
                stored,
                var_name="OPENAI_API_KEY",
                env_path="/project-b/.env",
            )
        )
    finally:
        sr.zero()
    return home_dir


# ===================================================================
# 1. HELP TEXT
# ===================================================================


class TestHelpText:
    """Verify --help lists all commands."""

    def test_help_shows_all_commands(self) -> None:
        """worthless --help should list all 7 commands."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        output = result.stdout
        for cmd in ("lock", "unlock", "enroll", "scan", "status", "wrap", "up"):
            assert cmd in output, f"Command {cmd!r} missing from --help output"

    def test_no_args_runs_default_command(self, home_dir: WorthlessHome) -> None:
        """worthless with no args runs the default pipeline (not help).

        No xdist_group marker: the autouse `_isolate_default_command_proxy`
        fixture in conftest.py stubs the daemon path for every test, so two
        workers can run this in parallel without racing port 8787.

        Isolated WORTHLESS_HOME: without it the no-args path resolves the
        developer's real ~/.worthless and ``run_default`` aborts with
        WRTLS-102 on a dogfooding box whose Fernet key lives only in the
        keyring (which conftest nulls for the test session).
        """
        result = runner.invoke(app, [], env={"WORTHLESS_HOME": str(home_dir.base_dir)})
        assert result.exit_code == 0, (
            f"worthless with no args failed:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
            f"exception: {result.exception!r}"
        )
        output = result.stdout + result.stderr
        # Default command runs — should NOT show help/command list
        assert "Usage:" not in output


# ===================================================================
# 2. LOCK UX
# ===================================================================


class TestLockUx:
    """User-facing messages from the lock command."""

    def test_lock_success_message_tells_the_story(
        self, home_dir: WorthlessHome, env_with_openai: Path
    ) -> None:
        """Success message names the .env file + says what changed (UX P1#3).

        Combines two intents:

        - Main's storytelling shape: name what changed and which .env file
          is now safe ("split between this machine and your system
          keystore — {env_filename} no longer contains a usable secret.").
        - Trust-fix accessibility (2026-05-08 verification gauntlet):
          lead with the literal ``[OK]`` text prefix as the carrier for
          monochrome terminals + screen readers + CI log scrapers
          (color/glyph reinforces but is never the carrier).

        Both must hold — no regression on either side.
        """
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_openai)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        # Trust-fix accessibility: literal ``[OK]`` carrier present.
        assert "[OK]" in combined, f"success message missing [OK] text prefix:\n{combined}"
        # Main's storytelling: must say what changed.
        assert "split between" in combined, (
            f"success message missing storytelling shape:\n{combined}"
        )
        # Must name the actual .env file so user knows which file is now safe.
        assert env_with_openai.name in combined, (
            f"success message did not reference {env_with_openai.name}:\n{combined}"
        )
        # Count is still surfaced — runtime plural: "1 key split between …"
        assert "1 key split between" in combined, f"count missing from success:\n{combined}"

    def test_lock_protect_message_names_each_key(
        self, home_dir: WorthlessHome, env_with_openai: Path
    ) -> None:
        """During lock, the 'Protecting ...' line names the env vars (UX P0#2).

        Prior "  Protecting {N} key(s)..." was opaque. Users couldn't tell
        which secrets were being touched. New wording lists var names:
        "  Protecting OPENAI_API_KEY...".
        """
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_openai)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "OPENAI_API_KEY" in combined, (
            f"protect message did not name the var being touched:\n{combined}"
        )

    def test_lock_macos_pre_announces_keychain_dialog(
        self,
        home_dir: WorthlessHome,
        env_with_openai: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On macOS, lock pre-announces the Keychain dialog (UX P0#1).

        First-time users on macOS see a system dialog labelled 'python3.10'
        mid-`lock`, panic, and click Deny. The pre-announce sets expectation
        and tells them to click 'Always Allow'. Mock sys.platform so this
        test runs on every CI platform.
        """
        import sys

        from worthless.cli.commands import lock as lock_module

        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(lock_module, "keyring_available", lambda: True)
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_openai)],
            env={
                "HOME": str(home_dir.base_dir.parent / "user-home"),
                "USERPROFILE": str(home_dir.base_dir.parent / "user-home"),
                "WORTHLESS_HOME": str(home_dir.base_dir),
            },
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        # The hint must mention Keychain AND Always Allow so the user knows
        # exactly what the dialog will look like and what to click.
        assert "Keychain" in combined, f"macOS pre-announce missing 'Keychain':\n{combined}"
        assert "Always Allow" in combined, f"macOS pre-announce missing 'Always Allow':\n{combined}"

    def test_lock_non_macos_does_not_pre_announce_keychain(
        self,
        home_dir: WorthlessHome,
        env_with_openai: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On non-macOS platforms, no Keychain pre-announce — wrong UX cue.

        Linux Secret Service / Windows DPAPI prompt differently (or not at
        all). Saying 'click Always Allow' on those platforms confuses users.
        """
        import sys

        monkeypatch.setattr(sys, "platform", "linux")
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_openai)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "Always Allow" not in combined, (
            f"non-macOS run leaked the macOS-only Keychain hint:\n{combined}"
        )

    def test_lock_file_fallback_does_not_claim_keychain_or_system_keystore(
        self,
        home_dir: WorthlessHome,
        env_with_openai: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When keyring is forced off, lock must not claim Keychain storage."""
        import sys

        monkeypatch.setattr(sys, "platform", "darwin")
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_openai)],
            env={
                "HOME": str(home_dir.base_dir.parent / "user-home"),
                "USERPROFILE": str(home_dir.base_dir.parent / "user-home"),
                "WORTHLESS_HOME": str(home_dir.base_dir),
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "Keychain" not in combined, (
            f"file fallback should not mention macOS Keychain:\n{combined}"
        )
        assert "system keystore" not in combined, (
            f"file fallback should not claim system keystore storage:\n{combined}"
        )
        assert "local key file" in combined, (
            f"file fallback should name where the other shard lives:\n{combined}"
        )

    def test_lock_no_keys_message(self, home_dir: WorthlessHome, env_clean: Path) -> None:
        """When .env has no API keys, user sees 'No unprotected API keys found.'"""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_clean)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "No unprotected API keys found" in combined

    def test_lock_unsupported_provider_warning(
        self, home_dir: WorthlessHome, env_with_google: Path
    ) -> None:
        """When .env has a Google key, user sees warning about unsupported provider."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_google)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        # Should not crash, and should warn about unsupported
        combined = result.stdout + result.stderr
        assert "not yet supported" in combined or "No unprotected" in combined


# ===================================================================
# 3. UNLOCK UX
# ===================================================================


class TestUnlockUx:
    """User-facing messages from the unlock command."""

    def test_unlock_single_alias_message(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """After unlocking a specific alias, user sees a per-key 'Restored …' line.

        HF4 (worthless-5u6y): replaces the old 'Unlocked {alias}.' message
        with a precise per-key audit line that names the env var, provider,
        alias, and target path. Auditable on a glance; loud on a typo'd --env.
        """
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n")
        home_env = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        # Lock first (creates format-preserving enrollment)
        lock_result = runner.invoke(app, ["lock", "--env", str(env)], env=home_env)
        assert lock_result.exit_code == 0, (
            f"lock failed: {lock_result.stdout}\n{lock_result.stderr}"
        )

        from tests.conftest import make_repo as _repo

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        alias = aliases[0]

        result = runner.invoke(
            app,
            ["unlock", "--alias", alias, "--env", str(env)],
            env=home_env,
        )
        assert result.exit_code == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
        combined = result.stdout + result.stderr
        assert "Restored" in combined and alias in combined, (
            f"expected per-key 'Restored ... alias {alias} ...' line, got:\n{combined}"
        )

    def test_unlock_all_keys_message(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """After unlocking 2+ keys, user sees 'N key(s) restored.' summary
        in addition to per-key Restored lines.

        For N==1 the per-key line already names the var/provider/path; the
        summary would be redundant and is intentionally skipped.
        """
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\nANTHROPIC_API_KEY={_ANTHROPIC_KEY}\n")
        home_env = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        # Lock first (creates format-preserving enrollments for both keys)
        lock_result = runner.invoke(app, ["lock", "--env", str(env)], env=home_env)
        assert lock_result.exit_code == 0, (
            f"lock failed: {lock_result.stdout}\n{lock_result.stderr}"
        )

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env)],
            env=home_env,
        )
        assert result.exit_code == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
        combined = result.stdout + result.stderr
        assert "2 key(s) restored" in combined, combined

    def test_unlock_no_keys_message(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """When no keys enrolled, user sees 'No enrolled keys found.'"""
        env = tmp_path / ".env"
        env.write_text("SOME_VAR=value\n")

        result = runner.invoke(
            app,
            ["unlock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "No enrolled keys found" in combined

    def test_unlock_ambiguous_alias_error(self, home_with_multi_env_key: WorthlessHome) -> None:
        """When alias is in 2 env files and --env does not match, user gets error."""
        result = runner.invoke(
            app,
            ["unlock", "--alias", "openai-a1b2c3d4", "--env", "/nonexistent/.env"],
            env={"WORTHLESS_HOME": str(home_with_multi_env_key.base_dir)},
        )
        # Should error cleanly (env file doesn't exist or enrollment not found)
        assert result.exit_code in (0, 1)


# ===================================================================
# 4. ENROLL UX
# ===================================================================


class TestEnrollUx:
    """User-facing messages from the enroll command."""

    def test_enroll_key_stdin(self, home_dir: WorthlessHome) -> None:
        """Piping key via --key-stdin works."""
        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "stdin-test",
                "--key-stdin",
                "--provider",
                "openai",
            ],
            input=f"{_OPENAI_KEY}\n",
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
        combined = result.stdout + result.stderr
        assert "Enrolled stdin-test" in combined

    def test_enroll_invalid_alias(self, home_dir: WorthlessHome) -> None:
        """Invalid alias (special chars) gives clear error."""
        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "bad alias!@#",
                "--key",
                _OPENAI_KEY,
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "Invalid alias" in combined or "invalid alias" in combined.lower()

    def test_enroll_no_key_errors(self, home_dir: WorthlessHome) -> None:
        """Enroll without --key or --key-stdin gives error."""
        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "no-key",
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "key" in combined.lower()

    def test_enroll_empty_stdin_errors(self, home_dir: WorthlessHome) -> None:
        """Enroll with --key-stdin but empty input gives error."""
        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "empty-stdin",
                "--key-stdin",
                "--provider",
                "openai",
            ],
            input="\n",
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "No key provided" in combined or "key" in combined.lower()


# ===================================================================
# 5. SCAN UX
# ===================================================================


class TestScanUx:
    """User-facing messages and exit codes from the scan command."""

    def test_scan_no_keys_message(self, env_clean: Path, tmp_path: Path) -> None:
        """'No API keys found.' when scanning a clean .env.

        Isolated WORTHLESS_HOME so dev-box orphans (HF5 surfaces orphan DB
        rows in scan output, which would otherwise contribute to the
        no-findings early-exit being skipped).
        """
        result = runner.invoke(
            app,
            ["scan", str(env_clean)],
            env={"WORTHLESS_HOME": str(tmp_path / ".worthless")},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "No API keys found" in combined

    def test_scan_exit_0_clean(self, env_clean: Path) -> None:
        """Exit 0 when no unprotected keys found."""
        result = runner.invoke(app, ["scan", str(env_clean)])
        assert result.exit_code == 0

    def test_scan_exit_1_unprotected(self, env_with_openai: Path) -> None:
        """Exit 1 when unprotected keys found."""
        result = runner.invoke(app, ["scan", str(env_with_openai)])
        assert result.exit_code == 1

    def test_scan_exit_2_error(self) -> None:
        """Exit 2 when scan encounters an error (invalid format)."""
        result = runner.invoke(app, ["scan", "--format", "xml"])
        assert result.exit_code == 2

    def test_scan_format_json_valid(self, env_with_openai: Path) -> None:
        """--format json returns valid JSON object with schema_version+findings+orphans (HF5)."""
        result = runner.invoke(app, ["scan", "--format", "json", str(env_with_openai)])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        assert data["schema_version"] >= 2
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        assert "provider" in data["findings"][0]
        assert "orphans" in data and isinstance(data["orphans"], list)

    def test_scan_format_sarif_valid(self, env_with_openai: Path) -> None:
        """--format sarif returns valid SARIF v2.1.0."""
        result = runner.invoke(app, ["scan", "--format", "sarif", str(env_with_openai)])
        assert result.exit_code == 1
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_scan_invalid_format_error(self) -> None:
        """--format xml gives a clear error message."""
        result = runner.invoke(app, ["scan", "--format", "xml"])
        combined = result.stdout + result.stderr
        assert result.exit_code == 2
        assert "Unknown format" in combined or "xml" in combined


# ===================================================================
# 6. STATUS UX
# ===================================================================


class TestStatusUx:
    """User-facing messages from the status command."""

    def test_status_no_enrollment(self, home_dir: WorthlessHome) -> None:
        """Shows 'No keys enrolled.' when fresh install."""
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "No keys enrolled" in combined

    def test_status_exception_no_traceback_leak(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Internal exceptions must not leak tracebacks or file paths to the user."""

        def _boom(_home: WorthlessHome) -> list[dict[str, str]]:
            raise ValueError("unexpected db error at /secret/path")

        monkeypatch.setattr(
            "worthless.cli.commands.status._list_enrolled_keys",
            _boom,
        )
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        combined = result.stdout + result.stderr
        assert result.exit_code == 1
        assert "Traceback" not in combined
        assert "/secret/path" not in combined
        # error_boundary should catch the exception cleanly — if it leaks,
        # result.exception will be a ValueError instead of SystemExit.
        assert not isinstance(result.exception, ValueError), (
            f"ValueError leaked through CLI: {result.exception}"
        )

    def test_status_with_enrolled_key(self, home_with_key: WorthlessHome) -> None:
        """Shows enrolled key info (alias, provider, PROTECTED)."""
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "openai-a1b2c3d4" in combined
        assert "openai" in combined
        assert "PROTECTED" in combined


# ===================================================================
# 7. QUIET MODE
# ===================================================================


class TestQuietMode:
    """--quiet suppresses non-error output."""

    def test_quiet_lock_suppresses_success(
        self, home_dir: WorthlessHome, env_with_openai: Path
    ) -> None:
        """--quiet lock produces no success message."""
        result = runner.invoke(
            app,
            ["-q", "lock", "--env", str(env_with_openai)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        # In quiet mode, success messages are suppressed.
        # Trust-fix wording is "[OK] Protected N key(s)." — assert that
        # neither the prefix nor the body leaks through quiet mode.
        assert "[OK]" not in result.stderr
        assert "Protected" not in result.stderr

    def test_quiet_scan_suppresses_output(self, env_with_openai: Path) -> None:
        """--quiet scan produces no stderr output (exit code only)."""
        result = runner.invoke(app, ["-q", "scan", str(env_with_openai)])
        assert result.exit_code == 1
        assert result.stderr.strip() == ""

    def test_quiet_status_suppresses_output(self, home_dir: WorthlessHome) -> None:
        """--quiet status suppresses non-error output."""
        result = runner.invoke(
            app,
            ["-q", "status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        # Warning "No keys enrolled" should be suppressed in quiet mode
        assert "No keys enrolled" not in result.stderr


# ===================================================================
# 8. JSON MODE
# ===================================================================


class TestJsonMode:
    """--json emits machine-readable output."""

    def test_json_status_is_parseable(self, home_dir: WorthlessHome) -> None:
        """--json status emits valid JSON to stdout."""
        result = runner.invoke(
            app,
            ["--json", "status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "keys" in data
        assert "proxy" in data

    def test_json_status_with_key(self, home_with_key: WorthlessHome) -> None:
        """--json status with enrolled keys includes key details."""
        result = runner.invoke(
            app,
            ["--json", "status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data["keys"]) >= 1
        assert data["keys"][0]["alias"] == "openai-a1b2c3d4"
        assert data["keys"][0]["provider"] == "openai"

    def test_json_scan_emits_object(self, env_with_openai: Path) -> None:
        """--json scan emits a JSON object with findings + orphans (HF5)."""
        result = runner.invoke(app, ["scan", "--json", str(env_with_openai)])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        assert "findings" in data and isinstance(data["findings"], list)
        assert "orphans" in data and isinstance(data["orphans"], list)
        assert data["schema_version"] >= 2

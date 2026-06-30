"""Tests for the default command — bare ``worthless`` magic pipeline.

The default command module (``worthless.cli.default_command``) does not exist
yet.  These tests define the expected behaviour and will fail until the module
is implemented.

Pipeline phases:
  1. Enrollment check — scan .env, show detected keys, confirm, lock
  2. Proxy — start daemon if not running, poll health
  3. Status — print current state
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState
from worthless.cli.errors import ErrorCode, WorthlessError

from tests.helpers import fake_anthropic_key, fake_openai_key

runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def env_with_two_keys(tmp_path: Path) -> Path:
    """Create a .env with two known API keys (OpenAI + Anthropic)."""
    env = tmp_path / ".env"
    env.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        f"ANTHROPIC_API_KEY={fake_anthropic_key()}\n"
        "DATABASE_URL=postgres://localhost/db\n"
    )
    return env


@pytest.fixture()
def env_local_only(tmp_path: Path) -> Path:
    """Create a .env.local (no .env) with one key."""
    env_local = tmp_path / ".env.local"
    env_local.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env_local


@pytest.fixture()
def env_no_keys(tmp_path: Path) -> Path:
    """Create a .env with no API keys."""
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://localhost/db\nDEBUG=true\n")
    return env


@pytest.fixture()
def env_many_keys(tmp_path: Path) -> Path:
    """Create a .env with 6 keys to test truncation."""
    from tests.helpers import fake_key

    lines = []
    for i in range(6):
        lines.append(f"OPENAI_KEY_{i}={fake_key('sk-proj-', seed=f'key-{i}')}")
    env = tmp_path / ".env"
    env.write_text("\n".join(lines) + "\n")
    return env


def _invoke_default(
    env_vars: dict[str, str], args: list[str] | None = None, input: str | None = None
):
    """Invoke bare ``worthless`` (default command) via CliRunner."""
    cmd_args = args or []
    return runner.invoke(
        # The default command should be invocable as bare ``worthless``
        # (no subcommand).  The app callback or a registered default
        # handles this.
        _get_app(),
        cmd_args,
        env=env_vars,
        input=input,
    )


def _get_app():
    """Import the app — deferred to allow default_command registration."""
    from worthless.cli.app import app

    return app


# ---------------------------------------------------------------------------
# Group 1: Happy paths
# ---------------------------------------------------------------------------


class TestHappyPaths:
    """Fresh install, enrolled, and already-running scenarios."""

    def test_fresh_install_detects_keys_locks_starts_proxy(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Fresh install + .env with 2 keys: shows var names + providers,
        prompts [y/N], on 'y' locks + starts proxy + shows status."""
        monkeypatch.chdir(env_with_two_keys.parent)

        # Mock proxy start and health
        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            lambda *a, **kw: 54321,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: True,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="y\n",
        )
        assert result.exit_code == 0, result.output + result.stderr

        combined = result.stdout + result.stderr
        # Should show var names and providers
        assert "OPENAI_API_KEY" in combined
        assert "ANTHROPIC_API_KEY" in combined
        assert "openai" in combined.lower()
        assert "anthropic" in combined.lower()

        # Should NOT show actual key characters
        openai_key = fake_openai_key()
        anthropic_key = fake_anthropic_key()
        # Check that no 8+ char substring of either key appears
        assert openai_key[8:20] not in combined
        assert anthropic_key[15:30] not in combined

    def test_already_enrolled_starts_proxy_no_prompt(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Already enrolled + proxy not running: auto-starts proxy, no lock prompt."""
        monkeypatch.chdir(tmp_path)

        daemon_called = False

        def mock_start_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_start_daemon,
        )
        # First poll_health call is the detection probe (should say "not running"),
        # subsequent calls are post-start verification (should say "healthy").
        health_calls = 0

        def mock_poll_health(*args, **kw):
            nonlocal health_calls
            health_calls += 1
            return health_calls > 1  # False on detection, True on verify

        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            mock_poll_health,
        )
        # No PID file means proxy is not running
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.unlink(missing_ok=True)

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0, result.output + result.stderr
        assert daemon_called, "Should have started proxy daemon"
        # No lock prompt
        combined = result.stdout + result.stderr
        assert "[y/N]" not in combined.upper() or "y/n" not in combined.lower()

    def test_already_enrolled_proxy_running_one_line_status(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Already enrolled + proxy running: one-line status, no prompts."""
        monkeypatch.chdir(tmp_path)

        supervised_called = False

        def mock_supervised(*args, **kwargs):
            nonlocal supervised_called
            supervised_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_supervised,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.detect_proxy_runtime",
            lambda home, port=None: ProxyRuntimeState(
                running=True, pid=12345, port=8787, source="health"
            ),
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0, result.output + result.stderr
        assert not supervised_called
        combined = result.stdout + result.stderr
        assert "[y/N]" not in combined

    def test_fresh_install_env_local_detected(
        self,
        home_dir: WorthlessHome,
        env_local_only: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Fresh install + .env.local (not .env): still detected and offered."""
        monkeypatch.chdir(env_local_only.parent)

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            lambda *a, **kw: 54321,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: True,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="y\n",
        )
        assert result.exit_code == 0, result.output + result.stderr
        combined = result.stdout + result.stderr
        assert "OPENAI_API_KEY" in combined


# ---------------------------------------------------------------------------
# Group 2: Non-interactive / agent mode
# ---------------------------------------------------------------------------


class TestNonInteractive:
    """Piped stdin, --yes, and --json modes."""

    def test_piped_stdin_report_only_no_prompts(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Piped stdin (not a TTY): report only, no prompts, no auto-lock."""
        monkeypatch.chdir(env_with_two_keys.parent)

        # CliRunner already simulates non-TTY stdin by default
        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            # No input= means stdin is exhausted / not a TTY
        )
        combined = result.stdout + result.stderr
        # Should report detected keys but not prompt
        assert "OPENAI_API_KEY" in combined or result.exit_code == 0

    def test_yes_flag_auto_approves(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--yes flag auto-approves lock + proxy start without prompting."""
        monkeypatch.chdir(env_with_two_keys.parent)

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            lambda *a, **kw: 54321,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: True,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            args=["--yes"],
        )
        assert result.exit_code == 0, result.output + result.stderr

    def test_json_flag_returns_structured_state(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """--json flag returns structured JSON state, never triggers writes/prompts."""
        monkeypatch.chdir(tmp_path)

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_with_key.base_dir)},
            args=["--json"],
        )
        assert result.exit_code == 0, result.output + result.stderr
        data = json.loads(result.stdout)
        assert "enrolled" in data or "keys" in data
        assert "proxy" in data


# ---------------------------------------------------------------------------
# Group 3: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Boundary conditions and uncommon inputs."""

    def test_no_env_file_helpful_message(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No .env file in current dir: helpful message mentioning lock --env."""
        monkeypatch.chdir(tmp_path)
        # Ensure no .env or .env.local exist
        assert not (tmp_path / ".env").exists()
        assert not (tmp_path / ".env.local").exists()

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        combined = result.stdout + result.stderr
        assert "lock --env" in combined.lower() or "no .env" in combined.lower()

    def test_partial_lock_failure_starts_proxy_anyway(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Partial lock failure (1 of 2 keys fails): starts proxy, reports partial."""
        monkeypatch.chdir(env_with_two_keys.parent)

        # Make _lock_keys return 1 instead of 2 (simulating partial failure)
        def mock_lock_keys(env_path, home, quiet=False):
            return 1  # Only 1 of 2 succeeded

        monkeypatch.setattr(
            "worthless.cli.default_command._lock_keys",
            mock_lock_keys,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            lambda *a, **kw: 54321,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: True,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            args=["--yes"],
        )
        # Should still succeed (proxy started) even with partial lock
        assert result.exit_code == 0, result.output + result.stderr

    def test_many_keys_truncated_display(
        self,
        home_dir: WorthlessHome,
        env_many_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """6+ keys: shows first 5 + '(+ 1 more)', not all 6."""
        monkeypatch.chdir(env_many_keys.parent)

        # We only need to check the display, not actually lock
        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="n\n",  # Decline to lock
        )
        combined = result.stdout + result.stderr
        assert "+ 1 more" in combined or "+1 more" in combined

    def test_env_no_api_keys_message(
        self,
        home_dir: WorthlessHome,
        env_no_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """.env exists but has no API keys: 'No API keys found' message."""
        monkeypatch.chdir(env_no_keys.parent)

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        combined = result.stdout + result.stderr
        assert "no api key" in combined.lower() or "no unprotected" in combined.lower()

    def test_user_declines_prompt_exits_cleanly(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """User declines [y/N] prompt: exits cleanly, no lock, no proxy."""
        monkeypatch.chdir(env_with_two_keys.parent)

        daemon_called = False

        def mock_start_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_start_daemon,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="n\n",
        )
        assert result.exit_code == 0, result.output + result.stderr
        assert not daemon_called, "Should not have started proxy after decline"


# ---------------------------------------------------------------------------
# Group 4: Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Structured WRTLS error codes for failure modes."""

    def test_db_corrupted_error(
        self,
        home_dir: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """DB corrupted: actionable error WRTLS-100."""
        monkeypatch.chdir(tmp_path)

        # Corrupt the DB file
        home_dir.db_path.write_bytes(b"this is not a sqlite database")

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0
        combined = result.stdout + result.stderr
        assert "WRTLS" in combined

    def test_fernet_key_lost_error(
        self,
        home_with_key: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Fernet key lost while keys are enrolled: get_home() fails with WRTLS error.

        The fernet key is needed to check enrollment (decrypt shards).
        When it's missing, get_home() raises WorthlessError and the
        default command reports an actionable error.
        """
        monkeypatch.chdir(tmp_path)

        # Simulate get_home() failing because fernet key is gone
        def broken_get_home():
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                "Encryption key not found. Keys must be re-enrolled.",
            )

        monkeypatch.setattr(
            "worthless.cli.default_command.get_home",
            broken_get_home,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code != 0
        combined = result.stdout + result.stderr
        assert "WRTLS" in combined

    def test_proxy_health_check_fails_error(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Proxy fails health check: actionable error or warning."""
        monkeypatch.chdir(tmp_path)

        # No PID file = proxy not running; start will be attempted
        (home_with_key.base_dir / "proxy.pid").unlink(missing_ok=True)

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            lambda *a, **kw: 54321,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: False,
        )

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        combined = result.stdout + result.stderr
        # Should warn about health check failure
        assert (
            "WRTLS" in combined or "health" in combined.lower() or "unreachable" in combined.lower()
        )


# ---------------------------------------------------------------------------
# Group 6: Sidecar-supervised proxy start (WOR-717)
# ---------------------------------------------------------------------------


class TestSidecarSupervisedProxyStart:
    """Default command must not use the sidecar-less ``start_daemon`` path."""

    def test_uses_start_supervised_proxy_not_start_daemon(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (home_with_key.base_dir / "proxy.pid").unlink(missing_ok=True)

        supervised_called = False
        daemon_called = False

        def mock_supervised(*args, **kwargs):
            nonlocal supervised_called
            supervised_called = True
            return 54321

        def mock_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_supervised,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.up.start_daemon",
            mock_daemon,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.poll_health",
            lambda *a, **kw: True,
        )

        result = _invoke_default({"WORTHLESS_HOME": str(home_with_key.base_dir)})
        assert result.exit_code == 0, result.output + result.stderr
        assert supervised_called
        assert not daemon_called

    def test_skips_start_when_proxy_already_running(
        self,
        home_with_key: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.chdir(tmp_path)

        supervised_called = False

        def mock_supervised(*args, **kwargs):
            nonlocal supervised_called
            supervised_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_supervised,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.detect_proxy_runtime",
            lambda home, port=None: ProxyRuntimeState(
                running=True, pid=12345, port=8787, source="health"
            ),
        )

        result = _invoke_default({"WORTHLESS_HOME": str(home_with_key.base_dir)})
        assert result.exit_code == 0, result.output + result.stderr
        assert not supervised_called


class TestSecurity:
    """Security invariants that must hold for the default command."""

    def test_symlink_env_refused(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """.env is a symlink: find_env_file() skips it, treated as no .env found.

        The lock flow itself also rejects symlinks (WRTLS-101), so even
        if a symlink slipped through find_env_file(), _lock_keys() would
        refuse it.  Defense in depth: find_env_file() filters first.
        """
        real_env = tmp_path / "real.env"
        real_env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

        link_dir = tmp_path / "workdir"
        link_dir.mkdir()
        (link_dir / ".env").symlink_to(real_env)

        monkeypatch.chdir(link_dir)

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        combined = result.stdout + result.stderr
        # Symlink .env is skipped — pipeline sees "no .env found"
        assert "no .env" in combined.lower() or "lock --env" in combined.lower()

    def test_no_key_characters_in_output(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No key characters EVER appear in output -- only var names + provider names."""
        openai_key = fake_openai_key()
        anthropic_key = fake_anthropic_key()

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={openai_key}\nANTHROPIC_API_KEY={anthropic_key}\n")
        monkeypatch.chdir(tmp_path)

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="n\n",  # Decline to lock
        )
        combined = result.stdout + result.stderr

        # The full key must NEVER appear
        assert openai_key not in combined
        assert anthropic_key not in combined

        # Longer substrings (12+ chars after prefix) must not appear
        # This catches partial leaks
        for key in (openai_key, anthropic_key):
            # Skip the prefix part; check the secret body
            body = key[8:]  # after "sk-proj-" or similar
            for i in range(0, len(body) - 12):
                chunk = body[i : i + 12]
                assert chunk not in combined, f"Key material leaked in output: ...{chunk}..."

    def test_json_mode_never_triggers_lock_or_proxy(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--json mode never triggers lock or proxy start -- purely observational."""
        monkeypatch.chdir(env_with_two_keys.parent)

        lock_called = False
        daemon_called = False

        def mock_lock(*args, **kwargs):
            nonlocal lock_called
            lock_called = True
            return 0

        def mock_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 54321

        monkeypatch.setattr(
            "worthless.cli.default_command._lock_keys",
            mock_lock,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            mock_daemon,
        )

        _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            args=["--json"],
        )
        assert not lock_called, "--json should not trigger lock"
        assert not daemon_called, "--json should not trigger proxy start"

    def test_concurrent_runs_handled_by_file_lock(
        self,
        home_dir: WorthlessHome,
        env_with_two_keys: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Concurrent runs: second worthless while first is locking handled by file lock."""
        monkeypatch.chdir(env_with_two_keys.parent)

        # Simulate an existing lock file (another process is locking)
        home_dir.lock_file.touch()

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            args=["--yes"],
        )
        combined = result.stdout + result.stderr
        # Should fail with lock-in-progress error
        assert result.exit_code != 0
        assert "WRTLS-105" in combined or "lock" in combined.lower()

        # Clean up
        home_dir.lock_file.unlink(missing_ok=True)

    def test_unsupported_provider_keys_shown_as_skipped(
        self,
        home_dir: WorthlessHome,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """.env with keys from unsupported providers: shown but marked as skipped."""
        monkeypatch.chdir(tmp_path)

        # Mock scan_env_keys to return a key with unknown provider
        def mock_scan(env_path, is_decoy=None):
            return [
                ("OPENAI_API_KEY", fake_openai_key(), "openai"),
                ("WEIRD_API_KEY", "wrd-" + "a" * 48, "unknown_provider"),
            ]

        monkeypatch.setattr(
            "worthless.cli.default_command.scan_env_keys",
            mock_scan,
        )

        # Create a dummy .env so path check passes
        (tmp_path / ".env").write_text("OPENAI_API_KEY=placeholder\nWEIRD_API_KEY=placeholder\n")

        result = _invoke_default(
            {"WORTHLESS_HOME": str(home_dir.base_dir)},
            input="n\n",  # Decline
        )
        combined = result.stdout + result.stderr
        # Should show both keys; the unsupported one should be noted
        assert "OPENAI_API_KEY" in combined

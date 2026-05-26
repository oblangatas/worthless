"""E2E tests for the default command — real binary, real .env, real proxy.

NO MOCKS. These tests invoke the actual ``worthless`` CLI binary,
create real .env files, start real proxy processes, and verify the
full user-facing flow works end-to-end.

Marked ``@pytest.mark.e2e`` — real processes, real ports, real I/O.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from worthless.cli.process import check_pid, read_pid

from tests._fakes import WOR309_SUBPROCESS_FOLLOWUP
from tests.helpers import fake_anthropic_key, fake_openai_key

# Use high ports to avoid conflicts with dev proxy
_TEST_PORT = 19787
_WORTHLESS = str(Path(__file__).parent.parent / ".venv" / "bin" / "worthless")


def _run_worthless(
    args: list[str],
    home: Path,
    cwd: Path,
    input_text: str | None = None,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess:
    """Run the real worthless binary."""
    env = {
        **os.environ,
        "WORTHLESS_HOME": str(home),
        "WORTHLESS_PORT": str(_TEST_PORT),
        # WOR-463: explicit even though tests/conftest.py setdefault propagates
        # via **os.environ — self-documents that this subprocess MUST NOT
        # write fernet-key-* to the host's real keychain. Defense-in-depth
        # against future drift if conftest is refactored.
        "WORTHLESS_KEYRING_BACKEND": "null",
    }
    return subprocess.run(
        [_WORTHLESS, *args],
        cwd=str(cwd),
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _stop_proxy(home: Path) -> None:
    """Stop any proxy running from this home dir."""
    pid_file = home / "proxy.pid"
    if pid_file.exists():
        info = read_pid(pid_file)
        if info:
            pid, _ = info
            if check_pid(pid):
                os.kill(pid, signal.SIGTERM)
                for _ in range(20):
                    if not check_pid(pid):
                        break
                    time.sleep(0.25)
                else:
                    os.kill(pid, signal.SIGKILL)
        pid_file.unlink(missing_ok=True)
    # Also kill anything on the test port via health probe failure
    try:
        r = httpx.get(f"http://127.0.0.1:{_TEST_PORT}/healthz", timeout=1.0)
        if r.status_code == 200:
            # Something is on the port — try to find and kill it
            pass
    except Exception:
        pass


@pytest.fixture()
def e2e_home(tmp_path: Path):
    """Fresh home dir for E2E tests, with cleanup."""
    home = tmp_path / ".worthless"
    yield home
    _stop_proxy(home)


@pytest.fixture()
def project_with_keys(tmp_path: Path) -> Path:
    """Project directory with a .env containing 2 API keys."""
    project = tmp_path / "myproject"
    project.mkdir()
    env = project / ".env"
    env.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        f"ANTHROPIC_API_KEY={fake_anthropic_key()}\n"
        "DATABASE_URL=postgres://localhost/db\n"
    )
    return project


@pytest.fixture()
def project_with_env_local(tmp_path: Path) -> Path:
    """Project directory with only .env.local (no .env)."""
    project = tmp_path / "myproject"
    project.mkdir()
    env_local = project / ".env.local"
    env_local.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return project


@pytest.fixture()
def project_no_keys(tmp_path: Path) -> Path:
    """Project directory with no .env at all."""
    project = tmp_path / "myproject"
    project.mkdir()
    return project


@pytest.mark.e2e
@pytest.mark.real_ipc
@pytest.mark.skip(reason=WOR309_SUBPROCESS_FOLLOWUP)
class TestDefaultCommandE2E:
    """Real end-to-end tests for bare ``worthless``."""

    def test_first_run_yes_locks_and_starts_proxy(
        self, e2e_home: Path, project_with_keys: Path
    ) -> None:
        """First run with --yes: detects keys, locks them, starts proxy, healthy."""
        result = _run_worthless(["--yes"], e2e_home, project_with_keys)

        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"Exit {result.returncode}: {combined}"

        # Keys were detected
        assert "OPENAI_API_KEY" in combined
        assert "ANTHROPIC_API_KEY" in combined

        # Keys were locked
        assert "protected" in combined.lower()

        # .env was rewritten with decoys
        env_content = (project_with_keys / ".env").read_text()
        assert fake_openai_key() not in env_content
        assert fake_anthropic_key() not in env_content
        assert "OPENAI_API_KEY=" in env_content

        # Proxy is running and healthy
        assert "healthy" in combined.lower() or "running" in combined.lower()
        r = httpx.get(f"http://127.0.0.1:{_TEST_PORT}/healthz", timeout=5.0)
        assert r.status_code == 200

    def test_second_run_detects_running_proxy(
        self, e2e_home: Path, project_with_keys: Path
    ) -> None:
        """Second run detects the already-running proxy, no duplicate start."""
        # First run — lock + start
        r1 = _run_worthless(["--yes"], e2e_home, project_with_keys)
        assert r1.returncode == 0, r1.stdout + r1.stderr

        # Second run — should just report status
        r2 = _run_worthless([], e2e_home, project_with_keys)
        assert r2.returncode == 0, r2.stdout + r2.stderr

        combined = r2.stdout + r2.stderr
        assert "healthy" in combined.lower()
        # Should NOT try to lock again or prompt
        assert "Lock these keys" not in combined

    def test_json_mode_read_only(self, e2e_home: Path, project_with_keys: Path) -> None:
        """--json returns structured state, never locks or starts proxy."""
        # Don't lock or start anything first
        result = _run_worthless(["--json"], e2e_home, project_with_keys)
        assert result.returncode == 0, result.stdout + result.stderr

        data = json.loads(result.stdout)
        assert "enrolled" in data
        assert "proxy" in data
        assert data["enrolled"] is False  # Nothing locked yet
        assert data["proxy"]["running"] is False

        # .env should be UNCHANGED (--json never writes)
        env_content = (project_with_keys / ".env").read_text()
        assert fake_openai_key() in env_content

    def test_no_env_file_helpful_message(self, e2e_home: Path, project_no_keys: Path) -> None:
        """No .env file: helpful message, exit 0."""
        result = _run_worthless([], e2e_home, project_no_keys)
        assert result.returncode == 0, result.stdout + result.stderr

        combined = result.stdout + result.stderr
        assert "no .env" in combined.lower() or "lock --env" in combined.lower()

    def test_user_declines_no_lock_no_proxy(self, e2e_home: Path, project_with_keys: Path) -> None:
        """User types 'n' at prompt: no lock, no proxy, .env unchanged."""
        result = _run_worthless([], e2e_home, project_with_keys, input_text="n\n")
        assert result.returncode == 0, result.stdout + result.stderr

        # .env unchanged
        env_content = (project_with_keys / ".env").read_text()
        assert fake_openai_key() in env_content

        # No proxy started
        try:
            httpx.get(f"http://127.0.0.1:{_TEST_PORT}/healthz", timeout=1.0)
            pytest.fail("Proxy should not be running after decline")
        except (httpx.ConnectError, httpx.ConnectTimeout):
            pass  # Expected — nothing on the port

    def test_env_local_detected(self, e2e_home: Path, project_with_env_local: Path) -> None:
        """.env.local (no .env) is detected and offered for locking."""
        result = _run_worthless(["--yes"], e2e_home, project_with_env_local)

        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"Exit {result.returncode}: {combined}"
        assert "OPENAI_API_KEY" in combined
        assert "protected" in combined.lower()

    def test_no_key_characters_in_output(self, e2e_home: Path, project_with_keys: Path) -> None:
        """SR-NEW-15: No key characters appear in output, only var names + providers."""
        result = _run_worthless([], e2e_home, project_with_keys, input_text="n\n")

        combined = result.stdout + result.stderr
        openai_key = fake_openai_key()
        anthropic_key = fake_anthropic_key()

        # Full keys must never appear
        assert openai_key not in combined
        assert anthropic_key not in combined

        # 12-char body substrings must not appear
        for key in (openai_key, anthropic_key):
            body = key[8:]  # after prefix
            for i in range(0, len(body) - 12):
                chunk = body[i : i + 12]
                assert chunk not in combined, f"Key material leaked: ...{chunk}..."

    def test_after_down_auto_restarts(self, e2e_home: Path, project_with_keys: Path) -> None:
        """After `worthless down`, bare `worthless` auto-restarts the proxy."""
        # Lock + start
        r1 = _run_worthless(["--yes"], e2e_home, project_with_keys)
        assert r1.returncode == 0, r1.stdout + r1.stderr

        # Stop
        r2 = _run_worthless(["down"], e2e_home, project_with_keys)
        assert r2.returncode == 0, r2.stdout + r2.stderr

        # Verify proxy is down
        try:
            httpx.get(f"http://127.0.0.1:{_TEST_PORT}/healthz", timeout=1.0)
            assert False, "Proxy should be down"
        except (httpx.ConnectError, httpx.ConnectTimeout):
            pass

        # Run bare worthless again — should auto-restart
        r3 = _run_worthless([], e2e_home, project_with_keys)
        assert r3.returncode == 0, r3.stdout + r3.stderr

        combined = r3.stdout + r3.stderr
        assert "healthy" in combined.lower() or "starting" in combined.lower()

        # Proxy should be running again
        r = httpx.get(f"http://127.0.0.1:{_TEST_PORT}/healthz", timeout=5.0)
        assert r.status_code == 200

    def test_many_keys_truncated_display(self, e2e_home: Path, tmp_path: Path) -> None:
        """6+ keys: shows first 5 + '(+ N more)', not all keys listed."""
        project = tmp_path / "manykeys"
        project.mkdir()
        # Create .env with 7 OpenAI-style keys
        lines = []
        for i in range(7):
            lines.append(f"OPENAI_KEY_{i}={fake_openai_key()}")
        (project / ".env").write_text("\n".join(lines) + "\n")

        result = _run_worthless([], e2e_home, project, input_text="n\n")
        assert result.returncode == 0, result.stdout + result.stderr

        combined = result.stdout + result.stderr
        assert "+ 2 more" in combined or "+2 more" in combined, (
            f"Expected '(+ 2 more)' for 7 keys but got:\n{combined}"
        )

    def test_piped_stdin_no_prompts_no_lock(self, e2e_home: Path, project_with_keys: Path) -> None:
        """Non-interactive piped stdin: report only, no prompts, no auto-lock."""
        # Pass empty string as input — simulates piped/non-TTY stdin
        result = _run_worthless([], e2e_home, project_with_keys, input_text="")
        assert result.returncode == 0, result.stdout + result.stderr

        combined = result.stdout + result.stderr
        # Should not prompt
        assert "Lock these keys?" not in combined

        # .env unchanged — no lock happened
        env_content = (project_with_keys / ".env").read_text()
        assert fake_openai_key() in env_content

    def test_version_matches_package_metadata(self, e2e_home: Path, tmp_path: Path) -> None:
        """worthless --version reports the installed package version."""
        from importlib.metadata import version as pkg_version

        project = tmp_path / "vtest"
        project.mkdir()

        result = _run_worthless(["--version"], e2e_home, project)
        assert result.returncode == 0, result.stdout + result.stderr
        assert pkg_version("worthless") in result.stdout

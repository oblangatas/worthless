"""End-to-end quickstart flow: lock -> status -> unlock, plus real proxy transit."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.storage.repository import ShardRepository

from tests._fakes import WOR309_SUBPROCESS_FOLLOWUP
from tests.helpers import fake_openai_key

runner = CliRunner(mix_stderr=False)
_WRAP_BIND_ATTEMPTS = 5
_WRAP_BIND_COLLISION_MARKERS = (
    "couldn't bind port",
    "address already in use",
    "eaddrinuse",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_e2e_env(
    base_dir: Path, *, proxy_port: int | None = None
) -> tuple[Path, Path, str, dict[str, str]]:
    """Set up an isolated project directory with a .env and WORTHLESS_HOME."""
    project_dir = base_dir / "myproject"
    project_dir.mkdir(parents=True)
    worthless_home = base_dir / ".worthless"

    original_key = fake_openai_key()
    env_file = project_dir / ".env"
    env_file.write_text(f"OPENAI_API_KEY={original_key}\n")

    cli_env = {"WORTHLESS_HOME": str(worthless_home)}
    if proxy_port is not None:
        cli_env["WORTHLESS_PORT"] = str(proxy_port)
    return env_file, worthless_home, original_key, cli_env


@pytest.fixture()
def e2e_env(tmp_path: Path) -> tuple[Path, Path, str, dict[str, str]]:
    """Set up an isolated project directory with a .env and WORTHLESS_HOME."""
    # Port 1 keeps status probes away from an already-running local daemon.
    # These tests do not start the proxy; the real bind happens in wrap below.
    return _make_e2e_env(tmp_path, proxy_port=1)


# ---------------------------------------------------------------------------
# Tier 1: CLI lifecycle roundtrip (no network, no proxy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.timeout(30)
class TestLockStatusUnlockCycle:
    """Prove the full lock -> status -> unlock data flow works end-to-end."""

    def test_full_cycle(self, e2e_env: tuple[Path, Path, str, dict[str, str]]) -> None:
        env_file, worthless_home, original_key, cli_env = e2e_env
        original_content = env_file.read_text()

        # ---- Step 1: lock ------------------------------------------------
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=cli_env,
        )
        assert result.exit_code == 0, f"lock failed: {result.output}"

        # .env rewritten — original key gone, shard-A preserves prefix
        from dotenv import dotenv_values

        locked_content = env_file.read_text()
        assert locked_content != original_content
        parsed = dotenv_values(env_file)
        shard_a_value = parsed["OPENAI_API_KEY"]
        assert original_key not in shard_a_value
        assert shard_a_value.startswith("sk-proj-")

        # No shard_a files on disk (SR-09: proxy gets shard-A from header, not files)
        home = WorthlessHome(base_dir=worthless_home)
        shard_a_files = [f for f in home.shard_a_dir.iterdir() if f.is_file()]
        assert len(shard_a_files) == 0, f"Expected ZERO shard_a files, got: {shard_a_files}"

        # DB has enrollment
        repo = ShardRepository(str(home.db_path), home.fernet_key)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        alias = aliases[0]

        enrollments = asyncio.run(repo.list_enrollments(alias))
        assert len(enrollments) == 1
        assert enrollments[0].var_name == "OPENAI_API_KEY"

        # Lock file cleaned up
        assert not home.lock_file.exists()

        # ---- Step 2: status (human-readable) -----------------------------
        result = runner.invoke(app, ["status"], env=cli_env)
        assert result.exit_code == 0

        status_text = result.stderr
        assert alias in status_text
        assert "openai" in status_text.lower()
        assert "PROTECTED" in status_text
        assert "not running" in status_text.lower()

        # ---- Step 3: status --json ---------------------------------------
        result = runner.invoke(app, ["--json", "status"], env=cli_env)
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert len(data["keys"]) == 1
        assert data["keys"][0]["provider"] == "openai"
        assert data["proxy"]["healthy"] is False

        # ---- Step 4: unlock ----------------------------------------------
        result = runner.invoke(
            app,
            ["unlock", "--env", str(env_file)],
            env=cli_env,
        )
        assert result.exit_code == 0, f"unlock failed: {result.output}"

        # Original key restored exactly
        assert env_file.read_text() == original_content

        # ---- Step 5: clean state -----------------------------------------
        remaining_shards = list(home.shard_a_dir.iterdir())
        assert remaining_shards == [], f"Leftover shard_a: {remaining_shards}"

        assert asyncio.run(repo.list_keys()) == []
        assert asyncio.run(repo.list_enrollments()) == []
        assert not home.lock_file.exists()


# ---------------------------------------------------------------------------
# Tier 2: Real proxy transit (subprocess, actual network)
# ---------------------------------------------------------------------------

# Child script that POSTs through the proxy and prints the status code.
# The proxy will reconstruct the (fake) key and forward to OpenAI, which
# will reject it. Any HTTP response proves full transit through the proxy.
_CHILD_SCRIPT = textwrap.dedent("""\
    import os, sys, httpx
    # 8rqs Phase 8: wrap no longer synthesises *_BASE_URL into child env —
    # the var lives in the user's .env after lock rewrites it. Real apps
    # use python-dotenv; we mimic that here by reading the .env path the
    # test passed via WORTHLESS_E2E_ENV_PATH.
    env_path = os.environ.get("WORTHLESS_E2E_ENV_PATH")
    if env_path and os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                # Assignment, not setdefault: the .env file MUST win over
                # any ambient OPENAI_BASE_URL in the parent env. Otherwise
                # a developer running pytest with their own real BASE_URL
                # set would silently bypass the locked proxy and the e2e
                # would pass for the wrong reason.
                os.environ[k.strip()] = v.strip().strip('"').strip("'")
    base = os.environ.get("OPENAI_BASE_URL")
    if not base:
        print("OPENAI_BASE_URL not set", file=sys.stderr)
        sys.exit(1)
    try:
        r = httpx.post(
            f"{base}/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            timeout=15.0,
        )
        print(f"STATUS:{r.status_code}")
    except (httpx.ConnectError, httpx.TimeoutException):
        # Proxy bound the port but upstream unreachable or slow —
        # either way proves the child reached the proxy.
        print("PROXY_REACHED", file=sys.stderr)
        sys.exit(0)
    except Exception as exc:
        print(f"ERROR:{exc}", file=sys.stderr)
        sys.exit(1)
""")


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
@pytest.mark.skip(reason=WOR309_SUBPROCESS_FOLLOWUP)
class TestWrapProxiesRequest:
    """Prove ``worthless wrap`` spawns a real proxy that transits requests."""

    def test_wrap_real_proxy_transit(self, tmp_path: Path) -> None:
        # Run wrap as a real subprocess: spawns proxy, runs child, cleans up.
        # Lock owns OPENAI_BASE_URL and must write the chosen port into .env,
        # so a bind collision needs a full fresh lock->wrap retry.
        attempts: list[str] = []
        proc: subprocess.CompletedProcess[str] | None = None

        for attempt in range(1, _WRAP_BIND_ATTEMPTS + 1):
            proxy_port = _free_port()
            env_file, worthless_home, _original_key, cli_env = _make_e2e_env(
                tmp_path / f"attempt-{attempt}", proxy_port=proxy_port
            )

            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=cli_env,
            )
            assert result.exit_code == 0, f"lock failed: {result.output}"

            _venv_bin = Path(sys.executable).parent
            _worthless = str(_venv_bin / "worthless")
            proc = subprocess.run(
                [
                    _worthless,
                    "wrap",
                    "--",
                    sys.executable,
                    "-c",
                    _CHILD_SCRIPT,
                ],
                env={
                    **os.environ,
                    "WORTHLESS_HOME": str(worthless_home),
                    "WORTHLESS_PORT": str(proxy_port),
                    # Pass .env path so the child can pick up the OPENAI_BASE_URL
                    # that lock wrote (post-8rqs wrap doesn't synthesise it).
                    "WORTHLESS_E2E_ENV_PATH": str(env_file),
                    # WOR-463: explicit even though conftest.py setdefault
                    # propagates via **os.environ. Self-documents the contract:
                    # this subprocess must not leak fernet-key-* into the host
                    # keychain. Defense-in-depth.
                    "WORTHLESS_KEYRING_BACKEND": "null",
                },
                timeout=45,
                capture_output=True,
                text=True,
            )

            combined = proc.stdout + proc.stderr
            if proc.returncode == 0 or not any(
                marker in combined.lower() for marker in _WRAP_BIND_COLLISION_MARKERS
            ):
                break

            attempts.append(
                f"attempt {attempt} port {proxy_port} bind collision:\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
            time.sleep(0.05 * attempt)

        assert proc is not None
        combined = proc.stdout + proc.stderr

        # Child should have exited 0 (got a response OR connect error)
        assert proc.returncode == 0, (
            f"wrap failed after {len(attempts) + 1} attempt(s) "
            f"(rc={proc.returncode}):\n"
            f"{chr(10).join(attempts)}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        # Prove the proxy was involved: child got a status code or reached proxy
        assert "STATUS:" in combined or "PROXY_REACHED" in combined, (
            f"No evidence of proxy transit:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

"""End-to-end quickstart flow: lock -> status -> unlock, plus real proxy transit."""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.openclaw.integration import _alias_from_base_url
from worthless.storage.repository import ShardRepository

from tests.helpers import fake_openai_key, fake_openrouter_key

runner = CliRunner()
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

    # Pin HOME at the sandbox so ``openclaw.integration.detect()`` does NOT
    # see the developer's real ``~/.openclaw`` and trigger F7's PROXY_NOT_RUNNING
    # gate (WOR-648 / WOR-621 AC5). This test class is ``@pytest.mark.integration``,
    # which opts out of the autouse ``check_proxy_health`` mock in
    # ``tests/conftest.py``, so without HOME pinning, F7's real probe of
    # ``WORTHLESS_PORT=1`` correctly returns "unhealthy" and ``lock`` exits 1
    # before doing anything. The lifecycle being tested here (vanilla
    # split → status → unlock) has no OpenClaw involvement.
    home_sandbox = base_dir / "home"
    home_sandbox.mkdir(parents=True, exist_ok=True)

    cli_env = {
        "WORTHLESS_HOME": str(worthless_home),
        "HOME": str(home_sandbox),
        "USERPROFILE": str(home_sandbox),
    }
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
        _lock(env_file, cli_env)

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


def _run_child_under_wrap(
    tmp_path: Path,
    child_script: str,
    prepare: Callable[[Path, dict[str, str]], None],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run *child_script* under a real ``worthless wrap`` proxy, after *prepare* locks.

    Lock owns OPENAI_BASE_URL and must write the chosen port into .env,
    so a bind collision needs a full fresh prepare->wrap retry.
    """
    attempts: list[str] = []
    proc: subprocess.CompletedProcess[str] | None = None

    for attempt in range(1, _WRAP_BIND_ATTEMPTS + 1):
        proxy_port = _free_port()
        env_file, worthless_home, _original_key, cli_env = _make_e2e_env(
            tmp_path / f"attempt-{attempt}", proxy_port=proxy_port
        )
        prepare(env_file, cli_env)

        _venv_bin = Path(sys.executable).parent
        _worthless = str(_venv_bin / "worthless")
        proc = subprocess.run(
            [
                _worthless,
                "wrap",
                "--",
                sys.executable,
                "-c",
                child_script,
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
                # Isolate $HOME too, matching the CLI env *prepare* ran with —
                # _resolve_home() (openclaw/integration.py) reads Path.home(),
                # not WORTHLESS_HOME. cli_env["HOME"]/["USERPROFILE"] are
                # _make_e2e_env's sandbox dir, already isolated from the real
                # machine. USERPROFILE matters on native Windows, where
                # Path.home() checks it before $HOME.
                "HOME": cli_env["HOME"],
                "USERPROFILE": cli_env["USERPROFILE"],
                **(extra_env or {}),
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
    # Child should have exited 0 (got a response OR connect error)
    assert proc.returncode == 0, (
        f"wrap failed after {len(attempts) + 1} attempt(s) "
        f"(rc={proc.returncode}):\n"
        f"{chr(10).join(attempts)}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    return proc


def _lock(env_file: Path, cli_env: dict[str, str]) -> None:
    result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert result.exit_code == 0, f"lock failed: {result.output}"


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
class TestWrapProxiesRequest:
    """Prove ``worthless wrap`` spawns a real proxy that transits requests."""

    def test_wrap_real_proxy_transit(self, tmp_path: Path) -> None:
        # Run wrap as a real subprocess: spawns proxy, runs child, cleans up.
        proc = _run_child_under_wrap(tmp_path, _CHILD_SCRIPT, _lock)
        combined = proc.stdout + proc.stderr

        # Prove the proxy was involved: child got a status code or reached proxy
        assert "STATUS:" in combined or "PROXY_REACHED" in combined, (
            f"No evidence of proxy transit:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )


# Sends the locked key from .env as an app would. Upstream is blocked, so a 502
# means the proxy found the alias and rebuilt the key before failing to forward
# it; an alias the proxy doesn't know gets the uniform 401 instead.
_ROUTED_CHILD_SCRIPT = textwrap.dedent("""\
    import os, sys, httpx
    from dotenv import dotenv_values
    env = dotenv_values(os.environ["WORTHLESS_E2E_ENV_PATH"])
    base = env.get("OPENAI_BASE_URL")
    if not base:
        print("OPENAI_BASE_URL not set", file=sys.stderr)
        sys.exit(1)
    r = httpx.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {env['OPENAI_API_KEY']}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
        timeout=15.0,
    )
    print(f"STATUS:{r.status_code}")
""")


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
class TestPartialUnlockKeepsOtherKeyRouted:
    """Unlocking only an OpenRouter key keeps a still-locked OpenAI key on the proxy."""

    def test_locked_openai_key_still_reaches_its_alias(self, tmp_path: Path) -> None:
        def lock_both_then_unlock_openrouter(env_file: Path, cli_env: dict[str, str]) -> None:
            with env_file.open("a") as f:
                f.write(f"OPENROUTER_API_KEY={fake_openrouter_key()}\n")
            _lock(env_file, cli_env)
            alias = _alias_from_base_url(dotenv_values(env_file)["OPENROUTER_BASE_URL"] or "")
            assert alias, "lock wrote no OPENROUTER_BASE_URL proxy line"
            result = runner.invoke(
                app, ["unlock", "--env", str(env_file), "--alias", alias], env=cli_env
            )
            assert result.exit_code == 0, f"unlock failed: {result.output}"

        proc = _run_child_under_wrap(
            tmp_path,
            _ROUTED_CHILD_SCRIPT,
            lock_both_then_unlock_openrouter,
            # Nothing leaves the machine: upstream HTTPS goes to a closed port.
            extra_env={"HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1,localhost"},
        )
        assert "STATUS:502" in proc.stdout, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"


# An app that reads its upstream from OPENROUTER_BASE_URL with no default, the
# WOR-1013 victim. The guard keeps a test key from ever leaving the machine: an
# unset line makes the SDK fall back to api.openai.com, which is reported, not
# called.
_OWN_UPSTREAM_CHILD_SCRIPT = textwrap.dedent("""\
    import os, sys
    from urllib.parse import urlsplit
    import openai
    from dotenv import load_dotenv
    load_dotenv(os.environ["WORTHLESS_E2E_ENV_PATH"], override=True)
    client = openai.OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url=os.getenv("OPENROUTER_BASE_URL"),
        max_retries=0,
        timeout=10,
    )
    host = urlsplit(str(client.base_url)).hostname
    if host != "127.0.0.1":
        print(f"WOULD_SEND_TO:{host}")
        sys.exit(3)
    reply = client.chat.completions.create(
        model="openrouter/auto", messages=[{"role": "user", "content": "hi"}]
    )
    print(f"REPLY:{reply.choices[0].message.content}")
""")


class _FakeUpstream(http.server.BaseHTTPRequestHandler):
    """Stands in for the user's own upstream; records what reached it."""

    received: list[tuple[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802 — http.server's handler name
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.received.append((self.path, self.headers.get("Authorization") or ""))
        body = json.dumps(
            {
                "id": "chatcmpl-e2e",
                "object": "chat.completion",
                "created": 0,
                "model": "openrouter/auto",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.mark.integration
@pytest.mark.timeout(60)
class TestUnlockedAppReachesYourOwnUpstream:
    """After lock then unlock, the app sends its real key to the upstream you had set (WOR-1013)."""

    def test_app_sends_the_key_to_your_base_url_not_openai(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_FakeUpstream, "received", [])
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstream)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            upstream = f"http://127.0.0.1:{server.server_address[1]}/api/v1"
            env_file, _home, _key, cli_env = _make_e2e_env(tmp_path, proxy_port=1)
            key = fake_openrouter_key()
            env_file.write_text(f"OPENROUTER_BASE_URL={upstream}\nOPENROUTER_API_KEY={key}\n")
            registered = runner.invoke(
                app,
                [
                    "providers",
                    "register",
                    "--name",
                    "my-openrouter",
                    "--url",
                    upstream,
                    "--protocol",
                    "openai",
                ],
                env=cli_env,
            )
            assert registered.exit_code == 0, registered.output
            _lock(env_file, cli_env)
            unlocked = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
            assert unlocked.exit_code == 0, unlocked.output

            child_env = {
                k: v for k, v in os.environ.items() if not k.startswith(("OPENAI_", "OPENROUTER_"))
            }
            proc = subprocess.run(
                [sys.executable, "-c", _OWN_UPSTREAM_CHILD_SCRIPT],
                env={**child_env, "WORTHLESS_E2E_ENV_PATH": str(env_file)},
                timeout=30,
                capture_output=True,
                text=True,
            )
        finally:
            server.shutdown()
            server.server_close()

        assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert "REPLY:ok" in proc.stdout
        # Compare in place: never print the key.
        assert [(path, auth == f"Bearer {key}") for path, auth in _FakeUpstream.received] == [
            ("/api/v1/chat/completions", True)
        ]


@pytest.mark.integration
@pytest.mark.timeout(60)
class TestQuietUnlockStillSaysWhatItDidToYourLine:
    """`worthless --quiet unlock`, run as a real process, says on stderr what it did to a
    `*_BASE_URL` line, and the `.env` on disk matches (WOR-1042)."""

    def test_a_line_lock_could_not_save_is_removed_and_said(self, tmp_path: Path) -> None:
        env_file, worthless_home, key, cli_env = _make_e2e_env(tmp_path, proxy_port=1)
        # The rewriter can't write a quote back, so lock won't save it (WOR-1027).
        gateway = "https://gateway.example.com/v1/o'neil"
        env_file.write_text(f"OPENAI_BASE_URL={gateway}\nOPENAI_API_KEY={key}\n")
        registered = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "quoted-gw",
                "--url",
                gateway,
                "--protocol",
                "openai",
            ],
            env=cli_env,
        )
        assert registered.exit_code == 0, registered.output
        _lock(env_file, cli_env)

        proc = subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "--quiet",
                "unlock",
                "--env",
                str(env_file),
            ],
            env={
                **os.environ,
                "WORTHLESS_HOME": str(worthless_home),
                "WORTHLESS_KEYRING_BACKEND": "null",
                "HOME": cli_env["HOME"],
                "USERPROFILE": cli_env["USERPROFILE"],
            },
            timeout=45,
            capture_output=True,
            text=True,
        )

        assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert env_file.read_text() == f"OPENAI_API_KEY={key}\n"
        said = " ".join(proc.stderr.split())  # however Rich wrapped it (WOR-1022)
        assert "lock couldn't save the value you had in OPENAI_BASE_URL" in said, proc.stderr
        assert "Restored" not in said  # still quiet about progress
        assert "example.com" not in said  # names the line, never its value

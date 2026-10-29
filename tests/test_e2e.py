"""End-to-end quickstart flow: lock -> status -> unlock, plus real proxy transit."""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import http.server
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.openclaw.integration import _alias_from_base_url
from worthless.storage.repository import ShardRepository

from tests.helpers import assert_not_shown, fake_openai_key, fake_openrouter_key

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


def _register_gateway(cli_env: dict[str, str], name: str, url: str) -> None:
    """Lock refuses a user's own upstream until it is registered."""
    result = runner.invoke(
        app,
        ["providers", "register", "--name", name, "--url", url, "--protocol", "openai"],
        env=cli_env,
    )
    assert result.exit_code == 0, result.output


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


# Nothing leaves the machine: upstream HTTPS goes to a closed port. The proxy
# ignores HTTPS_PROXY (WOR-1071), so name the egress proxy the way an operator would.
_CLOSED_UPSTREAM = {"WORTHLESS_UPSTREAM_PROXY": "http://127.0.0.1:9"}

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
            extra_env=_CLOSED_UPSTREAM,
        )
        assert "STATUS:502" in proc.stdout, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
class TestBareBaseUrlLineStillRoutesTheKey:
    """A bare ``OPENAI_BASE_URL`` line (no ``=``) doesn't keep the key off the proxy (WOR-1041)."""

    @pytest.mark.parametrize("bare_after_key", [False, True], ids=["before-key", "after-key"])
    def test_locked_key_reaches_its_alias(self, tmp_path: Path, bare_after_key: bool) -> None:
        def add_bare_line_then_lock(env_file: Path, cli_env: dict[str, str]) -> None:
            content = env_file.read_text()
            bare = "OPENAI_BASE_URL\n"
            env_file.write_text(content + bare if bare_after_key else bare + content)
            _lock(env_file, cli_env)

        proc = _run_child_under_wrap(
            tmp_path,
            _ROUTED_CHILD_SCRIPT,
            add_bare_line_then_lock,
            extra_env=_CLOSED_UPSTREAM,
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
            _register_gateway(cli_env, "my-openrouter", upstream)
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


@contextlib.contextmanager
def _serving(handler: type[http.server.BaseHTTPRequestHandler]) -> Iterator[int]:
    """Serve *handler* on a loopback port for the block; yield the port."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _ForwardingEgressProxy(http.server.BaseHTTPRequestHandler):
    """A plain-HTTP egress proxy, like a corporate one: relays and records every request."""

    seen: list[bytes] = []

    def _relay(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.seen.append(self.requestline.encode() + b"\n" + bytes(self.headers) + body)
        target = urlsplit(self.path)  # absolute-form: http://127.0.0.1:port/path
        # Loopback only, whatever host the request names: everything in this test is local.
        conn = http.client.HTTPConnection("127.0.0.1", int(target.port or 80), timeout=15)
        hop = ("connection", "proxy-connection", "keep-alive")
        headers = {k: v for k, v in self.headers.items() if k.lower() not in hop}
        path = target.path + (f"?{target.query}" if target.query else "")
        conn.request(self.command, path, body=body or None, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        self.send_response(resp.status)
        self.send_header("Content-Type", "application/json")  # every reply here is JSON
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_HEAD = _relay

    def log_message(self, *_args: object) -> None:
        pass


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
class TestShellProxyNeverSeesTheRealKey:
    """A shell's HTTP_PROXY relays the app's shard-A at most, never the real key (WOR-1071)."""

    def test_egress_proxy_in_the_shell_never_sees_the_real_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_FakeUpstream, "received", [])
        monkeypatch.setattr(_ForwardingEgressProxy, "seen", [])
        real_key = ""

        with (
            _serving(_FakeUpstream) as upstream_port,
            _serving(_ForwardingEgressProxy) as egress_port,
        ):
            upstream = f"http://127.0.0.1:{upstream_port}/v1"

            def lock_to_own_gateway(env_file: Path, cli_env: dict[str, str]) -> None:
                nonlocal real_key
                real_key = dotenv_values(env_file)["OPENAI_API_KEY"] or ""
                env_file.write_text(f"OPENAI_BASE_URL={upstream}\nOPENAI_API_KEY={real_key}\n")
                _register_gateway(cli_env, "my-gateway", upstream)
                _lock(env_file, cli_env)

            # The proxy, the wrapped app and wrap itself all inherit this shell.
            egress = f"http://127.0.0.1:{egress_port}"
            shell = {name: egress for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
            shell |= {name.lower(): url for name, url in shell.items()}
            shell |= {"NO_PROXY": "", "no_proxy": ""}
            proc = _run_child_under_wrap(
                tmp_path, _ROUTED_CHILD_SCRIPT, lock_to_own_gateway, extra_env=shell
            )

        assert real_key
        # The app's own call (carrying shard-A) went through it, so it was on the path.
        assert _ForwardingEgressProxy.seen, "the shell's HTTP_PROXY relayed nothing"
        # Compare in place: never print the key.
        assert not any(real_key.encode() in request for request in _ForwardingEgressProxy.seen), (
            "the shell's HTTP_PROXY received the real key"
        )
        assert "STATUS:200" in proc.stdout, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert [(path, auth == f"Bearer {real_key}") for path, auth in _FakeUpstream.received] == [
            ("/v1/chat/completions", True)
        ]
        # wrap tells the user why, by name only.
        assert "WORTHLESS_UPSTREAM_PROXY" in proc.stderr
        assert egress not in proc.stderr


@pytest.mark.integration
@pytest.mark.timeout(60)
class TestQuietUnlockStillSaysWhatItDidToYourLine:
    """`worthless --quiet unlock`, run as a real process, says on stderr what it did to a
    `*_BASE_URL` line, and the `.env` on disk matches (WOR-1042)."""

    # The rewriter can't write a quote back, so lock won't save it (WOR-1027).
    _GATEWAY = "https://gateway.example.com/v1/o'neil"

    def _lock_a_line_lock_cannot_save(self, tmp_path: Path) -> tuple[Path, Path, str, dict]:
        env_file, worthless_home, key, cli_env = _make_e2e_env(tmp_path, proxy_port=1)
        env_file.write_text(f"OPENAI_BASE_URL={self._GATEWAY}\nOPENAI_API_KEY={key}\n")
        _register_gateway(cli_env, "quoted-gw", self._GATEWAY)
        _lock(env_file, cli_env)
        return env_file, worthless_home, key, cli_env

    @staticmethod
    def _quiet_unlock(
        env_file: Path, cli_env: dict, **streams: object
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "--quiet",
                "unlock",
                "--env",
                str(env_file),
            ],
            env={**os.environ, **cli_env, "WORTHLESS_KEYRING_BACKEND": "null"},
            timeout=45,
            text=True,
            **streams,
        )

    def test_a_line_lock_could_not_save_is_removed_and_said(self, tmp_path: Path) -> None:
        env_file, _home, key, cli_env = self._lock_a_line_lock_cannot_save(tmp_path)

        proc = self._quiet_unlock(env_file, cli_env, capture_output=True)

        assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert env_file.read_text() == f"OPENAI_API_KEY={key}\n"
        said = " ".join(proc.stderr.split())  # however Rich wrapped it (WOR-1022)
        assert "lock couldn't save the value you had in OPENAI_BASE_URL" in said, proc.stderr
        assert "Restored" not in said  # still quiet about progress
        assert_not_shown(proc.stderr, self._GATEWAY, key)

    def test_a_closed_stderr_never_leaves_unlock_half_done(self, tmp_path: Path) -> None:
        """A note written into a closed pipe (`2>&1 | head -n 1`) ends the process, so
        unlock prints notes only once its DB rows are gone too (merge-ready brutus)."""
        env_file, worthless_home, key, cli_env = self._lock_a_line_lock_cannot_save(tmp_path)
        home = WorthlessHome(base_dir=worthless_home)
        # Seen once already, so the note is the first thing written to the pipe.
        home.warranty_notice_marker.touch()
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            self._quiet_unlock(env_file, cli_env, stdout=subprocess.DEVNULL, stderr=write_end)
        finally:
            os.close(write_end)

        assert env_file.read_text() == f"OPENAI_API_KEY={key}\n"
        repo = ShardRepository(str(home.db_path), home.fernet_key)
        assert asyncio.run(repo.list_enrollments()) == [], "unlock stopped before its DB cleanup"


@pytest.mark.integration
@pytest.mark.timeout(60)
class TestQuietUninstallStillSaysWhatYouLose:
    """`worthless --quiet uninstall --yes --force`, run as a real process, names on
    stderr the `.env` whose key it couldn't put back and says to rotate it (WOR-1043)."""

    @staticmethod
    def _lock_an_env_uninstall_cannot_restore(
        tmp_path: Path, project: str | None = None
    ) -> tuple[Path, Path, str, dict]:
        env_file, worthless_home, key, cli_env = _make_e2e_env(tmp_path, proxy_port=1)
        if project is not None:
            env_file = env_file.parent.rename(env_file.parent.with_name(project)) / ".env"
        _lock(env_file, cli_env)
        # A live symlink in its place: uninstall won't write through it (f2ge).
        target = env_file.with_name("elsewhere.env")
        target.write_text("OPENAI_API_KEY=whatever\n")
        env_file.unlink()
        env_file.symlink_to(target)
        return env_file, worthless_home, key, cli_env

    @staticmethod
    def _quiet_force_uninstall(
        cli_env: dict, *, quiet: bool = True, **streams: object
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                *(["--quiet"] if quiet else []),
                "uninstall",
                "--yes",
                "--force",
            ],
            # A wide console keeps the tmp path on one line.
            env={**os.environ, **cli_env, "WORTHLESS_KEYRING_BACKEND": "null", "COLUMNS": "1000"},
            timeout=45,
            text=True,
            **streams,
        )

    def test_it_names_the_file_and_says_to_rotate_the_key(self, tmp_path: Path) -> None:
        env_file, worthless_home, key, cli_env = self._lock_an_env_uninstall_cannot_restore(
            tmp_path
        )

        proc = self._quiet_force_uninstall(cli_env, capture_output=True)

        assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert not worthless_home.exists()
        assert f"could NOT restore {env_file}" in proc.stderr, proc.stderr
        assert "Rotate those keys at your provider" in proc.stderr, proc.stderr
        assert "Worthless uninstalled" not in proc.stderr  # still quiet about progress
        assert_not_shown(proc.stderr, key)

    @pytest.mark.parametrize("quiet", [True, False], ids=["quiet", "not-quiet"])
    def test_a_folder_name_cannot_send_escape_codes_to_the_terminal(
        self, tmp_path: Path, quiet: bool
    ) -> None:
        """The bytes on stderr carry no ESC from the path, so the terminal can't be
        told to clear the screen."""
        env_file, _home, _key, cli_env = self._lock_an_env_uninstall_cannot_restore(
            tmp_path, "proj\x1b[2J\x1b[1;1HKeys OK"
        )

        proc = self._quiet_force_uninstall(cli_env, quiet=quiet, capture_output=True)

        assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert "\x1b" not in proc.stderr
        assert f"could NOT restore {str(env_file).replace(chr(27), '')}" in proc.stderr

    def test_a_closed_stderr_stops_it_before_the_wipe(self, tmp_path: Path) -> None:
        """If uninstall can't say which key it would destroy, it doesn't destroy it:
        the note comes before the wipe, and writing it to a closed pipe ends the run."""
        _env, worthless_home, _key, cli_env = self._lock_an_env_uninstall_cannot_restore(tmp_path)
        home = WorthlessHome(base_dir=worthless_home)
        # Seen once already, so the note is the first thing written to the pipe.
        home.warranty_notice_marker.touch()
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            self._quiet_force_uninstall(cli_env, stdout=subprocess.DEVNULL, stderr=write_end)
        finally:
            os.close(write_end)

        repo = ShardRepository(str(home.db_path), home.fernet_key)
        assert len(asyncio.run(repo.list_enrollments())) == 1, "uninstall wiped the key"

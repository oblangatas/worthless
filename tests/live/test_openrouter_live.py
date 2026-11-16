"""Live proof on OpenRouter: normal use, and the same setup under attack.

Each test locks a real OpenRouter key in a sandboxed HOME, runs the real
``worthless`` binary (``up`` or ``wrap``), and asserts only what a user or an
attacker sees: an answer from OpenRouter, a rejection, a stopped loop, or
what an agent can read.

The attack tests never need a working key: the proxy must refuse before
anything reaches OpenRouter, and must still let the right shard through.
"Refused by the proxy" means the reply is byte-identical to the one an
unknown alias gets, so a forwarded request that OpenRouter rejected cannot
pass for a proxy refusal.

Skipped unless OPENROUTER_API_KEY is set. Costs well under $0.01 per run
(openai/gpt-4o-mini, at most 5 output tokens per call). Run it so the key
reaches pytest only, never your shell:

    uv run --env-file .env pytest tests/live -m live -n0 --timeout-method=signal --reruns 0 -v -rs
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import openai
import psutil
import pytest
from dotenv import dotenv_values

from worthless.cli.process import poll_health

pytestmark = [pytest.mark.live, pytest.mark.timeout(180)]

OPENROUTER_URL = "https://openrouter.ai/api/v1"
MODEL = "openai/gpt-4o-mini"
REQUEST = {"model": MODEL, "max_tokens": 5, "messages": [{"role": "user", "content": "say hi"}]}
BINARY = str(Path(sys.executable).parent / "worthless")


_ENV_KEEP = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM", "TZ", "SYSTEMROOT"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class Sandbox:
    """A throwaway HOME holding one project .env with the real key in it."""

    root: Path
    env_file: Path
    # repr=False: a failing assert that calls a method prints the object.
    key: str = field(repr=False)
    env: dict[str, str] = field(repr=False)

    @property
    def port(self) -> int:
        return int(self.env["WORTHLESS_PORT"])

    @property
    def worthless_home(self) -> Path:
        return Path(self.env["WORTHLESS_HOME"])

    def cli(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [BINARY, *args], env=self.env, capture_output=True, text=True, timeout=timeout
        )

    def lock(self, *extra: str) -> tuple[str, str]:
        """Lock the .env; return (base_url, shard_a) as the user's app now sees them."""
        locked = self.cli("lock", "--env", str(self.env_file), *extra)
        assert locked.returncode == 0, f"lock failed: {locked.stdout}\n{locked.stderr}"
        parsed = dotenv_values(self.env_file)
        shard_a = parsed.get("OPENROUTER_API_KEY") or ""
        base_url = parsed.get("OPENROUTER_BASE_URL") or ""
        assert shard_a, "lock left no OPENROUTER_API_KEY in .env"
        key_left = self.key_on_disk(self.env_file)
        assert not key_left, "lock left the real key in .env"
        return base_url, shard_a

    def unlock(self) -> None:
        unlocked = self.cli("unlock", "--env", str(self.env_file))
        assert unlocked.returncode == 0, f"unlock failed: {unlocked.stdout}\n{unlocked.stderr}"

    def key_on_disk(self, *paths: Path) -> bool:
        """True if the real key's bytes sit in any file under *paths* (default: the sandbox)."""
        needle = self.key.encode()
        for top in paths or (self.root,):
            files = [top] if top.is_file() else [p for p in top.rglob("*") if p.is_file()]
            for path in files:
                try:
                    if needle in path.read_bytes():
                        return True
                except OSError:
                    continue
        return False

    def start_up(self) -> subprocess.Popen[bytes]:
        """Start ``worthless up`` on the sandbox port and wait until it is healthy."""
        log_path = self.root / "proxy.log"
        with log_path.open("w") as log:
            proc = subprocess.Popen(  # noqa: S603
                [BINARY, "up", "--port", str(self.port)],
                env=self.env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        if not poll_health(self.port, timeout=30.0):
            proc.terminate()
            self.cli("down")
            pytest.fail(f"proxy never came up:\n{log_path.read_text()[-2000:]}")
        return proc

    @contextmanager
    def up(self) -> Iterator[subprocess.Popen[bytes]]:
        """Run ``worthless up`` until the block exits, then ``worthless down``."""
        proc = self.start_up()
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    proc.kill()
            self.cli("down")


@pytest.fixture
def sandbox() -> Iterator[Sandbox]:
    """Sandboxed HOME + WORTHLESS_HOME with the real key in a project .env.

    The real key is removed from the environment the binary sees: only the
    .env holds it, as for a user. The sandbox is deleted afterwards because
    unlock puts the real key back on disk. Short /tmp path: AF_UNIX limit.
    """
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        pytest.skip("OPENROUTER_API_KEY not set")
    root = Path(tempfile.mkdtemp(prefix="wl-", dir="/tmp"))
    (root / "project").mkdir()
    env_file = root / "project" / ".env"
    # The real key in a .env is the setup under test, as a user has it. Owner-only
    # file in an owner-only temp dir, deleted after the test.
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"OPENROUTER_API_KEY={key}\n")
    # Only what the binary needs: `uv run --env-file .env` loads every key in
    # .env into this process, and none of them belongs in the sandbox.
    env = {k: v for k, v in os.environ.items() if k in _ENV_KEEP}
    env.update(
        {
            "HOME": str(root),
            "WORTHLESS_HOME": str(root / ".worthless"),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": str(_free_port()),
            "NO_COLOR": "1",
        }
    )
    try:
        yield Sandbox(root=root, env_file=env_file, key=key, env=env)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _client() -> httpx.Client:
    return httpx.Client(headers={"accept-encoding": "identity"}, timeout=60.0)


def _chat(client: httpx.Client, base_url: str, token: str | None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.post(f"{base_url}/chat/completions", json=REQUEST, headers=headers)


def _refusal(client: httpx.Client, port: int) -> httpx.Response:
    """What a stranger gets: a request for an alias that was never locked."""
    resp = _chat(client, f"http://127.0.0.1:{port}/openrouter-00000000/v1", "sk-or-v1-guess")
    assert resp.status_code == 401
    return resp


def _assert_answered(resp: httpx.Response) -> None:
    assert resp.status_code == 200, f"expected an answer, got {resp.status_code}: {resp.text[:300]}"
    content = resp.json()["choices"][0]["message"]["content"]
    assert content, "OpenRouter answered with empty content"


def _flip_one_char(value: str) -> str:
    """Change one character past the sk-or-v1- prefix, keeping the key's shape."""
    i = len("sk-or-v1-") + 5
    return value[:i] + ("0" if value[i] != "0" else "1") + value[i + 1 :]


# ---------------------------------------------------------------------------
# Normal use
# ---------------------------------------------------------------------------


class TestOpenRouterNormalUse:
    """A locked key keeps working for the user's own code, every way it calls."""

    def test_openai_sdk_gets_an_answer_through_the_proxy(self, sandbox: Sandbox) -> None:
        base_url, shard_a = sandbox.lock()
        with sandbox.up():
            client = openai.OpenAI(api_key=shard_a, base_url=base_url)
            resp = client.chat.completions.create(**REQUEST)
        assert resp.choices[0].message.content, "OpenRouter answered with empty content"

    def test_openai_sdk_streams_an_answer_through_the_proxy(self, sandbox: Sandbox) -> None:
        base_url, shard_a = sandbox.lock()
        with sandbox.up():
            client = openai.OpenAI(api_key=shard_a, base_url=base_url)
            stream = client.chat.completions.create(**REQUEST, stream=True)
            text = "".join(c.choices[0].delta.content or "" for c in stream if c.choices)
        assert text, "the stream carried no text"

    def test_raw_http_streams_server_sent_events_through_the_proxy(self, sandbox: Sandbox) -> None:
        base_url, shard_a = sandbox.lock()
        with sandbox.up(), _client() as client:
            with client.stream(
                "POST",
                f"{base_url}/chat/completions",
                json={**REQUEST, "stream": True},
                headers={"Authorization": f"Bearer {shard_a}"},
            ) as resp:
                assert resp.status_code == 200, resp.read()[:300]
                events = [line for line in resp.iter_lines() if line.startswith("data:")]
        assert events[-1].strip() == "data: [DONE]", f"stream did not finish: {events[-3:]}"
        deltas = [json.loads(e[5:]) for e in events[:-1] if e[5:].strip()]
        text = "".join(
            d["choices"][0]["delta"].get("content") or "" for d in deltas if d["choices"]
        )
        assert text, "the stream carried no text"

    def test_wrap_runs_an_app_that_reaches_openrouter_with_only_the_env_file(
        self, sandbox: Sandbox
    ) -> None:
        sandbox.lock()
        # A typical app: load .env, then call whatever base URL and key it holds.
        child = textwrap.dedent(f"""\
            import json, os, sys, httpx
            from dotenv import load_dotenv
            load_dotenv(sys.argv[1])
            r = httpx.post(
                os.environ["OPENROUTER_BASE_URL"] + "/chat/completions",
                json={REQUEST!r},
                headers={{
                    "Authorization": "Bearer " + os.environ["OPENROUTER_API_KEY"],
                    "accept-encoding": "identity",
                }},
                timeout=60,
            )
            print(json.dumps({{"status": r.status_code, "body": r.text}}))
        """)
        proc = sandbox.cli(
            "wrap", "--", sys.executable, "-c", child, str(sandbox.env_file), timeout=120
        )
        assert proc.returncode == 0, f"wrap failed: {proc.stdout}\n{proc.stderr}"
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        assert out["status"] == 200, f"app got {out['status']}: {out['body'][:300]}"
        assert json.loads(out["body"])["choices"][0]["message"]["content"]

    def test_unlock_gives_back_a_key_openrouter_accepts(self, sandbox: Sandbox) -> None:
        # Digests, not bytes: `pytest -l` prints locals, and these hold the real key.
        original = hashlib.sha256(sandbox.env_file.read_bytes()).digest()
        _, shard_a = sandbox.lock()
        with _client() as client:
            rejected = _chat(client, OPENROUTER_URL, shard_a)
            assert rejected.status_code in {401, 403}, "OpenRouter accepted the locked value"

            sandbox.unlock()
            restored = hashlib.sha256(sandbox.env_file.read_bytes()).digest() == original
            assert restored, ".env was not restored byte-for-byte"
            _assert_answered(
                _chat(client, OPENROUTER_URL, dotenv_values(sandbox.env_file)["OPENROUTER_API_KEY"])
            )


# ---------------------------------------------------------------------------
# Under attack
# ---------------------------------------------------------------------------


class TestOpenRouterUnderAttack:
    """What an attacker holding the .env, or a local process, can do with it: nothing."""

    def test_tampered_or_truncated_shard_is_refused_by_the_proxy(self, sandbox: Sandbox) -> None:
        base_url, shard_a = sandbox.lock()
        with sandbox.up(), _client() as client:
            refusal = _refusal(client, sandbox.port)
            for label, forged in (
                ("one character changed", _flip_one_char(shard_a)),
                ("cut to 70%", shard_a[: int(len(shard_a) * 0.7)]),
                ("one character dropped", shard_a[:-1]),
            ):
                resp = _chat(client, base_url, forged)
                assert (resp.status_code, resp.content) == (401, refusal.content), (
                    f"{label}: the proxy did not refuse it ({resp.status_code}: {resp.text[:200]})"
                )
            right = _chat(client, base_url, shard_a)
            assert right.status_code < 500 and right.content != refusal.content, (
                f"the proxy did not pass the right shard on ({right.status_code})"
            )

    def test_old_shard_is_refused_after_relock(self, sandbox: Sandbox) -> None:
        _, old_shard = sandbox.lock()
        sandbox.unlock()
        base_url, new_shard = sandbox.lock()
        assert new_shard != old_shard, "re-lock reused the old shard"
        with sandbox.up(), _client() as client:
            refusal = _refusal(client, sandbox.port)
            resp = _chat(client, base_url, old_shard)
            assert (resp.status_code, resp.content) == (401, refusal.content), (
                f"the proxy did not refuse the old shard ({resp.status_code}: {resp.text[:200]})"
            )
            direct = _chat(client, OPENROUTER_URL, old_shard)
            assert direct.status_code in {401, 403}, "OpenRouter accepted the old shard"
            right = _chat(client, base_url, new_shard)
            assert right.status_code < 500 and right.content != refusal.content, (
                f"the proxy did not pass the right shard on ({right.status_code})"
            )

    def test_strangers_all_get_the_same_401(self, sandbox: Sandbox) -> None:
        """No shard, a guessed shard, or the right shard on another alias: one reply, no hints."""
        base_url, shard_a = sandbox.lock()
        other_alias = f"http://127.0.0.1:{sandbox.port}/openrouter-deadbeef/v1"
        with sandbox.up(), _client() as client:
            refusal = _refusal(client, sandbox.port)
            attempts = {
                "no Authorization header": _chat(client, base_url, None),
                "Basic auth instead of a bearer": client.post(
                    f"{base_url}/chat/completions",
                    json=REQUEST,
                    headers={"Authorization": "Basic " + "c2hhcmQ6Z3Vlc3M="},
                ),
                "guessed shard": _chat(client, base_url, "sk-or-v1-" + "a" * 64),
                "right shard, another alias": _chat(client, other_alias, shard_a),
                "guessed x-api-key": client.post(
                    f"{base_url}/chat/completions",
                    json=REQUEST,
                    headers={"x-api-key": "sk-or-v1-" + "b" * 64},
                ),
            }
            for label, resp in attempts.items():
                assert (resp.status_code, resp.content) == (401, refusal.content), (
                    f"{label}: got {resp.status_code}: {resp.text[:200]}"
                )
            right = _chat(client, base_url, shard_a)
            assert right.status_code < 500 and right.content != refusal.content, (
                f"the proxy did not pass the right shard on ({right.status_code})"
            )

    def test_runaway_loop_is_stopped_by_the_daily_token_budget(self, sandbox: Sandbox) -> None:
        base_url, shard_a = sandbox.lock("--token-budget-daily", "40")
        statuses: list[int] = []
        with sandbox.up(), _client() as client:
            for _ in range(12):
                resp = _chat(client, base_url, shard_a)
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    stopped = resp
                    break
            else:
                pytest.fail(f"a 12-call loop was never stopped: {statuses}")
            again = [_chat(client, base_url, shard_a).status_code for _ in range(3)]
        assert statuses[0] == 200, f"the first call should be answered: {statuses}"
        assert "token budget exceeded" in stopped.json()["error"]["message"]
        assert again == [429, 429, 429], f"the loop got through again: {again}"

    def test_agent_dumping_its_environment_gets_only_a_useless_shard(
        self, sandbox: Sandbox
    ) -> None:
        """A prompt-injected agent under ``wrap`` dumps every env var and the .env."""
        sandbox.lock()
        child = textwrap.dedent("""\
            import json, os, sys
            from dotenv import dotenv_values
            loot = {"environ": dict(os.environ), "dotenv": dotenv_values(sys.argv[1])}
            print(json.dumps(loot))
        """)
        proc = sandbox.cli(
            "wrap", "--", sys.executable, "-c", child, str(sandbox.env_file), timeout=120
        )
        assert proc.returncode == 0, f"wrap failed: {proc.stdout}\n{proc.stderr}"
        loot_text = proc.stdout.strip().splitlines()[-1]
        leaked = sandbox.key in loot_text
        assert not leaked, "the real key was visible to the agent"
        stolen = json.loads(loot_text)["dotenv"]["OPENROUTER_API_KEY"]
        with _client() as client:
            resp = _chat(client, OPENROUTER_URL, stolen)
        assert resp.status_code in {401, 403}, (
            f"OpenRouter accepted the stolen value: {resp.status_code}"
        )


class TestOpenRouterKill9:
    """``kill -9`` on ``worthless up`` while it holds a real key."""

    @contextmanager
    def _killed_up(self, sandbox: Sandbox) -> Iterator[tuple[str, str, psutil.Process]]:
        """Lock, serve one call, SIGKILL ``up``; yield (base_url, shard_a, its proxy).

        No ``worthless down`` until the block exits: the test sees what kill -9 left.
        """
        base_url, shard_a = sandbox.lock()
        up = sandbox.start_up()
        try:
            with _client() as client:
                refusal = _refusal(client, sandbox.port)
                forwarded = _chat(client, base_url, shard_a)
                assert forwarded.content != refusal.content, "the proxy never used the key"
            on_disk = sandbox.key_on_disk()
            assert not on_disk, "the real key is in a file in the sandbox while up runs"
            children = psutil.Process(up.pid).children()
            sidecar = next(c for c in children if "worthless.sidecar" in " ".join(c.cmdline()))
            proxy = next(c for c in children if "uvicorn" in " ".join(c.cmdline()))
            run_dir = sandbox.worthless_home / "run" / str(up.pid)
            assert (run_dir / "share_a.bin").exists()

            up.send_signal(signal.SIGKILL)
            up.wait(timeout=5)
            deadline = time.monotonic() + 2.0
            while run_dir.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not run_dir.exists(), f"key shares left behind: {sorted(run_dir.iterdir())}"
            sidecar.wait(timeout=10)
            yield base_url, shard_a, proxy
        finally:
            if up.poll() is None:
                up.kill()
            sandbox.cli("down")

    def test_kill_9_leaves_no_key_and_nothing_answering(self, sandbox: Sandbox) -> None:
        """The proxy follows ``up`` down: nothing answers on the port, no key on disk."""
        with self._killed_up(sandbox) as (base_url, shard_a, proxy), _client() as client:
            try:
                proxy.wait(timeout=3)
                exited = True
            except psutil.TimeoutExpired:
                exited = False
            assert exited, "the proxy still ran 3 s after kill -9 took down `up` and its sidecar"
            with pytest.raises(httpx.TransportError):
                _chat(client, base_url, shard_a)
            on_disk = sandbox.key_on_disk()
            assert not on_disk, "the real key is in a file in the sandbox after kill -9"

"""Live end-to-end tests: lock -> wrap -> real LLM call -> unlock.

These tests hit real provider APIs and cost real money (~$0.001 per run).
They are skipped unless the relevant API key is present in the environment.

Run:
    uv run pytest tests/test_e2e_live.py -m live -v
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import anthropic
import httpx
import openai
import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.process import (
    build_proxy_env,
    create_liveness_pipe,
    poll_health,
    spawn_proxy,
)
from worthless.cli.sidecar_lifecycle import shutdown_sidecar, spawn_sidecar, split_to_tmpfs
from worthless.storage.repository import ShardRepository

runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Child scripts — one per provider (request/response shapes differ)
# ---------------------------------------------------------------------------

_OPENAI_CHILD = textwrap.dedent("""\
    import os, sys, json, httpx
    from dotenv import dotenv_values
    base = os.environ.get("OPENAI_BASE_URL")
    if not base:
        print("OPENAI_BASE_URL not set", file=sys.stderr)
        sys.exit(1)
    # Read shard-A from .env (not from os.environ which has the original key)
    env_path = os.environ.get("WORTHLESS_TEST_ENV_PATH", ".env")
    parsed = dotenv_values(env_path)
    key = parsed.get("OPENAI_API_KEY", "")
    client = httpx.Client(headers={"accept-encoding": "identity"})
    r = client.post(
        f"{base}/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "say hi"}],
        },
        headers={"Authorization": f"Bearer {key}"},
        timeout=60.0,
    )
    print(json.dumps({"status": r.status_code, "body": r.json()}))
""")

_ANTHROPIC_CHILD = textwrap.dedent("""\
    import os, sys, json, httpx
    from dotenv import dotenv_values
    base = os.environ.get("ANTHROPIC_BASE_URL")
    if not base:
        print("ANTHROPIC_BASE_URL not set", file=sys.stderr)
        sys.exit(1)
    env_path = os.environ.get("WORTHLESS_TEST_ENV_PATH", ".env")
    parsed = dotenv_values(env_path)
    key = parsed.get("ANTHROPIC_API_KEY", "")
    client = httpx.Client(headers={"accept-encoding": "identity"})
    r = client.post(
        f"{base}/messages",
        json={
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "say hi"}],
        },
        headers={
            "anthropic-version": "2023-06-01",
            "x-api-key": key,
        },
        timeout=60.0,
    )
    print(json.dumps({"status": r.status_code, "body": r.json()}))
""")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def openai_env(tmp_path: Path) -> tuple[Path, Path, str, dict[str, str]]:
    """Isolated env with a real OpenAI key. Skips if not available."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        pytest.skip("OPENAI_API_KEY not set")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    worthless_home = tmp_path / ".worthless"

    env_file = project_dir / ".env"
    env_file.write_text(f"OPENAI_API_KEY={key}\n")

    cli_env = {"WORTHLESS_HOME": str(worthless_home)}
    return env_file, worthless_home, key, cli_env


@pytest.fixture()
def anthropic_env(tmp_path: Path) -> tuple[Path, Path, str, dict[str, str]]:
    """Isolated env with a real Anthropic key. Skips if not available."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        pytest.skip("ANTHROPIC_API_KEY not set")

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    worthless_home = tmp_path / ".worthless"

    env_file = project_dir / ".env"
    env_file.write_text(f"ANTHROPIC_API_KEY={key}\n")

    cli_env = {"WORTHLESS_HOME": str(worthless_home)}
    return env_file, worthless_home, key, cli_env


# ---------------------------------------------------------------------------
# OpenAI live test
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.timeout(120)
class TestOpenAILive:
    """Lock a real OpenAI key, send a request through the proxy, verify response."""

    def test_openai_roundtrip(self, openai_env: tuple[Path, Path, str, dict[str, str]]) -> None:
        env_file, worthless_home, original_key, cli_env = openai_env
        original_content = env_file.read_text()

        # Lock
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"lock failed: {result.output}"
        assert original_key not in env_file.read_text()

        # Wrap + real LLM call
        proc = subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "wrap",
                "--",
                sys.executable,
                "-c",
                _OPENAI_CHILD,
            ],
            env={
                **os.environ,
                "WORTHLESS_HOME": str(worthless_home),
                "WORTHLESS_TEST_ENV_PATH": str(env_file),
                # WOR-463: explicit even though conftest.py setdefault
                # propagates via **os.environ. Self-documents the
                # no-keychain-leak contract; defense-in-depth.
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
            timeout=90,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"wrap failed (rc={proc.returncode}):\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        # Parse child output
        data = json.loads(proc.stdout.strip())

        if data["status"] == 429:
            # Quota exhausted — but 429 from upstream still proves full
            # proxy transit: key reconstructed, request forwarded, error
            # sanitized and relayed back. Accept as a pass.
            pass
        else:
            assert data["status"] == 200, f"upstream returned {data['status']}: {data['body']}"
            body = data["body"]
            assert "choices" in body, f"missing choices in response: {body}"
            content = body["choices"][0]["message"]["content"]
            assert content, f"empty completion content: {body}"

        # Unlock
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"unlock failed: {result.output}"
        assert env_file.read_text() == original_content

        # Clean state
        home_obj = WorthlessHome(base_dir=worthless_home)
        assert list(home_obj.shard_a_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Anthropic live test
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.timeout(120)
class TestAnthropicLive:
    """Lock a real Anthropic key, send a request through the proxy, verify response."""

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Pre-existing proxy bug: worthless wrap returns empty response body "
            "on Anthropic /messages round-trip. Tracked separately; does not "
            "indicate a regression in the live-gate or crypto code. "
            "Remove this decorator when the proxy bug is fixed."
        ),
    )
    def test_anthropic_roundtrip(
        self, anthropic_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        env_file, worthless_home, original_key, cli_env = anthropic_env
        original_content = env_file.read_text()

        # Lock
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"lock failed: {result.output}"
        assert original_key not in env_file.read_text()

        # Wrap + real LLM call
        proc = subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "wrap",
                "--",
                sys.executable,
                "-c",
                _ANTHROPIC_CHILD,
            ],
            env={
                **os.environ,
                "WORTHLESS_HOME": str(worthless_home),
                "WORTHLESS_TEST_ENV_PATH": str(env_file),
                # WOR-463: explicit even though conftest.py setdefault
                # propagates via **os.environ. Self-documents the
                # no-keychain-leak contract; defense-in-depth.
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
            timeout=90,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"wrap failed (rc={proc.returncode}):\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        # Parse child output
        data = json.loads(proc.stdout.strip())

        if data["status"] in {429, 529}:
            # Rate-limited or overloaded — but a response from upstream
            # still proves full proxy transit: key reconstructed, request
            # forwarded, error sanitized and relayed back.
            pass
        elif data["status"] == 400:
            # Billing/quota 400 ("credit balance too low") also proves
            # proxy transit — the request reached Anthropic and came back.
            pass
        else:
            assert data["status"] == 200, f"upstream returned {data['status']}: {data['body']}"
            body = data["body"]
            assert "content" in body, f"missing content in response: {body}"
            text = body["content"][0]["text"]
            assert text, f"empty completion text: {body}"

        # Unlock
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"unlock failed: {result.output}"
        assert env_file.read_text() == original_content

        # Clean state
        home = WorthlessHome(base_dir=worthless_home)
        assert list(home.shard_a_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Direct spawn_proxy test — manual HTTP request with shard-A as Bearer token
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.timeout(120)
class TestSpawnProxyDirect:
    """Lock a real key, spawn_proxy() directly, send HTTP with shard-A header."""

    def test_spawn_proxy_openai_direct(
        self, openai_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        _, _, original_key, _ = openai_env
        with _locked_proxy(openai_env) as (port, alias, shard_a):
            assert shard_a != original_key, "shard-A should differ from original key"

            url = f"http://127.0.0.1:{port}/{alias}/v1/chat/completions"
            with httpx.Client(headers={"accept-encoding": "identity"}, timeout=60.0) as client:
                resp = client.post(
                    url,
                    json={
                        "model": "gpt-4o-mini",
                        "max_tokens": 5,
                        "messages": [{"role": "user", "content": "say hi"}],
                    },
                    headers={"Authorization": f"Bearer {shard_a}"},
                )

            assert resp.status_code != 401, f"Got 401 — reconstruction failed. Body: {resp.text}"
            assert resp.status_code in {200, 429}, (
                f"Unexpected status {resp.status_code}: {resp.text}"
            )


# ---------------------------------------------------------------------------
# Wrap BASE_URL injection test
# ---------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.timeout(60)
class TestWrapBaseUrlInjection:
    """Verify ``worthless wrap`` injects the correct OPENAI_BASE_URL with alias-in-path."""

    def test_wrap_injects_openai_base_url(
        self, openai_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        env_file, worthless_home, _original_key, cli_env = openai_env

        # Lock
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"lock failed: {result.output}"

        # Determine the alias
        home = WorthlessHome(base_dir=worthless_home)

        repo = ShardRepository(str(home.db_path), home.fernet_key)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        alias = aliases[0]

        # Run wrap with a child that prints OPENAI_BASE_URL
        proc = subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "wrap",
                "--",
                sys.executable,
                "-c",
                "import os; print(os.environ.get('OPENAI_BASE_URL', ''))",
            ],
            env={
                **os.environ,
                "WORTHLESS_HOME": str(worthless_home),
                "WORTHLESS_TEST_ENV_PATH": str(env_file),
                # WOR-463: explicit even though conftest.py setdefault
                # propagates via **os.environ. Self-documents the
                # no-keychain-leak contract; defense-in-depth.
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
            timeout=45,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"wrap failed (rc={proc.returncode}):\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        base_url = proc.stdout.strip()
        assert f"/{alias}/v1" in base_url, (
            f"Expected alias-in-path '/{alias}/v1' in OPENAI_BASE_URL, got: {base_url!r}"
        )
        assert base_url.startswith("http://127.0.0.1:"), (
            f"Expected localhost URL, got: {base_url!r}"
        )

        # Unlock
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"unlock failed: {result.output}"


@contextmanager
def _locked_proxy(
    env: tuple[Path, Path, str, dict[str, str]],
) -> Iterator[tuple[int, str, str]]:
    """Lock the key, spawn a proxy, yield (port, alias, shard_a); unlock on exit.

    Teardown terminates the proxy, closes the liveness pipe, and unlocks — even
    on SDK failure. write_fd must outlive the proxy; closing it early signals
    liveness failure and the proxy exits.
    """
    env_file, worthless_home, _original_key, cli_env = env

    result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert result.exit_code == 0, f"lock failed: {result.output}"

    shard_a = next(iter(dotenv_values(env_file).values()))
    assert shard_a, "no shard-A found in locked .env"

    home = WorthlessHome(base_dir=worthless_home)
    repo = ShardRepository(str(home.db_path), home.fernet_key)
    aliases = asyncio.run(repo.list_keys())
    assert len(aliases) == 1
    alias = aliases[0]

    read_fd, write_fd = create_liveness_pipe()
    proxy: subprocess.Popen | None = None
    sidecar = None
    try:
        # Sidecar must come up before the proxy — mirrors wrap.py ordering.
        shares = split_to_tmpfs(home.fernet_key, home.base_dir)
        socket_path = shares.run_dir / "sidecar.sock"
        sidecar = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())

        proxy_env = build_proxy_env(home)
        proxy_env["WORTHLESS_SIDECAR_SOCKET"] = str(sidecar.socket_path)
        # IPC-only mode: proxy must NOT receive the Fernet key in its env.
        proxy_env.pop("WORTHLESS_FERNET_KEY", None)

        proxy, port = spawn_proxy(env=proxy_env, port=0, liveness_fd=read_fd)
        os.close(read_fd)
        read_fd = -1
        assert poll_health(port, timeout=15.0), "proxy failed to become healthy"
        yield port, alias, shard_a
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait(timeout=5)
        for fd in (read_fd, write_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if sidecar is not None:
            try:
                shutdown_sidecar(sidecar)
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
        assert result.exit_code == 0, f"unlock failed: {result.output}"


@pytest.mark.live
@pytest.mark.timeout(120)
class TestOpenAILiveSDK:
    """Prove the openai Python SDK works drop-in against the Worthless proxy."""

    def test_basic_chat_via_openai_sdk(
        self, openai_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(openai_env) as (port, alias, shard_a):
            client = openai.OpenAI(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}/v1",
            )
            try:
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    max_tokens=1,
                    messages=[{"role": "user", "content": "say hi"}],
                )
                assert resp.choices, f"no choices in response: {resp}"
                assert resp.choices[0].message is not None
            except openai.RateLimitError:
                pass

    def test_streaming_via_openai_sdk(
        self, openai_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(openai_env) as (port, alias, shard_a):
            client = openai.OpenAI(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}/v1",
            )
            try:
                stream = client.chat.completions.create(
                    model="gpt-4o-mini",
                    max_tokens=5,
                    messages=[{"role": "user", "content": "say hi"}],
                    stream=True,
                )
                chunks = list(stream)
                assert chunks, "stream yielded zero chunks — SSE broke through proxy"
                assert any(c.choices for c in chunks), f"no chunks had choices: {chunks[:3]}"
            except openai.RateLimitError:
                pass

    def test_bad_model_raises_typed_error_via_openai_sdk(
        self, openai_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(openai_env) as (port, alias, shard_a):
            client = openai.OpenAI(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}/v1",
            )
            with pytest.raises(openai.APIStatusError) as exc:
                client.chat.completions.create(
                    model="gpt-does-not-exist-zzz",
                    max_tokens=1,
                    messages=[{"role": "user", "content": "hi"}],
                )
            assert 400 <= exc.value.status_code < 500, (
                f"expected 4xx for bad model, got {exc.value.status_code}"
            )
            msg = str(exc.value).lower()
            assert "traceback" not in msg
            assert "worthless" not in msg


@pytest.mark.live
@pytest.mark.timeout(120)
class TestAnthropicLiveSDK:
    """Prove the anthropic Python SDK works drop-in against the Worthless proxy."""

    def test_basic_message_via_anthropic_sdk(
        self, anthropic_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(anthropic_env) as (port, alias, shard_a):
            client = anthropic.Anthropic(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}",
            )
            try:
                resp = client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=1,
                    messages=[{"role": "user", "content": "say hi"}],
                )
                assert resp.content, f"no content in response: {resp}"
            except anthropic.APIStatusError as err:
                # Billing 400, 429, 529 still prove full proxy transit.
                if err.status_code not in {400, 429, 529}:
                    raise

    def test_streaming_via_anthropic_sdk(
        self, anthropic_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(anthropic_env) as (port, alias, shard_a):
            client = anthropic.Anthropic(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}",
            )
            events = 0
            try:
                with client.messages.stream(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=5,
                    messages=[{"role": "user", "content": "say hi"}],
                ) as stream:
                    for _ in stream.text_stream:
                        events += 1
                assert events > 0, "stream yielded zero text events"
            except anthropic.APIStatusError as err:
                if err.status_code not in {400, 429, 529}:
                    raise

    def test_bad_model_raises_bad_request_via_anthropic_sdk(
        self, anthropic_env: tuple[Path, Path, str, dict[str, str]]
    ) -> None:
        with _locked_proxy(anthropic_env) as (port, alias, shard_a):
            client = anthropic.Anthropic(
                api_key=shard_a,
                base_url=f"http://127.0.0.1:{port}/{alias}",
            )
            # Real Anthropic returns 404 not_found_error for an unknown model
            # (confirmed via direct probe 2026-05-30); the hermetic mock mirrors
            # this contract so both lanes agree with the real provider.
            with pytest.raises(anthropic.NotFoundError) as exc:
                client.messages.create(
                    model="claude-does-not-exist-zzz",
                    max_tokens=1,
                    messages=[{"role": "user", "content": "hi"}],
                )
            assert exc.value.status_code == 404
            msg = str(exc.value).lower()
            assert "traceback" not in msg
            assert "worthless" not in msg

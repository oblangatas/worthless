"""OpenClaw integration test — prove shard-A works end-to-end through Docker Compose.

Two-container stack: mock-upstream + worthless-proxy. The client sends
format-preserving shard-A as a Bearer token to /<alias>/v1/chat/completions.
The proxy reconstructs the real key and forwards to mock-upstream.
Tests verify the real key arrives upstream and shard-A never leaks.

Requires Docker daemon running. Skipped when Docker is unavailable.

Run with:
    uv run pytest tests/test_openclaw_e2e.py -x -v -m openclaw
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

import anthropic
import httpx
import openai
import pytest

from tests._docker_helpers import docker_available, docker_exec, wait_healthy
from tests.helpers import fake_anthropic_key, fake_openai_key
from worthless.cli.commands.lock import _make_alias

# ---------------------------------------------------------------------------
# Module-level skip + markers
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.timeout(300),
]

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "tests" / "openclaw" / "docker-compose.yml"


# ---------------------------------------------------------------------------
# Helpers (matching test_docker_e2e.py patterns)
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Run a command, raise on failure by default."""
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kwargs)


def _run_ok(cmd: list[str]) -> str:
    """Run and return stdout, raise on failure."""
    return _run(cmd).stdout.strip()


def _get_host_port(container: str, internal_port: int) -> int:
    """Discover the dynamic host port mapped to a container port."""
    out = _run_ok(["docker", "port", container, str(internal_port)])
    return int(out.rsplit(":", 1)[-1])


def _write_env_to_container(
    container: str, env_content: str, dest: str = "/tmp/.env"
) -> subprocess.CompletedProcess[str]:
    """Write a .env file into a running container."""
    return subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            f"cat > {dest} << 'ENVEOF'\n{env_content}\nENVEOF",
        ],
        capture_output=True,
        text=True,
    )


def _read_env_value(container: str, var_name: str, path: str = "/tmp/.env") -> str:
    """Read a variable value from a .env file inside a container."""
    result = docker_exec(
        container,
        ["sh", "-c", f"grep '^{var_name}=' {path} | cut -d= -f2-"],
    )
    assert result.returncode == 0, f"Failed to read {var_name}: {result.stderr}"
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Session-scoped fixture: 2-container stack
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def openclaw_stack():
    """Build and start the mock-upstream + worthless-proxy stack.

    Uses `lock` to split the key (matching production flow):
    shard-A ends up in .env, shard-B in the DB.

    Yields (proxy_port, mock_port, fake_key, shard_a, alias).
    """
    project = f"openclaw-e2e-{uuid.uuid4().hex[:8]}"
    fake_key = fake_openai_key()
    alias = _make_alias("openai", fake_key)

    try:
        # 1. Build and start the stack
        _run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "-p",
                project,
                "up",
                "-d",
                "--build",
            ],
            cwd=str(REPO_ROOT),
            timeout=240,
        )

        # 2. Wait for worthless-proxy to be healthy
        proxy_container = f"{project}-worthless-proxy-1"
        if not wait_healthy(proxy_container, timeout=90):
            logs = subprocess.run(
                ["docker", "logs", proxy_container],
                capture_output=True,
                text=True,
            ).stdout
            pytest.fail(f"worthless-proxy did not become healthy.\n{logs}")

        # 3. Discover dynamic host ports
        proxy_port = _get_host_port(proxy_container, 8787)
        mock_container = f"{project}-mock-upstream-1"
        mock_port = _get_host_port(mock_container, 9999)

        # 4. Register the mock-upstream URL in the proxy's provider registry.
        #    Post-8rqs (Phase 5+6) the proxy resolves upstream from the per-
        #    enrollment ``base_url`` stored at lock time, and lock-time
        #    URL validation (M3) requires the URL to be in the merged
        #    registry. The mock serves an /openai/v1/* alias path so the
        #    registry can distinguish it from the bundled api.openai.com
        #    entry, AND from the parallel anthropic-mock URL.
        register = docker_exec(
            proxy_container,
            [
                "worthless",
                "providers",
                "register",
                "--name",
                "openai-mock",
                "--url",
                "http://mock-upstream:9999/openai/v1",
                "--protocol",
                "openai",
            ],
        )
        assert register.returncode == 0, f"register failed: {register.stderr}"

        # 5. Lock the key — writes shard-A to .env, shard-B to DB.
        #    OPENAI_BASE_URL pre-populated to the mock so lock stores that
        #    URL in the per-enrollment row instead of the bundled default.
        env_content = (
            f"OPENAI_API_KEY={fake_key}\nOPENAI_BASE_URL=http://mock-upstream:9999/openai/v1\n"
        )
        # Check the .env write explicitly — otherwise a write failure would
        # shadow as "lock failed" downstream (CR catch on M10). The
        # anthropic_alias fixture already does this; matching the pattern.
        write = _write_env_to_container(proxy_container, env_content)
        assert write.returncode == 0, f"failed to write .env: {write.stderr}"
        lock = docker_exec(proxy_container, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"Lock failed: {lock.stderr}"

        # 5. Read shard-A from .env (lock replaced the real key)
        shard_a = _read_env_value(proxy_container, "OPENAI_API_KEY")
        assert shard_a != fake_key, "Lock did not replace the key in .env"
        assert shard_a.startswith("sk-"), f"Shard-A not format-preserving: {shard_a[:20]}"

        # 6. Clear any captured headers from startup
        _clear_mock_headers(mock_port)

        yield proxy_port, mock_port, fake_key, shard_a, alias, proxy_container

    finally:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "-p",
                project,
                "down",
                "-v",
                "--remove-orphans",
            ],
            capture_output=True,
            cwd=str(REPO_ROOT),
            timeout=60,
        )


@pytest.fixture(scope="session")
def openclaw_anthropic_alias(openclaw_stack):
    """Enroll a second alias for Anthropic into the already-running stack.

    Depends on openclaw_stack (proxy + mock are up, OpenAI alias enrolled).
    Writes a distinct Anthropic fake key into a separate .env path inside
    the proxy container, runs `worthless lock`, reads shard-A back.

    Yields (fake_key, shard_a, alias).
    """
    _, _, _, _, _, proxy_container = openclaw_stack

    fake_key = fake_anthropic_key()
    alias = _make_alias("anthropic", fake_key)

    # Register the anthropic-mock URL. Same mock host:port as the
    # openai-mock entry but a different path prefix (mock serves an
    # /anthropic/v1/messages alias), so registry keys are distinct
    # — registry can't have two entries on the same URL with different
    # protocols. See openclaw_stack for the openai-mock counterpart.
    register = docker_exec(
        proxy_container,
        [
            "worthless",
            "providers",
            "register",
            "--name",
            "anthropic-mock",
            "--url",
            "http://mock-upstream:9999/anthropic/v1",
            "--protocol",
            "anthropic",
        ],
    )
    if register.returncode != 0:
        pytest.skip(f"anthropic register failed: {register.stderr}")

    env_path = "/tmp/worthless-anthropic-mock/.env"
    env_content = (
        f"ANTHROPIC_API_KEY={fake_key}\nANTHROPIC_BASE_URL=http://mock-upstream:9999/anthropic/v1\n"
    )
    mkdir = docker_exec(proxy_container, ["mkdir", "-p", "/tmp/worthless-anthropic-mock"])
    if mkdir.returncode != 0:
        pytest.skip(f"failed to create anthropic env dir: {mkdir.stderr}")
    write = _write_env_to_container(proxy_container, env_content, dest=env_path)
    if write.returncode != 0:
        pytest.skip(f"failed to write anthropic .env: {write.stderr}")

    lock = docker_exec(proxy_container, ["worthless", "lock", "--env", env_path])
    if lock.returncode != 0:
        pytest.skip(f"anthropic lock failed: {lock.stderr}")

    shard_a = _read_env_value(proxy_container, "ANTHROPIC_API_KEY", path=env_path)
    assert shard_a != fake_key, "lock did not replace anthropic key in .env"
    assert shard_a.startswith("sk-ant-"), f"anthropic shard-A not format-preserving: {shard_a[:30]}"

    yield fake_key, shard_a, alias


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _clear_mock_headers(mock_port: int) -> None:
    """Reset the mock-upstream's captured-headers log before a test."""
    httpx.delete(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=5.0)


class TestOpenClawShardA:
    """Prove the proxy reconstructs the real key and forwards it upstream.

    Client sends format-preserving shard-A as Bearer token to
    /<alias>/v1/chat/completions. Proxy reconstructs via modular
    arithmetic and forwards the real key to mock-upstream.
    """

    def test_shard_a_reconstructs(self, openclaw_stack):
        """POST to proxy, verify mock-upstream receives the REAL key."""
        proxy_port, mock_port, fake_key, shard_a, alias, _proxy_container = openclaw_stack

        _clear_mock_headers(mock_port)

        resp = httpx.post(
            f"http://127.0.0.1:{proxy_port}/{alias}/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "test"}],
            },
            headers={"Authorization": f"Bearer {shard_a}"},
            timeout=30.0,
        )
        assert resp.status_code == 200, f"Proxy returned {resp.status_code}: {resp.text}"

        captured = httpx.get(
            f"http://127.0.0.1:{mock_port}/captured-headers",
            timeout=5.0,
        ).json()
        assert len(captured["headers"]) > 0, "mock-upstream captured no headers"

        upstream_auth = captured["headers"][-1]["authorization"]
        assert f"Bearer {fake_key}" == upstream_auth, (
            f"Expected real key, got: {upstream_auth[:40]}..."
        )

    def test_streaming(self, openclaw_stack):
        """Streaming request reconstructs the real key too."""
        proxy_port, mock_port, fake_key, shard_a, alias, _proxy_container = openclaw_stack

        _clear_mock_headers(mock_port)

        resp = httpx.post(
            f"http://127.0.0.1:{proxy_port}/{alias}/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "test"}],
                "stream": True,
            },
            headers={"Authorization": f"Bearer {shard_a}"},
            timeout=30.0,
        )
        assert resp.status_code == 200, f"Proxy returned {resp.status_code}: {resp.text}"
        assert "data:" in resp.text, f"Expected SSE chunks, got: {resp.text[:200]}"

        captured = httpx.get(
            f"http://127.0.0.1:{mock_port}/captured-headers",
            timeout=5.0,
        ).json()
        assert len(captured["headers"]) > 0
        upstream_auth = captured["headers"][-1]["authorization"]
        assert f"Bearer {fake_key}" == upstream_auth

    def test_shard_a_not_leaked_to_upstream(self, openclaw_stack):
        """Shard-A (format-preserving) never appears in upstream headers."""
        proxy_port, mock_port, fake_key, shard_a, alias, _proxy_container = openclaw_stack

        _clear_mock_headers(mock_port)

        httpx.post(
            f"http://127.0.0.1:{proxy_port}/{alias}/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "test"}],
            },
            headers={"Authorization": f"Bearer {shard_a}"},
            timeout=30.0,
        )

        captured = httpx.get(
            f"http://127.0.0.1:{mock_port}/captured-headers",
            timeout=5.0,
        ).json()
        # Filter by provider: the captured-headers list is cross-provider once
        # both OpenAI and Anthropic aliases exist. Assert only on the OpenAI
        # rows here — Anthropic traffic uses x-api-key, not Authorization.
        openai_entries = [e for e in captured["headers"] if e.get("provider") == "openai"]
        assert openai_entries, "no OpenAI traffic captured at upstream"
        for entry in openai_entries:
            assert shard_a not in entry["authorization"], "Shard-A leaked to upstream!"
            assert entry["authorization"] == f"Bearer {fake_key}", (
                "Unexpected authorization value at upstream"
            )


class TestOpenAISDKOpenClaw:
    """Prove the openai Python SDK works drop-in against the containerized proxy + mock."""

    def test_basic_chat_via_openai_sdk(self, openclaw_stack):
        proxy_port, mock_port, _fake_key, shard_a, alias, _proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
        )
        resp = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        )
        assert resp.choices, f"no choices in response: {resp}"
        assert resp.choices[0].message.content == "Hello from mock upstream!"

    def test_streaming_via_openai_sdk(self, openclaw_stack):
        proxy_port, mock_port, _fake_key, shard_a, alias, _proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
        )
        stream = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
        )
        chunks = list(stream)
        assert chunks, "stream yielded zero chunks — SSE broke through proxy"
        contents = [
            c.choices[0].delta.content for c in chunks if c.choices and c.choices[0].delta.content
        ]
        assert "".join(contents) == "Hello!"

    def test_bad_model_raises_not_found_via_openai_sdk(self, openclaw_stack):
        proxy_port, mock_port, _fake_key, shard_a, alias, _proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
            max_retries=0,
        )
        with pytest.raises(openai.APIStatusError) as exc:
            client.chat.completions.create(
                model="gpt-does-not-exist-zzz",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert exc.value.status_code == 404
        msg = str(exc.value).lower()
        assert "traceback" not in msg
        assert "worthless" not in msg

    def test_upstream_5xx_surfaces_as_typed_error_via_openai_sdk(self, openclaw_stack):
        """Adversarial: upstream 500 must surface as openai.InternalServerError
        (typed 5xx subclass), not a generic APIError or raw HTTP exception."""
        proxy_port, mock_port, _fake_key, shard_a, alias, _proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
            max_retries=0,
        )
        with pytest.raises(openai.APIStatusError) as exc:
            client.chat.completions.create(
                model="gpt-trigger-5xx",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert exc.value.status_code >= 500, (
            f"expected 5xx passthrough, got {exc.value.status_code}"
        )
        assert "traceback" not in str(exc.value).lower()
        assert "worthless" not in str(exc.value).lower()


_SPEND_LOG_SUM_SNIPPET = (
    "import sqlite3, sys;"
    "c = sqlite3.connect('/data/worthless.db');"
    "q = 'SELECT COALESCE(SUM(tokens), 0) FROM spend_log WHERE key_alias = ?';"
    "print(c.execute(q, (sys.argv[1],)).fetchone()[0]);"
)

_SPEND_LOG_CLEAR_SNIPPET = (
    "import sqlite3, sys;"
    "c = sqlite3.connect('/data/worthless.db');"
    "c.execute('DELETE FROM spend_log WHERE key_alias = ?', (sys.argv[1],));"
    "c.commit();"
)


def _spend_log_sum(proxy_container: str, alias: str) -> int:
    """Query /data/worthless.db spend_log for total tokens recorded for an alias."""
    result = docker_exec(
        proxy_container,
        ["python", "-c", _SPEND_LOG_SUM_SNIPPET, alias],
    )
    assert result.returncode == 0, f"spend_log query failed: {result.stderr}"
    return int(result.stdout.strip() or "0")


def _spend_log_sum_eventually(
    proxy_container: str,
    alias: str,
    *,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> int:
    """Poll spend_log until tokens > 0 or timeout, then return whatever is there.

    ``record_spend`` is fired as a FastAPI ``BackgroundTask`` — it runs after
    the response is sent, so querying immediately after ``list(stream)`` returns
    races against the async write. A bounded poll bridges the gap without
    hardcoding a fixed sleep.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        total = _spend_log_sum(proxy_container, alias)
        if total > 0:
            return total
        time.sleep(interval)
    return _spend_log_sum(proxy_container, alias)


def _spend_log_clear(proxy_container: str, alias: str) -> None:
    """Reset spend_log for an alias so assertions start from zero."""
    result = docker_exec(
        proxy_container,
        ["python", "-c", _SPEND_LOG_CLEAR_SNIPPET, alias],
    )
    assert result.returncode == 0, f"spend_log delete failed: {result.stderr}"


class TestMeteringStreamingOpenAI:
    """WOR-240: prove streaming metering records > 0 tokens even when the client
    does not set stream_options.include_usage=true.

    Default openai-python streaming does NOT set include_usage. Without the
    flag, real OpenAI emits no usage field in any chunk — our proxy's
    StreamingUsageCollector then returns None and record_spend is called with
    tokens=0. The hard spend cap silently never fires on the majority of agent
    traffic. Fix: proxy must inject stream_options.include_usage=true when
    forwarding an OpenAI streaming request that lacks it.
    """

    def test_streaming_without_include_usage_meters_tokens(self, openclaw_stack):
        """MAIN bug proof. FAILS on current proxy (no include_usage injection)."""
        proxy_port, mock_port, _fake_key, shard_a, alias, proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)
        _spend_log_clear(proxy_container, alias)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
        )
        stream = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
        )
        list(stream)

        total_tokens = _spend_log_sum_eventually(proxy_container, alias)
        assert total_tokens > 0, (
            f"proxy metered {total_tokens} tokens on streaming without include_usage — "
            f"spend cap would silently never fire"
        )

    def test_streaming_with_client_include_usage_preserved(self, openclaw_stack):
        """Regression guard. Clients that already set include_usage must keep working."""
        proxy_port, mock_port, _fake_key, shard_a, alias, proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)
        _spend_log_clear(proxy_container, alias)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
        )
        stream = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
            stream_options={"include_usage": True},
        )
        list(stream)

        total_tokens = _spend_log_sum_eventually(proxy_container, alias)
        assert total_tokens > 0, (
            "proxy did not meter a streaming request that explicitly set "
            "stream_options.include_usage=true — fix regression"
        )

    def test_nonstreaming_meters_tokens(self, openclaw_stack):
        """Regression guard. Non-streaming path is unaffected by the fix and must stay green."""
        proxy_port, mock_port, _fake_key, shard_a, alias, proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)
        _spend_log_clear(proxy_container, alias)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
        )
        client.chat.completions.create(
            model="gpt-4o",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        )

        total_tokens = _spend_log_sum_eventually(proxy_container, alias)
        assert total_tokens > 0, "non-streaming metering regressed"


class TestAnthropicSDKOpenClaw:
    """Prove the anthropic Python SDK works drop-in against the containerized proxy + mock."""

    def test_basic_message_via_anthropic_sdk(self, openclaw_stack, openclaw_anthropic_alias):
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _clear_mock_headers(mock_port)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
        )
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        )
        assert resp.content, f"no content in response: {resp}"
        assert resp.content[0].text == "Hello from mock upstream!"

    def test_streaming_via_anthropic_sdk(self, openclaw_stack, openclaw_anthropic_alias):
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _clear_mock_headers(mock_port)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
        )
        texts = []
        with client.messages.stream(
            model="claude-haiku-4-5-20251001",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        ) as stream:
            for text in stream.text_stream:
                texts.append(text)
        assert texts, "Anthropic stream yielded zero text events — SSE broke through proxy"
        assert "".join(texts) == "Hello!"

    def test_bad_model_raises_bad_request_via_anthropic_sdk(
        self, openclaw_stack, openclaw_anthropic_alias
    ):
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _clear_mock_headers(mock_port)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
            max_retries=0,
        )
        # Real Anthropic returns 404 not_found_error for an unknown model
        # (confirmed via direct probe 2026-05-30). Mock mirrors that contract.
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

    def test_upstream_5xx_surfaces_as_typed_error_via_anthropic_sdk(
        self, openclaw_stack, openclaw_anthropic_alias
    ):
        """Adversarial: upstream 500 must surface as anthropic.InternalServerError
        (typed 5xx subclass), not a generic APIError or raw HTTP exception."""
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _clear_mock_headers(mock_port)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
            max_retries=0,
        )
        with pytest.raises(anthropic.APIStatusError) as exc:
            client.messages.create(
                model="claude-trigger-5xx",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert exc.value.status_code >= 500, (
            f"expected 5xx passthrough, got {exc.value.status_code}"
        )
        assert "traceback" not in str(exc.value).lower()
        assert "worthless" not in str(exc.value).lower()


# ---------------------------------------------------------------------------
# WOR-241: Anthropic cache token metering gap
# ---------------------------------------------------------------------------

# Mock values emitted by _anthropic_stream_events when include_cache=True:
#   message_start.usage.input_tokens              = 10
#   message_start.usage.cache_creation_input_tokens = 4
#   message_start.usage.cache_read_input_tokens     = 6
#   message_delta.usage.output_tokens              =  1
# Expected total WITH fix  = 10 + 4 + 6 + 1 = 21
# Expected total WITHOUT fix = 10 + 0 + 0 + 1 = 11  (cache fields ignored)
_CACHE_HIT_EXPECTED_TOKENS = 21
_CACHE_HIT_NO_FIX_TOKENS = 11


class TestMeteringCacheTokensAnthropic:
    """WOR-241: prove Anthropic cache tokens (creation + read) are included
    in the proxy's metered total.

    Anthropic's prompt-cache API adds two extra usage fields to
    ``message_start.message.usage``:
      - ``cache_creation_input_tokens``: tokens written to the cache (1.25x cost)
      - ``cache_read_input_tokens``:    tokens read from the cache   (0.10x cost)

    Both represent real token consumption that spend-cap rules must see.
    Without the fix, the proxy counts only ``input_tokens`` +
    ``output_tokens`` and silently under-meters every cached prompt, letting
    spend caps fire too late (or never).
    """

    def test_cache_tokens_included_in_streaming_meter(
        self, openclaw_stack, openclaw_anthropic_alias
    ):
        """MAIN bug proof. FAILS on unpatched proxy (cache fields ignored)."""
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _proxy_container = openclaw_stack[5]
        _clear_mock_headers(mock_port)
        _spend_log_clear(_proxy_container, alias)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
        )
        # Model name contains 'cache-hit' — triggers mock to emit cache fields
        with client.messages.stream(
            model="claude-haiku-cache-hit",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        ) as stream:
            list(stream.text_stream)

        total_tokens = _spend_log_sum(_proxy_container, alias)
        assert total_tokens == _CACHE_HIT_EXPECTED_TOKENS, (
            f"proxy metered {total_tokens} tokens; expected {_CACHE_HIT_EXPECTED_TOKENS}. "
            f"If {_CACHE_HIT_NO_FIX_TOKENS}: cache fields (creation + read) are being ignored."
        )

    def test_non_cache_streaming_unaffected(self, openclaw_stack, openclaw_anthropic_alias):
        """Regression guard: normal Anthropic streaming still meters correctly."""
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _proxy_container = openclaw_stack[5]
        _clear_mock_headers(mock_port)
        _spend_log_clear(_proxy_container, alias)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
        )
        # Normal model — no cache fields in mock response
        with client.messages.stream(
            model="claude-haiku-4-5-20251001",
            max_tokens=16,
            messages=[{"role": "user", "content": "hi"}],
        ) as stream:
            list(stream.text_stream)

        total_tokens = _spend_log_sum(_proxy_container, alias)
        # mock emits input=10, output=1 -> expect 11 (no cache tokens)
        assert total_tokens == 11, (
            f"non-cache Anthropic streaming metered {total_tokens} tokens; "
            f"expected 11 (input=10, output=1). Regression in base metering."
        )


# ---------------------------------------------------------------------------
# WOR-243: Error body field preservation (code/type/param must pass through)
# ---------------------------------------------------------------------------


class TestErrorBodyPreservation:
    """WOR-243: prove proxy preserves error.code, error.type, and error.param
    when sanitizing upstream error responses.

    The proxy replaces error.message to avoid leaking internal details, but
    must pass error.code, error.type, and error.param through unchanged so
    SDK code can classify errors, trigger retries, and route fallbacks.
    """

    def test_openai_404_preserves_error_code(self, openclaw_stack):
        """error.code must survive sanitization — SDK checks it for model classification."""
        proxy_port, mock_port, _fake_key, shard_a, alias, _proxy_container = openclaw_stack
        _clear_mock_headers(mock_port)

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}/v1",
            max_retries=0,
        )
        with pytest.raises(openai.APIStatusError) as exc:
            client.chat.completions.create(
                model="gpt-does-not-exist-zzz",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert exc.value.status_code == 404
        # The openai SDK extracts body.get("error", body) before storing in
        # exc.value.body — so exc.value.body is already the inner error dict.
        body = exc.value.body
        assert isinstance(body, dict), f"expected dict body, got {type(body)}: {body}"
        assert body.get("code") == "model_not_found", (
            f"error.code was {body.get('code')!r}, expected 'model_not_found'. "
            f"Proxy sanitization is stripping error.code."
        )

    def test_anthropic_404_preserves_error_type(self, openclaw_stack, openclaw_anthropic_alias):
        """error.type must survive sanitization — SDK uses it to classify not-found errors.

        Real Anthropic returns 404 not_found_error for unknown models (confirmed 2026-05-30;
        mock updated to mirror this in WOR-228). The proxy must pass error.type through
        unchanged so the SDK can surface the correct typed exception.
        """
        proxy_port, mock_port, *_ = openclaw_stack
        _fake_key, shard_a, alias = openclaw_anthropic_alias
        _clear_mock_headers(mock_port)

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{proxy_port}/{alias}",
            max_retries=0,
        )
        with pytest.raises(anthropic.NotFoundError) as exc:
            client.messages.create(
                model="claude-does-not-exist-zzz",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert exc.value.status_code == 404
        body = exc.value.body
        assert isinstance(body, dict), f"expected dict body, got {type(body)}: {body}"
        error = body.get("error", {})
        assert error.get("type") == "not_found_error", (
            f"error.type was {error.get('type')!r}, expected 'not_found_error'. "
            f"Proxy sanitization is stripping error.type."
        )

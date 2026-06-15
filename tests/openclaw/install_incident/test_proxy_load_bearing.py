"""WOR-545 / WOR-621 — the proxy must be load-bearing after ``worthless lock``.

This is the headline WOR-514 guarantee, proven end-to-end against a REAL
OpenClaw container talking to the REAL Worthless proxy:

    OpenClaw ──(Bearer shard-A → proxy /<alias>/v1)──► Worthless proxy
                                                            │ reconstruct shard-A ⊕ shard-B
                                                            ▼
                                                      mock upstream  (sees the REAL key)

Kill the proxy and the two halves never combine, so OpenClaw cannot reach
upstream — that failure is the feature. The flow:

1. ``docker compose up`` the mock-upstream + worthless-proxy stack.
2. ``worthless lock`` — shard-A to .env, shard-B to the DB (production split).
3. Start a pinned OpenClaw container on the stack network; wire its
   ``openai`` provider to the proxy's ``/<alias>/v1`` with shard-A as apiKey
   (what ``lock``'s OpenClaw integration does when co-located), restart it.
4. Drive a gateway chat — assert the mock received the REAL key (proxy
   reconstructed it) and never shard-A.
5. ``docker stop`` the proxy — drive a chat — assert the mock receives
   NOTHING (the agent cannot reach upstream). **The load-bearing proof.**
6. ``docker start`` the proxy — drive a chat — assert it reaches upstream
   again.

Honest scope: this proves "load-bearing after OpenClaw picks up the
rewrite", which today means after an OpenClaw restart (we restart in step
3). The no-restart live-reload is PR-2. OpenClaw is pinned so a release
that changes routing turns this red on purpose.

Marks: ``openclaw`` + ``docker``; skipped when Docker is unavailable. Heavy
(builds the proxy image, boots three containers, restarts OpenClaw, stops
and starts the proxy) — runs in the OpenClaw CI lane only.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from tests._docker_helpers import docker_available, docker_exec, wait_healthy
from tests.helpers import fake_openai_key
from worthless.cli.commands.lock import _make_alias

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "tests" / "openclaw" / "docker-compose.yml"
OPENCLAW_IMAGE = "ghcr.io/openclaw/openclaw:2026.5.3-1"
_MODEL = "openai/gpt-4o"

pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    # Heavy: image build + 3 containers + OpenClaw restarts + proxy stop/start.
    pytest.mark.timeout(900),
]


# --------------------------------------------------------------------------- #
# Thin docker / OpenClaw helpers (subprocess; mirrors test_routing_contract).
# --------------------------------------------------------------------------- #
def _run(
    args: list[str], *, check: bool = False, timeout: int = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _oc(container: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", container, "node", "openclaw.mjs", *args], timeout=timeout)


def _wait_oc(container: str, tries: int = 30) -> None:
    for _ in range(tries):
        if _oc(container, "config", "get", "gateway", timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"OpenClaw container {container} did not become ready")


def _route(container: str) -> subprocess.CompletedProcess:
    """Drive one agent turn through the gateway (the real incident path)."""
    sid = f"wor545-{uuid.uuid4().hex[:6]}"
    return _oc(container, "agent", "--session-id", sid, "--message", "hi", "--json", timeout=120)


def _captured(mock_port: int) -> list[dict]:
    r = httpx.get(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)
    return r.json().get("headers", [])


def _clear(mock_port: int) -> None:
    httpx.delete(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)


def _host_port(container: str, internal: int) -> int:
    out = _run(["docker", "port", container, str(internal)], check=True).stdout.strip()
    return int(out.rsplit(":", 1)[-1])


# --------------------------------------------------------------------------- #
# Stack: mock-upstream + worthless-proxy (compose) + a pinned OpenClaw
# container attached to the same network, wired to the proxy alias with
# shard-A. Module-scoped: the slow build/boot/lock happens once.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def loaded_stack():
    project = f"wor545-{uuid.uuid4().hex[:8]}"
    network = f"{project}_openclaw-net"
    oc = f"{project}-openclaw-driver"
    proxy = f"{project}-worthless-proxy-1"
    mock = f"{project}-mock-upstream-1"
    fake_key = fake_openai_key()
    alias = _make_alias("openai", fake_key)

    try:
        _run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", project, "up", "-d", "--build"],
            check=True,
            timeout=300,
        )
        if not wait_healthy(proxy, timeout=120):
            logs = _run(["docker", "logs", proxy]).stdout
            pytest.fail(f"worthless-proxy did not become healthy.\n{logs}")
        mock_port = _host_port(mock, 9999)

        # Register the mock URL, then lock — shard-A to .env, shard-B to DB.
        reg = docker_exec(
            proxy,
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
        assert reg.returncode == 0, f"register failed: {reg.stderr}"
        env = (
            "OPENAI_API_KEY=" + fake_key + "\nOPENAI_BASE_URL=http://mock-upstream:9999/openai/v1\n"
        )
        wr = docker_exec(proxy, ["sh", "-c", f"cat > /tmp/.env << 'EOF'\n{env}\nEOF"])
        assert wr.returncode == 0, f"write .env failed: {wr.stderr}"
        lock = docker_exec(proxy, ["worthless", "lock", "--env", "/tmp/.env"])  # noqa: S108
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"
        shard_a = docker_exec(
            proxy, ["sh", "-c", "grep '^OPENAI_API_KEY=' /tmp/.env | cut -d= -f2-"]
        ).stdout.strip()
        assert shard_a and shard_a != fake_key, "lock did not replace the key with shard-A"

        # Boot a pinned OpenClaw container on the stack network and wire its
        # provider to the proxy alias with shard-A (what lock's OpenClaw
        # integration does when co-located with the config).
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "--network",
                network,
                "-e",
                "OPENCLAW_ACCEPT_TERMS=yes",
                "--user",
                "node",
                OPENCLAW_IMAGE,
            ],
            check=True,
        )
        _wait_oc(oc)
        prov = {
            "baseUrl": f"http://worthless-proxy:8787/{alias}/v1",
            "api": "openai-completions",
            "models": [],
        }
        assert (
            _oc(
                oc, "config", "set", "models.providers.openai", json.dumps(prov), "--strict-json"
            ).returncode
            == 0
        )
        _oc(oc, "config", "set", "models.providers.openai.apiKey", shard_a)
        _oc(oc, "config", "set", "agents.defaults.model.primary", _MODEL)
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)

        yield {
            "oc": oc,
            "proxy": proxy,
            "mock_port": mock_port,
            "fake_key": fake_key,
            "shard_a": shard_a,
        }
    finally:
        _run(["docker", "rm", "-f", oc], timeout=60)
        _run(
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
            timeout=90,
        )


def test_proxy_is_load_bearing_after_lock(loaded_stack):
    """Kill the proxy → OpenClaw cannot reach upstream; restart → it can."""
    oc = loaded_stack["oc"]
    proxy = loaded_stack["proxy"]
    mock_port = loaded_stack["mock_port"]
    fake_key = loaded_stack["fake_key"]
    shard_a = loaded_stack["shard_a"]

    # 1. Baseline — proxy up: the chat SUCCEEDS and reaches the mock with the REAL key.
    _clear(mock_port)
    base_turn = _route(oc)
    assert base_turn.returncode == 0, (
        f"baseline agent turn did not succeed (rc={base_turn.returncode}); the kill-step proof is "
        f"only meaningful if the agent works when the proxy is up.\n{base_turn.stderr[-600:]}"
    )
    base = _captured(mock_port)
    assert len(base) >= 1, "baseline chat did not reach the mock upstream through the proxy"
    auths = " ".join(e.get("authorization", "") for e in base)
    assert fake_key in auths, "proxy did not reconstruct the real key to upstream"
    assert shard_a not in auths, "shard-A leaked to upstream — reconstruction is broken"

    # 2. THE PROOF — stop the proxy: the next chat FAILS at the proxy hop AND reaches nothing.
    # rc != 0 proves the agent actually TRIED and couldn't reach upstream, not that it no-op'd.
    _run(["docker", "stop", proxy], check=True, timeout=60)
    _clear(mock_port)
    down_turn = _route(oc)
    assert down_turn.returncode != 0, (
        "agent turn SUCCEEDED with the Worthless proxy stopped — proxy is NOT load-bearing "
        "(WOR-514 bypass reborn)."
    )
    assert _captured(mock_port) == [], (
        "OpenClaw reached upstream with the Worthless proxy STOPPED — "
        "the proxy is NOT load-bearing (WOR-514 bypass reborn)."
    )

    # 3. Restart the proxy: the chat SUCCEEDS again (rules out an unrelated agent failure).
    _run(["docker", "start", proxy], check=True, timeout=60)
    assert wait_healthy(proxy, timeout=120), "proxy did not recover after restart"
    _clear(mock_port)
    back_turn = _route(oc)
    assert back_turn.returncode == 0, f"agent turn failed after restart: {back_turn.stderr[-400:]}"
    assert len(_captured(mock_port)) >= 1, "proxy did not resume routing after restart"

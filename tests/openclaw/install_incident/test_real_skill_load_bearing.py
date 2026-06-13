"""WOR-664 (F13b) — real-skill, real-install end-to-end (the solo-dev flow).

WOR-545 proves the proxy is load-bearing by HAND-WIRING OpenClaw's config.
This proves the same guarantee via the REAL path a solo dev actually uses:
Worthless installed *next to* OpenClaw (one machine), the real skill present,
and `worthless lock` run through the real CLI doing the openclaw.json rewrite
itself — exercising THIS branch (F1 rewrite + the real skill), CI-safe.

Topology (verified by spike — no cross-container fernet/sidecar):
- one container from the derived image `worthless-oc-test:local` (OpenClaw +
  Worthless installed the real way: pinned uv → `uv tool install` the local
  wheel), running the Worthless daemon (`worthless up`, file-fernet) AND
  OpenClaw together — exactly the solo-dev setup;
- a separate mock-upstream container as the "provider".

Flow: install real skill → register mock upstream → `worthless lock` (splits
the key, rewrites openclaw.json → 127.0.0.1:8787/<alias>, F7 probe passes) →
OpenClaw restart → drive a gateway chat → mock receives the REAL key (proxy
reconstructed it), never shard-A → kill the daemon → next chat reaches
NOTHING (load-bearing) → restart → recovers.

The "AI autonomously chooses lock from a natural prompt" step needs a real
model turn and a real key — that is a separate LOCAL-ONLY test (WOR-664 c),
never CI. This test drives lock + the agent deterministically.

Marks: openclaw + docker; skipped when Docker is unavailable. Heavy
(builds the mock image, boots 2 containers, restarts OpenClaw, stops/starts
the daemon). Requires the derived image to be built first:
    uv build --wheel
    docker build -f tests/openclaw/Dockerfile.oc-worthless -t worthless-oc-test:local dist/
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from tests._docker_helpers import docker_available
from tests.helpers import fake_openai_key

REPO_ROOT = Path(__file__).resolve().parents[3]
OC_WORTHLESS_IMAGE = "worthless-oc-test:local"
MOCK_DOCKERFILE_DIR = str(REPO_ROOT / "tests" / "openclaw" / "mock-upstream")
_MOCK_PORT = 9999
_MODEL = "openai/gpt-4o"


def _image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.skipif(
        not _image_present(OC_WORTHLESS_IMAGE),
        reason=f"{OC_WORTHLESS_IMAGE} not built (see module docstring)",
    ),
    pytest.mark.timeout(900),
]


def _run(
    args: list[str], *, check: bool = False, timeout: int = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _exec(c: str, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", c, *args], timeout=timeout)


def _sh(c: str, script: str, *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(c, ["sh", "-c", script], timeout=timeout)


def _oc(c: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(c, ["node", "openclaw.mjs", *args], timeout=timeout)


def _wait_oc(c: str, tries: int = 40) -> None:
    for _ in range(tries):
        if _oc(c, "config", "get", "gateway", timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"OpenClaw container {c} did not become ready")


_HEALTHZ = (
    "python3 -c \"import urllib.request as u;u.urlopen('http://127.0.0.1:8787/healthz',timeout=2)\""
)


def _daemon_healthy(c: str) -> bool:
    return _sh(c, _HEALTHZ, timeout=15).returncode == 0


def _wait_daemon(c: str, up: bool, tries: int = 30) -> bool:
    for _ in range(tries):
        if _daemon_healthy(c) is up:
            return True
        time.sleep(1)
    return False


def _start_daemon(c: str) -> None:
    _run(["docker", "exec", "-d", c, "sh", "-c", "worthless up > /tmp/up.log 2>&1"])
    if not _wait_daemon(c, up=True):
        logs = _sh(c, "tail -10 /tmp/up.log").stdout
        raise RuntimeError(f"worthless daemon did not become healthy.\n{logs}")


def _stop_daemon(c: str) -> None:
    # Robust stop regardless of the exact CLI: try `down`, then kill the procs.
    _sh(
        c,
        "worthless down >/dev/null 2>&1 || true; pkill -f 'worthless up' 2>/dev/null || true; "
        "pkill -f uvicorn 2>/dev/null || true; pkill -f 'worthless.proxy' 2>/dev/null || true",
    )
    if not _wait_daemon(c, up=False):
        raise RuntimeError("worthless daemon still healthy after stop")


def _route(c: str) -> subprocess.CompletedProcess:
    sid = f"wor664-{uuid.uuid4().hex[:6]}"
    return _oc(c, "agent", "--session-id", sid, "--message", "hi", "--json", timeout=120)


def _captured(mock_port: int) -> list[dict]:
    return (
        httpx.get(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)
        .json()
        .get("headers", [])
    )


def _clear(mock_port: int) -> None:
    httpx.delete(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)


def _host_port(c: str, internal: int) -> int:
    out = _run(["docker", "port", c, str(internal)], check=True).stdout.strip()
    return int(out.rsplit(":", 1)[-1])


@pytest.fixture(scope="module")
def skill_stack():
    sfx = uuid.uuid4().hex[:8]
    net = f"wor664-net-{sfx}"
    mock = f"wor664-mock-{sfx}"
    oc = f"wor664-oc-{sfx}"
    mock_img = f"wor664-mockimg-{sfx}"
    real_key = fake_openai_key()
    mock_url = f"http://{mock}:{_MOCK_PORT}/openai/v1"

    try:
        _run(["docker", "build", "-t", mock_img, MOCK_DOCKERFILE_DIR], check=True, timeout=300)
        _run(["docker", "network", "create", net], check=True)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                mock,
                "--network",
                net,
                "--network-alias",
                mock,
                "-p",
                "127.0.0.1::9999",
                mock_img,
            ],
            check=True,
        )
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "--network",
                net,
                "-e",
                "OPENCLAW_ACCEPT_TERMS=yes",
                "--user",
                "node",
                OC_WORTHLESS_IMAGE,
            ],
            check=True,
        )
        _wait_oc(oc)
        mock_port = _host_port(mock, 9999)

        # Install the REAL skill (the image has the worthless bin; side-load
        # the skill file into the workspace OpenClaw scans).
        _sh(oc, "mkdir -p /home/node/.openclaw/workspace/skills/worthless")
        _run(
            [
                "docker",
                "cp",
                str(REPO_ROOT / "src/worthless/openclaw/skill_assets/SKILL.md"),
                f"{oc}:/home/node/.openclaw/workspace/skills/worthless/SKILL.md",
            ],
            check=True,
        )

        # Register the mock upstream so reconstruction forwards there.
        reg = _exec(
            oc,
            [
                "worthless",
                "providers",
                "register",
                "--name",
                "openai-mock",
                "--url",
                mock_url,
                "--protocol",
                "openai",
            ],
        )
        assert reg.returncode == 0, f"register failed: {reg.stderr}"

        # Daemon up FIRST (lock's F7 probe requires a healthy proxy).
        _start_daemon(oc)

        # Real lock: pre-seed OPENAI_BASE_URL=mock so the enrollment upstream
        # is the mock; lock splits the key + rewrites openclaw.json.
        _sh(
            oc,
            "mkdir -p /tmp/p && printf 'OPENAI_API_KEY=%s\\nOPENAI_BASE_URL=%s\\n' "
            f"'{real_key}' '{mock_url}' > /tmp/p/.env",
        )
        lock = _sh(oc, "cd /tmp/p && worthless lock --env .env")
        assert lock.returncode == 0, f"lock failed: {lock.stdout}\n{lock.stderr}"

        shard_a = _sh(oc, "grep '^OPENAI_API_KEY=' /tmp/p/.env | cut -d= -f2-").stdout.strip()
        assert shard_a and shard_a != real_key, "lock did not replace the key with shard-A"

        # OpenClaw must pick up the rewritten provider; set the default model + restart.
        _oc(oc, "config", "set", "agents.defaults.model.primary", _MODEL)
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)
        _start_daemon(oc)  # restart cleared the daemon process

        yield {"oc": oc, "mock_port": mock_port, "real_key": real_key, "shard_a": shard_a}
    finally:
        _run(["docker", "rm", "-f", oc, mock], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)
        _run(["docker", "image", "rm", "-f", mock_img], timeout=60)


def test_real_skill_install_makes_proxy_load_bearing(skill_stack):
    """The real skill is installed + visible, lock wired OpenClaw to the proxy,
    and killing the daemon halts the agent."""
    oc = skill_stack["oc"]
    mock_port = skill_stack["mock_port"]
    real_key = skill_stack["real_key"]
    shard_a = skill_stack["shard_a"]

    # The REAL skill is installed and the agent can see it (bin present).
    skills = _oc(oc, "skills", "list", "--json").stdout

    def _find(o):
        if isinstance(o, dict):
            if o.get("name") == "worthless":
                return o
            for v in o.values():
                r = _find(v)
                if r:
                    return r
        if isinstance(o, list):
            for v in o:
                r = _find(v)
                if r:
                    return r
        return None

    w = _find(json.loads(skills))
    assert w and w.get("modelVisible") is True, f"real skill not modelVisible: {w}"

    # Baseline — daemon up: the chat SUCCEEDS and reaches the mock with the REAL key.
    _clear(mock_port)
    base_turn = _route(oc)
    assert base_turn.returncode == 0, (
        f"baseline agent turn did not succeed (rc={base_turn.returncode}); the kill-step proof is "
        f"only meaningful if the agent works when the daemon is up.\n{base_turn.stderr[-600:]}"
    )
    base = _captured(mock_port)
    assert len(base) >= 1, "baseline chat did not reach the mock through the proxy"
    auths = " ".join(e.get("authorization", "") for e in base)
    assert real_key in auths, "proxy did not reconstruct the real key to upstream"
    assert shard_a not in auths, "shard-A leaked to upstream — reconstruction broken"

    # THE PROOF — stop the daemon: the next chat FAILS at the proxy hop AND reaches nothing.
    # rc != 0 proves the agent actually TRIED and couldn't reach upstream (probe shows
    # daemon-down → rc=1 "network connection error"), not that it silently no-op'd.
    _stop_daemon(oc)
    _clear(mock_port)
    down_turn = _route(oc)
    assert down_turn.returncode != 0, (
        "agent turn SUCCEEDED with the Worthless daemon stopped — proxy is NOT load-bearing."
    )
    assert _captured(mock_port) == [], (
        "OpenClaw reached upstream with the Worthless daemon STOPPED — "
        "proxy is NOT load-bearing via the real skill/install path."
    )

    # Restart — the chat SUCCEEDS again (rules out an unrelated, persistent agent failure).
    _start_daemon(oc)
    _clear(mock_port)
    back_turn = _route(oc)
    assert back_turn.returncode == 0, f"agent turn failed after restart: {back_turn.stderr[-400:]}"
    assert len(_captured(mock_port)) >= 1, "proxy did not resume routing after restart"

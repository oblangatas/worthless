"""WOR-777 — re-lock (rotation) actually updates the key OpenClaw runs with.

Mirrors ``test_real_skill_load_bearing``'s co-located topology (Worthless +
OpenClaw in one ``worthless-oc-test:local`` container + a mock upstream), but
proves the ROTATION guarantee end-to-end through a REAL agent chat:

1. ``lock`` K1 -> restart -> chat -> the mock upstream receives K1 (the proxy
   reconstructed it from shard-A1 ⊕ shard-B1).
2. ``lock`` K2 (a DIFFERENT key) -> restart -> chat -> the mock receives K2,
   **never K1**. The runtime now uses the rotated key. Without the WOR-777 fix
   OpenClaw's per-agent ``models.json`` cache merge-preserves K1's shard and the
   agent keeps sending K1 — this test goes red on that regression.
3. On disk: the agent ``models.json`` serves the new shard-A (Layer-2 neutralize
   removed the stale entry; OpenClaw regenerated it from the rotated config).

Marks: openclaw + docker; skipped when Docker is unavailable. Heavy (mock image
build, 2 containers, 2 real locks, 2 restarts, 3 chats). Requires the derived
image (build first, see ``test_real_skill_load_bearing``):
    uv build --wheel
    docker build -f tests/openclaw/Dockerfile.oc-worthless -t worthless-oc-test:local dist/

ponytail: the thin docker/OpenClaw helpers mirror the sibling load-bearing
tests; extract to tests/_docker_helpers if a 5th file needs them (worthless-rdp4).
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from tests._docker_helpers import docker_available
from tests.helpers import fake_key

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


def _route(c: str) -> subprocess.CompletedProcess:
    sid = f"wor777-{uuid.uuid4().hex[:6]}"
    return _oc(c, "agent", "--session-id", sid, "--message", "hi", "--json", timeout=120)


def _captured_auth(mock_port: int) -> str:
    headers = (
        httpx.get(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)
        .json()
        .get("headers", [])
    )
    return " ".join(e.get("authorization", "") for e in headers)


def _clear(mock_port: int) -> None:
    httpx.delete(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=10.0)


def _host_port(c: str, internal: int) -> int:
    out = _run(["docker", "port", c, str(internal)], check=True).stdout.strip()
    return int(out.rsplit(":", 1)[-1])


def _models_json_api_key(c: str) -> str:
    """Read providers.openai.apiKey from the agent models.json projection."""
    script = (
        'node -e \'const fs=require("fs");'
        'const p="/home/node/.openclaw/agents/main/agent/models.json";'
        'const d=JSON.parse(fs.readFileSync(p,"utf8"));'
        'process.stdout.write(((d.providers||{}).openai||{}).apiKey||"(none)")\''
    )
    return _sh(c, script).stdout.strip()


def _lock_new_key(c: str, mock_url: str, real_key: str) -> str:
    """Run a real ``worthless lock`` of ``real_key``; return the shard-A written to .env."""
    _sh(
        c,
        "mkdir -p /tmp/p && printf 'OPENAI_API_KEY=%s\\nOPENAI_BASE_URL=%s\\n' "
        f"'{real_key}' '{mock_url}' > /tmp/p/.env",
    )
    lock = _sh(c, "cd /tmp/p && worthless lock --env .env")
    assert lock.returncode == 0, f"lock failed: {lock.stdout}\n{lock.stderr}"
    shard_a = _sh(c, "grep '^OPENAI_API_KEY=' /tmp/p/.env | cut -d= -f2-").stdout.strip()
    assert shard_a and shard_a != real_key, "lock did not replace the key with shard-A"
    return shard_a


@pytest.fixture(scope="module")
def rotation_stack():
    sfx = uuid.uuid4().hex[:8]
    net = f"wor777-net-{sfx}"
    mock = f"wor777-mock-{sfx}"
    oc = f"wor777-oc-{sfx}"
    mock_img = f"wor777-mockimg-{sfx}"
    mock_url = f"http://{mock}:{_MOCK_PORT}/openai/v1"
    # Distinct high-entropy keys: fake_key is deterministic per seed, so two
    # different seeds guarantee a REAL rotation. (Same key => same alias =>
    # lock short-circuits as an idempotent re-lock and nothing rotates.)
    key1 = fake_key("sk-proj-", "wor777-rotate-k1")
    key2 = fake_key("sk-proj-", "wor777-rotate-k2")

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
            ],  # fmt: skip
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
            ],  # fmt: skip
            check=True,
        )
        _wait_oc(oc)
        mock_port = _host_port(mock, 9999)

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
        _start_daemon(oc)

        # --- Lock #1: K1 -> restart -> baseline chat must reach the mock with K1.
        shard_a1 = _lock_new_key(oc, mock_url, key1)
        _oc(oc, "config", "set", "agents.defaults.model.primary", _MODEL)
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)
        _start_daemon(oc)
        _clear(mock_port)
        base_turn = _route(oc)
        baseline_auth = _captured_auth(mock_port)

        # --- Lock #2: rotate to K2 (Layer-1 recognition lets re-lock proceed;
        #     Layer-2 neutralize drops the stale models.json entry).
        shard_a2 = _lock_new_key(oc, mock_url, key2)
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)
        _start_daemon(oc)
        # Post-rotation turn: OpenClaw regenerates models.json from the rotated
        # openclaw.json (the neutralize deleted the stale entry). This is the
        # rotation taking effect at the runtime; it must precede the on-disk
        # models.json assertion (otherwise the entry is simply absent).
        rotated_turn = _route(oc)

        yield {
            "oc": oc,
            "mock_port": mock_port,
            "key1": key1,
            "key2": key2,
            "shard_a1": shard_a1,
            "shard_a2": shard_a2,
            "baseline_rc": base_turn.returncode,
            "baseline_auth": baseline_auth,
            "rotated_rc": rotated_turn.returncode,
            "rotated_stderr": rotated_turn.stderr,
        }
    finally:
        _run(["docker", "rm", "-f", oc, mock], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)
        _run(["docker", "image", "rm", "-f", mock_img], timeout=60)


def test_relock_routes_the_new_key_through_the_proxy(rotation_stack):
    """After re-lock, a real agent chat sends the NEW key upstream — not the old
    one. This is the WOR-777 guarantee: rotation reaches the runtime."""
    oc = rotation_stack["oc"]
    mock_port = rotation_stack["mock_port"]
    key1, key2 = rotation_stack["key1"], rotation_stack["key2"]
    shard_a1, shard_a2 = rotation_stack["shard_a1"], rotation_stack["shard_a2"]

    # Sanity: the two locks produced different keys and different shards.
    assert key1 != key2 and shard_a1 != shard_a2, "test setup did not actually rotate the key"

    # Baseline (lock #1) reconstructed K1 to upstream — the rotation proof is only
    # meaningful if the agent worked before the rotation.
    assert rotation_stack["baseline_rc"] == 0, "baseline agent turn (lock #1) did not succeed"
    assert key1 in rotation_stack["baseline_auth"], (
        "baseline chat did not reach the mock with the real K1 — proxy/reconstruction broken"
    )
    assert shard_a1 not in rotation_stack["baseline_auth"], "shard-A1 leaked upstream"

    # THE PROOF: after re-lock, the chat reconstructs K2 upstream and NEVER K1.
    _clear(mock_port)
    turn = _route(oc)
    assert turn.returncode == 0, f"agent turn after re-lock failed:\n{turn.stderr[-600:]}"
    auth = _captured_auth(mock_port)
    assert key2 in auth, (
        "after re-lock the agent did NOT send the rotated key K2 upstream — rotation did not reach "
        "the runtime (WOR-777 regression: models.json merge-preserved the old shard)"
    )
    assert key1 not in auth, (
        "after re-lock the agent STILL sent the OLD key K1 upstream — the runtime kept the stale "
        "models.json projection (WOR-777 Layer-2 regression)"
    )
    assert shard_a2 not in auth, "shard-A2 leaked upstream — reconstruction is broken"


def test_relock_models_json_serves_the_new_shard(rotation_stack):
    """On disk: the agent models.json projection carries the NEW shard-A after
    rotation (Layer-2 neutralize -> OpenClaw regenerated from the rotated config)."""
    assert rotation_stack["rotated_rc"] == 0, (
        "post-rotation agent turn failed, so models.json could not regenerate:\n"
        f"{rotation_stack['rotated_stderr'][-500:]}"
    )
    served = _models_json_api_key(rotation_stack["oc"])
    assert served == rotation_stack["shard_a2"], (
        f"agent models.json serves {served[:14]}… but the rotated shard is "
        f"{rotation_stack['shard_a2'][:14]}… — stale projection not neutralized"
    )
    assert served != rotation_stack["shard_a1"], "models.json still serves the OLD shard-A1"


def test_exported_env_key_does_not_shadow_the_proxy_entry(rotation_stack):
    """Adversarial (the plan's HIGH-risk gate): after the neutralize deletes our
    entry, an EXPORTED ``OPENAI_API_KEY`` must NOT shadow the regenerated proxy
    entry — no direct-provider bypass. OpenClaw regenerates models.json from the
    rotated (proxy) config before resolving, so the exported sentinel never wins."""
    oc = rotation_stack["oc"]
    sentinel = fake_key("sk-proj-", "wor777-envshadow-sentinel")
    assert sentinel not in (rotation_stack["shard_a1"], rotation_stack["shard_a2"])

    sid = f"wor777-{uuid.uuid4().hex[:6]}"
    _exec(
        oc,
        [
            "sh",
            "-c",
            f"OPENAI_API_KEY='{sentinel}' node openclaw.mjs agent "
            f"--session-id {sid} --message hi --json",
        ],
        timeout=120,
    )
    served = _models_json_api_key(oc)
    assert served == rotation_stack["shard_a2"], (
        "an exported OPENAI_API_KEY shadowed the regenerated proxy entry — the agent could "
        "reach the provider directly, bypassing the proxy (route to WOR-654)"
    )
    assert sentinel not in served, "the exported sentinel key landed in models.json"

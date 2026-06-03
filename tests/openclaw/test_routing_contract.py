"""OpenClaw routing contract — version-drift guard (WOR-621).

This is the executable form of `engineering/research/openclaw/routing-behavior.md`.
Each parametrized case is a behavior *rule*: after `worthless lock` rewrites the
provider `baseUrl` in `openclaw.json` to the proxy, OpenClaw routes there —
regardless of a stale per-agent `models.json` baseUrl, a divergent per-model
`baseUrl`, the api type, or the config mode. The full matrix and its derivation
live in the research doc; this file pins the load-bearing subset to a specific
OpenClaw image so a release that changes routing turns CI red.

The probes that originally established these results (`tests/openclaw/probe-*.sh`)
were throwaway scaffolding; this contract replaces them.

Marks: `openclaw`, `docker`, skipped when Docker is unavailable. Heavy (spins
containers + restarts OpenClaw per case) — runs in the OpenClaw CI lane only.

Pinned image: bump `OPENCLAW_IMAGE`, re-run, and update the research doc when
OpenClaw is upgraded. A red run here on a bump is the *point* — it means routing
behavior moved and the lock design must be re-verified.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import time
import uuid

import pytest

OPENCLAW_IMAGE = "ghcr.io/openclaw/openclaw:2026.5.3-1"
MOCK_DOCKERFILE_DIR = "tests/openclaw/mock-upstream"
_MOCK_PORT = 9999


def docker_available() -> bool:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        return subprocess.run([docker_bin, "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        return False


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    # Heavy: builds an image, spins 3 containers, restarts OpenClaw per case.
    # Override the suite's short default pytest-timeout.
    pytest.mark.timeout(900),
]


# --------------------------------------------------------------------------- #
# Thin docker helpers (subprocess; no docker SDK dependency).
# --------------------------------------------------------------------------- #
def _run(
    args: list[str], *, check: bool = False, timeout: int = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _exec(container: str, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", container, *args], timeout=timeout)


def _oc(container: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(container, ["node", "openclaw.mjs", *args], timeout=timeout)


def _wait_oc(container: str, tries: int = 30) -> None:
    for _ in range(tries):
        if _oc(container, "config", "get", "gateway", timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"OpenClaw container {container} did not become ready")


def _restart(container: str) -> None:
    _run(["docker", "restart", container], check=True)
    _wait_oc(container)


def _hits(mock: str) -> int:
    """Number of requests the mock upstream has recorded."""
    code = (
        "import urllib.request,json;"
        "print(len(json.load(urllib.request.urlopen("
        f"'http://localhost:{_MOCK_PORT}/captured-headers'))['headers']))"
    )
    r = _exec(mock, ["python", "-c", code], timeout=30)
    return int(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip().isdigit() else -1


def _clear(mock: str) -> None:
    code = (
        "import urllib.request;"
        "urllib.request.urlopen(urllib.request.Request("
        f"'http://localhost:{_MOCK_PORT}/captured-headers',method='DELETE'))"
    )
    _exec(mock, ["python", "-c", code], timeout=30)


# --------------------------------------------------------------------------- #
# Stack fixture: one mock-upstream image, two mock containers (A=original,
# B=proxy), one OpenClaw container, on a private network. Module-scoped so the
# (slow) container startup happens once; each test resets config + restarts.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def stack():
    sfx = uuid.uuid4().hex[:8]
    net = f"wor-contract-net-{sfx}"
    mock_a = f"wor-contract-mockA-{sfx}"
    mock_b = f"wor-contract-mockB-{sfx}"
    oc = f"wor-contract-oc-{sfx}"
    mock_img = f"wor-contract-mock-{sfx}"
    names = [oc, mock_a, mock_b]

    try:
        _run(["docker", "build", "-t", mock_img, MOCK_DOCKERFILE_DIR], check=True, timeout=300)
        _run(["docker", "network", "create", net], check=True)
        for name in (mock_a, mock_b):
            _run(["docker", "run", "-d", "--name", name, "--network", net, mock_img], check=True)
        _run(
            [
                "docker", "run", "-d", "--name", oc, "--network", net,
                "-e", "OPENCLAW_ACCEPT_TERMS=yes", "--user", "node", OPENCLAW_IMAGE,
            ],
            check=True,
        )
        _wait_oc(oc)
        yield {
            "oc": oc,
            "mock_a": mock_a,
            "mock_b": mock_b,
            "url_a": f"http://{mock_a}:{_MOCK_PORT}",
            "url_b": f"http://{mock_b}:{_MOCK_PORT}",
        }
    finally:
        _run(["docker", "rm", "-f", *names], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)


def _high_entropy_key(prefix: str) -> str:
    """Realistic high-entropy value (clears worthless's entropy guard, unlike a
    `sk-...aaaa` placeholder — see the Probe fidelity caveat in routing-behavior.md)."""
    return f"{prefix}-{secrets.token_hex(24)}"


def _route_gateway(oc: str, model: str) -> None:
    """Drive one agent turn through the Gateway (the real incident path — not --local)."""
    sid = f"contract-{uuid.uuid4().hex[:6]}"
    _oc(oc, "agent", "--session-id", sid, "--message", "hi", "--json", timeout=120)


# --------------------------------------------------------------------------- #
# The contract: each row asserts the rewritten openclaw.json provider baseUrl (B)
# wins over whatever stale/divergent value is present, on the gateway path.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "case",
    [
        pytest.param("openai_clean", id="openai-clean-rewrite"),
        pytest.param("openai_stale_models_json", id="openai-stale-populated-models.json"),
        pytest.param("openai_per_model_baseurl", id="openai-per-model-baseurl-divergent"),
        pytest.param("openai_replace_mode", id="openai-replace-mode-stale-models.json"),
        pytest.param("anthropic_rewrite", id="anthropic-messages-rewrite"),
    ],
)
def test_openclaw_json_baseurl_is_authoritative_for_routing(stack, case):
    """Rewriting `openclaw.json` provider baseUrl -> proxy (B) routes the gateway
    request to B, even when a divergent baseUrl is preserved elsewhere."""
    oc, mock_a, mock_b = stack["oc"], stack["mock_a"], stack["mock_b"]
    url_a, url_b = stack["url_a"], stack["url_b"]

    # Full reset so a prior parametrized case (module-scoped container) can't leak in:
    # drop the per-agent models.json, the mode override, and any provider entries we
    # might re-create (a leftover entry makes `config set` refuse to clobber its apiKey).
    _exec(oc, ["sh", "-c", "rm -f /home/node/.openclaw/agents/main/agent/models.json"])
    _oc(oc, "config", "unset", "models.mode")
    _oc(oc, "config", "unset", "models.providers.openai")
    _oc(oc, "config", "unset", "models.providers.anthro")

    if case == "anthropic_rewrite":
        model = "anthro/claude-3-5-haiku"
        prov = {
            "baseUrl": url_a, "api": "anthropic-messages",
            "models": [{"id": "claude-3-5-haiku", "name": "Claude 3.5 Haiku"}],
        }
        r = _oc(oc, "config", "set", "models.providers.anthro", json.dumps(prov), "--strict-json")
        assert r.returncode == 0, f"anthro provider set failed: {r.stderr}"
        _oc(oc, "config", "set", "models.providers.anthro.apiKey", _high_entropy_key("sk-ant"))
        _oc(oc, "config", "set", "agents.defaults.model.primary", model)
        _restart(oc)
        # baseline -> A
        _clear(mock_a)
        _clear(mock_b)
        _route_gateway(oc, model)
        assert _hits(mock_a) >= 1 and _hits(mock_b) == 0, "anthropic baseline did not hit mockA"
        # rewrite -> B
        _oc(oc, "config", "set", "models.providers.anthro.baseUrl", url_b)
        _restart(oc)
    else:
        model = "openai/gpt-4o"
        prov = {"baseUrl": url_b + "/openai/v1", "api": "openai-completions", "models": []}
        if case == "openai_per_model_baseurl":
            # provider baseUrl = proxy(B); a model row pins a *divergent* per-model baseUrl=A
            prov["models"] = [{"id": "gpt-4o", "name": "gpt-4o", "baseUrl": url_a + "/openai/v1"}]
        r = _oc(oc, "config", "set", "models.providers.openai", json.dumps(prov), "--strict-json")
        assert r.returncode == 0, f"openai provider set failed: {r.stderr}"
        _oc(oc, "config", "set", "models.providers.openai.apiKey", _high_entropy_key("sk-proj"))
        _oc(oc, "config", "set", "agents.defaults.model.primary", model)
        if case == "openai_replace_mode":
            _oc(oc, "config", "set", "models.mode", "replace")
        _restart(oc)

        if case in ("openai_stale_models_json", "openai_replace_mode"):
            # Hand-write a stale POPULATED agent models.json pointing at A (the original).
            stale = {
                "providers": {
                    "openai": {
                        "baseUrl": url_a + "/openai/v1", "api": "openai-completions",
                        "apiKey": _high_entropy_key("sk-stale"),
                        "models": [{"id": "gpt-4o", "name": "gpt-4o"}],
                    }
                }
            }
            agent_dir = "/home/node/.openclaw/agents/main/agent"
            write_cmd = (
                f"mkdir -p {agent_dir} && "
                f"cat > {agent_dir}/models.json <<'JSON'\n{json.dumps(stale)}\nJSON"
            )
            _exec(oc, ["sh", "-c", write_cmd])
            _restart(oc)

    # Route on the gateway path; assert the request hit the proxy (B), not the original (A).
    _clear(mock_a)
    _clear(mock_b)
    _route_gateway(oc, model)
    a, b = _hits(mock_a), _hits(mock_b)
    assert b >= 1 and a == 0, (
        f"[{case}] routing did not follow the openclaw.json rewrite: mockA(original)={a} "
        f"mockB(proxy)={b}. OpenClaw routing behavior may have changed for {OPENCLAW_IMAGE} — "
        f"re-verify the lock design against engineering/research/openclaw/routing-behavior.md."
    )

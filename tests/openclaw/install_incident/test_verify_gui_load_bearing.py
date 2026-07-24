"""WOR-517 Tier-3 — ``worthless verify`` proven through a REAL browser + real install.

The most faithful reproduction of Ido's seat: Worthless installed the real way
(pinned ``uv`` → ``uv tool install`` the local wheel, via
``Dockerfile.oc-worthless``) and running the daemon *co-resident* with OpenClaw
in one container — a single host, exactly like a solo dev. A headless browser
drives the real OpenClaw Control-UI chat, then we ask ``worthless verify`` for
the truth.

Two independent facts, per the pre-code adversarial review (brutus):

* **(B) routing** — the browser chat produces its OWN attributable hit on the
  proxy: the mock upstream records the REAL reconstructed key (never shard-A).
  This is the assertion that actually closes WOR-514 — "OpenClaw works" and
  "verify GREEN" must not be conflatable while traffic bypasses.
* **(A) liveness** — ``worthless verify`` (co-resident with the proxy, which is
  where its loopback bind-probe can reach it) reports GREEN, earned by a fresh
  probe delta THIS call. Then kill the daemon → verify reports RED / proxy_down.
  The RED half asserts ONLY verify's verdict — a cached-token chat's outcome is
  nondeterministic and is deliberately not asserted.

Install honesty: this exercises the real ``uv`` install ENGINE against a local
wheel of THIS branch — NOT the hosted ``curl worthless.sh | sh`` (which serves
the published pin; that stays the manual release gate, and install.sh scrubs
local-index env by design so it cannot carry unreleased code).

Marks: ``openclaw``, ``docker``, ``playwright`` — opt-in local lane, not CI.
Requires the derived image built first:
    uv build --wheel
    docker build -f tests/openclaw/Dockerfile.oc-worthless -t worthless-oc-test:local dist/
"""

from __future__ import annotations

import json
import os
import re
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
_UI_PLACEHOLDER = "Message Assistant (Enter to send)"


def _image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 — package absent
        return False
    try:
        with sync_playwright() as p:
            return Path(p.chromium.executable_path).exists()
    except Exception:  # noqa: BLE001 — driver/browser not installed
        return False


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.playwright,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.skipif(
        not _image_present(OC_WORTHLESS_IMAGE),
        reason=f"{OC_WORTHLESS_IMAGE} not built (see module docstring)",
    ),
    pytest.mark.skipif(
        not _chromium_available(),
        reason="playwright + chromium not installed (run: playwright install chromium)",
    ),
    pytest.mark.timeout(900),
]


# --------------------------------------------------------------------------- #
# Thin docker / OpenClaw helpers (co-resident daemon flow mirrors
# test_real_skill_load_bearing; browser bits mirror test_control_ui_routing).
# --------------------------------------------------------------------------- #
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


def _wait_oc(c: str, tries: int = 45) -> None:
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
    _sh(
        c,
        "worthless down >/dev/null 2>&1 || true; pkill -f 'worthless up' 2>/dev/null || true; "
        "pkill -f uvicorn 2>/dev/null || true; pkill -f 'worthless.proxy' 2>/dev/null || true",
    )
    if not _wait_daemon(c, up=False):
        raise RuntimeError("worthless daemon still healthy after stop")


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


def _artifact_dir() -> Path:
    default = REPO_ROOT / "test-results" / "playwright"
    d = Path(os.environ.get("WORTHLESS_PW_ARTIFACTS", default))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _approve_device_from_page(oc: str, page) -> bool:  # noqa: ANN001 — Page is opaque here
    try:
        body = page.inner_text("body")
    except Exception:  # noqa: BLE001
        return False
    m = re.search(r"requestId[:\s]+([0-9a-fA-F][0-9a-fA-F-]{7,})", body)
    if not m:
        return False
    _oc(oc, "devices", "approve", m.group(1))
    return True


@pytest.fixture(scope="module")
def gui_worthless_stack():
    """OpenClaw + co-resident Worthless daemon (real uv-tool install) with the
    Control UI published on 18789, plus a mock upstream. ``worthless lock``
    rewrites openclaw.json to route the ``openai`` provider through the
    co-resident proxy — the real solo-dev path."""
    sfx = uuid.uuid4().hex[:8]
    net = f"wor517-net-{sfx}"
    mock = f"wor517-mock-{sfx}"
    oc = f"wor517-oc-{sfx}"
    mock_img = f"wor517-mockimg-{sfx}"
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
        # Publish 18789 exactly — the Control-UI SPA hardwires its gateway
        # websocket to it (matches test_control_ui_routing_playwright).
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "--network",
                net,
                "-p",
                "18789:18789",
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

        _start_daemon(oc)  # lock's F7 bind-probe requires a healthy proxy first

        _sh(
            oc,
            "mkdir -p /tmp/p && printf 'OPENAI_API_KEY=%s\\nOPENAI_BASE_URL=%s\\n' "
            f"'{real_key}' '{mock_url}' > /tmp/p/.env",
        )
        lock = _sh(oc, "cd /tmp/p && worthless lock --env .env")
        assert lock.returncode == 0, f"lock failed: {lock.stdout}\n{lock.stderr}"
        shard_a = _sh(oc, "grep '^OPENAI_API_KEY=' /tmp/p/.env | cut -d= -f2-").stdout.strip()
        assert shard_a and shard_a != real_key, "lock did not replace the key with shard-A"

        _oc(oc, "config", "set", "agents.defaults.model.primary", _MODEL)
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)
        _start_daemon(oc)  # restart cleared the daemon process

        cfg = _exec(oc, ["cat", "/home/node/.openclaw/openclaw.json"])
        assert cfg.returncode == 0, f"could not read openclaw.json: {cfg.stderr}"
        token = json.loads(cfg.stdout)["gateway"]["auth"]["token"]
        yield {
            "oc": oc,
            "mock_port": mock_port,
            "real_key": real_key,
            "shard_a": shard_a,
            "url": f"http://localhost:18789/#token={token}",
        }
    finally:
        _run(["docker", "rm", "-f", oc, mock], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)
        _run(["docker", "image", "rm", "-f", mock_img], timeout=60)


def _drive_ui_chat(gui_worthless_stack) -> None:
    """Open the Control UI in a headless browser, pair the device, send one chat."""
    from playwright.sync_api import sync_playwright

    oc = gui_worthless_stack["oc"]
    art = _artifact_dir()
    msg = f"verify-lane ping {uuid.uuid4().hex[:6]}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            box = None
            deadline = time.monotonic() + 180
            while box is None and time.monotonic() < deadline:
                page.goto(gui_worthless_stack["url"], timeout=45000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=10000)
                except Exception:  # noqa: BLE001 — best-effort
                    pass
                candidate = page.get_by_placeholder(_UI_PLACEHOLDER)
                try:
                    candidate.wait_for(state="visible", timeout=15000)
                    box = candidate
                except Exception:  # noqa: BLE001 — likely the device-pairing screen
                    _approve_device_from_page(oc, page)
                    page.wait_for_timeout(3000)
            if box is None:
                page.screenshot(path=str(art / "verify-lane-99-no-composer.png"), full_page=True)
                pytest.fail("Control UI chat composer never became ready within 180s")
            page.screenshot(path=str(art / "verify-lane-01-ready.png"), full_page=True)
            box.click()
            box.fill(msg)
            box.press("Enter")
            try:
                page.get_by_text(msg, exact=False).first.wait_for(timeout=15000)
            except Exception:  # noqa: BLE001 — transcript text isn't the assertion
                pass
            page.wait_for_timeout(3000)
            page.screenshot(path=str(art / "verify-lane-02-after-send.png"), full_page=True)
        finally:
            browser.close()


def test_verify_gui_load_bearing(gui_worthless_stack):
    oc = gui_worthless_stack["oc"]
    mock_port = gui_worthless_stack["mock_port"]
    real_key = gui_worthless_stack["real_key"]
    shard_a = gui_worthless_stack["shard_a"]

    # (B) ROUTING — a real browser chat produces its OWN proxy hit: the mock
    # sees the reconstructed REAL key, never shard-A. This is what closes WOR-514.
    _clear(mock_port)
    _drive_ui_chat(gui_worthless_stack)
    deadline = time.monotonic() + 45
    hits = _captured(mock_port)
    while not hits and time.monotonic() < deadline:
        time.sleep(2)
        hits = _captured(mock_port)
    assert hits, "the browser chat never reached upstream through the proxy (routing not proven)"
    auths = " ".join(h.get("authorization", "") for h in hits)
    assert real_key in auths, "proxy did not reconstruct the real key to upstream"
    assert shard_a not in auths, "shard-A leaked upstream — reconstruction is broken"

    # (A) LIVENESS — verify, co-resident with the proxy, earns GREEN from a
    # fresh probe delta this call.
    green = _exec(oc, ["worthless", "verify", "--json"], timeout=60)
    assert green.returncode == 0, f"verify was not GREEN with the daemon up:\n{green.stderr}"
    payload = json.loads(green.stdout)
    assert payload["verdict"] == "green", payload
    assert payload["aliases"] and all(a["routed"] for a in payload["aliases"]), payload

    # RED half — kill the daemon; verify (and ONLY verify) must flip to RED.
    _stop_daemon(oc)
    red = _exec(oc, ["worthless", "verify", "--json"], timeout=60)
    assert red.returncode == 73, (
        f"verify exit was {red.returncode}, expected 73 (RED):\n{red.stderr}"
    )
    down = json.loads(red.stdout)
    assert down["verdict"] == "red", down
    assert down["healthy"] is False, down
    assert down["reason"] == "proxy_down", down

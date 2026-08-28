"""LIVE (GUI): a real browser chat through the OpenClaw Control UI routes to the
provider ``baseUrl`` in ``openclaw.json`` — WOR-650 follow-up, GUI edition.

Coverage map for the WOR-650 follow-up:
  * unit         — ``test_lock_bind_confirmation.py`` (honesty + per-alias logic)
  * live CLI     — ``install_incident/test_adopt_recognition_docker.py``
                   (real ``worthless lock`` decline/adopt vs the real OpenClaw binary)
  * live routing — ``test_routing_contract.py`` (real agent turn via the gateway)
  * live GUI     — THIS FILE

This closes the last gap: a REAL USER, in a REAL BROWSER, driving OpenClaw's
Control-UI chat. Whatever ``baseUrl`` ``openclaw.json`` holds is where that chat
goes — which is exactly what a declined-vs-adopted ``worthless lock`` decides. We
point the provider at a mock upstream (standing in for the "foreign / left-in-
place" entry a declined adoption leaves), drive one chat with Playwright
(headless Chromium), and prove the agent turn reached the configured baseUrl.

Marks: ``openclaw``, ``docker``, ``playwright``. Skipped when Docker, the
``playwright`` package, or its Chromium build are unavailable — an opt-in lane,
exactly like the other heavy OpenClaw docker tests.

Pinned image: bump ``OPENCLAW_IMAGE`` in lockstep with the sibling docker tests.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

OPENCLAW_IMAGE = "ghcr.io/openclaw/openclaw:2026.5.3-1"
MOCK_DOCKERFILE_DIR = str(Path(__file__).resolve().parent / "mock-upstream")
_MOCK_PORT = 9999
_UI_PLACEHOLDER = "Message Assistant (Enter to send)"


def _artifact_dir() -> Path:
    """Durable, discoverable home for the Playwright snapshots — not the
    ephemeral pytest tmp dir. Defaults to ``<repo>/test-results/playwright``
    (gitignored); override with ``WORTHLESS_PW_ARTIFACTS``."""
    default = Path(__file__).resolve().parents[2] / "test-results" / "playwright"
    d = Path(os.environ.get("WORTHLESS_PW_ARTIFACTS", default))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _docker_available() -> bool:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        return subprocess.run([docker_bin, "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        return False


def _chromium_available() -> bool:
    """True only when both the playwright package AND its Chromium build exist."""
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
    pytest.mark.skipif(not _docker_available(), reason="Docker not available"),
    pytest.mark.skipif(
        not _chromium_available(),
        reason="playwright + chromium not installed (run: playwright install chromium)",
    ),
    # Heavy: builds an image, spins 2 containers, launches a browser.
    pytest.mark.timeout(900),
]


def _run(
    args: list[str], *, check: bool = False, timeout: int = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _exec(container: str, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", container, *args], timeout=timeout)


def _oc(container: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(container, ["node", "openclaw.mjs", *args], timeout=timeout)


def _wait_oc(container: str, tries: int = 45) -> None:
    for _ in range(tries):
        if _oc(container, "config", "get", "gateway", timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"OpenClaw container {container} did not become ready")


def _wait_http(url: str, tries: int = 30) -> None:
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — localhost test URL
                if resp.status < 500:
                    return
        except Exception:  # noqa: BLE001 — gateway still warming up
            pass
        time.sleep(2)
    raise RuntimeError(f"Control UI at {url} never answered")


def _hits(mock: str) -> int:
    """How many upstream requests the mock recorded (queried inside the container)."""
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


def _wait_for_hits(mock: str, *, deadline_s: float = 45.0) -> int:
    """Poll the mock's recorded-hit count until it reaches >=1 or the deadline.

    The upstream request is the load-bearing proof, but the agent turn's timing
    varies with host load — a single fixed window is flaky. Returns the final
    count (>=1 on success, else the last reading)."""
    end = time.monotonic() + deadline_s
    n = _hits(mock)
    while n < 1 and time.monotonic() < end:
        time.sleep(2)
        n = _hits(mock)
    return n


@pytest.fixture(scope="module")
def gui_stack():
    """OpenClaw Control UI (published on an ephemeral host port) + a mock upstream
    on a private network, provider ``openai`` -> the mock. Module-scoped: the
    slow container startup happens once."""
    sfx = uuid.uuid4().hex[:8]
    net = f"wor-gui-net-{sfx}"
    mock = f"wor-gui-mock-{sfx}"
    oc = f"wor-gui-oc-{sfx}"
    mock_img = f"wor-gui-mock-{sfx}"
    try:
        _run(["docker", "build", "-t", mock_img, MOCK_DOCKERFILE_DIR], check=True, timeout=300)
        _run(["docker", "network", "create", net], check=True)
        _run(["docker", "run", "-d", "--name", mock, "--network", net, mock_img], check=True)
        # Publish on the canonical 18789: the Control-UI SPA wires its gateway
        # websocket to that port, so a remapped host port leaves the chat UI
        # uninitialised (placeholder never appears). Matches launch_stack.sh.
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
                OPENCLAW_IMAGE,
            ],
            check=True,
        )
        _wait_oc(oc)
        # Provider -> the mock (the "foreign / left-in-place" baseUrl shape).
        prov = (
            f'{{"baseUrl":"http://{mock}:{_MOCK_PORT}/openai/v1",'
            '"api":"openai-completions","models":[{"id":"gpt-4o","name":"gpt-4o"}]}'
        )
        set_prov = _oc(oc, "config", "set", "models.providers.openai", prov, "--strict-json")
        assert set_prov.returncode == 0, set_prov.stderr
        set_key = _oc(
            oc, "config", "set", "models.providers.openai.apiKey", f"sk-proj-{uuid.uuid4().hex}"
        )
        assert set_key.returncode == 0, set_key.stderr
        set_model = _oc(oc, "config", "set", "agents.defaults.model.primary", "openai/gpt-4o")
        assert set_model.returncode == 0, set_model.stderr
        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)

        # Read the token from openclaw.json directly — ``config get`` REDACTS
        # secrets (returns "__OPENCLAW_REDACTED__"), which the Control UI rejects
        # as unauthorized. Matches launch_stack.sh / GUI_WALKTHROUGH.md.
        cfg = _exec(oc, ["cat", "/home/node/.openclaw/openclaw.json"])
        assert cfg.returncode == 0, f"could not read openclaw.json: {cfg.stderr}"
        token = json.loads(cfg.stdout)["gateway"]["auth"]["token"]
        base = "http://localhost:18789"
        _wait_http(base + "/")
        yield {"oc": oc, "mock": mock, "url": f"{base}/#token={token}"}
    finally:
        _run(["docker", "rm", "-f", oc, mock], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)
        # Remove the mock image we built — otherwise every run leaves a dangling
        # wor-gui-mock-* image behind.
        _run(["docker", "rmi", "-f", mock_img], timeout=60)


def _approve_device_from_page(oc: str, page) -> bool:  # noqa: ANN001 — Page is opaque here
    """The gateway shows a "device pairing required (requestId: X)" connect
    screen; read that id off the page and approve it in the container so the
    next connection from this browser device reaches the chat. Returns True if
    an approval was attempted."""
    try:
        body = page.inner_text("body")
    except Exception:  # noqa: BLE001
        return False
    m = re.search(r"requestId[:\s]+([0-9a-fA-F][0-9a-fA-F-]{7,})", body)
    if not m:
        return False
    _oc(oc, "devices", "approve", m.group(1))
    return True


def _dump_failure(page, console_msgs: list[str]) -> None:  # noqa: ANN001 — Page is opaque here
    """Capture what the browser actually rendered when the composer never appeared."""
    art = _artifact_dir()
    try:
        page.screenshot(path=str(art / "99-composer-not-ready.png"), full_page=True)
    except Exception as e:  # noqa: BLE001
        print("diagnostic screenshot failed:", e)
    try:
        body = page.inner_text("body")[:800].replace("\n", " | ")
    except Exception as e:  # noqa: BLE001
        body = f"(body unreadable: {e})"
    print("\n=== COMPOSER-NOT-READY DIAGNOSTICS ===")
    print("URL:", page.url)
    print("BODY[:800]:", body)
    print("CONSOLE[-25:]:", " || ".join(console_msgs[-25:]) or "(none)")


def test_control_ui_chat_routes_to_configured_baseurl(gui_stack) -> None:
    """Drive the real Control-UI chat with a headless browser; assert the agent
    turn reached the configured provider baseUrl (the mock). This is the GUI
    user's view of the same routing a declined-vs-adopted ``worthless lock``
    decides: the chat goes wherever ``openclaw.json`` points."""
    from playwright.sync_api import sync_playwright

    mock = gui_stack["mock"]
    _clear(mock)
    assert _hits(mock) == 0, "mock should start clean"

    msg = f"ping via Control UI + Playwright {uuid.uuid4().hex[:6]}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            console_msgs: list[str] = []
            page.on("console", lambda m: console_msgs.append(f"{m.type}: {m.text}"[:200]))
            page.on("pageerror", lambda e: console_msgs.append(f"pageerror: {e}"[:200]))
            # Cold-start resilience: a freshly-booted gateway serves the SPA
            # shell before the chat runtime is ready, so the composer can be
            # absent on the first paint. Reload until it appears (bounded) —
            # robust on the first attempt, no reliance on pytest reruns.
            box = None
            oc = gui_stack["oc"]
            # The gateway requires per-device PAIRING: the token reaches only the
            # "device pairing required (requestId: …)" connect screen. Each reload,
            # if the chat composer isn't up, read the requestId off that screen and
            # approve it in the container; once the device is paired the SPA
            # connects and the composer appears. (`networkidle` never settles —
            # the SPA holds a websocket open — so use `domcontentloaded`.)
            composer_deadline = time.monotonic() + 180
            while box is None and time.monotonic() < composer_deadline:
                page.goto(gui_stack["url"], timeout=45000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=10000)
                except Exception:  # noqa: BLE001 — best-effort
                    pass
                candidate = page.get_by_placeholder(_UI_PLACEHOLDER)
                try:
                    candidate.wait_for(state="visible", timeout=15000)
                    box = candidate
                except Exception:  # noqa: BLE001 — likely the pairing screen
                    _approve_device_from_page(oc, page)
                    page.wait_for_timeout(3000)
            if box is None:
                _dump_failure(page, console_msgs)
                pytest.fail(
                    "Control UI chat composer never became ready within 180s "
                    "(see 99-composer-not-ready.png + diagnostics above)"
                )
            artifacts = _artifact_dir()
            page.screenshot(path=str(artifacts / "01-chat-ready.png"), full_page=True)
            box.click()
            box.fill(msg)
            page.screenshot(path=str(artifacts / "02-message-typed.png"), full_page=True)
            box.press("Enter")
            # The message lands in the transcript, then the agent turn fires the
            # upstream call. Poll the mock hit (the load-bearing proof) on a
            # bounded deadline instead of one fixed window — slow hosts need more.
            try:
                page.get_by_text(msg, exact=False).first.wait_for(timeout=15000)
            except Exception:  # noqa: BLE001 — transcript rendering is not the assertion
                pass
            hits = _wait_for_hits(mock, deadline_s=45)
            page.screenshot(path=str(artifacts / "03-after-send.png"), full_page=True)
            print(f"\nPLAYWRIGHT SNAPSHOTS → {artifacts}")
            for name in ("01-chat-ready.png", "02-message-typed.png", "03-after-send.png"):
                print(f"  - {artifacts / name}")
        finally:
            browser.close()

    # Robust signal: the GUI chat's agent turn reached the configured baseUrl.
    # (We assert on the upstream hit, never on flaky SPA transcript text.)
    assert hits >= 1, (
        f"a real Control-UI chat must route to the configured provider baseUrl; "
        f"mock recorded {hits} upstream requests. If OpenClaw {OPENCLAW_IMAGE} "
        f"changed its GUI->gateway->provider path, re-verify the lock design."
    )

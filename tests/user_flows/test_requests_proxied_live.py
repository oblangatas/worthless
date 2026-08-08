"""``requests_proxied`` counts a provider-rejected request (worthless-ax9d).

A unit test CANNOT prove this fix, and that is the whole story of this bug. In
``tests/test_proxy.py`` the fixture builds its own ``RulesEngine`` and
``ASGITransport`` skips the lifespan; there, a rejected request DOES write a
``spend_log`` row, so the old billing-derived counter incremented too and a unit
test passes identically against broken and fixed code. Measured 2026-07-27.

The real daemon behaves differently: it writes no ``spend_log`` row for a request
the provider rejected (correctly — the user must not pay for it), so the old
counter sat at 0 while requests were being proxied fine.

So this test runs the real thing: the real ``worthless`` console script as its own
process, its real lifespan and rules engine, a real ``lock``, and a real HTTP
round-trip. The only stand-in is the upstream provider, which is a local server
that answers 401 — that keeps the test hermetic (no network, no API key) while
leaving every part of Worthless genuinely exercised.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.user_flow

_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _RejectingHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for the provider: answers every call 401, like a bad key would."""

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        payload = json.dumps({"error": {"message": "invalid key"}}).encode()
        self.send_response(401)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # noqa: A003 — silence the test log
        return


def _worthless_bin() -> Path:
    return Path(sys.executable).parent / "worthless"


def _wait_healthy(port: int, deadline: float) -> dict | None:
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(  # noqa: S310 — fixed loopback URL
                f"http://127.0.0.1:{port}/healthz", timeout=1
            ) as resp:
                return json.loads(resp.read())
        except Exception:  # noqa: BLE001 — not up yet
            time.sleep(0.25)
    return None


def test_a_provider_rejected_request_still_counts_as_proxied(tmp_path: Path) -> None:
    """Real daemon: one forwarded request the provider 401s must move the counter.

    Against the pre-fix code this fails with ``requests_proxied`` stuck at 0 —
    the operator-observed symptom, reproduced without a real provider key.
    """
    binary = _worthless_bin()
    if not binary.exists():  # pragma: no cover — depends on how the venv was built
        pytest.skip(f"no worthless console script at {binary}")

    upstream_port = _free_port()
    proxy_port = _free_port()

    upstream = http.server.HTTPServer(("127.0.0.1", upstream_port), _RejectingHandler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    home = tmp_path / "home"
    (home / ".worthless").mkdir(parents=True)
    # A user provider registry entry — the documented extension point. Without it
    # lock refuses an unregistered upstream URL.
    (home / ".worthless" / "providers.toml").write_text(
        f'[provider.localmock]\nurl = "http://127.0.0.1:{upstream_port}/v1"\nprotocol = "openai"\n',
        encoding="utf-8",
    )
    proj = home / "proj"
    proj.mkdir()
    env_file = proj / ".env"
    env_file.write_text(
        "LOCALMOCK_API_KEY=sk-live-ax9d-not-a-real-key-000111222333\n"
        f"LOCALMOCK_BASE_URL=http://127.0.0.1:{upstream_port}/v1\n",
        encoding="utf-8",
    )

    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    env.update(
        {
            "HOME": str(home),
            "WORTHLESS_HOME": str(home / ".worthless"),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": str(proxy_port),
            "NO_COLOR": "1",
        }
    )

    proxy = subprocess.Popen(  # noqa: S603
        [str(binary), "up", "--port", str(proxy_port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert _wait_healthy(proxy_port, time.monotonic() + _TIMEOUT_S), "proxy never came up"

        locked = subprocess.run(  # noqa: S603
            [str(binary), "lock", "--env", str(env_file), "--adopt"],
            env=env,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
            check=False,
        )
        body = env_file.read_text(encoding="utf-8")
        base_url = next(
            (
                ln.split("=", 1)[1].strip()
                for ln in body.splitlines()
                if ln.startswith("LOCALMOCK_BASE_URL=")
            ),
            "",
        )
        shard_a = next(
            (
                ln.split("=", 1)[1].strip()
                for ln in body.splitlines()
                if ln.startswith("LOCALMOCK_API_KEY=")
            ),
            "",
        )
        assert f"127.0.0.1:{proxy_port}" in base_url, (
            f"lock did not point the .env at the proxy.\nstdout: {locked.stdout}\n"
            f"stderr: {locked.stderr}\n.env now:\n{body}"
        )

        before = _wait_healthy(proxy_port, time.monotonic() + 5) or {}
        assert before.get("requests_proxied") == 0, "counter should start at zero"

        req = urllib.request.Request(  # noqa: S310 — fixed loopback URL
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(
                {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
            ).encode(),
            headers={"Authorization": f"Bearer {shard_a}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 401, f"expected the upstream's rejection to reach us, got {status}"

        # The counter moves in the request path, but give any background work a
        # moment before reading — a flaky read here would teach the wrong lesson.
        deadline = time.monotonic() + 10
        after = 0
        while time.monotonic() < deadline:
            after = (_wait_healthy(proxy_port, time.monotonic() + 2) or {}).get(
                "requests_proxied", 0
            )
            if after:
                break
            time.sleep(0.5)
    finally:
        upstream.shutdown()
        proxy.terminate()
        try:
            proxy.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proxy.kill()

    assert after == 1, (
        "a request the provider rejected was gated, reconstructed and forwarded — "
        f"it must count as proxied, but requests_proxied is {after}. This is the "
        "operator-observed symptom: status reports 0 while Worthless is working."
    )

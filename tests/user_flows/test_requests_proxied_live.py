"""``requests_proxied`` counts traffic; ``requests_billed`` counts spend (worthless-ax9d).

A unit test cannot prove this fix, and that is the whole story of the bug. In
``tests/test_proxy.py`` the fixture builds its own ``RulesEngine`` and
``ASGITransport`` skips the lifespan; there, a rejected request DOES write a
``spend_log`` row, so the OLD billing-derived counter incremented too and a unit test
passes identically against broken and fixed code. (A unit test that did exactly that
was written, watched pass against the reverted fix, and deleted.)

The real daemon behaves differently: it writes no ``spend_log`` row for a request the
provider rejected — correctly, the user must not pay for it — so the old counter sat
at 0 while requests were being proxied fine.

Proving the two numbers are genuinely different needs **two** requests against one
daemon: one the provider rejects, one it accepts. One request can only show a counter
moving; it cannot show the counters diverging.

Everything here is real except the provider: the real ``worthless`` console script as
its own process, its real lifespan and rules engine, a real ``lock``, real HTTP. The
upstream is a local server so the test stays hermetic — no network, no API key.
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

# The global default is 30s (pyproject) and the branch build keeps it. Only the
# installed-wheel run needs more: uv warms its tool env on the first call to a
# freshly installed binary (measured 5.3s cold vs 0.5s warm), and this test
# spawns the binary several times. Raising it unconditionally would drop the
# 30s guard on the branch run too, where a hang is a real signal.
_TIMEOUT_BUDGET = 60 if os.environ.get("WORTHLESS_TEST_BIN") else 30
pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.wheel_artifact,
    pytest.mark.timeout(_TIMEOUT_BUDGET),
]

_TIMEOUT_S = 60.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ScriptedProvider(http.server.BaseHTTPRequestHandler):
    """Provider stand-in. ``reject`` flips between a 401 and a 200-with-usage."""

    reject = True

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        if type(self).reject:
            status = 401
            payload = json.dumps({"error": {"message": "invalid key"}}).encode()
        else:
            status = 200
            # `usage` is what makes this billable — without it the proxy has
            # nothing to meter and the billing path is a no-op.
            payload = json.dumps(
                {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": "gpt-4o-mini",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
                }
            ).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # noqa: A003 — silence the test log
        return


def _worthless_bin() -> Path:
    """The console script under test.

    Defaults to the one beside the interpreter running the tests — the branch
    build. ``WORTHLESS_TEST_BIN`` aims this at a different binary, so CI can run
    the same test against an installed wheel: the artifact a user actually gets
    (worthless-d4h2). Without that, a packaging-only defect passes every test.
    """
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"


def _health(port: int, deadline: float) -> dict | None:
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(  # noqa: S310 — fixed loopback URL
                f"http://127.0.0.1:{port}/healthz", timeout=1
            ) as resp:
                return json.loads(resp.read())
        except Exception:  # noqa: BLE001 — not up yet
            time.sleep(0.25)
    return None


def _counters(port: int) -> tuple[int, int]:
    """(requests_proxied, requests_billed) straight from /healthz."""
    data = _health(port, time.monotonic() + 5) or {}
    return int(data.get("requests_proxied", 0)), int(data.get("requests_billed", 0))


def _await_proxied(port: int, expected: int) -> tuple[int, int]:
    """Poll until requests_proxied reaches *expected*, or give up after 10s.

    Billing is settled in a background task, so read it only after the traffic
    counter has landed — a bare sleep would be flaky and teach the wrong lesson.
    """
    deadline = time.monotonic() + 10
    proxied, billed = _counters(port)
    while proxied < expected and time.monotonic() < deadline:
        time.sleep(0.5)
        proxied, billed = _counters(port)
    time.sleep(1.0)  # let any settle/refund background task finish
    return _counters(port)


def _chat(base_url: str, shard_a: str) -> int:
    req = urllib.request.Request(  # noqa: S310 — fixed loopback URL
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(
            {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
        ).encode(),
        headers={"Authorization": f"Bearer {shard_a}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_proxied_counts_traffic_while_billed_counts_only_what_was_charged(
    tmp_path: Path,
) -> None:
    """Two requests, one daemon: the counters must diverge.

    * A request the provider **rejects** is proxied but not billed.
    * A request the provider **accepts** is both.

    Against the pre-fix code the first assertion fails with ``requests_proxied``
    stuck at 0 — the operator-observed symptom, reproduced without a real key.
    """
    binary = _worthless_bin()
    if not binary.exists():  # pragma: no cover — depends on how the venv was built
        pytest.skip(f"no worthless console script at {binary}")

    _ScriptedProvider.reject = True
    upstream_port = _free_port()
    proxy_port = _free_port()

    upstream = http.server.HTTPServer(("127.0.0.1", upstream_port), _ScriptedProvider)
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
        assert _health(proxy_port, time.monotonic() + _TIMEOUT_S), "proxy never came up"

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

        assert _counters(proxy_port) == (0, 0), "counters should start at zero"

        # --- 1. the provider rejects it -------------------------------------
        assert _chat(base_url, shard_a) == 401, "the provider's rejection should reach us"
        proxied, billed = _await_proxied(proxy_port, 1)
        assert proxied == 1, (
            "a request that was gated, reconstructed and forwarded must count as "
            f"proxied even when the provider rejects it — got {proxied}. This is the "
            "operator-observed symptom: status reads 0 while Worthless is working."
        )
        assert billed == 0, (
            f"a rejected request must NOT be billed — the user does not pay for it (got {billed})"
        )

        # --- 2. the provider accepts it -------------------------------------
        _ScriptedProvider.reject = False
        assert _chat(base_url, shard_a) == 200, "the accepted call should come back 200"
        proxied, billed = _await_proxied(proxy_port, 2)
    finally:
        _ScriptedProvider.reject = True
        upstream.shutdown()
        proxy.terminate()
        try:
            proxy.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proxy.kill()

    assert proxied == 2, (
        f"both requests were proxied, so the traffic meter must read 2, got {proxied}"
    )
    assert billed == 1, (
        f"only the accepted request is billable, so the spend meter must read 1, got {billed}. "
        "If this equals requests_proxied the two numbers have been conflated again — "
        "which is the bug."
    )

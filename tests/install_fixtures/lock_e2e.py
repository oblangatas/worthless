"""Post-install lock-lifecycle orchestration (runs INSIDE the container).

Proves the WOR-235 AC gap that `worthless --version` alone can't cover: a
fresh install can actually protect a real API key end-to-end. Chains
``worthless lock`` + ``worthless up`` + a proxied request through the
container-local proxy, then asserts the real key arrived at mock-upstream
(meaning shard-A in .env was reconstructed with shard-B from the DB).

Runs in the worthless-installed container; talks to mock-upstream on the
same Docker network. Stdlib-only so we never need pip inside the image.
Exits non-zero on any failure; the outer pytest test surfaces the logs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROXY_PORT = 8787
MOCK_URL = "http://mock-upstream:9999"
# OpenAI base URL on the mock — the proxy appends /chat/completions when
# forwarding requests under the alias.  Must match the path served by
# tests/openclaw/mock-upstream/app.py::chat_completions.
MOCK_OPENAI_BASE_URL = f"{MOCK_URL}/v1"
PROXY_HEALTH_URL = f"http://127.0.0.1:{PROXY_PORT}/healthz"


def fail(msg: str) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1


def fake_openai_key() -> str:
    """Mirror tests/helpers.py::fake_openai_key (stdlib-only)."""
    raw = hashlib.sha256(b"test-fixture-seed").digest()
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")[:48]
    # Split literal so secret scanners don't trip on this source.
    return "sk-" + "proj-" + body


def compute_alias(key: str) -> str:
    return "openai-" + hashlib.sha256(key.encode()).hexdigest()[:8]


def wait_until_healthy(url: str, deadline_s: float = 30.0) -> bool:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:  # noqa: S310
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def read_env_value(path: Path, var: str) -> str | None:
    with path.open() as f:
        for line in f:
            if line.startswith(f"{var}="):
                return line.rstrip("\n").split("=", 1)[1]
    return None


def main() -> int:
    env_dir = Path("/tmp/lock-e2e")  # noqa: S108 — ephemeral container, no symlink race
    env_dir.mkdir(parents=True, exist_ok=True)
    env_path = env_dir / ".env"

    real_key = fake_openai_key()
    # Write OPENAI_BASE_URL alongside OPENAI_API_KEY BEFORE locking so
    # ``worthless lock`` stores the mock URL on the per-enrollment row
    # (8rqs Phase 5+6 ripped the global WORTHLESS_UPSTREAM_OPENAI_URL
    # override).  Same pattern as tests/test_openclaw_e2e.py::openclaw_stack.
    with env_path.open("w") as f:
        f.write(f"OPENAI_API_KEY={real_key}\n")
        f.write(f"OPENAI_BASE_URL={MOCK_OPENAI_BASE_URL}\n")
    print(f"[1] wrote real key + base URL to {env_path} ({real_key[:10]}...)")

    # Register the mock URL in the user provider registry.  Lock refuses
    # an unregistered ``OPENAI_BASE_URL`` (M3 / Blocker #1: an attacker
    # who can write .env should not redirect the proxy at an arbitrary
    # upstream), so the URL must be in ~/.worthless/providers.toml
    # before lock runs.
    register = subprocess.run(  # noqa: S603, S607
        [  # noqa: S607
            "worthless",
            "providers",
            "register",
            "--name",
            "openai-mock",
            "--url",
            MOCK_OPENAI_BASE_URL,
            "--protocol",
            "openai",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if register.returncode != 0:
        sys.stdout.write(register.stdout)
        sys.stderr.write(register.stderr)
        return fail(f"`worthless providers register` exited {register.returncode}")
    print("[1.5] registered openai-mock provider")

    lock = subprocess.run(  # noqa: S603, S607
        ["worthless", "lock", "--env", str(env_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if lock.returncode != 0:
        sys.stdout.write(lock.stdout)
        sys.stderr.write(lock.stderr)
        return fail(f"`worthless lock` exited {lock.returncode}")
    print("[2] `worthless lock` succeeded")

    shard_a = read_env_value(env_path, "OPENAI_API_KEY")
    if not shard_a:
        return fail("OPENAI_API_KEY missing from .env after lock")
    if shard_a == real_key:
        return fail(".env still holds the real key — lock did not split")
    print(f"    shard-A rewritten ({shard_a[:10]}...)")

    alias = compute_alias(real_key)
    print(f"    alias: {alias}")

    # Capture proxy logs: on failure the outer pytest otherwise sees only
    # "exit code 1" with no clue why `worthless up` died inside the container.
    proxy_log = Path("/tmp/worthless-up.log")  # noqa: S108 — ephemeral container
    proxy_log_fh = proxy_log.open("w")
    proxy = subprocess.Popen(  # noqa: S603, S607
        ["worthless", "up"],  # noqa: S607
        stdout=proxy_log_fh,
        stderr=subprocess.STDOUT,
    )
    try:
        if not wait_until_healthy(PROXY_HEALTH_URL):
            proxy_log_fh.flush()
            sys.stderr.write(f"--- worthless up logs ---\n{proxy_log.read_text()}\n")
            return fail("proxy did not become healthy within 30s")
        print("[3] proxy healthy on :8787")

        clear_req = urllib.request.Request(  # noqa: S310
            f"{MOCK_URL}/captured-headers",
            method="DELETE",
        )
        urllib.request.urlopen(clear_req, timeout=5).read()  # noqa: S310

        post = urllib.request.Request(  # noqa: S310
            f"http://127.0.0.1:{PROXY_PORT}/{alias}/v1/chat/completions",
            data=json.dumps(
                {
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "hello"}],
                }
            ).encode(),
            headers={
                "Authorization": f"Bearer {shard_a}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(post, timeout=30) as r:  # noqa: S310
                body = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace")
            return fail(f"proxy returned HTTP {e.code}: {detail!r}")
        except urllib.error.URLError as e:
            return fail(f"proxy request errored: {e}")
        print(f"[4] proxy returned {status}, {len(body)} bytes")

        captured = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"{MOCK_URL}/captured-headers", timeout=5
            ).read()
        )
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
        proxy_log_fh.close()

    headers = captured.get("headers") or []
    if not headers:
        return fail("mock-upstream never saw a request — proxy did not forward")
    received = headers[-1].get("authorization", "").replace("Bearer ", "")
    if received != real_key:
        return fail(
            f"upstream received wrong key (expected {real_key[:10]}..., got {received[:10]}...)"
        )
    print("[5] upstream received real key — lock lifecycle PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

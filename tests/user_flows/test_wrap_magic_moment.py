"""v0.3.4 magic-moment integration test: real ``worthless wrap`` reaches the
proxy via .env without a daemon.

Closes the gap surfaced during HF10 (worthless-ahib) where the apparent
"wrap works end-to-end" verdict was contaminated by a stale ``worthless
up`` daemon hogging port 8787 across sessions. With the daemon killed,
fresh ``wrap`` calls used ``port=0`` (OS-random) and the child's .env URL
pointed at 8787 — the two never aligned, so the child got connection-
refused. v0.3.4 binds wrap to the same port lock wrote.

This test runs the real CLI in a subprocess (CliRunner can't supervise a
real wrap → subprocess.Popen child chain). Marked ``user_flow`` so the
default test sweep skips it; opt in with ``pytest -m user_flow``.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess  # nosec B404 — required for real CLI integration test
import sys
from pathlib import Path

import pytest

from tests.helpers import fake_openai_key
from tests.user_flows.helpers import scrubbed_cli_env


def _free_port() -> int:
    """Reserve a free TCP port on 127.0.0.1 and return it.

    The kernel won't reassign for a brief window after we close — good
    enough for the test, since wrap binds milliseconds after.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.user_flow
def test_wrap_child_reaches_proxy_via_env_url(tmp_path: Path) -> None:
    """The headline v0.3.4 contract: a child run under ``worthless wrap``
    that loads .env can reach ``/healthz`` on the proxy.

    Pre-fix: wrap bound port=0 (random), .env held 8787, child got
    connection-refused. Post-fix: wrap binds the port lock wrote.

    Uses ``WORTHLESS_PORT`` to avoid colliding with any real daemon on
    8787 on the dev machine.
    """
    worthless_bin = shutil.which("worthless")
    if worthless_bin is None:
        pytest.skip("worthless CLI not on PATH (install with `uv sync` first)")

    port = _free_port()

    home = tmp_path / ".worthless"
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

    # Inherit parent env so subprocesses can find Python/tooling, then overlay
    # the user-flow isolation contract so host-level integrations do not see
    # the developer machine's real home.
    cli_env = dict(os.environ)
    cli_env.update({k: v for k, v in scrubbed_cli_env(home).items() if v is not None})
    cli_env["WORTHLESS_PORT"] = str(port)
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        cli_env.pop(k, None)

    # Step 1: lock. Writes BASE_URL with our test port into .env.
    lock_proc = subprocess.run(  # nosec B603
        [worthless_bin, "lock", "--env", str(env_file)],
        env=cli_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert lock_proc.returncode == 0, (
        f"lock failed (returncode={lock_proc.returncode}):\n"
        f"STDOUT:\n{lock_proc.stdout}\nSTDERR:\n{lock_proc.stderr}"
    )

    env_after = env_file.read_text()
    assert f":{port}/" in env_after, (
        f"lock should have written port {port} into .env BASE_URL; got:\n{env_after}\n"
        f"lock STDOUT:\n{lock_proc.stdout}\nlock STDERR:\n{lock_proc.stderr}"
    )

    # Step 2: wrap with a python child that loads .env via dotenv, extracts
    # the BASE_URL port, and hits /healthz. Pure-python — no curl dependency.
    child_script = (
        "import re, sys, urllib.request;"
        "from dotenv import dotenv_values;"
        f"vals = dotenv_values({str(env_file)!r});"
        "url = vals.get('OPENAI_BASE_URL') or '';"
        "m = re.match(r'http://([^:/]+):(\\d+)/', url);"
        "assert m, f'no parseable BASE_URL: {url!r}';"
        "host, p = m.group(1), m.group(2);"
        "healthz = f'http://{host}:{p}/healthz';"
        "r = urllib.request.urlopen(healthz, timeout=5);"
        "body = r.read().decode();"
        "print('STATUS:' + str(r.status));"
        "print('BODY:' + body);"
    )
    wrap_proc = subprocess.run(  # nosec B603
        [
            worthless_bin,
            "wrap",
            "--",
            sys.executable,
            "-c",
            child_script,
        ],
        env=cli_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    combined = f"--- wrap STDOUT ---\n{wrap_proc.stdout}\n--- wrap STDERR ---\n{wrap_proc.stderr}"
    assert wrap_proc.returncode == 0, f"wrap exit {wrap_proc.returncode} (expected 0):\n{combined}"

    # The child printed STATUS: and BODY: lines; both should land in
    # wrap's stdout. STATUS:200 = the child reached wrap's proxy /healthz.
    assert "STATUS:200" in wrap_proc.stdout, (
        f"v0.3.4 magic-moment contract broken: child did not reach proxy "
        f"/healthz on the .env URL. Full output:\n{combined}"
    )
    assert '"status":"ok"' in wrap_proc.stdout, f"healthz response missing 'ok' status:\n{combined}"
    assert '"requests_proxied"' in wrap_proc.stdout, (
        f"healthz response missing 'requests_proxied' field:\n{combined}"
    )

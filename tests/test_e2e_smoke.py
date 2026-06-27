"""End-to-end smoke test — proves the core product promise.

Lifecycle: bootstrap home → lock a key → start proxy → /healthz → stop.

This test runs with a real (temp) home directory, real SQLite DB,
real Fernet encryption, and a real proxy process.  The only thing
mocked is the upstream LLM provider (we don't make real API calls).

Marked ``@pytest.mark.e2e`` so it can be selected or skipped in CI.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.lock import _lock_keys
from worthless.cli.commands.up import start_daemon
from worthless.cli.console import WorthlessConsole, set_console
from worthless.cli.process import (
    build_proxy_env,
    check_pid,
    disable_core_dumps,
    pid_path,
    poll_health,
    read_pid,
)

from tests._fakes import WOR309_SUBPROCESS_FOLLOWUP
from tests.helpers import fake_openai_key


@pytest.mark.e2e
@pytest.mark.real_ipc
@pytest.mark.skip(reason=WOR309_SUBPROCESS_FOLLOWUP)
class TestEndToEndSmoke:
    """Full lifecycle: bootstrap → lock → proxy → healthz → stop."""

    def test_lock_start_health_stop(self, tmp_path: Path) -> None:
        """The product promise: lock a key, start the proxy, it's healthy.

        Steps:
        1. Bootstrap a fresh home in tmp_path
        2. Create .env with a fake OpenAI key
        3. Lock the key (split + store + rewrite .env with decoy)
        4. Start proxy daemon on a random-ish port
        5. Verify /healthz returns 200
        6. Stop the proxy
        7. Verify PID file cleaned up
        """
        # 1. Bootstrap
        home = ensure_home(tmp_path / ".worthless")
        set_console(WorthlessConsole(quiet=True, json_mode=False))

        # 2. Create .env
        env_path = tmp_path / ".env"
        original_key = fake_openai_key()
        env_path.write_text(f"OPENAI_API_KEY={original_key}\n")

        # 3. Lock — key gets split, .env rewritten with decoy
        os.chdir(tmp_path)
        count = _lock_keys(env_path, home, quiet=True)
        assert count == 1, f"Expected 1 key locked, got {count}"

        # Verify .env was rewritten (original key no longer present)
        rewritten = env_path.read_text()
        assert original_key not in rewritten, "Original key should be replaced with decoy"
        assert "OPENAI_API_KEY=" in rewritten, "Var name should still be in .env"

        # 4. Start proxy daemon
        disable_core_dumps()
        proxy_env = build_proxy_env(home)
        port = 18787  # high port to avoid conflicts
        pf = pid_path(home)
        log_file = home.base_dir / "proxy.log"

        pid = start_daemon(proxy_env, port, pf, log_file, WorthlessConsole(quiet=True))

        try:
            # 5. Verify /healthz
            healthy = poll_health(port, timeout=10.0)
            assert healthy, "Proxy should be healthy after start"

            # Double-check with a direct HTTP call
            resp = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5.0)
            assert resp.status_code == 200

            # Verify PID file exists and contains correct PID
            info = read_pid(pf)
            assert info is not None
            recorded_pid, recorded_port = info
            assert recorded_pid == pid
            assert recorded_port == port

        finally:
            # 6. Stop the proxy
            if check_pid(pid):
                import signal

                os.kill(pid, signal.SIGTERM)
                # Wait for graceful shutdown
                for _ in range(20):
                    if not check_pid(pid):
                        break
                    time.sleep(0.25)
                else:
                    # Force kill if SIGTERM didn't work
                    os.kill(pid, signal.SIGKILL)

            # 7. Clean up PID file
            pf.unlink(missing_ok=True)

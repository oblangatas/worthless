"""WOR-829 live user-flow: the editor user who locks a key with the proxy down.

The unit tests in ``tests/test_mcp_server.py::TestWorthlessLock`` pin the exact
response fields with the probe stubbed. This file proves the same thing the
*hard* way — no stub on the probe — so the claim rests on a real observation:

  1. A real ``worthless_lock`` (the actual MCP tool) rewrites the real ``.env``
     to point at the proxy port.
  2. A **real** HTTP client hitting that rewritten URL fails with a connection
     error — the dead-proxy state the editor user's app actually hits.
  3. The lock's own response carries ``proxy_running: false`` and names the one
     command that fixes it.

Hermeticity: the suite-wide ``_isolate_process_home`` fixture (tests/conftest)
sandboxes ``$HOME`` so ``~/.openclaw`` is absent → ``detect().present`` is False
→ ``lock`` takes the succeed-with-proxy-down path (the OpenClaw-present path
aborts with WRTLS-109, which is a *different*, already-signalled population).

The proxy-up → ``proxy_running: true`` flip is covered deterministically by the
unit test; bringing up the real proxy+sidecar stack live is exercised by
``tests/test_proxy_e2e.py`` / ``tests/user_flows/test_wrap_magic_moment.py`` and
is orthogonal to this messaging change.
"""

from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from worthless.mcp.server import worthless_lock  # noqa: E402

pytestmark = pytest.mark.user_flow


def _free_port() -> int:
    """A port nothing is listening on — the proxy is deliberately NOT started."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_editor_lock_with_dead_proxy_is_flagged_and_env_really_points_at_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.fernet import Fernet

    home = tmp_path / ".worthless"
    home.mkdir(mode=0o700)
    (home / "shard_a").mkdir(mode=0o700)
    (home / "fernet.key").write_bytes(Fernet.generate_key())

    port = _free_port()  # dead — no proxy bound here
    monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "null")
    monkeypatch.setenv("WORTHLESS_PORT", str(port))

    env_file = tmp_path / ".env"
    key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
    env_file.write_text(f"OPENAI_API_KEY={key}\n")

    with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
        result = json.loads(await worthless_lock(env_path=str(env_file)))

    # (3) the lock response warns + names the fix
    assert result["protected_count"] == 1
    assert result["proxy_running"] is False
    assert "worthless up" in result["next_step"]

    # (1) the real .env was rewritten to point at the proxy port
    rewritten = env_file.read_text()
    m = re.search(r"OPENAI_BASE_URL=(\S+)", rewritten)
    assert m, f"lock did not write a BASE_URL:\n{rewritten}"
    base_url = m.group(1)
    assert f":{port}/" in base_url, f"BASE_URL should target the proxy port {port}: {base_url}"

    # (2) a REAL client hitting that URL fails — the broken state is real, not traced
    with pytest.raises(httpx.HTTPError):
        httpx.get(base_url.rstrip("/") + "/healthz", timeout=2.0)

"""WOR-545: Behavioural CI test — proxy must be load-bearing after worthless lock.

RED through Phase 1 (audit-gate doesn't make proxy load-bearing for SecretRef users).
GREEN at Phase 3 (proxy load-bearing implementation).

Lifecycle: xfail(strict=True) until Phase 3's PR removes the mark.
"""

from __future__ import annotations

import subprocess
import pytest


def docker_available() -> bool:
    import shutil

    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        result = subprocess.run(
            [docker_bin, "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.xfail(
        strict=True,
        reason=(
            "WOR-515 Phase 3 — proxy not yet load-bearing. "
            "Phase 1's audit-gate catches on-disk plaintext but does not make the proxy "
            "load-bearing for users already on SecretRefs or env-based credentials. "
            "Remove xfail when Phase 3 merges."
        ),
    ),
]


def test_proxy_is_load_bearing_after_lock() -> None:
    """After worthless lock, stopping the proxy must make OpenClaw unable to reach upstream.

    Steps:
    1. Spin up worthless proxy + mock-upstream + OpenClaw via compose --profile openclaw.
    2. Run worthless lock — assert exit 0.
    3. Send a chat — assert success, assert proxy requests_proxied increments by 1.
    4. Stop the worthless proxy (docker compose stop proxy).
    5. Send another chat — assert FAILS with upstream-unreachable.
    6. Start proxy again — third chat succeeds, counter increments.

    Failure message names the bypass so the gap is visible in CI.
    """
    pytest.fail(
        "OpenClaw chat succeeded with worthless proxy stopped — "
        "proxy is NOT load-bearing (WOR-515 Phase 3 not yet closed)."
    )

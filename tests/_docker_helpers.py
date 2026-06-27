"""Shared Docker helpers for integration tests.

Leading underscore so pytest doesn't collect this as a test module.
Consumers: tests/test_docker_e2e.py, tests/test_install_docker.py.

Imports that actually shell out (subprocess) live inside functions, so
importing this module at collection time does not probe the Docker daemon.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
import time


@functools.cache
def docker_available() -> bool:
    """True iff `docker` is on PATH AND the daemon responds to `docker info`.

    Pure predicate — never raises, never calls pytest.skip. Callers wrap
    the result in whatever skip/fail policy fits the test.
    """
    if shutil.which("docker") is None:
        return False
    try:
        probe = subprocess.run(  # noqa: S603
            ["docker", "info"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def docker_exec(container: str, cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run `cmd` inside an already-running container via `docker exec`."""
    return subprocess.run(  # noqa: S603
        ["docker", "exec", container, *cmd],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )


def wait_healthy(container: str, timeout: float = 60.0) -> bool:
    """Poll a container's health until it reports `healthy` or times out.

    Returns False early if the container is not running (e.g. crashed).
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = subprocess.run(  # noqa: S603
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if status == "healthy":
            return True
        if status in ("unhealthy", ""):
            state = subprocess.run(  # noqa: S603
                ["docker", "inspect", "--format", "{{.State.Status}}", container],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if state != "running":
                return False
        time.sleep(1)
    return False

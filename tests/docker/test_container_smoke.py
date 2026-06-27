"""Live end-to-end test for the WOR-307 sidecar container.

Builds ``docker/sidecar/Dockerfile`` and runs it, asserting that
``supervise.sh`` brings up the sidecar as uid ``worthless-crypto``,
the smoke client connects as ``worthless-proxy``, and a full
seal/open/attest roundtrip succeeds across the uid boundary.

Marked ``@pytest.mark.docker`` so it is skipped by default (the
project's pytest ``addopts`` excludes ``docker``-marked tests). Run
explicitly with::

    uv run pytest -m docker -v

The test auto-skips (not fails) when the ``docker`` CLI is missing
or the daemon is unreachable, so CI boxes without Docker stay green.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker


_IMAGE_TAG = "worthless-sidecar:smoke"
_DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "sidecar" / "Dockerfile"
_BUILD_CTX = Path(__file__).resolve().parents[2]


def _docker_available() -> bool:
    """Docker CLI + reachable daemon."""
    if shutil.which("docker") is None:
        return False
    # Deliberate PATH-resolved lookup: users install docker under wildly
    # varying prefixes (/usr/bin, /opt/homebrew/bin, Docker Desktop).
    # We already gated on ``shutil.which`` above.
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],  # noqa: S607
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


@pytest.fixture(scope="module")
def built_image() -> str:
    """Build the sidecar image once per test module; yield the tag."""
    if not _docker_available():
        pytest.skip("docker CLI or daemon unavailable")
    if not _DOCKERFILE.exists():
        pytest.fail(f"Dockerfile missing at {_DOCKERFILE}")

    build = subprocess.run(
        [  # noqa: S607 — PATH-resolved docker; gated by _docker_available above
            "docker",
            "build",
            "-f",
            str(_DOCKERFILE),
            "-t",
            _IMAGE_TAG,
            str(_BUILD_CTX),
        ],
        capture_output=True,
        timeout=300,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail(
            f"docker build failed (rc={build.returncode}):\n"
            f"stdout: {build.stdout.decode(errors='replace')}\n"
            f"stderr: {build.stderr.decode(errors='replace')}"
        )
    return _IMAGE_TAG


def test_container_roundtrip_succeeds_across_uid_boundary(built_image: str) -> None:
    """Full lifecycle: build → run → sidecar bind → smoke client roundtrip.

    Asserts each ``{step: ...}`` json line the smoke client prints and
    confirms the container exited 0. This pins the entire single-
    container topology for WOR-307 gate: tini, two uids, socket
    volume, 0660 mode, peer-uid enforcement, seal/open/attest.
    """
    started = time.monotonic()
    # --rm keeps the container from lingering; we rely on the smoke
    # client exiting on its own (it does), which triggers supervise.sh's
    # cleanup trap, which kills the sidecar, which causes tini to exit.
    run = subprocess.run(
        [  # noqa: S607 — PATH-resolved docker; gated by _docker_available above
            "docker",
            "run",
            "--rm",
            "--name",
            "worthless-sidecar-smoke",
            built_image,
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    elapsed = time.monotonic() - started

    stdout = run.stdout.decode(errors="replace")
    stderr = run.stderr.decode(errors="replace")
    detail = f"rc={run.returncode} elapsed={elapsed:.2f}s\nstdout:\n{stdout}\nstderr:\n{stderr}\n"

    # Parse every JSON line the smoke client printed on stdout.
    steps = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        step = payload.get("step")
        if step:
            steps[step] = payload

    assert "handshake" in steps, f"handshake step missing.\n{detail}"
    assert steps["handshake"]["ok"] is True
    assert sorted(steps["handshake"]["caps"]) == ["attest", "open", "seal"]

    assert "seal" in steps and steps["seal"]["ok"] is True, detail
    assert steps["seal"]["ct_len"] > 0

    assert "open" in steps and steps["open"]["ok"] is True, (
        f"open roundtrip failed — plaintext did not match.\n{detail}"
    )

    assert "attest" in steps and steps["attest"]["ok"] is True, detail
    assert steps["attest"]["evidence_len"] > 0

    assert "done" in steps, f"smoke client did not reach done step.\n{detail}"

    assert run.returncode == 0, f"container exited non-zero.\n{detail}"

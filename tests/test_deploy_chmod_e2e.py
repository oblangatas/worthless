# ruff: noqa: S104, S108, S603, S607
"""Kernel-level integration test for the fernet.key chmod path (WOR-465 A4).

Static text-grep can confirm strings are present in entrypoint.sh; only a
real container can confirm the kernel actually denies the proxy uid and
allows the sidecar uid. Strategy: pre-seed fernet.key, run entrypoint
(its chmod block runs synchronously before start.py exec's the proxy
that may later crash), then inspect via ephemeral ``docker run --user``
containers.

Run: ``uv run pytest tests/test_deploy_chmod_e2e.py -v -m docker``
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.timeout(180),
]

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
_SESSION_ID = uuid.uuid4().hex[:8]
IMAGE_TAG = os.environ.get("WORTHLESS_DOCKER_IMAGE", f"worthless-test:chmod-{_SESSION_ID}")

# Standard cap set the entrypoint needs for the priv-drop dance and the
# chown/chmod block. Identical to test_docker_e2e.py's container fixture
# so we exercise the same security posture as production.
_CAPS = [
    "--cap-drop=ALL",
    "--cap-add=SETUID",
    "--cap-add=SETGID",
    "--cap-add=SETPCAP",
    "--cap-add=DAC_OVERRIDE",
    "--cap-add=CHOWN",
    "--cap-add=FOWNER",
    "--security-opt=no-new-privileges",
]


@pytest.fixture(scope="module")
def image() -> str:
    """Build the image once for this module; reuse CI image if pre-built."""
    if os.environ.get("WORTHLESS_DOCKER_IMAGE"):
        yield IMAGE_TAG  # type: ignore[misc]
        return
    subprocess.run(  # noqa: S603
        ["docker", "build", "-t", IMAGE_TAG, "-f", str(DOCKERFILE), str(REPO_ROOT)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    yield IMAGE_TAG  # type: ignore[misc]
    subprocess.run(  # noqa: S603
        ["docker", "rmi", "-f", IMAGE_TAG],
        capture_output=True,  # noqa: S607
    )


def _seed_fernet_key(image: str, volume: str) -> None:
    """Drop a fake fernet.key into the volume so entrypoint's chmod fires.

    Entrypoint conditions on ``[ -f "$FERNET_PATH" ]`` and skips the chmod
    block if the file is absent. We seed it as ``root:root 0644`` so we
    can prove the chmod block actually changed it — not "test passed
    because the file was already in the target state."
    """
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-v",
            f"{volume}:/secrets",
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            # 32 bytes = a plausible Fernet key length; the byte content is
            # irrelevant — we never use it as a real key, only check perms.
            "printf 'fake-fernet-key-32-bytes-aaaaaaaa' > /secrets/fernet.key && "
            "chmod 0644 /secrets/fernet.key",
        ],
        check=True,
        capture_output=True,
    )


def _stat(image: str, volume: str, path: str) -> str:
    """Return ``'owner:group mode'`` for a path in a volume."""
    r = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-v",
            f"{volume}:/inspect:ro",
            "--entrypoint",
            "stat",
            image,
            "-c",
            "%U:%G %a",
            f"/inspect/{path}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


def _read_as(image: str, volume: str, user: str, path: str) -> tuple[int, str]:
    """Try to read a file in a volume as ``user``. Return ``(rc, output)``.

    Uses ``docker run --user`` so the kernel evaluates the open() against
    the named uid's effective groups — the actual security boundary.
    """
    r = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-v",
            f"{volume}:/inspect:ro",
            "--user",
            user,
            "--entrypoint",
            "cat",
            image,
            f"/inspect/{path}",
        ],
        capture_output=True,
        text=True,
    )
    return r.returncode, (r.stdout + r.stderr).strip()


_SEED_STATE = "root:root 644"


def _run_entrypoint(
    image: str,
    volume: str,
    container: str,
    env: dict[str, str],
    *,
    caps: list[str] | None = None,
    wait_for_exit: bool = False,
    timeout: float = 10.0,
) -> int | None:
    """Boot the image; either poll until chmod block runs, or wait for exit.

    Two modes:

    - ``wait_for_exit=False`` (default): poll ``stat`` every 100ms until
      ``fernet.key`` mode/owner differs from the seed (``root:root 644``),
      or ``timeout`` elapses. Returns ``None``. Use when the proxy is
      expected to live (or crash later — we only care the chmod ran).
    - ``wait_for_exit=True``: wait for the container to exit via
      ``docker wait``, return the integer exit code. Use when the
      entrypoint is expected to fail-closed before the proxy starts.

    ``caps`` defaults to ``_CAPS`` (the production cap set). Pass a
    custom list to simulate misconfigurations like a host filesystem
    that drops chown (drop ``--cap-add=CHOWN``).
    """
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container,
        "-v",
        f"{volume}:/secrets",
        "--read-only",
        "--tmpfs",
        "/tmp:noexec,nosuid",
    ]
    for k, v in env.items():
        cmd.extend(["-e", f"{k}={v}"])
    cmd.extend(caps if caps is not None else _CAPS)
    cmd.append(image)
    subprocess.run(cmd, check=True, capture_output=True)

    if wait_for_exit:
        wait = subprocess.run(
            ["docker", "wait", container],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
        return int(wait.stdout.strip())

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _stat(image, volume, "fernet.key") != _SEED_STATE:
            return None
        time.sleep(0.1)
    # Fall through if mode never changed — let the test's stat assertion
    # report the actual final state with full context.
    return None


def _cleanup(container: str, volume: str) -> None:
    subprocess.run(  # noqa: S603
        ["docker", "rm", "-f", container],
        capture_output=True,  # noqa: S607
    )
    subprocess.run(  # noqa: S603
        ["docker", "volume", "rm", "-f", volume],
        capture_output=True,  # noqa: S607
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_flag_on_fails_closed_when_chown_is_silently_dropped(image: str) -> None:
    """If chown silently no-ops, entrypoint exits 78 — no false security claim.

    Simulates a misconfigured host bind-mount (macOS Docker Desktop / WSL
    ``/mnt/c/...``) by dropping ``CAP_CHOWN``. With the cap removed,
    ``chown`` returns EPERM inside the container; ``2>/dev/null || true``
    swallows the error. ``chmod`` still succeeds (root chmod'ing a
    root-owned file needs no caps), so without the post-chmod stat check
    the file would settle at ``root:root 0400`` while the container
    claimed ``worthless-crypto:worthless-crypto 0400``. The owner
    mismatch trips the fail-closed check; container exits 78.
    """
    vol = f"chmod-failclosed-{uuid.uuid4().hex[:8]}"
    cnt = f"chmod-failclosed-{uuid.uuid4().hex[:8]}"
    try:
        _seed_fernet_key(image, vol)
        # Kernel-equivalent of "host filesystem ignored chown".
        caps_no_chown = [c for c in _CAPS if c != "--cap-add=CHOWN"]
        exit_code = _run_entrypoint(
            image,
            vol,
            cnt,
            env={
                "WORTHLESS_FERNET_IPC_ONLY": "1",
                "WORTHLESS_FERNET_KEY_PATH": "/secrets/fernet.key",
                "WORTHLESS_DEPLOY_MODE": "lan",
                "WORTHLESS_ALLOW_INSECURE": "true",
                "WORTHLESS_HOST": "0.0.0.0",
            },
            caps=caps_no_chown,
            wait_for_exit=True,
            timeout=30.0,
        )
        assert exit_code == 78, (
            "WOR-465 Phase A1 fail-closed: entrypoint must exit 78 "
            f"(EX_CONFIG) when fernet.key chown silently no-ops. Got {exit_code}. "
            "Without this check, an operator on a misconfigured host "
            "bind-mount would boot a container claiming IPC-only mode "
            "while the proxy can still read the key."
        )
        logs = subprocess.run(
            ["docker", "logs", cnt],
            capture_output=True,
            text=True,
            check=False,
        )
        combined = logs.stdout + logs.stderr
        assert "FATAL" in combined and "worthless-crypto:worthless-crypto 400" in combined, (
            "Fail-closed FATAL message must name the expected owner:group mode "
            f"so operators can debug. Got logs: {combined!r}"
        )
    finally:
        _cleanup(cnt, vol)


def test_flag_on_chowns_to_crypto_owner_and_locks_proxy_out(image: str) -> None:
    """WORTHLESS_FERNET_IPC_ONLY=1 → worthless-crypto:worthless-crypto 0400, proxy denied.

    This is the test that should have caught the chown root:worthless-crypto
    0400 bug. It exercises three claims at the kernel level:

    1. ownership flips to worthless-crypto:worthless-crypto
    2. mode is 0400 (owner-only, not group-readable)
    3. the worthless-crypto sidecar uid CAN read (owner bit), the
       worthless-proxy uid CANNOT (no group bit set)

    Static-text grep cannot make claim 3 — only a real kernel check can.
    """
    vol = f"chmod-on-{uuid.uuid4().hex[:8]}"
    cnt = f"chmod-on-{uuid.uuid4().hex[:8]}"
    try:
        _seed_fernet_key(image, vol)
        _run_entrypoint(
            image,
            vol,
            cnt,
            env={
                "WORTHLESS_FERNET_IPC_ONLY": "1",
                "WORTHLESS_FERNET_KEY_PATH": "/secrets/fernet.key",
                "WORTHLESS_DEPLOY_MODE": "lan",
                "WORTHLESS_ALLOW_INSECURE": "true",
                "WORTHLESS_HOST": "0.0.0.0",
            },
        )

        # Claim 1 + 2: ownership and mode
        owner_mode = _stat(image, vol, "fernet.key")
        assert owner_mode == "worthless-crypto:worthless-crypto 400", (
            "WOR-465 Phase A1: WORTHLESS_FERNET_IPC_ONLY=1 must flip "
            "fernet.key to worthless-crypto:worthless-crypto 0400 "
            f"(sidecar owns, owner-only). Got {owner_mode!r}. "
            "Common bug: chown root:worthless-crypto leaves owner=root, "
            "and 0400 then locks the sidecar out of its own key."
        )

        # Claim 3a: sidecar uid (worthless-crypto) CAN read via owner bit
        crypto_rc, crypto_out = _read_as(image, vol, "worthless-crypto", "fernet.key")
        assert crypto_rc == 0, (
            "WOR-465 Phase A1: worthless-crypto sidecar uid must be able "
            f"to read fernet.key (owner bit). Got rc={crypto_rc} "
            f"output={crypto_out!r}. If owner is root with mode 0400, the "
            "sidecar — the only legitimate reader — is locked out, and "
            "the flag becomes a denial-of-service."
        )

        # Claim 3b: proxy uid CANNOT read — kernel enforces the boundary
        proxy_rc, proxy_out = _read_as(image, vol, "worthless-proxy", "fernet.key")
        assert proxy_rc != 0, (
            "WOR-465 Phase A1: worthless-proxy uid MUST NOT be able to read "
            f"fernet.key when WORTHLESS_FERNET_IPC_ONLY=1. Got rc={proxy_rc}. "
            "This is the entire security claim of WOR-465 — if the proxy "
            "can still open() the key, the offline-key-theft gap is wide open."
        )
        assert "denied" in proxy_out.lower() or "eacces" in proxy_out.lower(), (
            "WOR-465 Phase A1: proxy read failure must be EACCES (kernel "
            f"denial), not some other error. Got: {proxy_out!r}"
        )
    finally:
        _cleanup(cnt, vol)


def test_default_locks_proxy_out_without_explicit_flag(image: str) -> None:
    """WOR-465 A4: Dockerfile ENV default=1 makes locked state the default.

    Without any WORTHLESS_FERNET_IPC_ONLY in the operator's env, the Docker
    image must still enforce worthless-crypto:worthless-crypto 0400 — the
    security claim must be opt-out (hard to weaken), not opt-in (easy to miss).

    RED before A4: Dockerfile ENV block lacks WORTHLESS_FERNET_IPC_ONLY=1,
    so the entrypoint defaults to root:worthless 0440 (proxy-readable).
    GREEN after A4: Dockerfile adds ENV WORTHLESS_FERNET_IPC_ONLY=1 and
    entrypoint removes the conditional.
    """
    vol = f"chmod-default-locked-{uuid.uuid4().hex[:8]}"
    cnt = f"chmod-default-locked-{uuid.uuid4().hex[:8]}"
    try:
        _seed_fernet_key(image, vol)
        # Deliberately do NOT set WORTHLESS_FERNET_IPC_ONLY — the Dockerfile
        # ENV default must carry the security claim without operator action.
        _run_entrypoint(
            image,
            vol,
            cnt,
            env={
                "WORTHLESS_FERNET_KEY_PATH": "/secrets/fernet.key",
                "WORTHLESS_DEPLOY_MODE": "lan",
                "WORTHLESS_ALLOW_INSECURE": "true",
                "WORTHLESS_HOST": "0.0.0.0",
            },
        )

        owner_mode = _stat(image, vol, "fernet.key")
        assert owner_mode == "worthless-crypto:worthless-crypto 400", (
            "WOR-465 A4: without explicit WORTHLESS_FERNET_IPC_ONLY, the "
            "Dockerfile ENV default must enforce worthless-crypto:worthless-crypto 0400. "
            f"Got {owner_mode!r}. The security claim must be the default, "
            "not opt-in — an operator who doesn't read the docs must still "
            "get the locked-down state."
        )

        # Kernel confirms: proxy uid has no read path (not in gid 10002).
        proxy_rc, proxy_out = _read_as(image, vol, "worthless-proxy", "fernet.key")
        assert proxy_rc != 0, (
            "WOR-465 A4: worthless-proxy uid MUST NOT be able to read "
            "fernet.key in the default Docker configuration (no explicit flag). "
            f"Got rc={proxy_rc}. This is the load-bearing claim: a Docker "
            "deployment without extra configuration is not vulnerable to "
            "offline key theft via proxy RCE."
        )
    finally:
        _cleanup(cnt, vol)


# Static (no-Docker) version of this check lives in test_entrypoint_static.py
# so it runs on every CI pass, not just the Docker lane.

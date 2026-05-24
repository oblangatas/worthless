"""Docker fresh-machine integration tests for install.sh.

Marked 'docker' (excluded from the default pytest run via pyproject.toml).
Run with: pytest -m docker tests/test_install_docker.py

Validates the fresh-box promise: a non-Python Linux box can run install.sh
and end up with a working `worthless` CLI. Also chains the lock lifecycle
against a mock upstream so `worthless --version` isn't the only behavior
proven. WOR-442 adds the Docker app journey: host-native Worthless locks a
project `.env`, then a separate app container uses the Docker host bridge to
call through the host proxy without receiving the raw key.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available
from tests._install_helpers import INSTALL_FIXTURES, REPO_ROOT
from tests.helpers import fake_openai_key

LOCK_E2E_SERVICE = "worthless-installed"
LOCK_E2E_COMPOSE = INSTALL_FIXTURES / "docker-compose.lock-e2e.yml"
MOCK_UPSTREAM_DOCKERFILE = REPO_ROOT / "tests" / "openclaw" / "mock-upstream" / "Dockerfile"

# Install matrix — all Supported tier. `linux/amd64` pinned so arm64 Macs
# still exercise amd64 coverage.
INSTALL_MATRIX = [
    "ubuntu-bare",  # 24.04, no python, no uv
    "ubuntu-2204-bare",  # 22.04 LTS — still the prod majority
    "ubuntu-with-uv",  # 24.04 + pre-installed uv (reuse path)
    "ubuntu-nonroot",  # 24.04 + non-root user, no sudo (WOR-318)
    "ubuntu-idempotency",  # 24.04, runs install.sh twice → expects no-op (WOR-317)
    "debian-12-bare",  # second glibc distro
    "alpine-bare",  # musl — uv fetches musl-compatible Python via PBS
]

# Per-fixture success marker. verify_install.sh (used by every fixture
# that exercises the fresh-box install AC) prints "OK: install verified".
# verify_idempotency.sh (WOR-317) prints "OK: install.sh is idempotent"
# instead — it's a different invariant, different message.
SUCCESS_MARKER = {
    "ubuntu-idempotency": "OK: install.sh is idempotent",
}
DEFAULT_SUCCESS_MARKER = "OK: install verified"

# Lock-lifecycle matrix — (distro_label, dockerfile_name). The compose file
# selects the dockerfile via the LOCK_E2E_DOCKERFILE env var.
LOCK_E2E_MATRIX = [
    ("ubuntu-bare", "Dockerfile.ubuntu-bare-lock-e2e"),
    ("debian-12", "Dockerfile.debian-12-lock-e2e"),
]

BUILD_PLATFORM = "linux/amd64"

# Per-step subprocess budgets (seconds). Comments capture WHY each value:
#
# BUILD_S — cold-cache CI runner: pulls pinned base-image digests (~50MB,
#   no shared layer reuse across digests), runs apt-get + install.sh which
#   downloads uv + worthless from PyPI. 240s was tight; bumped on PR #127.
# RUN_S — runs install.sh inside the container; bounded by uv tool install
#   + smoke test on a fresh-box.
# RMI_S — local-only image deletion.
# COMPOSE_UP_S — pulls 2 base images + builds 2 services + runs lock_e2e.py.
# COMPOSE_LOGS_S / COMPOSE_DOWN_S — local docker compose teardown.
# OUTER_BUFFER_S — buffer above sum-of-subprocess-budgets so pytest-timeout
#   doesn't preempt a legitimately slow stage before it can report.
BUILD_S = 480
RUN_S = 180
RMI_S = 30
COMPOSE_UP_S = 600
COMPOSE_LOGS_S = 30
COMPOSE_DOWN_S = 60
OUTER_BUFFER_S = 30

INSTALL_TIMEOUT = BUILD_S + RUN_S + RMI_S + OUTER_BUFFER_S
LOCK_E2E_TIMEOUT = COMPOSE_UP_S + COMPOSE_LOGS_S + COMPOSE_DOWN_S + OUTER_BUFFER_S
HOST_APP_TIMEOUT = 360
HOST_PROXY_BIND_ATTEMPTS = 5
HOST_PROXY_BIND_COLLISION_MARKERS = (
    "address already in use",
    "could not bind",
    "couldn't bind",
    "eaddrinuse",
    "port_in_use",
    "proxy already running",
)

APP_CONTAINER_CLIENT = r"""
import json
import os
import sys
import urllib.error
import urllib.request

key = os.environ.get("OPENAI_API_KEY", "")
base = os.environ.get("OPENAI_BASE_URL", "")
if not key:
    raise SystemExit("OPENAI_API_KEY missing in app container")
if not base:
    raise SystemExit("OPENAI_BASE_URL missing in app container")
if "127.0.0.1" in base:
    raise SystemExit(f"container received loopback base URL: {base}")
if "host.docker.internal" not in base:
    raise SystemExit(f"container base URL is not Docker-host routable: {base}")

body = json.dumps(
    {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello from container"}]}
).encode()
req = urllib.request.Request(
    f"{base.rstrip('/')}/chat/completions",
    data=body,
    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=30) as response:
        print(f"APP_REQUEST_STATUS={response.status}")
except urllib.error.HTTPError as exc:
    detail = exc.read()[:300].decode(errors="replace")
    print(f"APP_REQUEST_STATUS={exc.code}")
    print(f"APP_REQUEST_BODY={detail}")
    sys.exit(1)
"""


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
]


def _worthless_cli_args() -> list[str]:
    """Resolve the CLI under the current test interpreter, not a global install."""
    interpreter_dir = Path(sys.executable).parent
    binary = shutil.which("worthless", path=str(interpreter_dir))
    if binary:
        return [binary]
    return [sys.executable, "-m", "worthless.cli.app"]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_url(url: str, *, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = repr(exc)
        time.sleep(0.5)
    raise AssertionError(f"{url} did not become healthy within {timeout_s}s: {last_error}")


class HostProxyStartError(AssertionError):
    """Host proxy could not become healthy; carries process diagnostics."""

    def __init__(self, message: str, *, stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr

    @property
    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}\n{self}".lower()


def _run_host_cli(
    args: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [*_worthless_cli_args(), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _isolated_cli_env(tmp_path: Path, *, port: int) -> dict[str, str]:
    env = dict(os.environ)
    user_home = tmp_path / "user-home"
    worthless_home = tmp_path / "worthless-home"
    user_home.mkdir(parents=True, exist_ok=True)
    worthless_home.mkdir(parents=True, exist_ok=True)

    env.update(
        {
            "HOME": str(user_home),
            "USERPROFILE": str(user_home),
            "WORTHLESS_HOME": str(worthless_home),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": str(port),
            # Linux containers reach the host via the bridge gateway, so the
            # host proxy must bind beyond loopback for this Docker journey.
            "WORTHLESS_DEPLOY_MODE": "lan",
            "WORTHLESS_ALLOW_INSECURE": "true",
        }
    )
    for name in (
        "WORTHLESS_DB_PATH",
        "WORTHLESS_FERNET_KEY",
        "WORTHLESS_FERNET_KEY_PATH",
        "WORTHLESS_FERNET_FD",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
    ):
        env.pop(name, None)
    return env


@contextmanager
def _mock_upstream_image() -> Iterator[str]:
    image_tag = f"worthless-mock-upstream:host-app-{uuid.uuid4().hex[:8]}"

    build = subprocess.run(
        [  # noqa: S607
            "docker",
            "build",
            "--file",
            str(MOCK_UPSTREAM_DOCKERFILE),
            "--tag",
            image_tag,
            str(MOCK_UPSTREAM_DOCKERFILE.parent),
        ],
        capture_output=True,
        text=True,
        timeout=BUILD_S,
        check=False,
    )
    assert build.returncode == 0, (
        f"mock-upstream docker build failed:\nstdout:\n{build.stdout}\nstderr:\n{build.stderr}"
    )

    try:
        yield image_tag
    finally:
        subprocess.run(  # noqa: S603
            ["docker", "rmi", "-f", image_tag],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=RMI_S,
            check=False,
        )


@contextmanager
def _mock_upstream_container() -> Iterator[tuple[str, str]]:
    container_name = f"worthless-mock-upstream-{uuid.uuid4().hex[:8]}"

    with _mock_upstream_image() as image_tag:
        try:
            run = subprocess.run(
                [  # noqa: S607
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    container_name,
                    "-p",
                    "127.0.0.1::9999",
                    image_tag,
                ],
                capture_output=True,
                text=True,
                timeout=RUN_S,
                check=False,
            )
            assert run.returncode == 0, (
                f"mock-upstream docker run failed:\nstdout:\n{run.stdout}\nstderr:\n{run.stderr}"
            )

            port = subprocess.run(  # noqa: S603
                ["docker", "port", container_name, "9999"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert port.returncode == 0, (
                "mock-upstream port discovery failed:\n"
                f"stdout:\n{port.stdout}\nstderr:\n{port.stderr}"
            )
            host_port = port.stdout.strip().rsplit(":", 1)[-1]
            base_url = f"http://127.0.0.1:{host_port}"
            _wait_url(f"{base_url}/healthz")
            yield image_tag, base_url
        finally:
            subprocess.run(  # noqa: S603
                ["docker", "rm", "-f", container_name],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=RMI_S,
                check=False,
            )


def _run_app_container(
    *,
    image: str,
    env_file: Path,
    timeout: int = RUN_S,
) -> subprocess.CompletedProcess[str]:
    app_name = f"worthless-host-app-{uuid.uuid4().hex[:8]}"
    host_bridge_args = (
        ["--add-host", "host.docker.internal:host-gateway"]
        if sys.platform.startswith("linux")
        else []
    )
    return subprocess.run(
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "--name",
            app_name,
            *host_bridge_args,
            "--env-file",
            str(env_file),
            image,
            "python",
            "-c",
            APP_CONTAINER_CLIENT,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _assert_lock_writes_host_loopback(
    *,
    env_file: Path,
    real_key: str,
    proxy_port: int,
) -> str:
    locked_env = env_file.read_text(encoding="utf-8")
    assert real_key not in locked_env, "host lock left the raw key in .env"
    assert f"OPENAI_BASE_URL=http://127.0.0.1:{proxy_port}/" in locked_env, (
        "host lock did not write the host-loopback proxy URL expected before "
        f"the Docker bridge edit:\n{locked_env}"
    )
    return locked_env


def _write_docker_bridge_env(env_file: Path, *, locked_env: str, proxy_port: int) -> None:
    docker_env = locked_env.replace(
        f"127.0.0.1:{proxy_port}",
        f"host.docker.internal:{proxy_port}",
    )
    env_file.write_text(docker_env, encoding="utf-8")


@contextmanager
def _host_proxy(project: Path, *, env: dict[str, str], port: int) -> Iterator[None]:
    proxy = subprocess.Popen(  # noqa: S603
        [*_worthless_cli_args(), "up", "--port", str(port)],
        cwd=project,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        try:
            _wait_url(f"http://127.0.0.1:{port}/healthz", timeout_s=45.0)
        except AssertionError as exc:
            stdout, stderr = proxy.communicate(timeout=2) if proxy.poll() is not None else ("", "")
            raise HostProxyStartError(
                f"host proxy did not become healthy on port {port}: {exc}",
                stdout=stdout,
                stderr=stderr,
            ) from exc

        if proxy.poll() is not None:
            stdout, stderr = proxy.communicate(timeout=2)
            raise HostProxyStartError(
                f"host proxy exited before app container used port {port}",
                stdout=stdout,
                stderr=stderr,
            )

        yield
    finally:
        if proxy.poll() is None:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)


def _is_host_proxy_bind_collision(exc: HostProxyStartError) -> bool:
    return any(marker in exc.combined for marker in HOST_PROXY_BIND_COLLISION_MARKERS)


@pytest.mark.timeout(INSTALL_TIMEOUT)
@pytest.mark.parametrize("fixture", INSTALL_MATRIX)
def test_install_succeeds_on_distro(fixture: str) -> None:
    """Build image, run install.sh + verify_install.sh, assert both succeed."""
    dockerfile = INSTALL_FIXTURES / f"Dockerfile.{fixture}"
    # uuid suffix: xdist workers running retries or sibling jobs on the same
    # daemon must not race on a shared image tag.
    image_tag = f"worthless-install-test:{fixture}-{uuid.uuid4().hex[:8]}"
    assert dockerfile.is_file(), f"missing fixture: {dockerfile}"

    try:
        # DOCKER_BUILDKIT=1 forces the BuildKit frontend so RUN --mount=type=cache
        # directives in the fixtures (WOR-320) actually cache uv downloads
        # between matrix runs. Modern docker defaults to BuildKit, but older
        # CI runners and some daemon configs still fall back to the legacy
        # builder, which silently strips --mount.
        build = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker",
                "build",
                "--platform",
                BUILD_PLATFORM,
                "--file",
                str(dockerfile),
                "--tag",
                image_tag,
                str(REPO_ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=BUILD_S,
            check=False,
            env={**os.environ, "DOCKER_BUILDKIT": "1"},
        )
        assert build.returncode == 0, (
            f"docker build failed for {fixture}:\nstdout:\n{build.stdout}\nstderr:\n{build.stderr}"
        )

        run = subprocess.run(  # noqa: S603
            ["docker", "run", "--rm", "--platform", BUILD_PLATFORM, image_tag],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=RUN_S,
            check=False,
        )
        assert run.returncode == 0, (
            f"install + verify failed inside {fixture} container:\n"
            f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}"
        )
        # Each fixture's verify script emits an "OK: …" marker on success.
        # See SUCCESS_MARKER for the per-fixture overrides.
        marker = SUCCESS_MARKER.get(fixture, DEFAULT_SUCCESS_MARKER)
        assert marker in run.stdout, (
            f"verify script did not emit '{marker}' in {fixture}:\n"
            f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}"
        )
    finally:
        subprocess.run(  # noqa: S603
            ["docker", "rmi", "-f", image_tag],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=RMI_S,
            check=False,
        )


@pytest.mark.timeout(LOCK_E2E_TIMEOUT)
@pytest.mark.parametrize(("distro", "dockerfile_name"), LOCK_E2E_MATRIX)
def test_lock_lifecycle_end_to_end(distro: str, dockerfile_name: str) -> None:
    """Post-install: `worthless lock` + proxied request → real key at upstream.

    Chains install → lock → `worthless up` → request via proxy → verify
    mock-upstream saw the reconstructed real key. Teardown happens in
    ``finally`` so a timeout or assertion failure still cleans up.

    Parametrized across Ubuntu + Debian to catch glibc-version drift.
    """
    assert LOCK_E2E_COMPOSE.is_file(), f"missing fixture: {LOCK_E2E_COMPOSE}"

    # uuid suffix: xdist workers can share PIDs, so PID alone can collide.
    project = f"worthless-lock-e2e-{distro}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    compose_base = [
        "docker",
        "compose",
        "-f",
        str(LOCK_E2E_COMPOSE),
        "-p",
        project,
    ]
    # Minimal env — avoid leaking arbitrary WORTHLESS_* / provider keys from
    # the host into the compose build context and service env. Compose needs
    # HOME to locate its context cache; fall back to the runner's real HOME.
    # DOCKER_BUILDKIT=1 + COMPOSE_DOCKER_CLI_BUILD=1 ensure the lock-e2e
    # Dockerfiles' cache mounts (WOR-320) are honored on older daemons.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ["HOME"],
        "LOCK_E2E_DOCKERFILE": dockerfile_name,
        "DOCKER_BUILDKIT": "1",
        "COMPOSE_DOCKER_CLI_BUILD": "1",
    }

    up_stdout, up_stderr, up_rc = "", "", None
    logs_text = ""
    try:
        try:
            up = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    *compose_base,
                    "up",
                    "--build",
                    "--abort-on-container-exit",
                    "--exit-code-from",
                    LOCK_E2E_SERVICE,
                ],
                capture_output=True,
                text=True,
                timeout=COMPOSE_UP_S,
                check=False,
                env=env,
            )
            up_stdout, up_stderr, up_rc = up.stdout, up.stderr, up.returncode
        finally:
            # Always pull logs — especially on timeout, when `up` never finished
            # and the captured stdout is empty or partial.
            logs = subprocess.run(  # noqa: S603
                [*compose_base, "logs", "--no-color"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=COMPOSE_LOGS_S,
                check=False,
                env=env,
            )
            logs_text = f"{logs.stdout}\n{logs.stderr}"
    finally:
        subprocess.run(  # noqa: S603
            [*compose_base, "down", "-v", "--remove-orphans"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=COMPOSE_DOWN_S,
            check=False,
            env=env,
        )

    assert up_rc == 0, (
        f"{LOCK_E2E_SERVICE} ({distro}) exited {up_rc}.\n"
        f"--- compose up stdout ---\n{up_stdout}\n"
        f"--- compose up stderr ---\n{up_stderr}\n"
        f"--- service logs ---\n{logs_text}"
    )


@pytest.mark.timeout(HOST_APP_TIMEOUT)
def test_host_cli_locked_env_reaches_proxy_from_app_container(tmp_path: Path) -> None:
    """Scenario A: host Worthless + app container consuming the locked `.env`.

    This is the product Docker journey, not the server-image journey:
    the host CLI locks a project, the host proxy runs outside Docker, and a
    separate app container reads the rewritten `.env` through Docker's
    host bridge. The container must receive only shard-A plus the proxy URL;
    the mock upstream must receive the reconstructed real key.
    """
    attempts: list[str] = []

    with _mock_upstream_container() as (app_image, mock_base_url):
        for attempt in range(1, HOST_PROXY_BIND_ATTEMPTS + 1):
            project = tmp_path / f"project-{attempt}"
            project.mkdir()
            proxy_port = _free_port()
            cli_env = _isolated_cli_env(tmp_path / f"home-{attempt}", port=proxy_port)
            real_key = fake_openai_key()
            upstream_url = f"{mock_base_url}/v1"
            env_file = project / ".env"
            env_file.write_text(
                f"OPENAI_API_KEY={real_key}\nOPENAI_BASE_URL={upstream_url}\n",
                encoding="utf-8",
            )

            register = _run_host_cli(
                [
                    "providers",
                    "register",
                    "--name",
                    f"openai-mock-{uuid.uuid4().hex[:8]}",
                    "--url",
                    upstream_url,
                    "--protocol",
                    "openai",
                ],
                env=cli_env,
                cwd=project,
            )
            assert register.returncode == 0, (
                "host providers register failed:\n"
                f"stdout:\n{register.stdout}\nstderr:\n{register.stderr}"
            )

            lock = _run_host_cli(["lock", "--env", str(env_file)], env=cli_env, cwd=project)
            assert lock.returncode == 0, (
                f"host lock failed:\nstdout:\n{lock.stdout}\nstderr:\n{lock.stderr}"
            )

            locked_env = _assert_lock_writes_host_loopback(
                env_file=env_file,
                real_key=real_key,
                proxy_port=proxy_port,
            )
            _write_docker_bridge_env(
                env_file,
                locked_env=locked_env,
                proxy_port=proxy_port,
            )

            try:
                with _host_proxy(project, env=cli_env, port=proxy_port):
                    clear = urllib.request.Request(  # noqa: S310
                        f"{mock_base_url}/captured-headers",
                        method="DELETE",
                    )
                    urllib.request.urlopen(clear, timeout=5).read()  # noqa: S310

                    app = _run_app_container(image=app_image, env_file=env_file)
            except HostProxyStartError as exc:
                if not _is_host_proxy_bind_collision(exc):
                    raise
                attempts.append(
                    f"attempt {attempt} port {proxy_port} bind collision:\n"
                    f"stdout:\n{exc.stdout}\nstderr:\n{exc.stderr}"
                )
                time.sleep(0.05 * attempt)
                continue

            assert app.returncode == 0, (
                "app container could not use the locked .env through the host proxy "
                f"after {len(attempts) + 1} attempt(s):\n"
                f"{chr(10).join(attempts)}\nstdout:\n{app.stdout}\nstderr:\n{app.stderr}"
            )
            assert "APP_REQUEST_STATUS=200" in app.stdout, (
                f"app container request did not complete through the proxy:\n"
                f"stdout:\n{app.stdout}\nstderr:\n{app.stderr}"
            )
            assert real_key not in app.stdout
            assert real_key not in app.stderr

            captured = json.loads(
                urllib.request.urlopen(  # noqa: S310
                    f"{mock_base_url}/captured-headers", timeout=5
                ).read()
            )
            headers = captured.get("headers") or []
            assert headers, "mock upstream never saw the container request"
            received = headers[-1].get("authorization", "").replace("Bearer ", "")
            assert received == real_key, (
                "mock upstream did not receive the reconstructed real key from "
                f"the host proxy; captured={captured!r}"
            )
            break
        else:
            raise AssertionError(
                "host proxy could not start after bind-collision retries:\n"
                f"{chr(10).join(attempts)}"
            )


@pytest.mark.timeout(HOST_APP_TIMEOUT)
def test_app_container_fails_fast_when_locked_env_keeps_loopback_url(tmp_path: Path) -> None:
    """The common Docker mistake is visible: container loopback is not the host.

    The host lock command correctly writes a host-local URL first. If a user
    skips the documented Docker bridge edit, the app container should fail
    with wording that points at the actual problem instead of pretending the
    app, key, or upstream is broken.
    """
    project = tmp_path / "project"
    project.mkdir()
    proxy_port = _free_port()
    cli_env = _isolated_cli_env(tmp_path, port=proxy_port)
    real_key = fake_openai_key()
    env_file = project / ".env"
    env_file.write_text(f"OPENAI_API_KEY={real_key}\n", encoding="utf-8")

    lock = _run_host_cli(["lock", "--env", str(env_file)], env=cli_env, cwd=project)
    assert lock.returncode == 0, (
        f"host lock failed:\nstdout:\n{lock.stdout}\nstderr:\n{lock.stderr}"
    )
    _assert_lock_writes_host_loopback(env_file=env_file, real_key=real_key, proxy_port=proxy_port)

    with _mock_upstream_image() as image:
        app = _run_app_container(image=image, env_file=env_file)

    assert app.returncode != 0, "container app unexpectedly accepted host loopback .env"
    assert "container received loopback base URL" in app.stderr, (
        "container failure did not explain the Docker loopback problem:\n"
        f"stdout:\n{app.stdout}\nstderr:\n{app.stderr}"
    )


@pytest.mark.timeout(60)
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses POSIX directory write permissions",
)
def test_host_lock_unwritable_env_fails_without_phantom_enrollment(tmp_path: Path) -> None:
    """Bind-mount-like permission failure leaves no half-protected state."""
    project = tmp_path / "project"
    project.mkdir()
    proxy_port = _free_port()
    cli_env = _isolated_cli_env(tmp_path, port=proxy_port)
    real_key = fake_openai_key()
    env_file = project / ".env"
    original_env = f"OPENAI_API_KEY={real_key}\n"
    env_file.write_text(original_env, encoding="utf-8")

    project.chmod(0o500)
    try:
        lock = _run_host_cli(["lock", "--env", str(env_file)], env=cli_env, cwd=project)
    finally:
        project.chmod(0o700)

    output = f"{lock.stdout}\n{lock.stderr}"
    assert lock.returncode != 0, "lock unexpectedly succeeded against an unwritable .env dir"
    assert "unsafe rewrite refused" in output
    assert ".env is unchanged" in output
    assert env_file.read_text(encoding="utf-8") == original_env

    status = _run_host_cli(["status"], env=cli_env, cwd=project)
    assert status.returncode == 0, (
        f"status failed after refused lock:\nstdout:\n{status.stdout}\nstderr:\n{status.stderr}"
    )
    assert "No keys enrolled" in f"{status.stdout}\n{status.stderr}", (
        "refused lock left a phantom enrollment behind:\n"
        f"stdout:\n{status.stdout}\nstderr:\n{status.stderr}"
    )

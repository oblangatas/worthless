"""Docker end-to-end tests for the Worthless proxy container.

Requires Docker daemon running. Skipped when Docker is unavailable.
Marked with @pytest.mark.docker -- excluded from default test runs.

Run with:
    uv run pytest tests/test_docker_e2e.py -x -v -m docker
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import anthropic
import httpx
import openai
import pytest

from tests._docker_helpers import docker_available, docker_exec, wait_healthy
from tests.helpers import fake_anthropic_key, fake_openai_key
from worthless.cli.commands.lock import _make_alias

# ---------------------------------------------------------------------------
# Module-level skip + marker
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.timeout(90),
]

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"

# Use env var if set (CI builds image separately), otherwise build with a
# unique tag per test session to avoid races between parallel runs.
_SESSION_ID = uuid.uuid4().hex[:8]
IMAGE_TAG = os.environ.get("WORTHLESS_DOCKER_IMAGE", f"worthless-test:e2e-{_SESSION_ID}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Run a command, raise on failure by default."""
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kwargs)


def _run_ok(cmd: list[str]) -> str:
    """Run and return stdout, raise on failure."""
    return _run(cmd).stdout.strip()


def _cleanup_container(name: str) -> None:
    """Force-remove a container and its associated volumes if they exist."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(
        ["docker", "volume", "rm", "-f", f"{name}-data", f"{name}-secrets"],
        capture_output=True,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_image() -> str:
    """Build the Docker image once per session.

    If WORTHLESS_DOCKER_IMAGE is set (CI), skip the build and use that tag.
    """
    if os.environ.get("WORTHLESS_DOCKER_IMAGE"):
        # CI already built the image -- just use it
        yield IMAGE_TAG  # type: ignore[misc]
        return

    _run(
        [
            "docker",
            "build",
            "-t",
            IMAGE_TAG,
            "-f",
            str(DOCKERFILE),
            str(REPO_ROOT),
        ]
    )
    yield IMAGE_TAG  # type: ignore[misc]
    subprocess.run(["docker", "rmi", "-f", IMAGE_TAG], capture_output=True)


@pytest.fixture()
def container(docker_image: str) -> tuple[str, int]:
    """Run a standalone container (single /data volume, no compose)."""
    name = f"worthless-e2e-{uuid.uuid4().hex[:8]}"
    # Pre-cleanup in case a previous crashed run left a container with this name
    _cleanup_container(name)
    _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::8787",
            "-e",
            "WORTHLESS_DEPLOY_MODE=lan",
            "-e",
            "WORTHLESS_ALLOW_INSECURE=true",
            # Without this, deploy/start.py's _resolve_bind() returns
            # 127.0.0.1 for `lan` mode (only `public` mode auto-binds
            # 0.0.0.0).  Docker NAT then can't reach uvicorn from the
            # host: TCP RST on every host-side connection.  Real users
            # in `lan` mode set WORTHLESS_HOST explicitly to the LAN
            # iface; for the test container we want all interfaces so
            # the host-side httpx can reach the proxy through the
            # docker-published port.
            "-e",
            "WORTHLESS_HOST=0.0.0.0",
            "--read-only",
            "--tmpfs",
            "/tmp:noexec,nosuid",
            # WOR-466: sidecar stable-symlink lives at /run/worthless/sidecar.sock.
            # The image bakes /run/worthless root:worthless 0770 but Docker's
            # --tmpfs resets uid/gid to root:root — the probe (uid 10001) becomes
            # "other" with zero access → EACCES on stat.  Specifying
            # uid=0,gid=10001,mode=0770 restores the image intent: root owns,
            # worthless group (proxy + crypto) can rwx.
            "--tmpfs",
            "/run/worthless:uid=0,gid=10001,mode=0770",
            "-v",
            f"{name}-data:/data",
            "-v",
            f"{name}-secrets:/secrets",
            # WOR-310: drop all caps EXCEPT the six the runtime needs
            # *briefly* during the priv-drop dance.  The preexec_fn
            # clears the bounding set before exec, so the post-drop
            # process has zero caps anyway — same end-state as
            # --cap-drop=ALL.  The six:
            #   * SETUID / SETGID — setresuid/setresgid/setgroups
            #   * SETPCAP        — prctl(PR_CAPBSET_DROP)
            #   * DAC_OVERRIDE   — entrypoint bootstrap writes into
            #     /data which is owned by worthless-proxy (uid 10001);
            #     without DAC_OVERRIDE root is treated as "other"
            #     and mkdir /data/shard_a hits EACCES.
            #   * CHOWN          — entrypoint chowns bootstrap output
            #     to worthless-proxy after first boot.
            #   * FOWNER         — chmod fernet.key to 0400 after
            #     bootstrap touches a non-root-owned file.
            "--cap-drop=ALL",
            "--cap-add=SETUID",
            "--cap-add=SETGID",
            "--cap-add=SETPCAP",
            "--cap-add=DAC_OVERRIDE",
            "--cap-add=CHOWN",
            "--cap-add=FOWNER",
            "--security-opt=no-new-privileges",
            docker_image,
        ]
    )
    port = int(_run_ok(["docker", "port", name, "8787"]).rsplit(":", 1)[-1])
    try:
        if not wait_healthy(name):
            # Capture logs BEFORE _cleanup_container removes them; otherwise
            # CI shows only "did not become healthy" with no clue why the
            # entrypoint died.  See WOR-310 priv-drop dance: a stderr line
            # like ``setresuid: EPERM`` reveals an incompatible cap-drop;
            # ``WRTLS-114`` reveals a hardening assertion miss.
            logs = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                check=False,
            )
            inspect = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}} rc={{.State.ExitCode}}", name],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            raise AssertionError(
                f"Container {name} did not become healthy "
                f"(state: {inspect})\n"
                f"--- stdout ---\n{logs.stdout}\n"
                f"--- stderr ---\n{logs.stderr}"
            )
        yield name, port  # type: ignore[misc]
    finally:
        _cleanup_container(name)


@pytest.fixture()
def persistent_container(docker_image: str) -> tuple[str, int, str]:
    """Container with a named volume that survives stop/start."""
    name = f"worthless-e2e-persist-{uuid.uuid4().hex[:8]}"
    vol = f"worthless-e2e-data-{uuid.uuid4().hex[:8]}"
    # Pre-cleanup
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True)
    # Let Docker pick the host port to avoid bind conflicts on reruns
    _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::8787",
            "-e",
            "WORTHLESS_DEPLOY_MODE=lan",
            "-e",
            "WORTHLESS_ALLOW_INSECURE=true",
            # See container fixture: lan mode binds 127.0.0.1 by default;
            # we need 0.0.0.0 so docker NAT can reach uvicorn.
            "-e",
            "WORTHLESS_HOST=0.0.0.0",
            "-v",
            f"{vol}:/data",
            docker_image,
        ]
    )
    # Discover the assigned port
    port_out = _run_ok(["docker", "port", name, "8787"])
    port = int(port_out.strip().rsplit(":", 1)[-1])
    try:
        assert wait_healthy(name), f"Container {name} did not become healthy"
        yield name, port, vol  # type: ignore[misc]
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(
            ["docker", "volume", "rm", "-f", vol],
            capture_output=True,
        )


@pytest.fixture()
def compose_stack(docker_image: str) -> tuple[str, str]:
    """Run via docker-compose for volume separation tests.

    Uses a temporary override file to bind a dynamic host port instead
    of the hardcoded 8787 in deploy/docker-compose.yml, avoiding
    conflicts with other processes on the host.
    """
    project = f"worthless-e2e-{uuid.uuid4().hex[:8]}"
    compose_file = REPO_ROOT / "deploy" / "docker-compose.yml"
    env_file = REPO_ROOT / "deploy" / "docker-compose.env"
    override_file = REPO_ROOT / "deploy" / "docker-compose.override.yml"

    created_env = False
    if not env_file.exists():
        env_file.write_text(
            "WORTHLESS_DEPLOY_MODE=lan\n"
            "WORTHLESS_ALLOW_INSECURE=true\n"
            # Bind all interfaces so the host-side httpx in test_compose_*
            # can reach uvicorn through docker NAT (lan mode otherwise
            # binds 127.0.0.1 only — see deploy/start.py::_resolve_bind).
            "WORTHLESS_HOST=0.0.0.0\n"
        )
        created_env = True

    # Override port to dynamic to avoid bind conflicts
    override_file.write_text('services:\n  proxy:\n    ports:\n      - "127.0.0.1::8787"\n')

    try:
        _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-f",
                str(override_file),
                "-p",
                project,
                "up",
                "-d",
                "--build",
            ],
            cwd=str(REPO_ROOT),
        )

        container_name = f"{project}-proxy-1"
        assert wait_healthy(container_name, timeout=30), (
            f"Compose container {container_name} did not become healthy"
        )
        yield project, container_name  # type: ignore[misc]
    finally:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-f",
                str(override_file),
                "-p",
                project,
                "down",
                "-v",
                "--remove-orphans",
            ],
            capture_output=True,
            cwd=str(REPO_ROOT),
        )
        override_file.unlink(missing_ok=True)
        if created_env:
            env_file.unlink(missing_ok=True)


# ===================================================================
# Tier 1: Build
# ===================================================================


class TestBuild:
    """Image build and basic structure."""

    def test_image_builds(self, docker_image: str) -> None:
        """Image fixture succeeds -- proves the Dockerfile is valid."""
        assert docker_image == IMAGE_TAG

    def test_entrypoint_executable(self, docker_image: str) -> None:
        result = _run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "",
                docker_image,
                "test",
                "-x",
                "/entrypoint.sh",
            ]
        )
        assert result.returncode == 0

    def test_runs_as_non_root(self, container: tuple[str, int]) -> None:
        """The runtime PROCESSES (uvicorn + sidecar) must run as non-root.

        WOR-310 removed the static ``USER worthless`` directive so the
        entrypoint can start as root briefly to do the priv-drop dance
        (resolve uids, chown shares, setresuid).  After the dance,
        uvicorn runs as ``worthless-proxy`` (uid 10001) and the sidecar
        runs as ``worthless-crypto`` (uid 10002).  ``docker exec id``
        spawns a new shell which inherits the IMAGE's default user
        (root, since we dropped the USER directive) — that's expected
        and unrelated to the priv-drop.  We verify the SECURITY claim
        directly by walking ``/proc/<pid>/status`` for the uvicorn +
        sidecar runtime processes and asserting their Uid is non-zero.

        slim-bookworm has no ``ps``; we walk ``/proc`` from a busybox-
        compatible shell snippet that prints ``<pid> <uid> <comm>``
        per process.
        """
        name, _ = container
        result = docker_exec(
            name,
            [
                "sh",
                "-c",
                "for d in /proc/[0-9]*; do "
                'pid="${d##*/}"; '
                'comm=$(cat "$d/comm" 2>/dev/null) || continue; '
                'uid=$(awk "/^Uid:/{print \\$2; exit}" "$d/status" 2>/dev/null); '
                'echo "$pid $uid $comm"; '
                "done",
            ],
        )
        assert result.returncode == 0, (
            f"/proc walk failed: rc={result.returncode} stderr={result.stderr!r}"
        )
        # Match python (sidecar entrypoint is `python -m worthless.sidecar`)
        # AND uvicorn (proxy).  Tini (PID 1) is allowed to be root.
        runtime_lines = [
            line
            for line in result.stdout.splitlines()
            if any(needle in line.lower() for needle in ("uvicorn", "python"))
        ]
        assert runtime_lines, f"no uvicorn/python processes found; /proc walk:\n{result.stdout}"
        uids_seen: set[str] = set()
        for line in runtime_lines:
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            _pid, uid, _comm = parts
            assert uid != "0", (
                f"WOR-310 priv-drop failed: process running as uid=0:\n{line}\n"
                f"full /proc walk:\n{result.stdout}"
            )
            uids_seen.add(uid)
        # Two-uid topology: proxy (10001) and crypto sidecar (10002) MUST be
        # distinct.  A regression in spawn_sidecar / deploy/start.py that
        # silently drops both processes to the SAME non-root uid would pass
        # the bare uid != 0 check above while completely defeating the
        # ptrace / /proc/<pid>/mem wall this PR exists to enforce.  Pin the
        # exact uid pair here so the test fails loud on that regression.
        assert {"10001", "10002"}.issubset(uids_seen), (
            f"WOR-310 two-uid wall missing: expected both 10001 (proxy) and "
            f"10002 (crypto), saw uids {sorted(uids_seen)}.\n"
            f"full /proc walk:\n{result.stdout}"
        )


# ===================================================================
# Tier 2: Bootstrap
# ===================================================================


class TestBootstrap:
    """First-boot initialization checks."""

    def test_container_starts_healthy(self, container: tuple[str, int]) -> None:
        """Container fixture already asserts healthy -- this is explicit."""
        name, _ = container
        result = docker_exec(name, ["true"])
        assert result.returncode == 0

    def test_fernet_key_generated(self, container: tuple[str, int]) -> None:
        """Standalone container generates fernet.key in /data."""
        name, _ = container
        result = docker_exec(name, ["test", "-f", "/data/fernet.key"])
        assert result.returncode == 0, "fernet.key not found in /data"

    def test_db_initialized(self, container: tuple[str, int]) -> None:
        name, _ = container
        result = docker_exec(
            name,
            [
                "python",
                "-c",
                (
                    "import sqlite3; "
                    "c = sqlite3.connect('/data/worthless.db'); "
                    "tables = [r[0] for r in "
                    'c.execute("SELECT name FROM sqlite_master '
                    "WHERE type='table'\").fetchall()]; "
                    "print(tables)"
                ),
            ],
        )
        assert result.returncode == 0
        assert "shards" in result.stdout

    def test_fernet_key_permissions(self, container: tuple[str, int]) -> None:
        """fernet.key is worthless-crypto:worthless-crypto 0400 inside Docker.

        WOR-465 A4: unconditional lockdown — the sidecar (worthless-crypto)
        owns the key exclusively. Mode 0400 (owner-only) means the proxy uid
        (10001 = worthless-proxy) cannot open() the file even with group
        membership; only the sidecar uid (10002 = worthless-crypto) can read
        it. Owner is worthless-crypto (not root) so chown is load-bearing: the
        entrypoint fail-closed stat check exits 78 if a host bind-mount
        silently swallows the chown (e.g. macOS Docker Desktop, WSL /mnt/c).

        Bare-metal install.sh still uses 0400 single-uid (no group wall);
        tested in tests/test_bootstrap.py and test_cli_security_hardening.py.
        """
        name, _ = container
        # GNU coreutils stat inside Debian slim
        result = docker_exec(name, ["stat", "-c", "%a %U:%G", "/data/fernet.key"])
        assert result.returncode == 0
        assert result.stdout.strip() == "400 worthless-crypto:worthless-crypto", (
            f"WOR-465 A4: fernet.key must be worthless-crypto:worthless-crypto 0400 "
            f"in Docker (unconditional — no operator flag required). "
            f"Got {result.stdout.strip()!r}."
        )


# ===================================================================
# Tier 3: Persistence
# ===================================================================


class TestPersistence:
    """Data survives container restart."""

    def test_data_persists_across_restart(self, persistent_container: tuple[str, int, str]) -> None:
        name, _port, _vol = persistent_container

        # Enroll a fake key
        key = fake_openai_key()
        enroll = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                name,
                "worthless",
                "enroll",
                "--alias",
                "persist-test",
                "--key-stdin",
                "--provider",
                "openai",
            ],
            input=key,
            capture_output=True,
            text=True,
        )
        assert enroll.returncode == 0, f"enroll failed: {enroll.stderr}"

        # Stop and start (not rm)
        _run(["docker", "stop", name])
        _run(["docker", "start", name])
        assert wait_healthy(name, timeout=30), "Not healthy after restart"

        # Verify the alias still exists
        status = docker_exec(
            name,
            [
                "worthless",
                "--json",
                "status",
            ],
        )
        assert status.returncode == 0, f"status failed: {status.stderr}"
        assert "persist-test" in status.stdout


# ===================================================================
# Tier 4: Lifecycle
# ===================================================================


class TestLifecycle:
    """Enroll + proxy health."""

    def test_lock_and_healthz(self, container: tuple[str, int]) -> None:
        """Locking a key while the proxy is live + hitting /healthz works.

        Renamed from ``test_enroll_and_healthz`` because the underlying
        CLI command was renamed in 8rqs: ``worthless enroll`` was
        replaced with ``worthless lock --env``.  The old test asserted
        ``enroll.returncode == 0`` against a non-existent subcommand,
        which Typer printed as "No such command" but still returned
        rc=0 in some old releases — so the assertion never fired and
        the test silently exercised nothing before hitting /healthz.

        WOR-310 nuance: ``docker exec`` defaults to the IMAGE's user.
        Since we dropped ``USER worthless`` for the priv-drop entry,
        we explicitly run as ``worthless-proxy`` (uid 10001) so the
        ``worthless.db`` write owner matches the live proxy uid.
        """
        name, port = container

        # Write a fake .env, then lock it as worthless-proxy.  Mirrors
        # the openclaw_stack pattern in test_openclaw_e2e.py — the
        # supported 8rqs lock-time flow.
        key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={key}"
        write = subprocess.run(  # noqa: S603, S607
            [
                "docker",
                "exec",
                "-i",
                "--user",
                "worthless-proxy",
                name,
                "sh",
                "-c",
                "cat > /tmp/.env",
            ],
            input=env_content,
            capture_output=True,
            text=True,
        )
        assert write.returncode == 0, f"failed to write .env: {write.stderr}"

        # Sanity check: /healthz works BEFORE we touch the DB.  If this
        # fails, the failure is NOT lock-related — we want full
        # diagnostics (proxy logs + container state) so CI is
        # self-explanatory next iteration.
        try:
            pre = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5.0)
        except httpx.HTTPError as exc:
            logs = subprocess.run(  # noqa: S603, S607
                ["docker", "logs", "--tail", "200", name],
                capture_output=True,
                text=True,
                check=False,
            )
            inspect = subprocess.run(  # noqa: S603, S607
                [
                    "docker",
                    "inspect",
                    "--format",
                    "status={{.State.Status}} health={{.State.Health.Status}} "
                    "rc={{.State.ExitCode}}",
                    name,
                ],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            raise AssertionError(
                f"baseline /healthz failed pre-lock: {exc}\n"
                f"--- container state: {inspect}\n"
                f"--- proxy logs (last 200 lines) ---\n{logs.stdout}\n{logs.stderr}"
            ) from exc
        assert pre.status_code == 200, (
            f"baseline /healthz failed pre-lock: {pre.status_code} {pre.text!r}"
        )

        lock = subprocess.run(  # noqa: S603, S607
            [
                "docker",
                "exec",
                "--user",
                "worthless-proxy",
                name,
                "worthless",
                "lock",
                "--env",
                "/tmp/.env",
            ],
            capture_output=True,
            text=True,
        )
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Hit healthz post-lock.  If this fails, capture proxy logs so
        # CI shows what made uvicorn drop the connection.
        try:
            resp = httpx.get(
                f"http://127.0.0.1:{port}/healthz",
                timeout=5.0,
            )
        except httpx.HTTPError as exc:
            logs = subprocess.run(  # noqa: S603, S607
                ["docker", "logs", "--tail", "100", name],
                capture_output=True,
                text=True,
                check=False,
            )
            raise AssertionError(
                f"post-lock /healthz failed: {exc}\n"
                f"--- pre-lock /healthz returned: {pre.status_code} {pre.text!r}\n"
                f"--- lock stdout ---\n{lock.stdout}\n"
                f"--- lock stderr ---\n{lock.stderr}\n"
                f"--- proxy logs (last 100 lines) ---\n{logs.stdout}\n{logs.stderr}"
            ) from exc
        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body


# ===================================================================
# Tier 4a: Wave 6 features (default command, --json, --version)
# ===================================================================


class TestWave6Features:
    """Wave 6 features tested inside Docker — real container, no mocks."""

    def test_version_matches_package_metadata(self, container: tuple[str, int]) -> None:
        """worthless --version reports the installed package version inside the container."""
        from importlib.metadata import version as pkg_version

        name, _ = container
        result = docker_exec(name, ["worthless", "--version"])
        assert result.returncode == 0, f"--version failed: {result.stderr}"
        assert pkg_version("worthless") in result.stdout

    def test_json_mode_read_only(self, container: tuple[str, int]) -> None:
        """worthless --json returns structured state, never writes.

        The container proxy is running (entrypoint starts it), but no
        keys are enrolled. --json must report this without modifying
        any state.
        """
        name, _ = container
        result = docker_exec(name, ["worthless", "--json"])
        assert result.returncode == 0, f"--json failed: {result.stderr}"
        import json

        data = json.loads(result.stdout)
        assert "enrolled" in data
        assert "proxy" in data

    def test_json_mode_after_enroll(self, container: tuple[str, int]) -> None:
        """worthless --json reflects enrollment state after enroll."""
        name, _ = container
        key = fake_openai_key()

        # Enroll a key
        enroll = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                name,
                "worthless",
                "enroll",
                "--alias",
                "json-test",
                "--key-stdin",
                "--provider",
                "openai",
            ],
            input=key,
            capture_output=True,
            text=True,
        )
        assert enroll.returncode == 0, f"enroll failed: {enroll.stderr}"

        # Now --json should show enrolled
        result = docker_exec(name, ["worthless", "--json"])
        assert result.returncode == 0, f"--json failed: {result.stderr}"
        import json

        data = json.loads(result.stdout)
        assert data["enrolled"] is True

    def test_status_json_has_keys(self, container: tuple[str, int]) -> None:
        """worthless status --json shows enrolled key details."""
        name, _ = container
        key = fake_openai_key()

        # Enroll
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                name,
                "worthless",
                "enroll",
                "--alias",
                "status-test",
                "--key-stdin",
                "--provider",
                "openai",
            ],
            input=key,
            capture_output=True,
            text=True,
            check=True,
        )

        result = docker_exec(name, ["worthless", "--json", "status"])
        assert result.returncode == 0, f"status --json failed: {result.stderr}"
        assert "status-test" in result.stdout

    def test_no_key_chars_in_default_output(self, container: tuple[str, int]) -> None:
        """Default command output contains no key characters (SR-NEW-15).

        Lock a key via the .env flow, then verify the default command
        output never leaks key material.
        """
        name, _ = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)

        # Run default command with --yes
        result = docker_exec(name, ["sh", "-c", "cd /tmp && worthless --yes"])
        combined = result.stdout + result.stderr

        # Full key must never appear
        assert fake_key not in combined, "Full API key leaked in default command output"

        # 12-char body substrings must not appear
        body = fake_key[8:]  # after "sk-proj-" prefix
        for i in range(0, len(body) - 12):
            chunk = body[i : i + 12]
            assert chunk not in combined, f"Key material leaked in output: ...{chunk}..."


# ===================================================================
# Tier 4b: Lock + Wrap E2E flow (WOR-170)
# ===================================================================


def _write_env_to_container(
    container: str, env_content: str, dest: str = "/tmp/.env"
) -> subprocess.CompletedProcess[str]:
    """Write a .env file into a running container via docker exec + sh."""
    return subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            f"cat > {dest} << 'ENVEOF'\n{env_content}\nENVEOF",
        ],
        capture_output=True,
        text=True,
    )


class TestLockWrapE2E:
    """Tier 4b: Lock + Wrap flow inside Docker.

    Verifies the CORE user journey works end-to-end in the container:
    lock a .env file, then wrap a child process that routes through proxy.
    These tests satisfy WOR-170 AC: "docker compose up produces working
    proxy that handles lock+wrap flow."
    """

    def test_lock_enrolls_key_in_container(self, container: tuple[str, int]) -> None:
        """Lock rewrites .env with shard-A and stores enrollment in DB.

        What it tests: The ``worthless lock`` command inside the container
        successfully splits an API key, stores shard-B in DB, and replaces
        the original key in .env with format-preserving shard-A.

        Why it matters: This is the first step of the user journey. If lock
        fails inside Docker, the entire product is broken.

        Failure looks like: .env still contains the original key, or DB has
        no enrollment record.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        # Write .env into the container
        write_result = _write_env_to_container(name, env_content)
        assert write_result.returncode == 0, f"Failed to write .env: {write_result.stderr}"

        # Run lock
        lock_result = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock_result.returncode == 0, (
            f"'worthless lock' failed (exit {lock_result.returncode}): {lock_result.stderr}"
        )

        # Assert: .env was rewritten (original key is gone)
        cat_result = docker_exec(name, ["cat", "/tmp/.env"])
        assert cat_result.returncode == 0
        assert fake_key not in cat_result.stdout, (
            "Original API key still present in .env after lock -- decoy replacement failed"
        )

        # Assert: no shard_a files on disk (SR-09: shard-A goes to .env only)
        ls_result = docker_exec(name, ["ls", "/data/shard_a/"])
        if ls_result.returncode == 0:
            shard_files = ls_result.stdout.strip()
            assert not shard_files, f"Unexpected shard_a files after lock: {shard_files}"
        # If dir doesn't exist at all, that's also correct (SR-09)

        # Assert: DB has enrollment record
        db_check = docker_exec(
            name,
            [
                "python",
                "-c",
                (
                    "import sqlite3; "
                    "c = sqlite3.connect('/data/worthless.db'); "
                    "rows = c.execute('SELECT COUNT(*) FROM shards').fetchone(); "
                    "print(rows[0])"
                ),
            ],
        )
        assert db_check.returncode == 0
        count = int(db_check.stdout.strip())
        assert count > 0, "No enrollment records in DB after lock"

    def test_lock_writes_base_url_to_env(self, container: tuple[str, int]) -> None:
        """After lock, .env has the per-enrollment ``*_BASE_URL`` written by
        ``worthless lock``, and a child sourcing .env sees the alias-qualified
        URL pointing at the daemon's port.

        v0.3.4 contract (worthless-djoe): ``worthless wrap`` and ``worthless
        up`` are alternatives, not combinable on the same port. The Docker
        container's primary process IS ``worthless up`` (the daemon),
        so we test the daemon path directly: lock writes BASE_URL to .env,
        child sources .env, child sees the right URL pointing at the
        running daemon. ``worthless wrap`` inside an ``up`` container is
        nonsensical post-v0.3.4 — the pre-spawn check correctly rejects
        it. Pre-v0.3.4 wrap silently bound a random port and the test
        only passed because traffic went through the daemon anyway.

        Pre-8rqs (v0.3.2) the test read ``os.environ['OPENAI_BASE_URL']``
        directly because wrap synthesised it into the child env. Post-8rqs
        the contract moved to .env; this test follows.

        Failure looks like: BASE_URL not pointing at 127.0.0.1, or the
        var is missing from the sourced environment.

        Closes worthless-1td5 (Phase-8 docker-e2e drift).
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        # Lock first
        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Source .env directly (no `worthless wrap` wrapper — the container's
        # daemon already owns port 8787; wrap correctly refuses to start
        # a second proxy on the same port post-v0.3.4).
        result = docker_exec(
            name,
            [
                "sh",
                "-c",
                "set -a; . /tmp/.env; set +a; "
                "python -c \"import os; print(os.environ.get('OPENAI_BASE_URL', 'MISSING'))\"",
            ],
        )
        assert result.returncode == 0, f"sourcing .env failed: {result.stderr}"
        base_url = result.stdout.strip()
        assert base_url != "MISSING", (
            "OPENAI_BASE_URL not in .env after lock — the lock-side rewrite "
            "didn't fire (or wrote a different var name)"
        )
        # Tightened (CodeRabbit catch): exact match on the alias-qualified URL
        # instead of just "127.0.0.1 in base_url". A regression that drops
        # /{alias}/v1 from the rewritten URL would still pass the loose check
        # because localhost would still appear, but the proxy wouldn't route.
        alias = _make_alias("openai", fake_key)
        expected_base_url = f"http://127.0.0.1:8787/{alias}/v1"
        assert base_url == expected_base_url, (
            f"OPENAI_BASE_URL mismatch. expected={expected_base_url!r} actual={base_url!r}"
        )

    def test_proxy_reachable_after_lock(self, container: tuple[str, int]) -> None:
        """After lock, the daemon's proxy responds on /healthz.

        What it tests: The container's daemon (``worthless up`` running
        as PID 1) responds to /healthz on port 8787 — the same port lock
        wrote into .env.

        Why it matters: If the proxy is unreachable, the child can't
        proxy any LLM calls. This is the daemon-deployment smoke check.

        Renamed from ``test_proxy_reachable_during_wrap`` (v0.3.4): the
        old name implied wrap was the test subject, but in Docker the
        daemon owns the port. Wrap inside the daemon container hits the
        v0.3.4 pre-spawn check and refuses (correctly).

        Failure looks like: /healthz returns non-200 or connection refused.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Source .env, extract port, hit /healthz on the daemon directly.
        result = docker_exec(
            name,
            [
                "sh",
                "-c",
                (
                    "set -a; . /tmp/.env; set +a; "
                    'PORT=$(python -c "'
                    "from urllib.parse import urlparse; import os; "
                    "url = os.environ.get('OPENAI_BASE_URL', ''); "
                    "print(urlparse(url).port or 8787)"
                    '"); '
                    "for i in 1 2 3 4 5; do "
                    '  RESP=$(python -c "'
                    "import urllib.request; "
                    "r = urllib.request.urlopen('http://127.0.0.1:'+'$PORT'+'/healthz'); "
                    "print(r.status)"
                    '") && break || sleep 1; '
                    "done; "
                    'echo "HEALTH_STATUS=$RESP"'
                ),
            ],
        )
        assert result.returncode == 0, f"healthz probe failed: {result.stderr}"
        assert "HEALTH_STATUS=200" in result.stdout, (
            f"Proxy /healthz not reachable on daemon port. Output: {result.stdout}"
        )

    def test_lock_then_request_full_flow(self, container: tuple[str, int]) -> None:
        """Combined flow: lock -> child request routes through the daemon proxy.

        What it tests: After locking, a child sourcing .env can make an
        HTTP request whose path reaches the daemon proxy. The proxy will
        return an error (fake key, no real upstream call) but the
        REQUEST PATH must work end-to-end.

        Why it matters: This is the daemon-deployment user journey. Even
        without a real API key, the proxy receiving the request proves
        the plumbing works.

        Renamed from ``test_lock_wrap_full_flow`` (v0.3.4): the old name
        implied wrap was the carrier, but in Docker the daemon owns the
        port and wrap inside the daemon container is rejected by the
        pre-spawn check (correctly — they're alternatives).

        Failure looks like: Connection refused (daemon not running) or
        the request never reaches the proxy.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Pass the Python source via heredoc on stdin (`python3 -`) instead
        # of `python -c "..."`. `python -c` requires the source as a
        # shell-quoted string, and `repr()`-ing a multi-line script puts
        # literal `\n` characters into the shell argument that Python
        # interprets as line-continuation followed by garbage.
        py_snippet = (
            "import os, urllib.request, urllib.error, json\n"
            "base = os.environ['OPENAI_BASE_URL']\n"
            "key = os.environ.get('OPENAI_API_KEY', 'fake')\n"
            "url = f'{base}/chat/completions'\n"
            "msg = [{'role': 'user', 'content': 'hi'}]\n"
            "data = json.dumps({'model': 'gpt-4', 'messages': msg}).encode()\n"
            "hdrs = {'Content-Type': 'application/json', "
            "'Authorization': f'Bearer {key}'}\n"
            "req = urllib.request.Request(url, data=data, headers=hdrs)\n"
            "try:\n"
            "    urllib.request.urlopen(req)\n"
            "    print('STATUS=200')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(f'STATUS={e.code}')\n"
            "except urllib.error.URLError as e:\n"
            "    print(f'ERROR={e.reason}')\n"
        )
        shell_cmd = f"set -a; . /tmp/.env; set +a; python3 - <<'PYEOF'\n{py_snippet}PYEOF\n"
        result = docker_exec(name, ["sh", "-c", shell_cmd])
        assert result.returncode == 0, f"daemon request failed: {result.stderr}"
        output = result.stdout.strip()
        # The proxy MUST receive the request (not connection refused).
        # Any HTTP status code (even 4xx/5xx) means the daemon handled it.
        assert output.startswith("STATUS="), (
            f"Request did not reach proxy. Expected STATUS=<code>, got: {output}"
        )

    def test_wrap_inside_daemon_container_is_rejected(self, container: tuple[str, int]) -> None:
        """v0.3.4 contract: ``worthless wrap`` inside a ``worthless up`` container
        fails fast with the actionable diagnostic.

        Why this test exists: pre-v0.3.4 wrap silently bound a random port
        the child couldn't reach; the existing tests passed by accident
        because traffic went through the daemon. v0.3.4 makes wrap
        correctly refuse a second proxy on the same machine. This test
        pins the correct behavior so a regression that re-introduces
        the silent-double-spawn bug fails loudly.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Try to start wrap on top of the running daemon. Should fail.
        wrap_result = docker_exec(name, ["worthless", "wrap", "--", "echo", "should-not-run"])
        assert wrap_result.returncode != 0, (
            "wrap should refuse to start when the daemon already owns the port; "
            f"got returncode=0 with output: {wrap_result.stdout}"
        )
        # Diagnostic should name `worthless up` so the user knows the cause.
        combined_out = (wrap_result.stdout or "") + (wrap_result.stderr or "")
        assert "worthless up" in combined_out, (
            f"wrap's pre-spawn check should name `worthless up`. Got: {combined_out}"
        )
        assert "8787" in combined_out, (
            f"diagnostic should name the contested port. Got: {combined_out}"
        )


class TestDockerEdgeCases:
    """Edge cases for lock/wrap/unlock inside Docker containers.

    Tests unusual but realistic scenarios that could cause data loss,
    orphan processes, or confusing error messages.
    """

    def test_unlock_then_proxy_rejects_requests(self, container: tuple[str, int]) -> None:
        """After unlock removes enrollments, proxy has no keys to reconstruct.

        What it tests: After unlocking all keys, the proxy starts but
        returns an error on API requests (no shards to reconstruct from).

        Why it matters: Users who unlock and then try to use the proxy
        should get a clear error, not a hang or crash.

        Failure looks like: Proxy crashes, hangs, or returns 200 with
        garbage data.
        """
        name, port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        # Lock first
        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Unlock
        unlock = docker_exec(name, ["worthless", "unlock", "--env", "/tmp/.env"])
        assert unlock.returncode == 0, f"unlock failed: {unlock.stderr}"

        # Verify no shards remain
        db_check = docker_exec(
            name,
            [
                "python",
                "-c",
                (
                    "import sqlite3; "
                    "c = sqlite3.connect('/data/worthless.db'); "
                    "rows = c.execute('SELECT COUNT(*) FROM shards').fetchone(); "
                    "print(rows[0])"
                ),
            ],
        )
        assert db_check.returncode == 0
        count = int(db_check.stdout.strip())
        assert count == 0, f"Shards still in DB after unlock: {count}"

    def test_wrap_child_spawn_failure(self, container: tuple[str, int]) -> None:
        """wrap with a nonexistent binary exits non-zero, no orphan proxy.

        Why it matters: Orphan proxy processes would leak ports and
        memory inside the container.

        Note: The container runs its own uvicorn (entrypoint), so we
        count processes BEFORE and AFTER wrap — the count must not
        increase.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)
        lock = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

        # Count uvicorn processes BEFORE wrap (container's own proxy)
        _uvicorn_count_cmd = [
            "sh",
            "-c",
            "ls /proc/*/cmdline 2>/dev/null | xargs grep -l '[u]vicorn' 2>/dev/null | wc -l",
        ]
        before = docker_exec(name, _uvicorn_count_cmd)
        before_count = int(before.stdout.strip()) if before.returncode == 0 else 0

        # Wrap a nonexistent binary
        wrap_result = docker_exec(
            name,
            ["worthless", "wrap", "--", "/nonexistent/binary"],
        )
        assert wrap_result.returncode != 0, (
            "wrap should exit non-zero when child binary does not exist"
        )

        # Count AFTER — must not have increased
        after = docker_exec(name, _uvicorn_count_cmd)
        after_count = int(after.stdout.strip()) if after.returncode == 0 else 0
        assert after_count <= before_count, (
            f"Orphan proxy: uvicorn count went from {before_count} to {after_count}"
        )

    def test_lock_idempotent(self, container: tuple[str, int]) -> None:
        """Running lock twice on the same .env succeeds (already-locked keys skipped).

        What it tests: Idempotency of the lock command -- running it
        again on an already-locked .env should not error or double-enroll.

        Why it matters: Users may run lock multiple times (habit, scripts,
        CI). Double-enrollment would corrupt the shard mapping.

        Failure looks like: Second lock exits non-zero, or DB has
        duplicate enrollment records.
        """
        name, _port = container
        fake_key = fake_openai_key()
        env_content = f"OPENAI_API_KEY={fake_key}\n"

        _write_env_to_container(name, env_content)

        # First lock
        lock1 = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock1.returncode == 0, f"first lock failed: {lock1.stderr}"

        # Count enrollments
        count1_result = docker_exec(
            name,
            [
                "python",
                "-c",
                (
                    "import sqlite3; "
                    "c = sqlite3.connect('/data/worthless.db'); "
                    "print(c.execute('SELECT COUNT(*) FROM shards').fetchone()[0])"
                ),
            ],
        )
        count1 = int(count1_result.stdout.strip())

        # Second lock (should be idempotent)
        lock2 = docker_exec(name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock2.returncode == 0, f"second lock failed (not idempotent): {lock2.stderr}"

        # Count enrollments again -- should be same
        count2_result = docker_exec(
            name,
            [
                "python",
                "-c",
                (
                    "import sqlite3; "
                    "c = sqlite3.connect('/data/worthless.db'); "
                    "print(c.execute('SELECT COUNT(*) FROM shards').fetchone()[0])"
                ),
            ],
        )
        count2 = int(count2_result.stdout.strip())
        assert count2 == count1, (
            f"Double enrollment detected: {count1} shards after first lock, {count2} after second"
        )

    def test_container_read_only_filesystem(self, container: tuple[str, int]) -> None:
        """Writes to /data succeed but writes to /app fail (read-only root).

        What it tests: The container filesystem is read-only except for
        the /data volume mount.

        Why it matters: Read-only root prevents attackers from modifying
        application code or installing persistence mechanisms.

        Failure looks like: Writing to /app succeeds (filesystem not
        read-only).
        """
        name, _port = container

        # /data should be writable
        data_write = docker_exec(name, ["touch", "/data/test-rw-check"])
        assert data_write.returncode == 0, (
            f"/data should be writable but write failed: {data_write.stderr}"
        )
        # Clean up
        docker_exec(name, ["rm", "-f", "/data/test-rw-check"])

        # Root filesystem should be read-only. Write to /usr which is
        # always root-owned and not a mount/tmpfs — if this succeeds,
        # --read-only is not active. (The standalone container fixture
        # now passes --read-only, so this is a real test.)
        usr_write = docker_exec(name, ["touch", "/usr/test-ro-check"])
        assert usr_write.returncode != 0, (
            "/usr should not be writable -- container root filesystem is not "
            "read-only. Ensure container runs with --read-only flag."
        )


# ===================================================================
# Tier 5: Security (compose-specific)
# ===================================================================


class TestComposeSecurity:
    """Compose stack security hardening."""

    def test_compose_fernet_on_secrets_volume(self, compose_stack: tuple[str, str]) -> None:
        _project, cname = compose_stack
        # Compose sets WORTHLESS_FERNET_KEY_PATH=/secrets/fernet.key
        result = docker_exec(cname, ["test", "-f", "/secrets/fernet.key"])
        assert result.returncode == 0, "fernet.key not on /secrets volume"
        # Must NOT be on /data
        result = docker_exec(cname, ["test", "-f", "/data/fernet.key"])
        assert result.returncode != 0, "fernet.key should not be on /data in compose mode"

    def test_compose_read_only_filesystem(self, compose_stack: tuple[str, str]) -> None:
        _project, cname = compose_stack
        result = docker_exec(cname, ["touch", "/etc/test"])
        assert result.returncode != 0, "Filesystem should be read-only"
        assert "read-only" in result.stderr.lower() or "read only" in result.stderr.lower()

    def test_compose_non_root(self, compose_stack: tuple[str, str]) -> None:
        """Same as TestBuild::test_runs_as_non_root but for the compose stack.

        slim-bookworm has no ``ps``; we walk ``/proc`` and assert the
        runtime processes (uvicorn + python sidecar) are non-root.
        """
        _project, cname = compose_stack
        result = docker_exec(
            cname,
            [
                "sh",
                "-c",
                "for d in /proc/[0-9]*; do "
                'pid="${d##*/}"; '
                'comm=$(cat "$d/comm" 2>/dev/null) || continue; '
                'uid=$(awk "/^Uid:/{print \\$2; exit}" "$d/status" 2>/dev/null); '
                'echo "$pid $uid $comm"; '
                "done",
            ],
        )
        assert result.returncode == 0, (
            f"/proc walk failed: rc={result.returncode} stderr={result.stderr!r}"
        )
        runtime_lines = [
            line
            for line in result.stdout.splitlines()
            if any(needle in line.lower() for needle in ("uvicorn", "python"))
        ]
        assert runtime_lines, f"no runtime processes; /proc walk:\n{result.stdout}"
        uids_seen: set[str] = set()
        for line in runtime_lines:
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            _pid, uid, _comm = parts
            assert uid != "0", (
                f"WOR-310 compose priv-drop failed: process at uid=0:\n{line}\n"
                f"full /proc walk:\n{result.stdout}"
            )
            uids_seen.add(uid)
        # Two-uid topology check (mirrors test_runs_as_non_root): both
        # 10001 (proxy) and 10002 (crypto) must appear as distinct uids.
        # A same-uid drop would pass the uid != 0 check but defeat the
        # kernel uid wall — fail loud here instead.
        assert {"10001", "10002"}.issubset(uids_seen), (
            f"WOR-310 compose two-uid wall missing: expected both 10001 and "
            f"10002, saw {sorted(uids_seen)}.\nfull /proc walk:\n{result.stdout}"
        )


class TestSDKSmokeDocker:
    """Smoke: SDKs on the host can reach the production Docker image's proxy.

    Guards against regressions in the production image's route dispatch —
    e.g., if the Dockerfile stops shipping uvicorn or the worthless CLI,
    this catches it before release. Does NOT prove round-trip round-trip
    correctness; that's the Compose lane's job.

    Design note: plan originally called for in-container pip install of
    the SDKs, but the container's /tmp is mounted noexec (per the
    container fixture at line 179) and both openai and anthropic pull
    in Rust-compiled extensions (jiter, tokenizers) that can't import
    from noexec tmpfs. Running the SDKs from the host against the
    containerized proxy proves the same thing — "the image serves SDK
    requests" — without fighting the tmpfs policy.
    """

    def _enroll_fake_key(self, container_name: str, env_var: str, fake_key: str) -> None:
        env_content = f"{env_var}={fake_key}"
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "sh",
                "-c",
                f"cat > /tmp/.env << 'ENVEOF'\n{env_content}\nENVEOF",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        lock = docker_exec(container_name, ["worthless", "lock", "--env", "/tmp/.env"])
        assert lock.returncode == 0, f"lock failed: {lock.stderr}"

    def _read_shard_a(self, container_name: str, env_var: str) -> str:
        result = docker_exec(
            container_name,
            ["sh", "-c", f"grep '^{env_var}=' /tmp/.env | cut -d= -f2-"],
        )
        assert result.returncode == 0
        return result.stdout.strip()

    def test_openai_sdk_reaches_proxy_from_host(self, container: tuple[str, int]) -> None:
        name, port = container
        fake_key = fake_openai_key()
        alias = _make_alias("openai", fake_key)

        self._enroll_fake_key(name, "OPENAI_API_KEY", fake_key)
        shard_a = self._read_shard_a(name, "OPENAI_API_KEY")
        assert shard_a != fake_key
        assert shard_a.startswith("sk-")

        client = openai.OpenAI(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{port}/{alias}/v1",
        )
        with pytest.raises(openai.APIError) as exc:
            client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        err_name = type(exc.value).__name__
        err_str = str(exc.value).lower()
        assert "connectionerror" != err_name, (
            f"SDK raised raw ConnectionError — proxy unreachable: {exc.value}"
        )
        assert "traceback" not in err_str
        assert "worthless" not in err_str

    def test_anthropic_sdk_reaches_proxy_from_host(self, container: tuple[str, int]) -> None:
        name, port = container
        fake_key = fake_anthropic_key()
        alias = _make_alias("anthropic", fake_key)

        self._enroll_fake_key(name, "ANTHROPIC_API_KEY", fake_key)
        shard_a = self._read_shard_a(name, "ANTHROPIC_API_KEY")
        assert shard_a != fake_key
        assert shard_a.startswith("sk-ant-")

        client = anthropic.Anthropic(
            api_key=shard_a,
            base_url=f"http://127.0.0.1:{port}/{alias}",
        )
        with pytest.raises(anthropic.APIError) as exc:
            client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        err_name = type(exc.value).__name__
        err_str = str(exc.value).lower()
        assert "connectionerror" != err_name
        assert "traceback" not in err_str
        assert "worthless" not in err_str

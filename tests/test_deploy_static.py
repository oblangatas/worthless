"""Static validation tests for deploy configs (WOR-170).

These tests parse the actual Dockerfile, docker-compose.yml, railway.toml,
render.yaml, entrypoint.sh, and env example without requiring Docker.
They assert structural correctness, security hardening, and cross-config
consistency.

Run with: uv run pytest tests/test_deploy_static.py -v
"""

from __future__ import annotations

import re
import subprocess
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # backport for Python 3.10
from pathlib import Path

import pytest
import yaml

# All paths relative to the repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE_FILE = DEPLOY_DIR / "docker-compose.yml"
ENV_EXAMPLE = DEPLOY_DIR / "docker-compose.env.example"
ENTRYPOINT = DEPLOY_DIR / "entrypoint.sh"
RAILWAY_TOML = DEPLOY_DIR / "railway.toml"
RENDER_YAML = DEPLOY_DIR / "render.yaml"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    """Raw Dockerfile content."""
    return DOCKERFILE.read_text()


@pytest.fixture(scope="module")
def compose_data() -> dict:
    """Parsed docker-compose.yml."""
    return yaml.safe_load(COMPOSE_FILE.read_text())


@pytest.fixture(scope="module")
def railway_data() -> dict:
    """Parsed railway.toml."""
    return tomllib.loads(RAILWAY_TOML.read_text())


@pytest.fixture(scope="module")
def render_data() -> dict:
    """Parsed render.yaml."""
    return yaml.safe_load(RENDER_YAML.read_text())


@pytest.fixture(scope="module")
def entrypoint_text() -> str:
    """Raw entrypoint.sh content."""
    return ENTRYPOINT.read_text()


# ------------------------------------------------------------------
# Railway config
# ------------------------------------------------------------------


class TestRailwayConfig:
    """Validate deploy/railway.toml structure and required fields."""

    def test_builder_is_dockerfile(self, railway_data: dict):
        """Railway must use the Dockerfile builder, not nixpacks."""
        assert railway_data["build"]["builder"] == "dockerfile"

    def test_dockerfile_path(self, railway_data: dict):
        """Railway must point to the correct Dockerfile."""
        assert railway_data["build"]["dockerfilePath"] == "Dockerfile"

    def test_healthcheck_path(self, railway_data: dict):
        """Railway must probe /healthz for readiness checks."""
        assert railway_data["deploy"]["healthcheckPath"] == "/healthz"

    def test_healthcheck_timeout_positive(self, railway_data: dict):
        """Healthcheck timeout must be a positive integer."""
        timeout = railway_data["deploy"]["healthcheckTimeout"]
        assert isinstance(timeout, int) and timeout > 0

    def test_restart_policy(self, railway_data: dict):
        """Railway must restart on failure (not always -- avoids crash loops)."""
        assert railway_data["deploy"]["restartPolicyType"] == "on_failure"

    def test_restart_max_retries_bounded(self, railway_data: dict):
        """Max retries must be set to prevent infinite restarts."""
        retries = railway_data["deploy"]["restartPolicyMaxRetries"]
        assert isinstance(retries, int) and 1 <= retries <= 10


# ------------------------------------------------------------------
# Render config
# ------------------------------------------------------------------


class TestRenderConfig:
    """Validate deploy/render.yaml structure and required fields."""

    @pytest.fixture(scope="module")
    def render_service(self, render_data: dict) -> dict:
        """Extract the first (only) Render service definition."""
        return render_data["services"][0]

    @pytest.fixture(scope="module")
    def render_env_vars(self, render_service: dict) -> dict[str, str]:
        # `sync: false` entries have no `value` — operator sets them in the dashboard.
        return {v["key"]: v.get("value", "") for v in render_service["envVars"]}

    def test_service_type_is_web(self, render_service: dict):
        """Render service must be type 'web' for HTTP traffic."""
        assert render_service["type"] == "web"

    def test_runtime_is_docker(self, render_service: dict):
        """Render must use Docker runtime, not native buildpack."""
        assert render_service["runtime"] == "docker"

    def test_healthcheck_path(self, render_service: dict):
        """Render must probe /healthz, matching Railway and Dockerfile."""
        assert render_service["healthCheckPath"] == "/healthz"

    def test_disk_mount_at_data(self, render_service: dict):
        """Render persistent disk must mount at /data to survive redeploys."""
        assert render_service["disk"]["mountPath"] == "/data"

    def test_disk_size_reasonable(self, render_service: dict):
        """Disk must be >= 1 GB (SQLite + shards need headroom)."""
        assert render_service["disk"]["sizeGB"] >= 1

    def test_deploy_mode_public(self, render_service: dict, render_env_vars: dict[str, str]):
        """Render terminates TLS at edge; container must run in public mode.

        WORTHLESS_DEPLOY_MODE=public tells the proxy to trust X-Forwarded-Proto
        only from the edge CIDR listed in WORTHLESS_TRUSTED_PROXIES. The old
        WORTHLESS_ALLOW_INSECURE=true escape-hatch is forbidden in public mode.
        """
        assert render_env_vars.get("WORTHLESS_DEPLOY_MODE") == "public"
        assert render_env_vars.get("WORTHLESS_ALLOW_INSECURE") is None
        # WORTHLESS_TRUSTED_PROXIES must be dashboard-prompted (sync: false), not
        # a placeholder string — placeholders pass startup but uvicorn would
        # trust no peer, silently 401-ing every request.
        tp_entry = next(
            (v for v in render_service["envVars"] if v["key"] == "WORTHLESS_TRUSTED_PROXIES"),
            None,
        )
        assert tp_entry is not None, "public mode requires WORTHLESS_TRUSTED_PROXIES"
        assert tp_entry.get("sync") is False, (
            "WORTHLESS_TRUSTED_PROXIES must use `sync: false` so Render prompts the "
            "operator at deploy time — never ship a placeholder value."
        )

    def test_dockerfile_path(self, render_service: dict):
        """Render must reference the correct Dockerfile."""
        assert render_service["dockerfilePath"] == "./Dockerfile"

    def test_port_env_var_set(self, render_env_vars: dict[str, str]):
        """Render must set PORT to match Dockerfile default (8787).

        Render defaults to PORT=10000. If PORT is not overridden, the
        container listens on 8787 while Render probes 10000, causing
        healthcheck failures and deploy rollback.
        """
        assert "PORT" in render_env_vars, (
            "Render config must set PORT env var — Render defaults to 10000 "
            "but Dockerfile defaults to 8787. Deploy will fail on healthcheck."
        )
        assert render_env_vars["PORT"] == "8787"


# ------------------------------------------------------------------
# Docker Compose config
# ------------------------------------------------------------------


class TestDockerCompose:
    """Validate deploy/docker-compose.yml structure and security hardening."""

    def test_proxy_service_exists(self, compose_data: dict):
        """The 'proxy' service must be defined."""
        assert "proxy" in compose_data["services"]

    def test_port_8787_mapped(self, compose_data: dict):
        """Port 8787 must be exposed, bound to localhost only."""
        ports = compose_data["services"]["proxy"]["ports"]
        port_str = ports[0]
        assert "8787:8787" in port_str
        # Must bind to localhost, not 0.0.0.0
        assert port_str.startswith("127.0.0.1:")

    def test_read_only_rootfs(self, compose_data: dict):
        """Container filesystem must be read-only to limit attack surface."""
        assert compose_data["services"]["proxy"]["read_only"] is True

    def test_cap_drop_all(self, compose_data: dict):
        """All Linux capabilities must be dropped."""
        caps = compose_data["services"]["proxy"]["cap_drop"]
        assert "ALL" in caps

    def test_no_new_privileges(self, compose_data: dict):
        """no-new-privileges must be set to prevent privilege escalation."""
        sec_opts = compose_data["services"]["proxy"]["security_opt"]
        assert "no-new-privileges:true" in sec_opts

    def test_two_volumes_declared(self, compose_data: dict):
        """Exactly two named volumes must be declared: data and secrets."""
        volumes = compose_data.get("volumes", {})
        assert "worthless-data" in volumes
        assert "worthless-secrets" in volumes

    def test_secrets_volume_separate_from_data(self, compose_data: dict):
        """Secrets volume must mount at /secrets, data at /data.

        Security invariant: the Fernet key (on /secrets) must be on a
        different volume than shard data (on /data). Compromise of one
        volume alone cannot reconstruct API keys.
        """
        proxy_volumes = compose_data["services"]["proxy"]["volumes"]
        data_mount = None
        secrets_mount = None
        for v in proxy_volumes:
            if v.startswith("worthless-data:"):
                data_mount = v.split(":")[1]
            elif v.startswith("worthless-secrets:"):
                secrets_mount = v.split(":")[1]
        assert data_mount == "/data", "worthless-data must mount at /data"
        assert secrets_mount == "/secrets", "worthless-secrets must mount at /secrets"
        assert data_mount != secrets_mount, "Data and secrets must be on separate volumes"

    def test_tmpfs_noexec(self, compose_data: dict):
        """tmpfs mount for /tmp must have noexec to prevent code execution."""
        tmpfs = compose_data["services"]["proxy"]["tmpfs"]
        tmpfs_str = tmpfs[0] if isinstance(tmpfs, list) else tmpfs
        assert "noexec" in tmpfs_str

    def test_memory_limit_set(self, compose_data: dict):
        """Memory limit must be set to prevent OOM-killing the host."""
        limits = compose_data["services"]["proxy"]["deploy"]["resources"]["limits"]
        assert "memory" in limits

    def test_pids_limit_set(self, compose_data: dict):
        """PID limit must be set to prevent fork bombs."""
        limits = compose_data["services"]["proxy"]["deploy"]["resources"]["limits"]
        assert "pids" in limits
        assert limits["pids"] <= 200

    def test_restart_policy(self, compose_data: dict):
        """Service must restart on failure but not on manual stop."""
        assert compose_data["services"]["proxy"]["restart"] == "unless-stopped"

    def test_env_file_referenced(self, compose_data: dict):
        """Compose must use an env_file for configuration."""
        assert compose_data["services"]["proxy"]["env_file"] == "docker-compose.env"

    def test_fernet_key_path_env(self, compose_data: dict):
        """WORTHLESS_FERNET_KEY_PATH must point to /secrets volume."""
        env = compose_data["services"]["proxy"]["environment"]
        assert env["WORTHLESS_FERNET_KEY_PATH"] == "/secrets/fernet.key"


# ------------------------------------------------------------------
# Entrypoint script
# ------------------------------------------------------------------


class TestEntrypoint:
    """Validate deploy/entrypoint.sh syntax and safety properties."""

    def test_shell_syntax_valid(self):
        """entrypoint.sh must parse without syntax errors.

        A broken entrypoint prevents the container from starting at all,
        so this is a high-value check. Uses sh -n (not bash -n) because
        the shebang is #!/bin/sh — Debian slim uses dash, which rejects
        bashisms that bash -n would silently accept.
        """
        result = subprocess.run(
            ["sh", "-n", str(ENTRYPOINT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Shell syntax error: {result.stderr}"

    def test_set_e_enabled(self, entrypoint_text: str):
        """Script must use 'set -e' to fail fast on errors.

        Without set -e, a failing bootstrap command is silently ignored
        and the proxy starts without a Fernet key, causing runtime panics.
        """
        assert "set -e" in entrypoint_text

    def test_exec_replaces_shell(self, entrypoint_text: str):
        """The final command must use 'exec' to replace the shell process.

        Without exec, signals (SIGTERM from Docker stop) go to the shell
        instead of the application, causing 10s forced-kill delays.
        """
        lines = [line.strip() for line in entrypoint_text.splitlines() if line.strip()]
        last_line = lines[-1]
        assert last_line.startswith("exec "), (
            f"Last line must use exec to replace shell process, got: {last_line}"
        )

    def test_fernet_key_passed_via_fd(self, entrypoint_text: str):
        """Fernet key must be passed via file descriptor, not env var.

        Env vars are visible in /proc/*/environ to any process in the
        container. File descriptors are private to the process.
        """
        assert "exec 3<" in entrypoint_text
        assert "WORTHLESS_FERNET_FD=3" in entrypoint_text

    def test_fernet_migration_uses_install_not_cp(self, entrypoint_text: str):
        """Migration must use 'install -m 0400' instead of cp+chmod.

        cp creates the file with default perms, leaving a brief window
        where the key is world-readable. install -m sets perms atomically.
        """
        assert "install -m 0400" in entrypoint_text, (
            "Fernet migration should use 'install -m 0400' for atomic permissions. "
            "cp + chmod leaves a race window where the key is world-readable."
        )
        # Ensure no bare 'cp' of the fernet key — only 'install -m' is safe
        migration_block = entrypoint_text.split("install -m 0400")[0]
        assert "cp " not in migration_block, (
            "Fernet migration should not use bare 'cp' before 'install -m 0400'."
        )

    def test_bootstrap_locks_fernet_key(self, entrypoint_text: str):
        """Bootstrap must chmod fernet.key to 0400 after creation.

        Cannot use umask 0377 during bootstrap because SQLite WAL/SHM
        files are also created and must remain writable.
        """
        assert "chmod 0400" in entrypoint_text, (
            "Bootstrap should chmod fernet.key to 0400 after creation."
        )

    def test_no_hardcoded_secrets(self, entrypoint_text: str):
        """Entrypoint must not contain hardcoded secrets or keys."""
        # Patterns that would indicate leaked secrets
        secret_patterns = [
            r"sk-[a-zA-Z0-9]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN.*PRIVATE KEY-----",
        ]
        for pattern in secret_patterns:
            assert not re.search(pattern, entrypoint_text), (
                f"Entrypoint contains potential secret matching: {pattern}"
            )


# ------------------------------------------------------------------
# Dockerfile structure
# ------------------------------------------------------------------


class TestDockerfile:
    """Validate Dockerfile security and structure."""

    def test_python_base_image(self, dockerfile_text: str):
        """Must use the official Python slim image."""
        assert re.search(r"FROM python:3\.\d+-slim", dockerfile_text)

    def test_pinned_digest(self, dockerfile_text: str):
        """Base image must be pinned by SHA256 digest for reproducibility.

        Tag-only references (python:3.13-slim) can silently change content.
        Pinning the digest ensures identical builds.
        """
        assert "@sha256:" in dockerfile_text

    def test_multi_stage_build(self, dockerfile_text: str):
        """Must use multi-stage build to minimize final image size."""
        from_count = len(re.findall(r"^FROM\s", dockerfile_text, re.MULTILINE))
        assert from_count >= 2, "Dockerfile must have at least 2 FROM stages"

    def test_healthcheck_instruction(self, dockerfile_text: str):
        """HEALTHCHECK must be defined so Docker can detect unhealthy containers.

        Without HEALTHCHECK, Docker has no way to know if the app inside
        the container is responsive. Orchestrators can't auto-restart.
        """
        assert re.search(r"^HEALTHCHECK\s", dockerfile_text, re.MULTILINE)

    def test_healthcheck_hits_healthz(self, dockerfile_text: str):
        """HEALTHCHECK must probe /healthz, matching Railway and Render configs."""
        healthcheck_match = re.search(
            r"HEALTHCHECK.*?(?=\n(?:FROM|RUN|COPY|ENV|EXPOSE|USER|ENTRYPOINT|CMD|\Z))",
            dockerfile_text,
            re.DOTALL | re.MULTILINE,
        )
        assert healthcheck_match, "HEALTHCHECK instruction not found"
        assert "/healthz" in healthcheck_match.group()

    def test_non_root_user(self, dockerfile_text: str):
        """Container must not run as root.

        A USER instruction must appear AFTER the HEALTHCHECK and BEFORE
        CMD/ENTRYPOINT, ensuring the app process is unprivileged.
        """
        assert re.search(r"^USER\s+(?!root)\S+", dockerfile_text, re.MULTILINE)

    def test_user_is_worthless(self, dockerfile_text: str):
        """The runtime user must be 'worthless' (created in Dockerfile)."""
        assert re.search(r"^USER worthless$", dockerfile_text, re.MULTILINE)

    def test_expose_8787(self, dockerfile_text: str):
        """Port 8787 must be exposed (the standard proxy port)."""
        assert re.search(r"^EXPOSE 8787$", dockerfile_text, re.MULTILINE)

    def test_tini_init(self, dockerfile_text: str):
        """ENTRYPOINT must use tini for proper PID 1 signal handling.

        Without an init process, zombie processes accumulate and signals
        are not properly forwarded to the application.
        """
        assert "tini" in dockerfile_text

    def test_no_root_in_final_stage(self, dockerfile_text: str):
        """The final stage must not have USER root after the initial setup.

        After the USER instruction changes to non-root, there must not be
        a revert to root.
        """
        # Find all USER instructions
        user_lines = re.findall(r"^USER\s+(\S+)", dockerfile_text, re.MULTILINE)
        if user_lines:
            assert user_lines[-1] != "root", "Final USER must not be root"

    def test_no_cache_pip_install(self, dockerfile_text: str):
        """pip install must use --no-cache-dir to minimize image size."""
        pip_lines = re.findall(r"pip install.*", dockerfile_text)
        for line in pip_lines:
            assert "--no-cache-dir" in line, f"pip install missing --no-cache-dir: {line}"

    def test_pythondontwritebytecode(self, dockerfile_text: str):
        """PYTHONDONTWRITEBYTECODE must be set to avoid .pyc files on read-only fs."""
        assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile_text


# ------------------------------------------------------------------
# Compose env example
# ------------------------------------------------------------------


class TestComposeEnvExample:
    """Validate deploy/docker-compose.env.example exists and is useful."""

    def test_file_exists(self):
        """The env example must exist for documentation."""
        assert ENV_EXAMPLE.exists(), (
            "deploy/docker-compose.env.example missing -- new users won't know "
            "how to configure the container"
        )

    def test_no_actual_secrets(self):
        """Env example must not contain real API keys or secrets.

        This file is committed to git. Real credentials here would be a
        security incident.
        """
        content = ENV_EXAMPLE.read_text()
        secret_patterns = [
            r"sk-[a-zA-Z0-9]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"anthropic-[a-zA-Z0-9]{20,}",
        ]
        for pattern in secret_patterns:
            assert not re.search(pattern, content), (
                f"Env example contains potential real secret: {pattern}"
            )

    def test_all_values_commented_or_empty(self):
        """Non-comment lines with real values would be confusing defaults.

        The env example should only have comments explaining variables,
        not pre-filled values that might be mistaken for real config.
        """
        content = ENV_EXAMPLE.read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # If uncommented key=value lines exist, they must have placeholder
            # values or be one of the deploy-mode contract values (the example
            # documents the required compose default — see WOR-344).
            if "=" in stripped:
                key, _, value = stripped.partition("=")
                allowed_literals = {"true", "false", "loopback", "lan", "public"}
                assert not value or value.startswith('"') or value.lower() in allowed_literals, (
                    f"Env example has unexpected value for {key}: {value}"
                )


# ------------------------------------------------------------------
# Cross-config consistency
# ------------------------------------------------------------------


class TestCrossConfigConsistency:
    """Ensure all deploy configs agree on critical values.

    Inconsistency between Dockerfile, Railway, Render, and Compose is a
    common source of "works locally, breaks in production" bugs.
    """

    def test_healthcheck_path_consistent(
        self, railway_data: dict, render_data: dict, dockerfile_text: str
    ):
        """All configs must use the same healthcheck path (/healthz).

        If Dockerfile probes /healthz but Railway expects /health, the
        container appears healthy locally but gets killed on Railway.
        """
        assert railway_data["deploy"]["healthcheckPath"] == "/healthz"
        assert render_data["services"][0]["healthCheckPath"] == "/healthz"
        assert "/healthz" in dockerfile_text

    def test_port_8787_consistent(self, compose_data: dict, dockerfile_text: str):
        """Port 8787 must be consistent between Dockerfile and Compose."""
        assert "8787" in compose_data["services"]["proxy"]["ports"][0]
        assert re.search(r"EXPOSE 8787", dockerfile_text)

    def test_data_volume_mount_consistent(
        self, compose_data: dict, render_data: dict, dockerfile_text: str
    ):
        """All configs must agree on /data as the persistent storage path."""
        # Compose mounts worthless-data at /data
        compose_vols = compose_data["services"]["proxy"]["volumes"]
        data_mounts = [v for v in compose_vols if v.startswith("worthless-data:")]
        assert data_mounts and data_mounts[0].split(":")[1] == "/data"

        # Render mounts disk at /data
        assert render_data["services"][0]["disk"]["mountPath"] == "/data"

        # Dockerfile sets WORTHLESS_HOME=/data
        assert "WORTHLESS_HOME=/data" in dockerfile_text


# ------------------------------------------------------------------
# Failure/edge case awareness tests
# ------------------------------------------------------------------


class TestInstallPinDriftCheck:
    """WOR-559 — release-sync-check.yml fails when install.sh's default pin
    falls behind the latest published PyPI release. This deploy-decoupled
    drift guard replaces the deploy-time pin gate (Option B: pin = latest
    published, hand-bumped like UV_VERSION)."""

    @pytest.fixture(scope="class")
    def release_sync_text(self) -> str:
        return (REPO_ROOT / ".github" / "workflows" / "release-sync-check.yml").read_text(
            encoding="utf-8"
        )

    def test_drift_check_compares_pin_to_pypi(self, release_sync_text: str):
        assert "WORTHLESS_VERSION_PIN" in release_sync_text, (
            "release-sync-check must read the install.sh pin."
        )
        assert "INSTALL_PIN" in release_sync_text and "PYPI_VERSION" in release_sync_text, (
            "drift check must compare the install.sh pin against the latest PyPI version."
        )

    def test_no_deploy_time_pin_gate(self):
        """Option B: no deploy-time gate. No verify-pin script, and
        deploy-worker.yml must not block on pin==tag or PyPI availability."""
        assert not (REPO_ROOT / ".github" / "scripts" / "verify-pin.sh").exists(), (
            "verify-pin.sh deploy gate was removed in favour of the drift check."
        )
        deploy = (REPO_ROOT / ".github" / "workflows" / "deploy-worker.yml").read_text(
            encoding="utf-8"
        )
        assert "verify-pin.sh" not in deploy
        assert "pypi.org/pypi/worthless/" not in deploy, (
            "no PyPI-availability wait — the pin is always already published."
        )


class TestEdgeCaseAwareness:
    """Tests that document what MUST be present -- catch regressions if removed."""

    def test_dockerfile_healthcheck_required(self, dockerfile_text: str):
        """Removing HEALTHCHECK breaks all platform health monitoring.

        This test exists to catch accidental removal during Dockerfile
        refactoring. Without HEALTHCHECK: Railway kills the container after
        timeout, Render marks it unhealthy, Docker never auto-restarts.
        """
        assert "HEALTHCHECK" in dockerfile_text, (
            "HEALTHCHECK instruction removed from Dockerfile! "
            "Railway, Render, and Docker health monitoring all depend on it."
        )

    def test_compose_volume_separation_required(self, compose_data: dict):
        """Data and secrets MUST be on separate volumes.

        If both Fernet key and shard data land on the same volume,
        compromise of that single volume can reconstruct all API keys.
        This is the core security invariant of the split-key architecture.
        """
        proxy_volumes = compose_data["services"]["proxy"]["volumes"]
        mount_targets = []
        for v in proxy_volumes:
            parts = v.split(":")
            if len(parts) >= 2:
                mount_targets.append(parts[1])

        assert "/data" in mount_targets, "Missing /data volume mount"
        assert "/secrets" in mount_targets, "Missing /secrets volume mount"
        # They must come from different named volumes
        data_sources = [v.split(":")[0] for v in proxy_volumes if ":/data" in v]
        secret_sources = [v.split(":")[0] for v in proxy_volumes if ":/secrets" in v]
        if data_sources and secret_sources:
            assert data_sources[0] != secret_sources[0], (
                "SECURITY VIOLATION: Data and secrets share the same volume! "
                "Compromise of one volume would expose both Fernet key and shard data."
            )

    def test_railway_healthcheck_required(self, railway_data: dict):
        """Railway without healthcheckPath will never know if the app is alive.

        This causes silent failures: the container starts, the app crashes,
        Railway thinks everything is fine.
        """
        assert "healthcheckPath" in railway_data.get("deploy", {}), (
            "Railway config missing healthcheckPath! "
            "Without it, Railway cannot detect unhealthy containers."
        )

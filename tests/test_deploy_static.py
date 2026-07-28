"""Static validation tests for deploy configs (WOR-170).

These tests parse the actual Dockerfile, docker-compose.yml, railway.toml,
render.yaml, entrypoint.sh, and env example without requiring Docker.
They assert structural correctness, security hardening, and cross-config
consistency.

Run with: uv run pytest tests/test_deploy_static.py -v
"""

from __future__ import annotations

import os
import re
import shutil
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
RELEASE_SYNC_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-sync-check.yml"
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_NOTES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-notes.yml"
RELEASE_FANIN_SCRIPT = REPO_ROOT / ".github" / "scripts" / "release-fanin.sh"
EXTRACT_CHANGELOG_SCRIPT = REPO_ROOT / ".github" / "scripts" / "extract_changelog.py"
# The four independent publishers the auto-Release job fans in over.
PUBLISHER_WORKFLOWS = ["publish.yml", "publish-npm.yml", "publish-docker.yml", "deploy-worker.yml"]

# Fake `gh` for the fan-in behavioural tests: emits {"workflow_runs":[...]} per
# workflow file, driven by RUNS="file=status:conclusion,...". A missing file =>
# no runs (leg hasn't started). conclusion "null" => JSON null (in-progress).
_FANIN_GH_SHIM = r"""#!/usr/bin/env bash
path=""
for a in "$@"; do case "$a" in */actions/workflows/*/runs) path="$a";; esac; done
wf=$(printf '%s' "$path" | sed -E 's#.*/workflows/([^/]+)/runs#\1#')
spec=""
IFS=',' read -ra pairs <<<"${RUNS:-}"
for p in "${pairs[@]}"; do [ "${p%%=*}" = "$wf" ] && spec="${p#*=}"; done
if [ -z "$spec" ]; then echo '{"workflow_runs":[]}'; exit 0; fi
st="${spec%%:*}"; cc="${spec#*:}"
if [ "$cc" = "null" ]; then ccj=null; else ccj="\"$cc\""; fi
run="{\"head_sha\":\"${HEAD_SHA}\",\"status\":\"${st}\",\"conclusion\":${ccj}}"
printf '{"workflow_runs":[%s]}\n' "$run"
"""


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    """Raw Dockerfile content (all stages)."""
    return DOCKERFILE.read_text()


@pytest.fixture(scope="module")
def dockerfile_final_stage(dockerfile_text: str) -> str:
    """Just the final-stage content of the multi-stage Dockerfile.

    CR-3204010120: WOR-310 runtime assertions (USER directive absent,
    user/group creation, ownership, image LABEL) must be checked
    against the FINAL stage only — a builder-stage directive
    (e.g. a stray ``USER builder`` in the build stage) could
    otherwise satisfy or break a runtime check inadvertently.

    Returns content from the LAST ``FROM`` line to EOF.
    """
    from_indices = [m.start() for m in re.finditer(r"^FROM\s", dockerfile_text, re.MULTILINE)]
    if not from_indices:
        return dockerfile_text
    return dockerfile_text[from_indices[-1] :]


@pytest.fixture(scope="module")
def compose_data() -> dict:
    """Parsed docker-compose.yml."""
    return yaml.safe_load(COMPOSE_FILE.read_text())


@pytest.fixture(scope="module")
def railway_data() -> dict:
    """Parsed railway.toml."""
    return tomllib.loads(RAILWAY_TOML.read_text())


@pytest.fixture(scope="module")
def publish_text() -> str:
    """Raw publish.yml workflow content."""
    return PUBLISH_WORKFLOW.read_text()


@pytest.fixture(scope="module")
def publish_data() -> dict:
    """Parsed publish.yml workflow."""
    return yaml.safe_load(PUBLISH_WORKFLOW.read_text())


@pytest.fixture(scope="module")
def release_notes_data() -> dict:
    """Parsed release-notes.yml workflow (the auto-Release job)."""
    return yaml.safe_load(RELEASE_NOTES_WORKFLOW.read_text())


@pytest.fixture(scope="module")
def render_data() -> dict:
    """Parsed render.yaml."""
    return yaml.safe_load(RENDER_YAML.read_text())


@pytest.fixture(scope="module")
def entrypoint_text() -> str:
    """Raw entrypoint.sh content."""
    return ENTRYPOINT.read_text()


@pytest.fixture(scope="module")
def release_sync_text() -> str:
    """Raw release-sync-check.yml workflow content."""
    return RELEASE_SYNC_WORKFLOW.read_text()


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

    def test_fernet_key_not_passed_via_fd(self, entrypoint_text: str):
        """WOR-465 A4: Fernet key must NOT be passed via open file descriptor.

        A4 removes 'exec 3< fernet.key' and 'export WORTHLESS_FERNET_FD=3'
        to close the POSIX fd-inheritance vector: an open fd survives exec
        without O_CLOEXEC and is readable via /proc/self/fd/3 regardless of
        file permissions. The sidecar reads fernet.key directly (it owns it
        0400); the proxy never needs the raw key.
        """
        assert not re.search(r"\bexec\s+3<", entrypoint_text), (
            "WOR-465 A4: 'exec 3< fernet.key' (any whitespace variant) must be absent "
            "from entrypoint.sh. The open fd is inherited by uvicorn and bypasses the "
            "0400 permission regardless of file ownership."
        )
        assert "WORTHLESS_FERNET_FD" not in entrypoint_text, (
            "WOR-465 A4: WORTHLESS_FERNET_FD must not be exported. The proxy no "
            "longer reads the key directly; all crypto routes through IPC verbs."
        )

    def test_fernet_migration_uses_install_not_cp(self, entrypoint_text: str):
        """Migration must use 'install -m' instead of cp+chmod.

        cp creates the file with default perms, leaving a brief window
        where the key is world-readable. install -m sets perms
        atomically.

        Mode 0440 (not 0400) so the worthless group can read fernet.key
        post-chown — both proxy uid (bootstrap-validation) and crypto
        uid (sidecar reconstruct) need group-read access.  Final
        ownership root:worthless is fixed up in the priv-drop block.
        """
        assert "install -m 0440" in entrypoint_text, (
            "Fernet migration should use 'install -m 0440' for atomic permissions. "
            "cp + chmod leaves a race window where the key is world-readable."
        )
        # CR-3204010820: narrow the cp ban to FERNET-KEY paths only.
        # An unrelated `cp` earlier in entrypoint bootstrap (e.g.
        # copying a CA bundle, a config file, anything) shouldn't trip
        # this assertion — it's specifically the fernet key migration
        # that must use install -m for atomic permissions.
        migration_block = entrypoint_text.split("install -m 0440")[0]
        assert not re.search(
            r"\bcp\b[^\n]*(fernet\.key|\$FERNET_PATH|\$LEGACY_FERNET_PATH)",
            migration_block,
        ), (
            "Fernet-key migration should not use bare 'cp' for key material "
            "before 'install -m 0440'."
        )

    def test_ulimit_core_disabled_at_top_of_entrypoint(self, entrypoint_text: str):
        """WOR-310 D: ``ulimit -c 0`` must run before any python invocation.

        Belt-and-suspenders for Phase A's PR_SET_DUMPABLE=0. The Phase A
        guard runs INSIDE the sidecar python process; ulimit -c 0 here
        applies to EVERY process in the container, including the brief
        root-running entrypoint and any python bootstrap errors. If the
        kernel ever writes a core file, it'd contain the Fernet key in
        plaintext — this is one more line of defense.

        Pinned to be ``set -e``-adjacent so the early-exit semantics
        are clear; the trailing ``|| true`` is intentional for kernels
        that reject the call (containerd-shim sometimes does on lock).
        """
        # Find the line index of `set -e` and `ulimit -c 0`.
        lines = entrypoint_text.splitlines()
        set_e_idx = next((i for i, line in enumerate(lines) if line.strip() == "set -e"), -1)
        ulimit_idx = next(
            (i for i, line in enumerate(lines) if line.strip().startswith("ulimit -c 0")), -1
        )
        assert set_e_idx >= 0, "WOR-310 D: entrypoint must use 'set -e'"
        assert ulimit_idx >= 0, (
            "WOR-310 D: entrypoint MUST run 'ulimit -c 0' as defense in depth "
            "alongside Phase A's PR_SET_DUMPABLE=0."
        )
        assert ulimit_idx > set_e_idx, (
            "WOR-310 D: 'ulimit -c 0' must come AFTER 'set -e' so a failure to "
            "set the limit doesn't silently proceed (belt-and-suspenders only "
            "if the belt actually exists)."
        )
        # The ulimit line must precede every python invocation.
        first_python_idx = next(
            (
                i
                for i, line in enumerate(lines)
                if "python" in line and not line.strip().startswith("#")
            ),
            len(lines),
        )
        assert ulimit_idx < first_python_idx, (
            "WOR-310 D: 'ulimit -c 0' must precede every python invocation. "
            "If python crashes during bootstrap, the kernel must NOT write a core."
        )

    def test_privdrop_required_env_exported(self, entrypoint_text: str):
        """WOR-310 C3: entrypoint MUST export WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1
        BEFORE the final ``exec`` line.

        CR-3204010113: a regression that put the export AFTER the exec
        would silently no-op (the export never runs because exec
        replaces the process), and start.py would see the env unset →
        skip priv-drop → boot single-uid → defeat the v1.1 claim with
        no log line.  Pin both the existence AND the relative order.
        """
        export_match = re.search(
            r"^export\s+WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1\b",
            entrypoint_text,
            re.MULTILINE,
        )
        assert export_match, (
            "WOR-310 C3: entrypoint.sh must export "
            "WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1 before exec'ing start.py. "
            "Without it the priv-drop dance silently no-ops and the v1.1 "
            "security claim is broken with no log line."
        )
        # Find the final exec line.  The priv-drop guard must precede
        # the LAST exec (which replaces the process with start.py).
        exec_matches = list(re.finditer(r"^exec\s+\S", entrypoint_text, re.MULTILINE))
        assert exec_matches, "entrypoint.sh has no `exec` line"
        last_exec_pos = exec_matches[-1].start()
        assert export_match.start() < last_exec_pos, (
            "WOR-310 C3: WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1 export must "
            f"appear BEFORE the final exec (export at offset "
            f"{export_match.start()}, last exec at offset {last_exec_pos}). "
            "An export after exec would never run — the priv-drop dance "
            "would silently no-op."
        )

    def test_bootstrap_locks_fernet_key(self, entrypoint_text: str):
        """WOR-465 A4: fernet.key must be locked to worthless-crypto:worthless-crypto 0400.

        A4 makes this unconditional — no flag required. The sidecar uid (10002,
        gid 10002) reads via owner bit; the proxy uid (10001, not in gid 10002)
        is kernel-denied. Fail-closed stat check exits 78 on permission mismatch.
        """
        assert "chmod 0400" in entrypoint_text, (
            "WOR-465 A4: entrypoint must chmod fernet.key to 0400 (owner-only) "
            "after creation. The proxy uid is not in gid 10002; kernel rejects open()."
        )
        assert re.search(
            r'chown\s+worthless-crypto:worthless-crypto\s+["\']*\$FERNET_PATH',
            entrypoint_text,
        ), (
            "WOR-465 A4: fernet.key chown must target $FERNET_PATH — "
            "a generic chown on any arbitrary path is insufficient."
        )

    def test_fernet_key_chmod_unconditional_crypto_owner(self, entrypoint_text: str):
        """WOR-465 A4: fernet.key chmod must be unconditional — no flag gate.

        A4 removes the 'if WORTHLESS_FERNET_IPC_ONLY=1' branch from A1 and
        makes worthless-crypto:worthless-crypto 0400 the only state. The A1
        conditional gate is gone; there is no fallback 0440 path. The
        Dockerfile ENV WORTHLESS_FERNET_IPC_ONLY=1 ensures Python ProxySettings
        sees the locked state without any operator action.

        Owner MUST be worthless-crypto (not root) — with 0400, the owner is
        the only reader. chown root:worthless-crypto 0400 locks the sidecar out
        of its own key (the A1 bug caught by task-completion-validator on PR #158).
        """
        # No A1-style flag gate (if WORTHLESS_FERNET_IPC_ONLY = "1").
        # The flag may appear for other purposes (e.g. "= 0" operator warning).
        assert not any(
            "WORTHLESS_FERNET_IPC_ONLY" in line and '"1"' in line
            for line in entrypoint_text.splitlines()
            if not line.strip().startswith("#")
        ), (
            "WOR-465 A4: WORTHLESS_FERNET_IPC_ONLY='1' gate must be removed "
            "from entrypoint.sh. A4 makes the chmod unconditional."
        )
        # Unconditional chown to sidecar uid — anchored to $FERNET_PATH target.
        assert re.search(
            r'chown\s+worthless-crypto:worthless-crypto\s+["\']*\$FERNET_PATH',
            entrypoint_text,
        ), (
            "WOR-465 A4: entrypoint must unconditionally chown fernet.key to "
            "worthless-crypto:worthless-crypto targeting $FERNET_PATH — "
            "a generic chown on any path is insufficient."
        )
        assert "chmod 0400" in entrypoint_text, (
            "WOR-465 A4: entrypoint must chmod fernet.key to 0400 (owner-only). "
            "Proxy uid 10001 ∉ gid 10002; kernel rejects open()."
        )
        # No legacy 0440 fallback — the proxy-readable path is gone.
        assert "chmod 0440" not in entrypoint_text, (
            "WOR-465 A4: legacy 'chmod 0440' (root:worthless, proxy-readable) "
            "must not appear in entrypoint.sh. A4 removes the fallback path entirely."
        )

    def test_ipc_only_zero_exits_fatal(self, entrypoint_text: str) -> None:
        """WOR-465 A4: entrypoint exits 78 (EX_CONFIG) when WORTHLESS_FERNET_IPC_ONLY=0.

        fernet.key is unconditionally locked to worthless-crypto 0400; =0 would
        cause EACCES on the first direct key read. Fail closed immediately rather
        than starting a broken container. Must fire before any Python starts.
        """
        assert 'WORTHLESS_FERNET_IPC_ONLY:-1}" = "0"' in entrypoint_text, (
            "WOR-465 A4: entrypoint must check for WORTHLESS_FERNET_IPC_ONLY=0 "
            "and exit before Python starts."
        )
        assert "FATAL" in entrypoint_text, (
            "WOR-465 A4: the =0 check must emit a FATAL line to stderr."
        )
        assert "exit 78" in entrypoint_text, (
            "WOR-465 A4: the =0 check must exit 78 (EX_CONFIG) to refuse a broken container start."
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

    def test_healthcheck_uses_ipc_probe(self, dockerfile_text: str):
        """HEALTHCHECK must use the hybrid IPC sidecar probe (WOR-466).

        The old HTTP /healthz probe only proved uvicorn was alive — it missed
        two false-green failure modes: stale socket inode (sidecar died, inode
        lingered) and hung accept loop (sidecar alive but wedged).  The new
        probe runs ``python -m worthless.sidecar.health`` which does a real
        AF_UNIX IPC HELLO handshake, catching both failure modes.

        Railway and Render use /healthz for their own platform HTTP readiness
        checks; that is intentionally separate from the Docker HEALTHCHECK.
        """
        healthcheck_match = re.search(
            r"HEALTHCHECK.*?(?=\n[A-Z]|\Z)",
            dockerfile_text,
            re.DOTALL | re.MULTILINE,
        )
        assert healthcheck_match, "HEALTHCHECK instruction not found"
        assert "worthless.sidecar.health" in healthcheck_match.group(), (
            "HEALTHCHECK must invoke 'python -m worthless.sidecar.health' (WOR-466). "
            "Do not revert to the HTTP /healthz probe — it misses stale-inode and "
            "hung-accept-loop failure modes."
        )

    def test_no_static_user_directive(self, dockerfile_final_stage: str):
        """Container must NOT pin a USER at build time (WOR-310 two-uid topology).

        Pre-WOR-310 the Dockerfile ended with ``USER worthless``. The
        single-container blessed topology requires TWO uids (proxy +
        crypto) and a runtime privilege drop in ``deploy/start.py`` —
        which is impossible from a pre-dropped uid because the kernel
        won't let a non-root process call ``setresuid`` to a different
        uid. A static ``USER`` directive freezes the runtime uid at
        build time and prevents the dance entirely.

        See ``deploy/start.py::main`` for the runtime drop:
        ``setresuid(worthless-proxy)`` after spawning the sidecar as
        ``worthless-crypto`` and before ``execvp(uvicorn)``.
        """
        assert not re.search(r"^USER\s+\S+", dockerfile_final_stage, re.MULTILINE), (
            "WOR-310: Dockerfile must not pin a USER at build time. "
            "Privilege drop happens at runtime in deploy/start.py so the "
            "container can spawn the sidecar as worthless-crypto and run "
            "uvicorn as worthless-proxy from a single root entrypoint."
        )

    def test_creates_proxy_user_uid_10001(self, dockerfile_final_stage: str):
        """worthless-proxy must be a real user with a pinned uid (WOR-310).

        Pinning the uid (10001) keeps the runtime check
        ``assert os.getuid() == proxy_uid`` in ``deploy/start.py``
        deterministic across image rebuilds — a drifting uid would let a
        future Dockerfile edit silently flip uvicorn back to root.
        """
        assert re.search(
            r"useradd[^\n]*-r[^\n]*-u\s+10001[^\n]*worthless-proxy", dockerfile_final_stage
        ), (
            "WOR-310: missing 'useradd -r ... -u 10001 ... worthless-proxy' "
            "(-r pins this as a system account; without it useradd creates a "
            "login-capable user with a mailbox)"
        )

    def test_creates_crypto_user_uid_10002(self, dockerfile_final_stage: str):
        """worthless-crypto must be a real user with a pinned uid (WOR-310).

        Distinct uid from worthless-proxy is the kernel-enforced wall
        that defeats row 1 of the v1.1 red-team table: even with RCE in
        the proxy, ``ptrace`` and ``/proc/<crypto-pid>/mem`` are blocked
        because uid != uid. mlock + DUMPABLE=0 layer additional defense
        (see WOR-310 Phase A).
        """
        assert re.search(
            r"useradd[^\n]*-r[^\n]*-u\s+10002[^\n]*worthless-crypto", dockerfile_final_stage
        ), (
            "WOR-310: missing 'useradd -r ... -u 10002 ... worthless-crypto' "
            "(-r pins this as a system account)"
        )

    def test_shared_group_worthless(self, dockerfile_final_stage: str):
        """A shared 'worthless' group must let both uids share /run/worthless.

        Both uids belong to gid 10001 so the AF_UNIX socket file in
        ``/run/worthless/<pid>/sidecar.sock`` is accessible to either
        process via group permissions, while neither can read the
        other's process memory because uids differ.
        """
        assert re.search(
            r"groupadd[^\n]*-r[^\n]*-g\s+10001[^\n]*worthless\b", dockerfile_final_stage
        ), "WOR-310: missing 'groupadd -r ... -g 10001 worthless' (-r pins system group)"

    def test_creates_crypto_group_gid_10002(self, dockerfile_final_stage: str):
        """WOR-465 Phase A1: a dedicated ``worthless-crypto`` system group at
        gid 10002 must exist in the image, distinct from the shared
        ``worthless`` (gid 10001) group.

        Why: ``fernet.key`` currently sits at ``root:worthless 0440`` and
        the proxy uid is in group ``worthless`` — so a proxy RCE can
        ``open(O_RDONLY)`` and read the key, voiding WOR-310's
        "offline-key-theft blocked even with proxy RCE" claim.

        Phase A1 adds the gid as the *target* identity for fernet.key
        once ``WORTHLESS_FERNET_IPC_ONLY=1`` flips the entrypoint chmod
        to ``root:worthless-crypto 0400``. The proxy uid is NOT a member
        of this gid; the kernel rejects the open() that the gap relied
        on. Default-off via the env flag keeps docker-e2e green during
        the migration (Phases A2-A4 ship the IPC verbs and the flip).
        """
        assert re.search(
            r"groupadd[^\n]*-r[^\n]*-g\s+10002[^\n]*worthless-crypto\b",
            dockerfile_final_stage,
        ), (
            "WOR-465: missing 'groupadd -r ... -g 10002 worthless-crypto' "
            "(-r pins system group; gid 10002 is unique to the crypto uid "
            "so the proxy uid cannot reach fernet.key once mode flips to "
            "root:worthless-crypto 0400 under WORTHLESS_FERNET_IPC_ONLY=1)"
        )

    def test_crypto_user_is_member_of_crypto_group(self, dockerfile_final_stage: str):
        """worthless-crypto uid must be a member of the worthless-crypto gid.

        Without the supplementary group on the crypto user, no service
        identity in the image owns gid 10002 — chowning fernet.key to
        ``root:worthless-crypto 0400`` would lock out the sidecar too,
        not just the proxy. The crypto uid keeps ``-g worthless`` as
        its primary gid (needed for /run/worthless socket traversal)
        and gains ``-G worthless-crypto`` as supplementary.
        """
        assert re.search(
            r"useradd[^\n]*-G\s+worthless-crypto[^\n]*worthless-crypto\b",
            dockerfile_final_stage,
        ), (
            "WOR-465: worthless-crypto user must be a supplementary "
            "member of the worthless-crypto group (-G worthless-crypto). "
            "Otherwise nothing in the image can read fernet.key after "
            "Phase A4 chmods it to root:worthless-crypto 0400."
        )

    def test_worthless_crypto_home_nonexistent(self, dockerfile_final_stage: str):
        """worthless-crypto home dir must be /nonexistent (Q3 decision).

        Debian convention for service users with no real home. If
        anything tries to read $HOME for the crypto user, it errors
        instead of silently writing to a real directory the user could
        be tricked into accessing.
        """
        assert re.search(
            r"useradd[^\n]*-d\s+/nonexistent[^\n]*worthless-crypto", dockerfile_final_stage
        ), "WOR-310: worthless-crypto must have -d /nonexistent (Q3 decision)"

    def test_creates_run_worthless_dir(self, dockerfile_final_stage: str):
        """/run/worthless must be created so split_to_tmpfs has a writable home.

        Phase C sets WORTHLESS_RUN_DIR=/run/worthless so per-PID share
        and socket files land here. /run is normally tmpfs on Linux —
        we mkdir at build time to set the right ownership and mode
        before any process tries to write into it.
        """
        assert re.search(r"mkdir[^\n]*-p[^\n]*/run/worthless", dockerfile_final_stage), (
            "WOR-310: missing 'mkdir -p /run/worthless'"
        )

    def test_run_worthless_owned_root_worthless_group_0770(self, dockerfile_final_stage: str):
        """/run/worthless must be root:worthless 0770 (group-writable).

        Owner=root means neither uid can rename or chmod the dir.
        Group=worthless + mode 0770 means BOTH uids (proxy + crypto)
        can create their per-PID subdirs and the socket file, but no
        other user on the box (if /run/worthless ever leaks outside
        the container) can read either.
        """
        assert re.search(r"chown\s+root:worthless\s+/run/worthless", dockerfile_final_stage), (
            "WOR-310: /run/worthless must be chown'd root:worthless"
        )
        assert re.search(r"chmod\s+0?770\s+/run/worthless", dockerfile_final_stage), (
            "WOR-310: /run/worthless must be chmod 0770 (group-writable, world-blocked)"
        )

    def test_image_label_required_run_flags(self, dockerfile_final_stage: str):
        """Image must advertise --security-opt=no-new-privileges as required.

        ``no-new-privileges`` is what blocks the kernel's setuid-binary
        escalation route. We can't enforce it from inside the image —
        Docker has to be invoked with the flag — so we surface it via
        a LABEL the operator (or `docker inspect`) can read.

        Q2 decision: warn-loud at startup if the flag is absent, do
        NOT refuse to boot (Render/Fly users can't set it).
        """
        assert re.search(
            r'LABEL[^\n]*org\.worthless\.required-run-flags="?[^"\n]*--security-opt=no-new-privileges',
            dockerfile_final_stage,
        ), (
            "WOR-310: LABEL org.worthless.required-run-flags must mention "
            "--security-opt=no-new-privileges"
        )

    def test_image_label_recommended_run_flags(self, dockerfile_final_stage: str):
        """Image must advertise the cap-add allowlist needed for priv-drop.

        Plain ``--cap-drop=ALL`` is INCOMPATIBLE with the WOR-310
        priv-drop dance — setresuid/setresgid/setgroups need SETUID +
        SETGID; prctl(PR_CAPBSET_DROP) needs SETPCAP.  The recommended
        flags drop everything else and let the runtime clear the
        bounding set itself, so the post-drop end-state matches
        --cap-drop=ALL.  The LABEL documents intent without enforcing —
        the docs site (WOR-314) will reference it so the image is
        self-documenting.
        """
        match = re.search(
            r'LABEL[^\n]*org\.worthless\.recommended-run-flags="([^"]*)"',
            dockerfile_final_stage,
        )
        assert match, "WOR-310: missing LABEL org.worthless.recommended-run-flags"
        flags = match.group(1)
        for needed in (
            "--cap-add=SETUID",
            "--cap-add=SETGID",
            "--cap-add=SETPCAP",
            "--cap-add=DAC_OVERRIDE",
            "--cap-add=CHOWN",
            "--cap-add=FOWNER",
            # WOR-466: /run/worthless must be a writable tmpfs with gid=10001
            # (worthless group) so the HEALTHCHECK probe (uid 10001) can traverse
            # the directory and stat the stable sidecar.sock symlink.  Without
            # gid=10001, Docker resets the tmpfs to root:root and the probe gets
            # EACCES → "stat denied (permission)" → container never healthy.
            "--tmpfs /run/worthless:uid=0,gid=10001,mode=0770",
        ):
            assert needed in flags, (
                f"WOR-310: priv-drop / bootstrap requires {needed} in "
                f"recommended-run-flags; without it, entrypoint bootstrap "
                f"or the setres* dance fails and the container never "
                f"becomes healthy"
            )

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
        """Platform HTTP probes (Railway/Render) agree on /healthz; Dockerfile
        uses the IPC sidecar probe (WOR-466).

        Railway and Render use their own platform-level HTTP liveness check at
        /healthz — these two must stay in sync.  The Docker HEALTHCHECK now
        runs ``python -m worthless.sidecar.health`` (an AF_UNIX IPC probe)
        rather than an HTTP call; it is intentionally different and checked by
        ``test_healthcheck_uses_ipc_probe``.
        """
        assert railway_data["deploy"]["healthcheckPath"] == "/healthz"
        assert render_data["services"][0]["healthCheckPath"] == "/healthz"
        assert "worthless.sidecar.health" in dockerfile_text

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


# ------------------------------------------------------------------
# Release-sync-check workflow: trust-anchor invariants (worthless-xn4l)
# ------------------------------------------------------------------


class TestReleaseSyncTrustAnchor:
    """The daily release-sync monitor must anchor 'what shipped' to signed
    git tags, NOT to GitHub Release objects.

    Git `v*` tags are GPG-signed and deletion/re-point-locked by the
    `v-tags-signed` ruleset. GitHub Release objects have no such protection
    (anyone with write access can create/edit/delete one without a signed
    tag). Deriving the monitor's source of truth from a mutable, ungated
    Release object lets a forged Release define what the monitor then
    'verifies' against. These tests pin the fix (worthless-xn4l) so it
    cannot silently rot back to `gh release view`.
    """

    def test_no_gh_release_view(self, release_sync_text: str):
        """The monitor must not derive any trust signal from Release objects.

        `gh release view` reads the latest/ named GitHub Release object — a
        spoofable, ruleset-ungated source. Both the version chain (A1) and
        the deploy-lag date (A5) previously leaned on it, which caused a
        false drift alarm and a false stale-deploy alarm.
        """
        assert "gh release view" not in release_sync_text, (
            "release-sync-check.yml uses `gh release view` — it must derive "
            "the latest shipped version and tag date from signed git tags, "
            "not from mutable GitHub Release objects (worthless-xn4l)."
        )

    def test_latest_tag_from_signed_git_tags(self, release_sync_text: str):
        """Latest version comes from git tags, filtered to the signed `v*`
        pattern that the `v-tags-signed` ruleset gates.

        The `--list 'v[0-9]*'` filter is both the fix and the security
        boundary: only ruleset-protected `v*` tags can define 'latest', so a
        stray non-`v*` tag cannot skew the version sort.
        """
        assert re.search(
            r"git tag --sort=-version:refname --list 'v\[0-9\]\*'",
            release_sync_text,
        ), (
            "Latest tag must be resolved via "
            "`git tag --sort=-version:refname --list 'v[0-9]*'` — signed, "
            "ruleset-gated tags only (worthless-xn4l)."
        )
        # And refined to clean release tags only, so a prerelease (v0.3.7rc1)
        # cut before its release cannot be mistaken for "latest shipped".
        assert r"^v[0-9]+\.[0-9]+\.[0-9]+$" in release_sync_text, (
            "Latest tag must be filtered to clean vMAJOR.MINOR.PATCH release "
            "tags (grep '^v[0-9]+\\.[0-9]+\\.[0-9]+$'), excluding rc/prerelease "
            "tags that would skew the version sort (worthless-xn4l)."
        )

    def test_tag_date_from_git_not_release(self, release_sync_text: str):
        """A5's deploy-lag date must come from the git tag's creation time,
        not a Release object's publishedAt.

        A hand-created Release stamps publishedAt=now, which faked a stale
        deploy. `for-each-ref creatordate` reads the annotated tag's true
        creation time.
        """
        assert "creatordate" in release_sync_text, (
            "A5 must derive the tag date from the git tag "
            "(`git for-each-ref ... creatordate`), not a Release object "
            "(worthless-xn4l)."
        )


# ------------------------------------------------------------------
# Release-sync-check workflow: BEHAVIOURAL tests (worthless-xn4l)
#
# The class above only greps the workflow text. These run the ACTUAL shell
# extracted from the YAML against throwaway git repos with adversarial tag
# sets — proving the logic behaves, not just that the right strings exist.
# ------------------------------------------------------------------


def _git(cwd: Path, *args: str, when: str | None = None) -> None:
    """Run a git command in cwd with deterministic identity/time."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@e",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@e",
    }
    if when is not None:
        env["GIT_AUTHOR_DATE"] = when
        env["GIT_COMMITTER_DATE"] = when
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True)


def _extract_shell_line(workflow_text: str, needle: str) -> str:
    """Pull the exact on-disk shell line containing `needle` from the YAML.

    Extracting the real line (not a hand-copy) means these tests exercise
    whatever the workflow actually ships — they break if the line drifts.
    """
    for line in workflow_text.splitlines():
        if needle in line:
            return line.strip()
    raise AssertionError(f"no workflow line contains {needle!r}")


def _seed_repo(tmp_path: Path) -> Path:
    """A git repo with a single commit dated far in the past (2020)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "f").write_text("x")
    _git(repo, "add", "f")
    _git(repo, "commit", "-q", "-m", "c", when="2020-01-01T00:00:00")
    return repo


def _resolve_latest_tag(repo: Path, resolver_line: str) -> tuple[str, int]:
    """Run the extracted LATEST_TAG resolver line; return (tag, returncode)."""
    script = f'set -euo pipefail\n{resolver_line}\nprintf "%s" "$LATEST_TAG"'
    out = subprocess.run(["bash", "-c", script], cwd=repo, capture_output=True, text=True)
    return out.stdout.strip(), out.returncode


class TestReleaseSyncResolutionBehaviour:
    """Execute the workflow's real tag-resolution shell against fixtures."""

    def test_picks_latest_clean_release_tag(self, tmp_path: Path, release_sync_text: str):
        """rc, dashed, junk, and a stray higher non-release tag are all
        ignored; the highest clean vMAJOR.MINOR.PATCH wins.

        Mirrors the live tag set that broke this: v1.0 (the original stray)
        sorts above v0.3.6 under version sort and MUST be filtered out.
        """
        repo = _seed_repo(tmp_path)
        for tag in ["v0.3.5", "v0.3.6", "v0.3.7rc1", "v1.0", "v0.0.0-test", "v0.1-website-base"]:
            _git(repo, "tag", tag)
        line = _extract_shell_line(release_sync_text, "LATEST_TAG=$(git tag")
        tag, rc = _resolve_latest_tag(repo, line)
        assert rc == 0
        assert tag == "v0.3.6", f"expected v0.3.6, got {tag!r}"

    def test_a_real_higher_release_is_not_filtered(self, tmp_path: Path, release_sync_text: str):
        """(A) Negative / real-drift: the clean-semver filter must not be so
        aggressive it hides a genuine higher release.

        A real `v0.4.0` MUST win — so if PyPI lagged at 0.3.6, the downstream
        version-chain check would correctly fire. This proves the monitor
        still barks at a real fire, not just that it stopped crying wolf.
        """
        repo = _seed_repo(tmp_path)
        for tag in ["v0.3.6", "v0.4.0"]:
            _git(repo, "tag", tag)
        line = _extract_shell_line(release_sync_text, "LATEST_TAG=$(git tag")
        tag, _ = _resolve_latest_tag(repo, line)
        assert tag == "v0.4.0", "a real higher release must be detected, not filtered away"
        # A lagging PyPI (0.3.6) vs this tag is genuine drift the monitor flags.
        assert tag[1:] != "0.3.6"

    def test_no_clean_tag_does_not_crash(self, tmp_path: Path, release_sync_text: str):
        """`|| true` must absorb grep no-match / head SIGPIPE under pipefail,
        leaving LATEST_TAG empty for the guard to report — not a crash."""
        repo = _seed_repo(tmp_path)
        _git(repo, "tag", "nightly")  # non-matching tag only
        line = _extract_shell_line(release_sync_text, "LATEST_TAG=$(git tag")
        tag, rc = _resolve_latest_tag(repo, line)
        assert rc == 0, "pipefail must not crash when no clean release tag exists"
        assert tag == "", f"expected empty (guard handles it), got {tag!r}"

    def test_tag_date_is_creation_time_not_commit_date(
        self, tmp_path: Path, release_sync_text: str
    ):
        """(B) + point 3: an annotated tag created now on a 2020 commit must
        report ~now (creatordate), NOT 2020 (commit date).

        `git log -1 --format=%cI` would return the commit date and re-inflate
        deploy-lag; `for-each-ref creatordate` returns the true tag time. Also
        documents the lightweight-tag caveat: signed release tags are always
        annotated, so creatordate is the real signal here.
        """
        repo = _seed_repo(tmp_path)
        _git(repo, "tag", "-a", "v0.3.6", "-m", "release")  # annotated, created now
        line = _extract_shell_line(release_sync_text, "TAG_DATE=$(git for-each-ref")
        script = f'set -euo pipefail\nLATEST_TAG=v0.3.6\n{line}\nprintf "%s" "$TAG_DATE"'
        out = subprocess.run(["bash", "-c", script], cwd=repo, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert not out.stdout.startswith("2020"), (
            f"tag date {out.stdout!r} is the commit date (2020), not the tag "
            "creation date — A5 must use creatordate, not commit date"
        )


# ------------------------------------------------------------------
# publish.yml: signed-tag verification before publish (WOR-598)
# ------------------------------------------------------------------


class TestPublishTagVerification:
    """publish.yml must verify the maintainer's GPG-signed tag BEFORE it
    parses pyproject.toml or builds.

    Today publish.yml builds + Trusted-Publishes to PyPI on ANY pushed `v*`
    tag, while deploy-worker.yml already fail-closes on an unsigned tag — an
    asymmetry where anyone who can push a tag gets a PyPI release. The verify
    must be the FIRST step after checkout: the next step parses
    attacker-controlled pyproject.toml and the build step runs its build
    hooks (RCE surface), so the gate has to precede both.
    """

    def test_build_verifies_signed_tag_first(self, publish_data: dict):
        steps = publish_data["jobs"]["build"]["steps"]
        checkout_idx = next(
            (i for i, s in enumerate(steps) if "checkout" in str(s.get("uses", "")).lower()),
            None,
        )
        verify_idx = next(
            (i for i, s in enumerate(steps) if "verify-tag.sh" in str(s.get("run", ""))),
            None,
        )
        assert checkout_idx is not None, "publish.yml build job must check out the repo"
        assert verify_idx is not None, (
            "publish.yml build job must run .github/scripts/verify-tag.sh — PyPI "
            "must publish only from a maintainer-GPG-signed tag (WOR-598)."
        )
        assert verify_idx == checkout_idx + 1, (
            "verify-tag must be the FIRST step after checkout. Anything between "
            "checkout and verify (the pyproject parse + build hooks) would run "
            "against an unverified, attacker-pushable tag."
        )

    def test_verify_precedes_pyproject_parse(self, publish_data: dict):
        steps = publish_data["jobs"]["build"]["steps"]
        verify_idx = next(
            (i for i, s in enumerate(steps) if "verify-tag.sh" in str(s.get("run", ""))),
            None,
        )
        version_idx = next(
            (
                i
                for i, s in enumerate(steps)
                if "matches pyproject" in str(s.get("name", "")).lower()
            ),
            None,
        )
        assert verify_idx is not None
        if version_idx is not None:
            assert verify_idx < version_idx, (
                "tag-signature verify must precede the pyproject.toml parse, which "
                "reads attacker-controlled file contents."
            )

    def test_no_skip_path_triggers(self, publish_data: dict):
        # PyYAML parses the bare `on:` key as the boolean True, so check both.
        on_block = publish_data.get("on", publish_data.get(True))
        assert isinstance(on_block, dict), "publish.yml must have an on: trigger mapping"
        triggers = set(on_block.keys())
        # workflow_dispatch / workflow_call would let the `if: event_name ==
        # 'push'` guard on the verify step be skipped — publishing without a
        # signature check. Triggers must stay push-tags-only.
        assert triggers == {"push"}, (
            f"publish.yml triggers must be push-only (got {sorted(triggers)}); "
            "workflow_dispatch/workflow_call would bypass the signed-tag verify."
        )


# ------------------------------------------------------------------
# Auto-created GitHub Release guardrails (WOR-846)
# ------------------------------------------------------------------


class TestReleaseNotesGuardrails:
    """release-notes.yml creates the GitHub Release once all four publishers pass.

    It is the only workflow holding a ``contents: write`` token, so it must be
    structurally unable to (a) mint a tag — ``gh release create`` creates an
    unsigned tag if one is absent, which fails the GPG gate AND tombstones the
    version name permanently — or (b) execute attacker-pushable tag content while
    that token is live. Each test below pins one security-signed-off guardrail;
    they are described inline rather than by number, because `.github/` already
    uses an unrelated F-numbering (docker-security.yml) and the collision misled
    more than the shorthand saved.
    """

    @staticmethod
    def _job(data: dict) -> dict:
        return data["jobs"]["create-release"]

    @staticmethod
    def _runs(data: dict) -> str:
        steps = TestReleaseNotesGuardrails._job(data)["steps"]
        return "\n".join(str(s.get("run", "")) for s in steps)

    @staticmethod
    def _code(data: dict) -> str:
        """The run: blocks with shell comments stripped.

        Asserting a required flag against raw text is vacuous: the comments
        explaining WHY a flag matters also contain the flag, so deleting it from
        the command leaves the assertion green. TestGuardsCanActuallyFail caught
        exactly that here. Anything checking "this flag must be present" has to
        look at executable text only.
        """
        out = []
        for line in TestReleaseNotesGuardrails._runs(data).splitlines():
            if line.lstrip().startswith("#"):
                continue
            out.append(line.split(" #", 1)[0])
        return "\n".join(out)

    def test_top_level_permissions_are_read_only(self, release_notes_data: dict):
        # F3: the write scope must be opted into per-job, never granted workflow-wide.
        assert release_notes_data.get("permissions") == {"contents": "read"}

    def test_write_scope_is_job_local_and_minimal(self, release_notes_data: dict):
        # F3: contents:write only, plus actions:read for the fan-in API reads.
        perms = self._job(release_notes_data)["permissions"]
        assert perms.get("contents") == "write"
        assert set(perms) <= {"contents", "actions"}, (
            f"release job must not hold scopes beyond contents/actions (got {sorted(perms)}); "
            "id-token or packages would let it publish artifacts, not just notes."
        )

    def test_release_job_sits_behind_protected_environment(self, release_notes_data: dict):
        # F3: `release` environment carries the required-reviewer rule, so a
        # malicious workflow edit still can't cut a Release unattended.
        assert self._job(release_notes_data).get("environment") == "release"

    def test_fires_only_on_a_pushed_v_tag(self, release_notes_data: dict):
        # F2: workflow_run inherits the triggering event; anything but a real tag
        # push must be refused before the signed-tag verify is reachable. The gate
        # job is the entry point, and the privileged job hangs off it.
        cond = release_notes_data["jobs"]["gate"]["if"]
        assert "workflow_run.event == 'push'" in cond
        assert "head_branch, 'v'" in cond
        assert self._job(release_notes_data).get("needs") == "gate"

    def test_approval_is_requested_once_not_per_publisher(self, release_notes_data: dict):
        """The environment gate must NOT sit on a job that runs every firing.

        This workflow fires on each of four publisher completions. `environment:`
        prompts a required reviewer before a job's first step, so an environment on
        the every-firing job would ask for approval up to four times per release —
        the opposite of "push a signed tag and walk away". Only the job guarded by
        the fan-in verdict may carry it.
        """
        gate = release_notes_data["jobs"]["gate"]
        assert "environment" not in gate, (
            "the every-firing gate job must not carry `environment:` — it would "
            "prompt for approval on every publisher completion."
        )
        assert gate["permissions"].get("contents") == "read"
        assert self._job(release_notes_data)["if"] == "needs.gate.outputs.ready == 'true'"

    def test_reverifies_the_signed_tag_independently(self, release_notes_data: dict):
        """F5: the privileged job re-verifies the GPG signature itself.

        Non-vacuous on purpose. The first version of this test only asserted that
        the string "verify-tag.sh" appeared somewhere, which passed while the tag
        was handed over via GITHUB_REF_NAME — an assignment GitHub silently
        DISCARDS for GITHUB_*-prefixed names, so the script verified "main",
        failed closed, and no Release could ever be created. Assert the override
        actually reaches the script under a usable name.
        """
        step = next(
            s
            for s in self._job(release_notes_data)["steps"]
            if "verify-tag.sh" in str(s.get("run", ""))
        )
        env = step.get("env", {})
        assert "GITHUB_REF_NAME" not in env, (
            "GitHub ignores assignments to GITHUB_*-prefixed variables, so this "
            "override never arrives and verify-tag.sh checks the default branch."
        )
        ref = env.get("VERIFY_TAG_REF", "")
        assert "workflow_run.head_branch" in ref, (
            f"the tag under verification must come from the triggering event; got {ref!r}"
        )
        # ...and the script must actually honour that variable.
        verify_sh = (REPO_ROOT / ".github" / "scripts" / "verify-tag.sh").read_text()
        assert "VERIFY_TAG_REF" in verify_sh, (
            "verify-tag.sh does not read VERIFY_TAG_REF — the override is inert."
        )

    def test_cannot_mint_a_tag(self, release_notes_data: dict):
        # F1: --verify-tag aborts unless the git tag already exists; --target would
        # let the Release point at an arbitrary commit.
        code = self._code(release_notes_data)
        assert "--verify-tag" in code, (
            "gh release create must pass --verify-tag — without it, a missing tag is "
            "silently created UNSIGNED and the version name is tombstoned forever."
        )
        assert "--target" not in code, "no --target: the Release must follow the signed tag only"

    def test_runs_no_untrusted_tag_content(self, release_notes_data: dict):
        # F4: the job checks out the default branch and runs only trusted scripts.
        # A build/install step would execute tag-authored hooks with the write token live.
        runs = self._runs(release_notes_data)
        for forbidden in ("python -m build", "npm ci", "npm install", "pip install", "uv sync"):
            assert forbidden not in runs, (
                f"{forbidden!r} executes tag-content code while contents:write is live"
            )
        checkout = next(
            s
            for s in self._job(release_notes_data)["steps"]
            if "checkout" in str(s.get("uses", "")).lower()
        )
        assert checkout.get("with", {}).get("persist-credentials") is False
        # Dict-key membership, NOT a substring of str(dict): str({'ref': ...}) renders
        # as "{'ref': ...}", so a "ref:" substring test never matches and the guard
        # would pass even when the job checks out the tag (CodeRabbit, PR #462).
        assert "ref" not in checkout.get("with", {}), (
            "must check out the default branch, not the tag — scripts executed here must be trusted"
        )

    def test_is_idempotent_across_repeat_firings(self, release_notes_data: dict):
        # F8: up to four publisher completions fire this workflow for one tag.
        assert "concurrency" in release_notes_data
        assert "gh release view" in self._runs(release_notes_data), (
            "must skip when the Release already exists — repeat firings are expected"
        )

    def test_trigger_matches_the_publishers_actual_names(self, release_notes_data: dict):
        # Drift guard: workflow_run matches on DISPLAY name. Renaming a publisher
        # would silently orphan the fan-in and no Release would ever be created.
        on_block = release_notes_data.get("on", release_notes_data.get(True))
        listed = set(on_block["workflow_run"]["workflows"])
        actual = {
            yaml.safe_load((REPO_ROOT / ".github" / "workflows" / wf).read_text())["name"]
            for wf in PUBLISHER_WORKFLOWS
        }
        assert listed == actual, (
            "release-notes.yml workflow_run.workflows must equal the publishers' name: "
            f"fields exactly.\n  listed: {sorted(listed)}\n  actual: {sorted(actual)}"
        )

    def test_fanin_polls_every_publisher(self):
        # A publisher missing from the fan-in list would let the Release ship while
        # that leg had failed.
        text = RELEASE_FANIN_SCRIPT.read_text()
        for wf in PUBLISHER_WORKFLOWS:
            assert wf in text, f"release-fanin.sh must require {wf} to be green"

    def test_fanin_forces_get_on_the_api_call(self):
        # `gh api` silently POSTs when any -f field is present; the runs endpoint
        # only exists for GET, so without -X GET it 404s and (under set -e) the
        # whole fan-in aborts — no Release, ever. Verified live on v0.3.10. Pin it
        # so a future "cleanup" can't drop the flag and silently break every release.
        # Check the COMMAND, not the file text: the script's own comment says
        # "Do not remove -X GET", so a whole-file grep passes even after the flag
        # is deleted from the call — the guard was vacuous until TestGuardsCanActuallyFail
        # caught it. Assert on the executable line only.
        code = [
            line.split("#", 1)[0]
            for line in RELEASE_FANIN_SCRIPT.read_text().splitlines()
            if not line.lstrip().startswith("#")
        ]
        api_calls = [line for line in code if "gh api" in line]
        assert api_calls, "fan-in must call `gh api` to poll publisher status"
        for call in api_calls:
            assert "-X GET" in call, (
                "the gh api call must force GET — without it `-f` fields make gh "
                f"POST, the runs endpoint 404s, and the fan-in aborts:\n  {call.strip()}"
            )

    def test_changelog_extraction_picks_one_section(self):
        sample = (
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "## [0.3.10] — 2026-07-21\n\n### Security\n- the released thing\n\n"
            "## [0.3.9] — 2026-07-01\n\n- the older thing\n"
        )
        hit = subprocess.run(
            [sys.executable, str(EXTRACT_CHANGELOG_SCRIPT), "0.3.10"],
            input=sample,
            capture_output=True,
            text=True,
            check=False,
        )
        assert hit.returncode == 0
        assert "the released thing" in hit.stdout
        assert "the older thing" not in hit.stdout, "must stop at the next ## [ heading"
        assert "Unreleased" not in hit.stdout

        # Unknown version → exit 3 so the workflow falls back to --generate-notes
        # rather than publishing a Release with empty notes.
        miss = subprocess.run(
            [sys.executable, str(EXTRACT_CHANGELOG_SCRIPT), "9.9.9"],
            input=sample,
            capture_output=True,
            text=True,
            check=False,
        )
        assert miss.returncode == 3
        assert miss.stdout.strip() == ""


class TestReleaseFaninBehaviour:
    """Behavioural coverage for release-fanin.sh — run the REAL script against a
    fake `gh` on PATH and assert the ready verdict AND the exit code. Static
    string-greps cannot catch the silent-permanent-hold class of bug (a terminal
    non-success conclusion outside a hand-listed set being mistaken for "still
    waiting"), so these run the classifier for real. WOR-846."""

    ALL_GREEN = (
        "publish.yml=completed:success,publish-npm.yml=completed:success,"
        "publish-docker.yml=completed:success,deploy-worker.yml=completed:success"
    )

    @staticmethod
    def _run(tmp_path, runs_spec: str):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text(_FANIN_GH_SHIM)
        gh.chmod(0o755)
        out = tmp_path / "gh_output"
        out.touch()
        env = {
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(out),
            "GH_REPO": "o/w",
            "TAG": "v9.9.9",
            "HEAD_SHA": "deadbeef",
            "RUNS": runs_spec,
        }
        proc = subprocess.run(
            ["bash", str(REPO_ROOT / ".github" / "scripts" / "release-fanin.sh")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,  # a hung fan-in must fail this test fast, never stall the whole suite
        )
        ready = None
        for line in out.read_text().splitlines():
            if line.startswith("ready="):
                ready = line.split("=", 1)[1]
        return ready, proc.returncode, proc.stdout

    def test_all_four_green_is_ready_and_exits_zero(self, tmp_path):
        ready, rc, _ = self._run(tmp_path, self.ALL_GREEN)
        assert ready == "true"
        assert rc == 0

    def test_query_shape_holds_against_the_real_github_api(self, tmp_path):
        """Run the fan-in against the LIVE API and assert it reaches a verdict.

        The fake-`gh` tests above pin the decision logic but drive a stub, so they
        were blind to the bug that actually mattered: `gh api -f` silently switches
        to POST, there is no POST route for .../runs, it 404s, and under `set -e`
        the whole script aborts — no Release, on any tag, ever.

        Asserts REACHING a verdict, not which verdict. A bad query shape aborts
        mid-loop and never writes `ready=`, so absence of a verdict is the signal.
        Deliberately NOT asserting ready=="true" against a pinned release: GitHub
        expires workflow-run records (90 days by default), which would turn this
        into a test that goes red on a calendar date for reasons unrelated to the
        code. An expired tag simply yields ready=false — still a verdict, still a
        pass. Read-only; creates nothing.
        """
        if shutil.which("gh") is None:
            pytest.skip("gh CLI not installed")
        probe = subprocess.run(
            ["gh", "api", "/rate_limit"], capture_output=True, text=True, timeout=60, check=False
        )
        if probe.returncode != 0:
            pytest.skip("no authenticated/reachable GitHub API from this environment")
        slug = subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if slug.returncode != 0 or not slug.stdout.strip():
            pytest.skip("cannot resolve the repository slug from gh")
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        out = tmp_path / "gh_output"
        out.touch()
        env = {
            **os.environ,
            "GITHUB_OUTPUT": str(out),
            "GH_REPO": slug.stdout.strip(),
            # Any plausible tag works: we are exercising the QUERY, not a release.
            "TAG": "v0.3.10",
            "HEAD_SHA": head.stdout.strip(),
        }
        proc = subprocess.run(
            ["bash", str(REPO_ROOT / ".github" / "scripts" / "release-fanin.sh")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        ready = None
        for line in out.read_text().splitlines():
            if line.startswith("ready="):
                ready = line.split("=", 1)[1]
        combined = f"{proc.stdout}\n{proc.stderr}"
        assert ready in ("true", "false"), (
            "fan-in never reached a verdict against the real API — it aborted "
            "mid-query, which is exactly how the POST/404 bug presented. "
            f"ready={ready!r}\n{combined}"
        )
        assert "404" not in combined and "Not Found" not in combined, (
            f"real API rejected the fan-in's request shape:\n{combined}"
        )

    def test_a_failed_leg_holds_the_release_and_fails_loud(self, tmp_path):
        spec = self.ALL_GREEN.replace(
            "publish-npm.yml=completed:success", "publish-npm.yml=completed:failure"
        )
        ready, rc, out = self._run(tmp_path, spec)
        assert ready == "false"
        assert rc != 0, "a terminally-failed leg must fail the run so GitHub notifies"
        assert "::error" in out

    def test_startup_failure_is_not_mistaken_for_waiting(self, tmp_path):
        # The exact bug the old {failure,cancelled,timed_out} list missed: a
        # terminal non-success conclusion outside that set. Must block LOUD, not
        # sit silently "waiting" forever.
        spec = self.ALL_GREEN.replace(
            "publish-docker.yml=completed:success",
            "publish-docker.yml=completed:startup_failure",
        )
        ready, rc, _ = self._run(tmp_path, spec)
        assert ready == "false"
        assert rc != 0, "startup_failure/skipped/stale must block loudly, not wait forever"

    def test_an_in_progress_leg_waits_quietly(self, tmp_path):
        # Not-yet-finished is NOT a failure — exit 0 so a later firing can complete
        # the fan-in. Failing here would turn every early firing red.
        spec = self.ALL_GREEN.replace(
            "deploy-worker.yml=completed:success", "deploy-worker.yml=in_progress:null"
        )
        ready, rc, out = self._run(tmp_path, spec)
        assert ready == "false"
        assert rc == 0, "an in-progress leg must not fail the run"
        assert "::error" not in out

    def test_a_never_started_leg_waits_not_blocks(self, tmp_path):
        # A leg with no runs yet (omitted) is indistinguishable from "hasn't
        # started", so it waits (exit 0), unlike a terminal failure.
        spec = (
            "publish.yml=completed:success,publish-npm.yml=completed:success,"
            "publish-docker.yml=completed:success"  # deploy-worker absent
        )
        ready, rc, _ = self._run(tmp_path, spec)
        assert ready == "false"
        assert rc == 0


# ------------------------------------------------------------------
# install.sh pin ↔ pyproject version invariant (WOR-598, option iii guard)
# ------------------------------------------------------------------


class TestInstallPinMatchesPyproject:
    """`install.sh`'s baked `WORTHLESS_VERSION_PIN` must equal pyproject's version.

    The PR install-smoke override (`WORTHLESS_VERSION` on `pull_request`) installs
    the latest *published* version so a release PR's not-yet-published pin doesn't
    fail CI. This static guard ensures that convenience can't mask drift: the
    baked pin must always match the package version this repo ships, so the
    default `curl … | sh` installs exactly what we publish.
    """

    def test_pin_equals_pyproject_version(self):
        install_text = (REPO_ROOT / "install.sh").read_text()
        m = re.search(r'^WORTHLESS_VERSION_PIN="([^"]*)"', install_text, re.MULTILINE)
        assert m, 'install.sh must declare WORTHLESS_VERSION_PIN="..."'
        pin = m.group(1)
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        version = pyproject["project"]["version"]
        assert pin == version, (
            f"install.sh pin {pin!r} != pyproject version {version!r}. "
            "The default `curl | sh` must install the version this repo ships — "
            "bump them together (scripts/bump-version.sh)."
        )


# ------------------------------------------------------------------
# Meta-guards: catch the class of defect CI kept missing (WOR-846)
#
# Three times on this workstream a fully green suite hid a defect that made the
# feature non-functional: `gh api -f` silently switching to POST, an assertion
# that could not fail, and an env override GitHub discards. None were catchable
# by the tests themselves — they need tests ABOUT the tests and about the
# platform's rules.
# ------------------------------------------------------------------


# Variables GitHub sets automatically for every job. Assigning any of these in an
# `env:` block is silently IGNORED, so the value you think you passed never
# arrives. GITHUB_TOKEN is deliberately absent: it is NOT auto-provided, so
# passing it explicitly is both legal and the documented convention.
GITHUB_AUTOSET_ENV_VARS = frozenset(
    {
        "GITHUB_ACTION",
        "GITHUB_ACTIONS",
        "GITHUB_ACTOR",
        "GITHUB_API_URL",
        "GITHUB_BASE_REF",
        "GITHUB_ENV",
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_HEAD_REF",
        "GITHUB_JOB",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_REF_TYPE",
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_OWNER",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_NUMBER",
        "GITHUB_SERVER_URL",
        "GITHUB_SHA",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_WORKFLOW",
        "GITHUB_WORKSPACE",
    }
)


class TestNoWorkflowOverridesAutosetVars:
    """No workflow may assign a variable GitHub sets automatically.

    Regression guard for the WOR-846 blocker: release-notes.yml passed the tag to
    verify-tag.sh as ``GITHUB_REF_NAME``. GitHub discards assignments to its own
    default variables, so the script kept reading the default branch, failed
    closed, and no Release could ever be created — while actionlint, zizmor and
    37 CI checks all stayed green. A one-second check catches the whole class.
    """

    def test_no_workflow_assigns_an_autoset_variable(self):
        offenders: list[str] = []

        def walk(node, path: str, wf: str) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "env" and isinstance(value, dict):
                        for name in value:
                            if str(name) in GITHUB_AUTOSET_ENV_VARS:
                                offenders.append(f"{wf}{path}.env.{name}")
                    walk(value, f"{path}.{key}", wf)
            elif isinstance(node, list):
                for i, value in enumerate(node):
                    walk(value, f"{path}[{i}]", wf)

        workflow_dir = REPO_ROOT / ".github" / "workflows"
        for wf in sorted(workflow_dir.glob("*.yml")):
            walk(yaml.safe_load(wf.read_text()), "", wf.name)

        assert not offenders, (
            "these assignments are silently ignored by GitHub, so the value never "
            "reaches the step — use a non-reserved name (e.g. VERIFY_TAG_REF):\n  "
            + "\n  ".join(offenders)
        )


# Each entry: (label, file, find, replace, the guard test that MUST then fail).
# Adding a security guard to TestReleaseNotesGuardrails without adding a mutation
# here is how a vacuous assertion slips in — twice already on this workstream.
GUARD_MUTATIONS = [
    (
        "drop --verify-tag (job could mint an unsigned tag)",
        ".github/workflows/release-notes.yml",
        # Anchor on the command, not the comment above it that also names the flag.
        "--verify-tag $NOTES",
        "$NOTES",
        "test_cannot_mint_a_tag",
    ),
    (
        "pass the tag via a variable GitHub ignores",
        ".github/workflows/release-notes.yml",
        "VERIFY_TAG_REF:",
        "GITHUB_REF_NAME:",
        "test_reverifies_the_signed_tag_independently",
    ),
    (
        "let the API call fall back to POST",
        ".github/scripts/release-fanin.sh",
        # Anchor on the call itself; the header comment also contains "-X GET".
        '/runs" -X GET',
        '/runs"',
        "test_fanin_forces_get_on_the_api_call",
    ),
    (
        "grant write at the workflow level",
        ".github/workflows/release-notes.yml",
        "permissions:\n  contents: read",
        "permissions:\n  contents: write",
        "test_top_level_permissions_are_read_only",
    ),
    (
        "drop the protected environment",
        ".github/workflows/release-notes.yml",
        "    environment: release\n",
        "",
        "test_release_job_sits_behind_protected_environment",
    ),
    (
        "check out the tag instead of the default branch",
        ".github/workflows/release-notes.yml",
        # Anchor on fetch-depth so this lands on the create-release checkout, not
        # the gate job's — the guard inspects create-release.
        "          fetch-depth: 0\n          persist-credentials: false",
        "          fetch-depth: 0\n          ref: refs/tags/v9.9.9\n"
        "          persist-credentials: false",
        "test_runs_no_untrusted_tag_content",
    ),
]


class TestGuardsCanActuallyFail:
    """Every security guard must be provably capable of failing.

    Twice on this workstream a guard was structurally incapable of failing and
    passed on broken code: ``"ref:" not in str(dict)`` (a substring that can never
    occur once a dict is stringified) and a bare grep for ``"verify-tag.sh"`` that
    stayed green while the tag was handed over via a variable GitHub discards.
    Both looked like coverage. Neither was.

    So: mutate the thing each guard protects, and require the guard to go RED.
    A guard that survives its own mutation is not protecting anything.
    """

    @pytest.mark.parametrize(
        ("label", "rel_path", "find", "replace", "guard_test"),
        [pytest.param(*m, id=m[4]) for m in GUARD_MUTATIONS],
    )
    def test_guard_fails_when_its_subject_is_broken(
        self, tmp_path, label, rel_path, find, replace, guard_test
    ):
        # Work on a full copy so nothing mutates the real tree — safe under xdist.
        shutil.copytree(REPO_ROOT / ".github", tmp_path / ".github")
        (tmp_path / "tests").mkdir()
        shutil.copy(Path(__file__), tmp_path / "tests" / Path(__file__).name)

        target = tmp_path / rel_path
        original = target.read_text()
        assert find in original, (
            f"mutation {label!r} no longer applies — {rel_path} does not contain "
            f"{find!r}. Update GUARD_MUTATIONS to match the current code."
        )
        target.write_text(original.replace(find, replace, 1))

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(tmp_path / "tests" / Path(__file__).name),
                # Exclude this harness: `-k <name>` also matches the parametrize
                # id below, which would make the subprocess re-run the harness
                # recursively (and mask the guard's own verdict).
                "-k",
                f"{guard_test} and not guard_fails_when",
                "-p",
                "no:randomly",
                "-p",
                "no:cacheprovider",
                "-q",
                "--no-header",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert proc.returncode != 0, (
            f"{guard_test} PASSED against a deliberately broken workflow "
            f"({label}). The guard is vacuous — it asserts something that cannot "
            f"fail, so it is not protecting the invariant it claims to.\n"
            f"{proc.stdout[-2000:]}"
        )

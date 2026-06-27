"""WOR-432 — Sideloaded worthless skill yields a protected request end-to-end.

Stack: mock-upstream + worthless-proxy + openclaw gateway (--profile openclaw).

The test sideloads the worthless SKILL.md the way `clawhub install worthless`
would (the skill is not published on ClawHub yet), patches openclaw.json so
the worthless-test provider points at the running proxy, then triggers an
agent turn via `openclaw agent --local --json` and asserts the mock upstream
received the reconstructed real key — never shard-A.

Three observable hops, one assertion at each:
  1. Skill file — SKILL.md installed in the bind-mounted skills dir.
  2. Provider routing — `openclaw agent` succeeds with model worthless-test/gpt-4o.
  3. Key reconstruction — mock-upstream /captured-headers shows real key, no shard-A.

Run:
    uv run pytest tests/test_openclaw_skill_e2e.py -m openclaw -v

Requires Docker daemon. Skipped when Docker unavailable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from tests._docker_helpers import docker_available, docker_exec, wait_healthy
from tests.helpers import fake_openai_key
from worthless.cli.commands.lock import _make_alias

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "tests" / "openclaw" / "docker-compose.yml"
OC_CONFIG_DIR = REPO_ROOT / "tests" / "openclaw" / "openclaw-config"
SKILL_ASSETS_DIR = REPO_ROOT / "src" / "worthless" / "openclaw" / "skill_assets"

pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.timeout(300),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Run a command, raise on failure."""
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kwargs)


def _run_ok(cmd: list[str]) -> str:
    return _run(cmd).stdout.strip()


def _host_port(container: str, internal_port: int) -> int:
    """Return the dynamic host port mapped to container's internal_port."""
    out = _run_ok(["docker", "port", container, str(internal_port)])
    return int(out.rsplit(":", 1)[-1])


def _write_env_to_container(
    container: str,
    env_content: str,
    dest: str = "/tmp/.env",  # noqa: S108 (path is inside the container, not host)
) -> None:
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
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
    assert result.returncode == 0, f"failed to write .env: {result.stderr}"


def _read_env_value(
    container: str,
    var_name: str,
    path: str = "/tmp/.env",  # noqa: S108
) -> str:
    result = docker_exec(
        container,
        ["sh", "-c", f"grep '^{var_name}=' {path} | cut -d= -f2-"],
    )
    assert result.returncode == 0, f"failed to read {var_name}: {result.stderr}"
    return result.stdout.strip()


def _clear_mock_headers(mock_port: int) -> None:
    httpx.delete(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=5)


def _wait_openclaw_ready(container: str, timeout: float = 90.0) -> None:
    """Poll until OpenClaw's /healthz responds ok inside the container.

    OpenClaw has no Docker HEALTHCHECK directive so we can't use wait_healthy().
    We exec a one-shot fetch against the internal port instead.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = docker_exec(
            container,
            [
                "node",
                "-e",
                (
                    "fetch('http://127.0.0.1:18789/healthz')"
                    ".then(r=>r.json())"
                    ".then(j=>process.exit(j.ok?0:1))"
                    ".catch(()=>process.exit(1))"
                ),
            ],
        )
        if result.returncode == 0:
            return
        time.sleep(3)
    pytest.fail(f"OpenClaw gateway did not become ready in {timeout}s")


# ---------------------------------------------------------------------------
# Session-scoped fixture: 3-container stack + skill sideload
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def clawhub_stack():
    """Bring up proxy + mock-upstream + openclaw. Sideload the skill.

    Workflow mirrors what `clawhub install worthless` + `worthless lock` would
    do for a real user, so we can assert the full chain without a published
    skill or a live ClawHub account.

    Yields (proxy_port, mock_port, fake_key, shard_a, alias, oc_container).

    Restores git-tracked openclaw-config/ files on teardown so the worktree
    stays clean after the run.
    """
    project = f"oc-wor432-{uuid.uuid4().hex[:8]}"
    fake_key = fake_openai_key()
    alias = _make_alias("openai", fake_key)

    # Snapshot git-tracked files we will modify during the test.
    oc_json_path = OC_CONFIG_DIR / "openclaw.json"
    oc_json_original = oc_json_path.read_text(encoding="utf-8")
    skills_dest = OC_CONFIG_DIR / "skills" / "worthless"
    skills_pre_existed = skills_dest.exists()

    try:
        # 1. Bring up the full lane including the openclaw profile.
        _run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "-p",
                project,
                "--profile",
                "openclaw",
                "up",
                "-d",
                "--build",
            ],
            cwd=str(REPO_ROOT),
            timeout=300,
        )

        proxy_c = f"{project}-worthless-proxy-1"
        oc_c = f"{project}-openclaw-1"
        mock_c = f"{project}-mock-upstream-1"

        assert wait_healthy(proxy_c, timeout=90), "worthless-proxy did not become healthy"
        _wait_openclaw_ready(oc_c, timeout=90)

        proxy_port = _host_port(proxy_c, 8787)
        mock_port = _host_port(mock_c, 9999)

        # 2. Register mock-upstream URL in the proxy's provider registry.
        #    (Matches the pattern in test_openclaw_e2e.py / openclaw_stack.)
        register = docker_exec(
            proxy_c,
            [
                "worthless",
                "providers",
                "register",
                "--name",
                "openai-mock",
                "--url",
                "http://mock-upstream:9999/openai/v1",
                "--protocol",
                "openai",
            ],
        )
        assert register.returncode == 0, f"providers register failed: {register.stderr}"

        # 3. Write a .env with the fake key and lock it.
        #    Lock writes shard-A back to .env; shard-B goes to the proxy DB.
        env_content = (
            f"OPENAI_API_KEY={fake_key}\nOPENAI_BASE_URL=http://mock-upstream:9999/openai/v1\n"
        )
        _write_env_to_container(proxy_c, env_content)
        lock = docker_exec(proxy_c, ["worthless", "lock", "--env", "/tmp/.env"])  # noqa: S108
        assert lock.returncode == 0, f"worthless lock failed: {lock.stderr}"

        shard_a = _read_env_value(proxy_c, "OPENAI_API_KEY")
        assert shard_a != fake_key, "lock did not replace the key with shard-A"
        assert shard_a.startswith("sk-"), f"shard-A not format-preserving: {shard_a[:20]!r}"

        # 4. Sideload the worthless SKILL.md into the bind-mounted skills dir.
        #    This replicates what `clawhub install worthless` would do.
        #    The bind-mount is: tests/openclaw/openclaw-config/ → /home/node/.openclaw/
        #    so skills land at tests/openclaw/openclaw-config/skills/worthless/SKILL.md
        skills_dest.mkdir(parents=True, exist_ok=True)
        skill_src = SKILL_ASSETS_DIR / "SKILL.md"
        shutil.copy2(skill_src, skills_dest / "SKILL.md")

        # 5. Patch openclaw.json so worthless-test provider routes through the
        #    proxy at the correct alias path, authenticated with shard-A.
        #    The openclaw container reads this file via the bind-mount (live).
        oc_cfg = json.loads(oc_json_path.read_text(encoding="utf-8"))
        oc_cfg["models"]["providers"]["worthless-test"].update(
            {
                "baseUrl": f"http://worthless-proxy:8787/{alias}/v1",
                "apiKey": shard_a,
            }
        )
        oc_json_path.write_text(
            json.dumps(oc_cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # 6. Clear accumulated headers before assertions.
        _clear_mock_headers(mock_port)

        yield proxy_port, mock_port, fake_key, shard_a, alias, oc_c

    finally:
        # Tear down Docker stack.
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "-p",
                project,
                "--profile",
                "openclaw",
                "down",
                "-v",
                "--remove-orphans",
            ],
            capture_output=True,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
        # Restore git-tracked config files so the worktree stays clean.
        oc_json_path.write_text(oc_json_original, encoding="utf-8")
        if not skills_pre_existed:
            shutil.rmtree(skills_dest, ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestClawhubInstallProducesProtectedRequest:
    """WOR-432: sideloaded skill + wired provider → real key at upstream, no shard-A."""

    def test_skill_file_installed_in_bind_mount(self, clawhub_stack) -> None:
        """Hop 1: SKILL.md is present in the bind-mounted skills dir.

        Confirms the sideload landed in the path OpenClaw reads at startup.
        We assert on the file directly (no reliance on `openclaw skills list
        --json` which may not exist or may report 'disabled' because the
        worthless binary is not in the OpenClaw container's PATH).
        """
        skill_file = OC_CONFIG_DIR / "skills" / "worthless" / "SKILL.md"
        assert skill_file.is_file(), f"SKILL.md not found at {skill_file}"
        content = skill_file.read_text(encoding="utf-8")
        assert "name: worthless" in content, "SKILL.md missing name frontmatter"
        assert "requires" in content, "SKILL.md missing requires block"

    def test_agent_turn_produces_reconstructed_key_at_upstream(
        self,
        clawhub_stack,
    ) -> None:
        """Hops 2 + 3: agent turn routes through proxy; real key arrives at upstream.

        `openclaw agent --local --model worthless-test/gpt-4o` sends a request
        using the worthless-test provider config (baseUrl = our proxy). The proxy
        receives shard-A as the Bearer token, looks up shard-B, reconstructs the
        real key, and forwards to mock-upstream. The mock records every
        Authorization header at GET /captured-headers — we assert the real key
        arrived and shard-A never appeared there.
        """
        proxy_port, mock_port, fake_key, shard_a, alias, oc_c = clawhub_stack

        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker",
                "exec",
                oc_c,
                "openclaw",
                "agent",
                "--local",
                "--json",
                "--session-id",
                "wor432-test",
                "--model",
                "worthless-test/gpt-4o",
                "--message",
                "Reply with exactly: pong",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert result.returncode == 0, (
            f"openclaw agent failed.\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        payload = json.loads(result.stdout)
        # openclaw agent --local --json returns {"payloads": [...], "meta": {...}}
        # Success is indicated by non-empty payloads and meta.aborted == False.
        assert payload.get("payloads") and not payload.get("meta", {}).get("aborted"), (
            f"agent returned failure: {payload}"
        )

        # Verify the mock upstream received the reconstructed key.
        captured = httpx.get(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=5).json()
        openai_entries = [e for e in captured["headers"] if e.get("provider") == "openai"]
        assert openai_entries, (
            "No upstream traffic captured — the proxy was not reached. "
            f"Check that openclaw.json baseUrl points to proxy at :{proxy_port}. "
            f"Alias: {alias!r}."
        )

        for entry in openai_entries:
            # Real key must have arrived upstream.
            got_auth = entry.get("authorization", "")
            assert got_auth == f"Bearer {fake_key}", (
                f"Upstream received wrong key.\n  got:  {got_auth!r}\n  want: Bearer {fake_key!r}"
            )
            # Shard-A must never appear in any upstream Authorization header.
            assert shard_a not in got_auth, (
                f"SECURITY: shard-A leaked to upstream! authorization={got_auth!r}"
            )

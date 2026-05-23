"""WOR-515 Phase 1 AC 11 — Real-container audit gate CI test.

Runs ``openclaw secrets audit --json`` inside the real
``ghcr.io/openclaw/openclaw:2026.5.3-1`` container against a seeded
openclaw.json that has multi-provider plaintext API keys.

Verifies:
- Gate classifies findings correctly against live container output
- Blocking findings list every non-worthless provider (anthropic, custom)
- gateway.auth.token is advisory (not blocking)
- format_gate_error_message names every blocking file:jsonPath

Marked openclaw+docker; skipped automatically when Docker is unavailable.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available
from worthless.openclaw.audit import (
    AuditResult,
    check_auth_profiles_direct,
    classify_findings,
    format_gate_error_message,
    parse_audit_result,
)

# ---------------------------------------------------------------------------
# Docker availability guard
# ---------------------------------------------------------------------------

_OPENCLAW_IMAGE = (
    "ghcr.io/openclaw/openclaw:2026.5.3-1"
    "@sha256:142f70fa2751bdedf03648ae427372fff3f92ac0e96ab91abb3824b088c38b7b"
)

pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
]

# ---------------------------------------------------------------------------
# Seeded config helpers
# ---------------------------------------------------------------------------

#: Seeded openclaw.json — two non-worthless providers with plaintext apiKeys
#: plus a gateway auth token (advisory, must be ignored by gate).
_SEEDED_OPENCLAW_JSON: dict = {
    "version": 1,
    "gateway": {
        "auth": {"token": "oc-ui-session-token-plaintext-1234567890abcdef"},
        "baseUrl": "http://127.0.0.1:18789",
    },
    "models": {
        "providers": {
            "anthropic": {
                "apiKey": "sk-ant-api03-AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF00000000",
                "baseUrl": "https://api.anthropic.com",
            },
            "custom-openai-provider": {
                "apiKey": "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "baseUrl": "https://api.openai.com/v1",
            },
        }
    },
}

_EMPTY_AUTH_PROFILES: dict = {"version": 1, "profiles": []}


@pytest.fixture(scope="session")
def _openclaw_image_pulled() -> None:
    """Pull the OpenClaw image once per test session; skip on network failure."""
    docker_bin = "docker"
    pull = subprocess.run(
        [docker_bin, "pull", _OPENCLAW_IMAGE],
        capture_output=True,
        timeout=120,
    )
    if pull.returncode != 0:
        pytest.skip(f"Cannot pull {_OPENCLAW_IMAGE}: {pull.stderr.decode()[:200]}")


def _seed_openclaw_config(base: Path) -> None:
    """Write a seeded openclaw config tree under *base*."""
    base.mkdir(parents=True, exist_ok=True)
    (base / "openclaw.json").write_text(json.dumps(_SEEDED_OPENCLAW_JSON))
    agents_dir = base / "agents" / "main" / "agent"
    agents_dir.mkdir(parents=True, exist_ok=True)
    (agents_dir / "auth-profiles.json").write_text(json.dumps(_EMPTY_AUTH_PROFILES))


def _run_container_audit(config_dir: Path) -> AuditResult:
    """Run ``openclaw secrets audit --json`` inside the real container.

    Mounts *config_dir* at ``/home/node/.openclaw`` (read-only).
    Returns the parsed :class:`~worthless.openclaw.audit.AuditResult`.

    Raises ``AssertionError`` if the command exits non-zero or emits bad JSON.
    The caller must ensure the image is already pulled (use ``_openclaw_image_pulled``).
    """
    docker_bin = "docker"
    result = subprocess.run(
        [
            docker_bin,
            "run",
            "--rm",
            "--user",
            "node",
            "--entrypoint",
            "openclaw",
            "-e",
            "OPENCLAW_ACCEPT_TERMS=yes",
            "-v",
            f"{config_dir}:/home/node/.openclaw:ro",
            _OPENCLAW_IMAGE,
            "secrets",
            "audit",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    # openclaw secrets audit exits 0 for both clean and findings status
    assert result.returncode == 0, (
        f"openclaw secrets audit exited {result.returncode}\nstderr: {result.stderr[:500]}"
    )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(f"openclaw audit --json emitted non-JSON: {exc}\n{result.stdout[:300]}")

    return parse_audit_result(data)


# ---------------------------------------------------------------------------
# AC 11 tests
# ---------------------------------------------------------------------------


class TestAC11RealContainerAuditGate:
    """AC 11: real container produces findings our gate correctly classifies."""

    def test_seeded_plaintext_produces_blocking_findings(
        self, _openclaw_image_pulled: None
    ) -> None:
        """Gate classifies live container output — anthropic + custom are blocking.

        gateway.auth.token is advisory (in IGNORE_JSON_PATHS), not blocking.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            _seed_openclaw_config(config_dir)
            result = _run_container_audit(config_dir)

        auth_blocking = check_auth_profiles_direct(result.files_scanned)
        classification = classify_findings(result, auth_blocking)

        assert classification.unknown_codes == (), (
            f"Unexpected unknown codes from live container: {classification.unknown_codes}"
        )

        blocking_paths = {b.json_path for b in classification.blocking}
        assert "models.providers.anthropic.apiKey" in blocking_paths, (
            f"anthropic not in blocking: {blocking_paths}"
        )
        assert "models.providers.custom-openai-provider.apiKey" in blocking_paths, (
            f"custom-openai-provider not in blocking: {blocking_paths}"
        )
        # gateway.auth.token must be advisory (IGNORE_JSON_PATHS)
        assert "gateway.auth.token" not in blocking_paths

    def test_gate_message_lists_every_blocking_finding(self, _openclaw_image_pulled: None) -> None:
        """format_gate_error_message names all blocking file:jsonPath pairs.

        Validates AC 4 (aggregation, no short-circuit) and AC 5 (remediation
        names ``openclaw secrets configure`` with no non-interactive flags —
        M0 confirmed configure requires a TTY).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            _seed_openclaw_config(config_dir)
            result = _run_container_audit(config_dir)

        auth_blocking = check_auth_profiles_direct(result.files_scanned)
        classification = classify_findings(result, auth_blocking)

        assert classification.blocking, "Expected blocking findings from seeded config"

        msg = format_gate_error_message(classification.blocking)

        assert "anthropic" in msg, f"anthropic missing from gate message:\n{msg}"
        assert "custom-openai-provider" in msg, (
            f"custom-openai-provider missing from gate message:\n{msg}"
        )
        # Remediation — no flags (M0: configure requires TTY)
        assert "openclaw secrets configure" in msg
        assert "plaintext" in msg.lower()

# ruff: noqa: S607  # test file — docker subprocess calls use "docker" not a full path
"""WOR-515 Phase 1 AC 11 — Real-container audit gate CI test.

Runs ``openclaw secrets audit --json`` inside the real
``ghcr.io/openclaw/openclaw:2026.5.3-1`` container against a seeded
config that has multi-provider plaintext API keys.

Verified config structure (M0 re-probe 2026-05-23):
- Provider API keys live in ``agents/main/agent/models.json`` with schema
  ``{"providers": {"<name>": {"apiKey": "..."}}}``
- Container requires ``openclaw setup`` first — hand-crafted openclaw.json
  produces REF_UNRESOLVED; only setup-initialised configs trigger PLAINTEXT_FOUND
- Audit jsonPath format is ``providers.<name>.apiKey`` (no ``models.`` prefix)

Verifies:
- Gate classifies findings correctly against live container output
- Blocking findings list every non-worthless provider (anthropic, custom)
- gateway.auth.token is advisory (not blocking)
- format_gate_error_message names every blocking file:jsonPath

Marked openclaw+docker; skipped automatically when Docker is unavailable.
"""

from __future__ import annotations

import json
import secrets
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
# Seed helpers
# ---------------------------------------------------------------------------


#: models.json — two non-worthless providers with real-prefix plaintext apiKeys.
#: Provider keys live in agents/main/agent/models.json, NOT in openclaw.json.
#: Confirmed by M0 re-probe against ghcr.io/openclaw/openclaw:2026.5.3-1.
def _make_models_json() -> dict:
    """Return a models.json dict with real-prefix plaintext API keys."""
    ant_key = f"sk-ant-api03-{secrets.token_urlsafe(71)}"
    oai_key = f"sk-{secrets.token_urlsafe(36)}"
    return {
        "providers": {
            "anthropic": {"apiKey": ant_key, "baseUrl": "https://api.anthropic.com"},
            "custom-openai-provider": {
                "apiKey": oai_key,
                "baseUrl": "https://api.openai.com/v1",
            },
        }
    }


@pytest.fixture(scope="session")
def _openclaw_image_pulled() -> None:
    """Pull the OpenClaw image once per test session; skip on network failure."""
    pull = subprocess.run(
        ["docker", "pull", _OPENCLAW_IMAGE],  # noqa: S607
        capture_output=True,
        timeout=120,
    )
    if pull.returncode != 0:
        pytest.skip(f"Cannot pull {_OPENCLAW_IMAGE}: {pull.stderr.decode()[:200]}")


def _seed_openclaw_config(base: Path) -> None:
    """Initialise a valid OpenClaw config tree under *base* with plaintext keys.

    Two-phase:
    1. ``openclaw setup`` — creates openclaw.json + workspace directories.
    2. Inject ``agents/main/agent/models.json`` with plaintext provider keys
       and add ``gateway.auth.token`` to openclaw.json for the advisory-finding
       test (gateway token must be in IGNORE_JSON_PATHS, not blocking).
    """
    base.mkdir(parents=True, exist_ok=True)
    base.chmod(0o777)  # container runs as node (uid 1000); must be world-writable

    # Phase 1: let the container initialise a valid config
    subprocess.run(  # noqa: S607
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "OPENCLAW_ACCEPT_TERMS=yes",
            "-v",
            f"{base}:/home/node/.openclaw",
            _OPENCLAW_IMAGE,
            "openclaw",
            "setup",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )

    # Phase 2: inject plaintext provider keys into models.json
    agent_dir = base / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "models.json").write_text(
        json.dumps(_make_models_json(), indent=2), encoding="utf-8"
    )
    (agent_dir / "auth-profiles.json").write_text(json.dumps({"profiles": []}), encoding="utf-8")

    # Add plaintext gateway token to openclaw.json (must stay advisory)
    config_path = base / "openclaw.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.setdefault("gateway", {})["auth"] = {"token": "oc-session-plaintext-abc123deadbeef"}
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _run_container_audit(config_dir: Path) -> AuditResult:
    """Run ``openclaw secrets audit --json`` inside the real container.

    Mounts *config_dir* at ``/home/node/.openclaw`` (writable — setup already
    ran before this call; audit itself is read-only in practice).
    Returns the parsed :class:`~worthless.openclaw.audit.AuditResult`.

    Raises ``AssertionError`` if the command exits non-zero or emits bad JSON.
    The caller must ensure the image is already pulled (use ``_openclaw_image_pulled``).
    """
    result = subprocess.run(  # noqa: S607
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "OPENCLAW_ACCEPT_TERMS=yes",
            "-v",
            f"{config_dir}:/home/node/.openclaw",
            _OPENCLAW_IMAGE,
            "openclaw",
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
        Provider keys are in agents/main/agent/models.json; jsonPath is
        ``providers.<name>.apiKey`` (confirmed by M0 re-probe 2026-05-23).
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
        assert "providers.anthropic.apiKey" in blocking_paths, (
            f"anthropic not in blocking: {blocking_paths}"
        )
        assert "providers.custom-openai-provider.apiKey" in blocking_paths, (
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

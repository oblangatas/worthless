"""Regression tests for the OpenClaw install incident (WOR-514).

Each test encodes an invariant the incident proved is violated:

  * WOR-515 -- ``worthless lock`` reports success while OpenClaw can still
    reach the provider without the proxy (cached token + un-rewired agent).
  * WOR-516 -- ``worthless lock`` corrupts ``openclaw.json``: it rewrites an
    unreadable config from scratch and silently narrows the file mode.

Originally all committed as ``xfail(strict=True)`` (Phase 0 "reproduce the
incident"). As fixes land, each flips: routing (F1, WOR-621) and sibling-config
survival (WOR-516) now PASS. The two still-open invariants stay ``xfail(strict=True)``
with a tracking bead -- so CI is green AND any silent fix is flagged (XPASS):
  * cached-credential bypass -> worthless-pee0 (HIGH#3, v2.0-shaped)
  * openclaw.json file-mode/FS-gate parity -> worthless-qbr0 (P3, inert shard-A)

Reproduction harness + captured evidence: ``reproduce.py`` and ``fixtures/``
in this directory.
"""

from __future__ import annotations

import json
import stat

import pytest

from tests.openclaw.install_incident.reproduce import (
    REAL_KEY,
    agent_primary_model,
    read_json_lenient,
    run_lock,
    seed,
)

# Each test invokes the real ``worthless lock`` CLI via subprocess.
pytestmark = pytest.mark.timeout(240)


def test_lock_routes_agent_through_proxy_or_does_not_claim_success(tmp_path):
    """After a successful ``lock``, the provider the default agent uses must
    point at the worthless proxy -- otherwise the agent keeps using the real
    key and ``lock`` must not report plain success.

    F1 (WOR-621) retired the legacy ``worthless-<provider>`` decoy: lock now
    rewrites the ORIGINAL provider entry in place (e.g. ``openai``) so its
    ``baseUrl`` points at the proxy. "Routed" is therefore signalled by the
    default model's provider no longer pointing at the real upstream -- NOT
    by a ``worthless-`` prefix, which F1 no longer writes.
    """
    paths = seed(tmp_path)
    result = run_lock(paths)
    after = read_json_lenient(paths["cfg"])

    default_model = agent_primary_model(after) or ""
    provider_name = default_model.split("/", 1)[0] if "/" in default_model else default_model
    base_url = (
        after.get("models", {}).get("providers", {}).get(provider_name, {}).get("baseUrl", "")
    )
    # F1 routes by rewriting the original provider's baseUrl to the proxy
    # (``http://<host>/<alias>/v1``). A surviving real upstream means the
    # agent still bypasses the proxy.
    routed = base_url != "" and "api.openai.com" not in base_url
    assert routed or result.returncode != 0, (
        f"lock exited {result.returncode} but the agent's default provider "
        f"{provider_name!r} still has baseUrl {base_url!r} -- OpenClaw bypasses the proxy"
    )


@pytest.mark.xfail(
    strict=True,
    reason="HIGH#3 deferred to worthless-pee0 (cache neutralization, v2.0-shaped). "
    "OpenClaw resolves the cached real key before shard-A; lock does not yet "
    "neutralize auth-profiles.json/models.json. Tracked, not silently passing.",
)
def test_lock_neutralizes_cached_credential_or_fails_loud(tmp_path):
    """OpenClaw caches the real token in ``auth-profiles.json``. After
    ``lock`` that cached credential must be gone -- or ``lock`` must exit
    non-zero so the user knows protection did not take."""
    paths = seed(tmp_path)
    result = run_lock(paths)
    after_auth = read_json_lenient(paths["auth_profiles"])

    cached_key_live = REAL_KEY in json.dumps(after_auth)
    assert (not cached_key_live) or result.returncode != 0, (
        "lock exited 0 but the real key is still cached in auth-profiles.json "
        "-- OpenClaw will use it and bypass the proxy"
    )


def test_lock_preserves_sibling_config_on_unreadable_file(tmp_path):
    """If ``openclaw.json`` is unreadable to the worthless process, ``lock``
    must not silently rewrite it from scratch. The user's gateway / channels
    / agents config must survive -- or ``lock`` must refuse (non-zero exit)."""
    paths = seed(tmp_path)
    paths["cfg"].chmod(0o000)
    result = run_lock(paths)
    after = read_json_lenient(paths["cfg"])

    siblings = {"gateway", "channels", "agents"}
    survived = siblings.issubset(after.keys())
    assert survived or result.returncode != 0, (
        f"lock exited {result.returncode} and destroyed sibling config keys: "
        f"{sorted(siblings - after.keys())}"
    )


@pytest.mark.xfail(
    strict=True,
    reason="Deferred to worthless-qbr0 (openclaw.json FS-gate + mode parity, P3). "
    "Post-lock openclaw.json holds only inert shard-A, so the 0o644->0o600 "
    "narrowing is near-zero confidentiality impact. Tracked, not silently passing.",
)
def test_lock_preserves_openclaw_file_mode(tmp_path):
    """``lock`` must not silently narrow ``openclaw.json``'s permissions. A
    group/world-readable config must keep its mode."""
    paths = seed(tmp_path)
    before_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)
    result = run_lock(paths)
    after_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)

    assert after_mode == before_mode or result.returncode != 0, (
        f"lock exited {result.returncode} and changed openclaw.json mode "
        f"{oct(before_mode)} -> {oct(after_mode)}"
    )

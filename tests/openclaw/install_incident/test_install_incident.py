"""Regression tests for the OpenClaw install incident (WOR-514).

Each test encodes an invariant the incident proved is violated:

  * WOR-515 -- ``worthless lock`` reports success while OpenClaw can still
    reach the provider without the proxy (cached token + un-rewired agent).
  * WOR-516 -- ``worthless lock`` corrupts ``openclaw.json``: it rewrites an
    unreadable config from scratch and silently narrows the file mode.

They are committed as ``xfail(strict=True)``: they FAIL today -- documenting
the live defect -- and will XPASS, forcing removal of the marker, once the
Phase 1-3 fixes land. This is the Phase 0 "reproduce the incident" deliverable.

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

_WOR_515 = "WOR-515: worthless lock leaves OpenClaw able to bypass the proxy"
_WOR_516 = "WOR-516: worthless lock corrupts openclaw.json"


@pytest.mark.xfail(reason=_WOR_515, strict=True)
def test_lock_routes_agent_through_proxy_or_does_not_claim_success(tmp_path):
    """After a successful ``lock``, OpenClaw's default agent must route
    through a worthless provider -- otherwise the agent keeps using the real
    key and ``lock`` must not report plain success."""
    paths = seed(tmp_path)
    result = run_lock(paths)
    after = read_json_lenient(paths["cfg"])

    default_model = agent_primary_model(after) or ""
    routed = default_model.startswith("worthless-")
    assert routed or result.returncode != 0, (
        f"lock exited {result.returncode} but the agent's default model is "
        f"{default_model!r} -- OpenClaw still bypasses the proxy"
    )


@pytest.mark.xfail(reason=_WOR_515, strict=True)
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


@pytest.mark.xfail(reason=_WOR_516, strict=True)
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


@pytest.mark.xfail(reason=_WOR_516, strict=True)
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

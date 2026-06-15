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
    fake_proxy_health,
    read_json_lenient,
    run_lock,
    seed,
)

# Each test invokes the real ``worthless lock`` CLI via subprocess.
pytestmark = pytest.mark.timeout(240)

# ``lock`` signals "protection did not take" with a DELIBERATE audit exit code:
#   73 -- blocking plaintext present (the key is still exposed); lock refused
#   87 -- audit could not verify / state changed; lock refused
# The "or fails loud" half of the invariants below must accept ONLY these
# deliberate refusals. A bare non-zero exit (an unrelated crash, or a leaked env
# var tripping a spurious failure) is NOT the agent loudly refusing -- counting it
# as a pass is the false-XPASS that flaked these xfail-strict tests in CI.
_LOCK_REFUSED_EXITS = frozenset({73, 87})


def _lock_refused(result) -> bool:
    """True iff ``lock`` deliberately refused (audit exit), not merely crashed."""
    return result.returncode in _LOCK_REFUSED_EXITS


@pytest.fixture
def proxy_port():
    """A port where a fake-healthy proxy answers ``/healthz``.

    ``lock``'s WRTLS-109 gate (WOR-648 / WOR-621 F7) aborts before the OpenClaw
    integration unless a proxy is live. These tests are ABOUT that integration,
    so they must clear the gate -- otherwise lock no-ops and every invariant
    below holds vacuously. Passed to ``run_lock(paths, proxy_port=...)``.
    """
    with fake_proxy_health() as port:
        yield port


def test_lock_routes_agent_through_proxy_or_does_not_claim_success(tmp_path, proxy_port):
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
    result = run_lock(paths, proxy_port=proxy_port)
    after = read_json_lenient(paths["cfg"])

    default_model = agent_primary_model(after) or ""
    provider_name = default_model.split("/", 1)[0] if "/" in default_model else default_model
    base_url = (
        after.get("models", {}).get("providers", {}).get(provider_name, {}).get("baseUrl", "")
    )
    # F1 routes by rewriting the provider's baseUrl to the proxy:
    # ``http://<proxy-host>/<alias>/v1`` where alias is ``<provider>-<hash>``.
    # Assert that proxy-alias structure -- a bare "not api.openai.com" check
    # would also accept ANY other real upstream (api.anthropic.com, openrouter)
    # or an attacker host, so a regression routing off the proxy would ship
    # green. The alias path is the host-independent F1 signature.
    routed = (
        f"/{provider_name}-" in base_url
        and base_url.rstrip("/").endswith("/v1")
        and "api.openai.com" not in base_url
    )
    assert routed or _lock_refused(result), (
        f"lock exited {result.returncode} but the agent's default provider "
        f"{provider_name!r} has baseUrl {base_url!r} -- not a proxy alias URL, "
        "OpenClaw bypasses the proxy (a deliberate refusal would exit 73/87, "
        "not crash -- a bare non-zero must not pass this vacuously)"
    )


@pytest.mark.xfail(
    strict=True,
    reason="HIGH#3 deferred to worthless-pee0 (cache neutralization, v2.0-shaped). "
    "OpenClaw resolves the cached real key before shard-A; lock does not yet "
    "neutralize auth-profiles.json/models.json. Tracked, not silently passing.",
)
def test_lock_neutralizes_cached_credential_or_fails_loud(tmp_path, proxy_port):
    """OpenClaw caches the real token in ``auth-profiles.json``. After
    ``lock`` that cached credential must be gone -- or ``lock`` must exit
    non-zero so the user knows protection did not take."""
    paths = seed(tmp_path)
    result = run_lock(paths, proxy_port=proxy_port)
    after_auth = read_json_lenient(paths["auth_profiles"])

    cached_key_live = REAL_KEY in json.dumps(after_auth)
    assert (not cached_key_live) or _lock_refused(result), (
        f"lock exited {result.returncode} but the real key is still cached in "
        "auth-profiles.json -- OpenClaw will use it and bypass the proxy "
        "(a deliberate refusal would exit 73/87, not silently succeed)"
    )


def test_lock_preserves_sibling_config_on_unreadable_file(tmp_path, proxy_port):
    """If ``openclaw.json`` is unreadable to the worthless process, ``lock``
    must not silently rewrite it from scratch. The user's gateway / channels
    / agents config must survive -- or ``lock`` must refuse (non-zero exit)."""
    paths = seed(tmp_path)
    paths["cfg"].chmod(0o000)
    result = run_lock(paths, proxy_port=proxy_port)
    after = read_json_lenient(paths["cfg"])

    siblings = {"gateway", "channels", "agents"}
    survived = siblings.issubset(after.keys())
    assert survived or _lock_refused(result), (
        f"lock exited {result.returncode} and destroyed sibling config keys: "
        f"{sorted(siblings - after.keys())} "
        "(a deliberate refusal would exit 73/87, not crash)"
    )


@pytest.mark.xfail(
    strict=True,
    reason="Deferred to worthless-qbr0 (openclaw.json FS-gate + mode parity, P3). "
    "Post-lock openclaw.json holds only inert shard-A, so the 0o644->0o600 "
    "narrowing is near-zero confidentiality impact. Tracked, not silently passing.",
)
def test_lock_preserves_openclaw_file_mode(tmp_path, proxy_port):
    """``lock`` must not silently narrow ``openclaw.json``'s permissions. A
    group/world-readable config must keep its mode."""
    paths = seed(tmp_path)
    # Pin the original mode explicitly. ``seed`` writes via ``write_text``, whose
    # mode is ``0o666 & ~umask`` -- so ``before_mode`` would otherwise vary by
    # runner umask (0o644 on macOS/umask 022; 0o600 on a restrictive CI umask).
    # When the original is already 0o600 the "narrowing to 0o600" this invariant
    # checks is invisible -> the xfail-strict flips to XPASS on those runners.
    # A group-readable 0o644 is exactly the case the invariant is about.
    paths["cfg"].chmod(0o644)
    before_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)
    result = run_lock(paths, proxy_port=proxy_port)
    after_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)

    assert after_mode == before_mode or _lock_refused(result), (
        f"lock exited {result.returncode} and changed openclaw.json mode "
        f"{oct(before_mode)} -> {oct(after_mode)} "
        "(a deliberate refusal would exit 73/87, not crash)"
    )

"""F8 (WOR-658) — bind-confirmation after lock.

Threat: lock today can print [OK] and exit 0 even when the rewritten
OpenClaw provider entry still routes to the upstream API directly — the
silent-bypass class that bit WOR-514. The user sees a green checkmark and
believes the proxy is in the path; the next OpenClaw agent turn leaks the
real key anyway.

What this pins: after lock-core succeeds at rewriting the OpenClaw entry,
lock must send a synthetic request through the rewritten config and observe
the proxy's ``requests_proxied`` counter increment. The result is persisted
to ``$WORTHLESS_HOME/last-lock-status.json`` so ``worthless status`` /
``worthless doctor`` can report "locked AND routing", not just "locked."

When the counter doesn't tick, lock refuses to claim success: it exits
non-zero and the sentinel records the failure.

Spec: WOR-621 plan §F8 / PR-2, AC10 (first half).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.commands import lock as lock_mod
from worthless.cli.sentinel import sentinel_path
from worthless.openclaw.errors import OpenclawErrorCode
from worthless.openclaw.integration import OpenclawApplyResult, OpenclawIntegrationEvent

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures — kept local rather than promoting to conftest.py because the
# bind-confirmation tests need a specific counter-stubbing fixture shape
# that other openclaw tests don't share.
# ---------------------------------------------------------------------------


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    """A ``.env`` with one fake OpenAI key — drives a single-provider lock."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME so ``detect()`` probes the tmp workspace, not the dev's real
    ``~/.openclaw``."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Pre-stage ``~/.openclaw/`` with workspace + a valid openclaw.json so
    lock's OpenClaw integration stage actually runs."""
    openclaw_dir = sandboxed_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(sandboxed_home)
    return {"home": sandboxed_home, "workspace": workspace, "config_path": config_path}


def _patch_proxy_counter(
    monkeypatch: pytest.MonkeyPatch,
    lock_mod,  # noqa: ANN001 — module type opaque from this layer
    *,
    tick_on_fire: bool,
    include_probe_field: bool = True,
) -> dict[str, int]:
    """Wire a shared in-memory probe counter:

    * ``check_proxy_health`` returns ``state["counter"]`` (always healthy so
      F7's pre-flight gate stays out of the way) as ``bind_probe_count`` —
      the new WOR-658 field. The presence of the field is the squatter-
      resistance signal lock-side uses to recognise a worthless proxy.
    * ``_fire_synthetic_request`` increments the counter when
      ``tick_on_fire=True`` (the GREEN happy path) and leaves it untouched
      otherwise (silent-bypass failure mode).
    * ``include_probe_field=False`` simulates a squatter on the port —
      healthz answers 200 but without the ``bind_probe_count`` key. Lock
      side must classify as ``skipped, reason=proxy_unrecognised``, NOT
      treat the missing field as a failure.

    Resilient to any call-count refactor in lock-flow: bind-confirmation
    proves routing iff the counter the next ``check_proxy_health`` returns
    is strictly greater than the one the previous read returned.
    """
    state = {"counter": 100}

    def fake_check_proxy_health(port):  # noqa: ANN001 — match real signature loosely
        result: dict[str, object] = {
            "healthy": True,
            "port": port,
            "mode": "ok",
            "requests_proxied": 0,
        }
        if include_probe_field:
            result["bind_probe_count"] = state["counter"]
        return result

    def fake_fire_synthetic_request(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202 — opaque stub
        if tick_on_fire:
            state["counter"] += 1
        # Always "reached" in the mock — the proxy is conceptually present.
        # Real-world classify: reached + no-tick = fail (silent bypass).
        return True

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_check_proxy_health)
    monkeypatch.setattr(
        lock_mod, "_fire_synthetic_request", fake_fire_synthetic_request, raising=False
    )
    return state


# ---------------------------------------------------------------------------
# RED tests — these fail today (no bind-confirmation exists). Lock just
# returns 0 and writes a sentinel WITHOUT a ``bind_confirmation`` field.
# ---------------------------------------------------------------------------


def test_lock_sentinel_includes_bind_confirmation_on_success(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a successful lock, the sentinel carries a bind_confirmation
    proving the rewritten entry routes through the proxy."""
    from worthless.cli.commands import lock as lock_mod

    _patch_proxy_counter(monkeypatch, lock_mod, tick_on_fire=True)
    wl_home = openclaw_present["home"] / ".worthless"

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    assert result.exit_code == 0, result.stdout

    sentinel = json.loads(sentinel_path(wl_home).read_text())
    assert "bind_confirmation" in sentinel, (
        "WOR-658: lock must persist a bind_confirmation field after a "
        "successful OpenClaw rewrite — proof the entry actually routes."
    )
    bc = sentinel["bind_confirmation"]
    assert bc["status"] == "pass", (
        f"bind_confirmation.status must be 'pass' when the synthetic request "
        f"ticks requests_proxied (5 -> 6). Got: {bc!r}"
    )
    assert bc["delta"] >= 1, (
        f"bind_confirmation.delta must record the observed counter increase. Got: {bc!r}"
    )
    assert isinstance(bc.get("aliases"), list) and bc["aliases"], (
        "bind_confirmation.aliases must name the providers it confirmed routing for."
    )


def test_lock_exits_nonzero_when_bind_confirmation_fails(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Counter does not tick → the synthetic request never reached the proxy
    → the rewritten entry isn't actually routing. Lock must NOT claim
    success: it exits non-zero and records the failure in the sentinel so
    ``worthless status`` shows DEGRADED."""
    from worthless.cli.commands import lock as lock_mod

    _patch_proxy_counter(monkeypatch, lock_mod, tick_on_fire=False)
    wl_home = openclaw_present["home"] / ".worthless"

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    assert result.exit_code == 91, (
        "WOR-658: lock must exit 91 (bind-confirmation refusal) when the "
        f"synthetic request didn't tick bind_probe_count. Got {result.exit_code}. "
        "91 is distinct from 87 (CONFIG_UNREADABLE) and 73 (OpenClaw partial-fail) "
        "so wrappers can tell 'lock didn't write' from 'lock wrote but routing is broken'."
    )

    sentinel = json.loads(sentinel_path(wl_home).read_text())
    bc = sentinel.get("bind_confirmation", {})
    assert bc.get("status") == "fail", (
        f"bind_confirmation.status must be 'fail' when counter delta == 0. "
        f"Got sentinel: {sentinel!r}"
    )
    # WOR-658 + api-designer finding: ``is_partial()`` must fire on the new
    # bind-fail state. The sentinel pair we wrote (status=partial,
    # openclaw=failed) is what ``is_partial`` already recognises.
    assert sentinel["status"] == "partial"
    assert sentinel["openclaw"] == "failed"


# ---------------------------------------------------------------------------
# Proxy-restart resilience: the probe counter is in-memory and resets to 0
# when the proxy bounces. A restart between BEFORE and AFTER reads gives
# negative delta — that's inconclusive, NOT a fail.
# ---------------------------------------------------------------------------


def test_lock_skipped_when_proxy_restart_resets_counter(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Counter resets mid-flight (proxy restart) → negative delta. Lock
    must classify ``skipped, reason=proxy_restarted`` and exit 0 — refusing
    to manufacture a fail verdict against a moving target."""
    from worthless.cli.commands import lock as lock_mod

    state = {"counter": 500, "restart_after_n_health_reads": 1}

    def fake_check_proxy_health(port):  # noqa: ANN001
        # After the first read (the bind-confirm BEFORE), pretend the proxy
        # restarted: counter resets to a small number (the synthetic fires
        # in between bumped it 1-N times from 0).
        result: dict[str, object] = {
            "healthy": True,
            "port": port,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": state["counter"],
        }
        if state["restart_after_n_health_reads"] > 0:
            state["restart_after_n_health_reads"] -= 1
        else:
            # Simulate the restart: in-memory counter is now ~0 + fires.
            state["counter"] = 1
        return result

    def fake_fire_synthetic_request(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        return True

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_check_proxy_health)
    monkeypatch.setattr(
        lock_mod, "_fire_synthetic_request", fake_fire_synthetic_request, raising=False
    )

    wl_home = openclaw_present["home"] / ".worthless"

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    assert result.exit_code == 0, (
        f"WOR-658: lock must exit 0 (skipped, not fail) when the proxy restarts "
        f"between before/after reads — that's inconclusive, not a bypass. "
        f"Got {result.exit_code}: {result.output}"
    )

    sentinel = json.loads(sentinel_path(wl_home).read_text())
    bc = sentinel.get("bind_confirmation", {})
    assert bc.get("status") == "skipped"
    assert bc.get("reason") == "proxy_restarted", (
        f"reason must name the restart case explicitly so doctor can suggest "
        f"the right remediation. Got: {bc!r}"
    )
    assert bc.get("delta", 0) < 0, "delta must be negative (counter reset)"


# ---------------------------------------------------------------------------
# Squatter-resistance: a foreign HTTP server on the port is NOT a worthless
# proxy. Lock must not interpret its counter as proof of routing.
# ---------------------------------------------------------------------------


def test_lock_skipped_when_proxy_does_not_expose_bind_probe_count(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``/healthz`` answers 200 but the body lacks ``bind_probe_count``,
    the responder is NOT a worthless proxy (it could be a random service
    squatting on the port). Lock must classify the verdict as ``skipped``
    with ``reason=proxy_unrecognised`` and exit 0 — refusing to manufacture
    a fail verdict against an unrecognised peer.
    """
    from worthless.cli.commands import lock as lock_mod

    _patch_proxy_counter(monkeypatch, lock_mod, tick_on_fire=True, include_probe_field=False)
    wl_home = openclaw_present["home"] / ".worthless"

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    assert result.exit_code == 0, (
        f"WOR-658: lock must exit 0 (skipped, not fail) when /healthz lacks "
        f"bind_probe_count — unrecognised peer is inconclusive, not a bypass. "
        f"Got {result.exit_code}: {result.output}"
    )

    sentinel = json.loads(sentinel_path(wl_home).read_text())
    bc = sentinel.get("bind_confirmation", {})
    assert bc.get("status") == "skipped"
    assert bc.get("reason") == "proxy_unrecognised", (
        f"reason must name the squatter signal explicitly so doctor can "
        f"surface the right remediation. Got: {bc!r}"
    )


# ---------------------------------------------------------------------------
# WOR-658 Fix 12: user-facing wording stays approachable.
# The substring "synthetic" survives only in code identifiers
# (_fire_synthetic_request, reason="synthetic_unreachable") — NEVER in the
# strings the human sees when lock prints a result. This guard catches a
# future refactor that smuggles the engineer-term back in.
# ---------------------------------------------------------------------------


def test_lock_failure_message_does_not_use_engineer_speak(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The [FAIL] message reads to a non-engineer: 'test request' not
    'synthetic request'. Regression guard for Fix 12."""
    from worthless.cli.commands import lock as lock_mod

    _patch_proxy_counter(monkeypatch, lock_mod, tick_on_fire=False)
    wl_home = openclaw_present["home"] / ".worthless"

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    out = result.output
    assert "test request" in out.lower(), (
        f"[FAIL] message must say 'test request' (Fix 12). Got:\n{out}"
    )
    assert "synthetic" not in out.lower(), (
        f"User-facing strings must not say 'synthetic' — engineer-speak. Got:\n{out}"
    )


# ---------------------------------------------------------------------------
# WOR-658 Fix 9: surface inconclusive (skipped) bind-confirmation states.
#
# Without this, lock prints a green [OK] when the bind probe couldn't even
# RUN — same silent-bypass class the feature was built to expose, just with
# a different proximate cause (proxy died mid-confirm, healthz raised, etc.).
# ---------------------------------------------------------------------------


def test_lock_warns_on_skipped_bind_confirmation_inconclusive(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When bind-confirmation classifies skipped with an inconclusive
    reason (proxy was up, then went away), lock emits a [WARN] line so the
    user knows routing wasn't actually proven."""
    from worthless.cli.commands import lock as lock_mod

    # Fake the helpers so _confirm_bind returns skipped+proxy_unhealthy_after.
    calls = {"n": 0}

    def fake_health(_port):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "healthy": True,
                "port": 0,
                "mode": "ok",
                "requests_proxied": 0,
                "bind_probe_count": 5,
            }
        return {"healthy": False, "port": 0, "mode": None, "requests_proxied": 0}

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True, raising=False)

    wl_home = openclaw_present["home"] / ".worthless"
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_HOME": str(wl_home),
        },
    )
    assert result.exit_code == 0, "skipped is inconclusive, not a failure — exit 0"
    out = result.output
    assert "[WARN]" in out, (
        f"Lock must emit [WARN] on skipped+inconclusive bind-confirmation (Fix 9). Got:\n{out}"
    )
    assert "inconclusive" in out.lower() or "wasn't proven" in out.lower(), (
        f"[WARN] message must explain the state, not just say [WARN]. Got:\n{out}"
    )


# ---------------------------------------------------------------------------
# WOR-650 follow-up — per-alias bind verdict. The global counter ticking
# proves "a probe reached the proxy", not "THIS alias's rewrite routes". When
# the proxy reports per-alias counts, _confirm_bind must require EACH confirmed
# alias to tick — so a probe for one alias can't vouch for another.
# ---------------------------------------------------------------------------


def _seq_health(monkeypatch, before: dict, after: dict) -> None:
    """Stub check_proxy_health to return ``before`` on the first call and
    ``after`` on every later call, and make every synthetic fire 'reach'."""
    calls = {"n": 0}

    def fake_health(port):  # noqa: ANN001
        calls["n"] += 1
        return dict(before if calls["n"] == 1 else after, port=port)

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True, raising=False)


def test_confirm_bind_passes_when_each_alias_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-alias happy path: every confirmed alias's OWN count moves → pass."""
    planned = [
        SimpleNamespace(provider="openai", alias="o-1"),
        SimpleNamespace(provider="anthropic", alias="a-1"),
    ]
    _seq_health(
        monkeypatch,
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 0,
            "bind_probe_aliases": {},
        },
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 2,
            "bind_probe_aliases": {"o-1": 1, "a-1": 1},
        },
    )
    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "pass", result


def test_confirm_bind_partial_route_is_fail_not_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case the global counter masked: lock TWO providers, only one alias's
    probe registers. The global delta is 1 (>0) — old logic would say 'pass'.
    Per-alias says 'fail' and NAMES the alias whose probe didn't register, so
    one alias's tick can't be mistaken for another's on a multi-provider lock.
    (Probe attribution, not full route validation — see _classify_bind_per_alias.)"""
    planned = [
        SimpleNamespace(provider="openai", alias="o-1"),
        SimpleNamespace(provider="anthropic", alias="a-1"),
    ]
    _seq_health(
        monkeypatch,
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 0,
            "bind_probe_aliases": {},
        },
        # Only o-1 ticked; a-1 never routed. Global delta = 1 > 0.
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 1,
            "bind_probe_aliases": {"o-1": 1},
        },
    )
    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "fail", (
        f"global delta>0 must NOT pass when a confirmed alias didn't tick. Got {result!r}"
    )
    assert result["not_routing"] == ["a-1"], result
    assert result["delta"] == 1, "global delta WOULD have passed under the old logic"


def test_confirm_bind_falls_back_to_global_without_per_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Older proxy that doesn't surface bind_probe_aliases → the global
    tri-state still applies (graceful degradation, no per-alias regression)."""
    planned = [SimpleNamespace(provider="openai", alias="o-1")]
    _seq_health(
        monkeypatch,
        {"healthy": True, "mode": "ok", "requests_proxied": 0, "bind_probe_count": 0},
        {"healthy": True, "mode": "ok", "requests_proxied": 0, "bind_probe_count": 1},
    )
    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "pass", result


def test_confirm_bind_per_alias_proxy_restart_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-alias path, hostile: the proxy restarts mid-flight so its in-memory
    counters reset (delta < 0, alias map empty). That's inconclusive, NOT a
    fail — we refuse to manufacture a 'not routing' verdict against a bounced
    proxy. Mirrors the global-counter restart guard, but on the per-alias path."""
    planned = [SimpleNamespace(provider="openai", alias="o-1")]
    _seq_health(
        monkeypatch,
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 500,
            "bind_probe_aliases": {},
        },
        # Restart: counter + per-alias map reset to ~0 between before/after reads.
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 1,
            "bind_probe_aliases": {},
        },
    )
    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "skipped", result
    assert result.get("reason") == "proxy_restarted", result


def test_confirm_bind_per_alias_unreachable_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-alias path, hostile: every synthetic fire fails at the network layer
    (reached == 0), so the proxy never saw the probe. Inconclusive
    (synthetic_unreachable), NOT a fail — the test harness, not the rewrite,
    is what didn't reach the proxy."""
    planned = [SimpleNamespace(provider="openai", alias="o-1")]

    def fake_health(port):  # noqa: ANN001
        return {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 5,
            "bind_probe_aliases": {},
            "port": port,
        }

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_health)
    # Every fire fails to reach the proxy.
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: False, raising=False)

    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "skipped", result
    assert result.get("reason") == "synthetic_unreachable", result


def test_confirm_bind_per_alias_restart_wins_over_partial_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeRabbit (Major): a proxy restart is inconclusive even when only SOME
    aliases look stale. ``before`` has a previously-counted alias (o-1=100) while
    we confirm [o-1, a-1]; the proxy bounces (delta<0) and re-probes both to ~1,
    so a-1 looks 'routed' (1 > 0) but o-1 looks stale (1 <= 100). The restart
    signal must WIN → skipped/proxy_restarted, never a 'fail' against a bounced
    proxy."""
    planned = [
        SimpleNamespace(provider="openai", alias="o-1"),
        SimpleNamespace(provider="anthropic", alias="a-1"),
    ]
    _seq_health(
        monkeypatch,
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 100,
            "bind_probe_aliases": {"o-1": 100},
        },
        # Bounced: counter + per-alias map reset, then the fires re-probe both to ~1.
        {
            "healthy": True,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 2,
            "bind_probe_aliases": {"o-1": 1, "a-1": 1},
        },
    )
    result = lock_mod._confirm_bind(planned, host="127.0.0.1", port=1)
    assert result["status"] == "skipped", result
    assert result.get("reason") == "proxy_restarted", result


# ---------------------------------------------------------------------------
# WOR-650 follow-up — a declined adoption (entry left in place) must NOT read
# as a clean [OK]/pass: header is [WARN], sentinel is DEGRADED, and the
# skipped provider is NOT bind-probed (probing it would fake a pass).
# ---------------------------------------------------------------------------


def test_finalise_warns_and_degrades_when_entry_left_in_place(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    skip_evt = OpenclawIntegrationEvent(
        code=OpenclawErrorCode.PROVIDER_ADOPTION_SKIPPED,
        level="info",
        detail="skipped 'openai': proxy-shaped entry wasn't adopted. Re-run with --adopt.",
        extra={"provider": "openai"},
    )
    result = OpenclawApplyResult(
        detected=True,
        config_path=None,
        workspace_path=None,
        skill_path=None,
        providers_set=("anthropic",),
        providers_skipped=(("openai", "unrecognized_not_adopted"),),
        skill_installed=False,
        events=(skip_evt,),
    )
    planned = [
        SimpleNamespace(provider="openai", alias="openai-foreign"),
        SimpleNamespace(provider="anthropic", alias="anthropic-x"),
    ]

    class _Console:
        def __init__(self) -> None:
            self.success: list[str] = []
            self.hint: list[str] = []
            self.warning: list[str] = []
            self.failure: list[str] = []

        def print_success(self, m: str) -> None:
            self.success.append(m)

        def print_hint(self, m: str) -> None:
            self.hint.append(m)

        def print_warning(self, m: str) -> None:
            self.warning.append(m)

        def print_failure(self, m: str) -> None:
            self.failure.append(m)

    console = _Console()

    confirm_calls: dict[str, object] = {}

    def fake_confirm_bind(planned_arg, *, host, port):  # noqa: ANN001, ANN202
        confirm_calls["planned"] = planned_arg
        return {
            "status": "skipped",
            "reason": "no_aliases",
            "delta": 0,
            "aliases": [],
            "reached": 0,
        }

    monkeypatch.setattr(lock_mod, "_confirm_bind", fake_confirm_bind)

    sentinel_calls: dict[str, object] = {}

    def fake_write_sentinel(home, **kwargs):  # noqa: ANN001, ANN003, ANN202
        sentinel_calls.update(kwargs)
        return tmp_path / "sentinel.json"

    monkeypatch.setattr(lock_mod, "_write_lock_sentinel", fake_write_sentinel)

    rc = lock_mod._finalise_openclaw_success(
        planned,
        result,
        console,
        False,
        SimpleNamespace(base_dir=tmp_path),
        proxy_host="127.0.0.1",
    )

    # 1. No bare [OK] header — a [WARN] incomplete header instead.
    assert not any("[OK] OpenClaw integration:" in m for m in console.success), (
        f"declined adoption must NOT print a clean [OK]. success={console.success!r}"
    )
    assert any(m.startswith("[WARN] OpenClaw integration incomplete") for m in console.warning), (
        f"expected a [WARN] incomplete header. warnings={console.warning!r}"
    )
    # 2. Sentinel is DEGRADED — the partial/failed pair is_partial() recognises.
    assert sentinel_calls["status"] == "partial"
    assert sentinel_calls["openclaw"] == "failed"
    # 3. Only the provider actually written is bind-confirmed; the skipped one
    #    isn't probed (firing for it would manufacture a false pass).
    confirmed_aliases = [p.alias for p in confirm_calls["planned"]]
    assert confirmed_aliases == ["anthropic-x"], (
        f"skipped 'openai' must not be probed; confirmed={confirmed_aliases!r}"
    )
    # 4. Exit code stays 0 — the interactive user chose to decline.
    assert rc == 0

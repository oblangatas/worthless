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

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.sentinel import sentinel_path

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
) -> dict[str, int]:
    """Wire a shared in-memory proxy counter:

    * ``check_proxy_health`` returns ``state["counter"]`` (always healthy so
      F7's pre-flight gate stays out of the way).
    * ``_fire_synthetic_request`` increments the counter when
      ``tick_on_fire=True`` (the GREEN happy path) and leaves it untouched
      otherwise (silent-bypass failure mode).

    Resilient to any call-count refactor in lock-flow: bind-confirmation
    proves routing iff the counter the next ``check_proxy_health`` returns
    is strictly greater than the one the previous read returned.
    """
    state = {"counter": 100}

    def fake_check_proxy_health(port):  # noqa: ANN001 — match real signature loosely
        return {
            "healthy": True,
            "port": port,
            "mode": "ok",
            "requests_proxied": state["counter"],
        }

    def fake_fire_synthetic_request(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202 — opaque stub
        if tick_on_fire:
            state["counter"] += 1

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
    assert result.exit_code != 0, (
        "WOR-658: lock must refuse to claim success when the synthetic request "
        "didn't tick requests_proxied. Silent-bypass class (WOR-514)."
    )

    sentinel = json.loads(sentinel_path(wl_home).read_text())
    bc = sentinel.get("bind_confirmation", {})
    assert bc.get("status") == "fail", (
        f"bind_confirmation.status must be 'fail' when counter delta == 0. "
        f"Got sentinel: {sentinel!r}"
    )

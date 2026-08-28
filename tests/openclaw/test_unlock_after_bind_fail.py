"""WOR-658 Fix 7: unlock cleanly restores after a bind-confirmation failure.

When lock exits 91 (proof-of-routing failed), the .env, the DB, and
openclaw.json have all been written. The user-facing message points at
`worthless unlock` as one recovery path; this test pins that the path
actually works — unlock from the bind-fail state restores the original
.env byte-for-byte and clears the DB enrollment.

Without this guarantee, the [WARN]/[FAIL] guidance is a lie: lock would
have stranded the user in a half-state with no clean way back.
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


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def openclaw_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Pre-stage ~/.openclaw with workspace + empty providers so lock-core
    runs and apply_openclaw rewrites the entry."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    openclaw_dir = home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(home)
    return {"home": home, "workspace": workspace, "config_path": config_path}


def _patch_proxy_for_bind_fail(monkeypatch: pytest.MonkeyPatch, lock_mod) -> None:
    """Force _confirm_bind to classify FAIL: counter is readable and
    static (probe-recognized squatter-resistance signal present) but
    doesn't tick across the synthetic fire."""

    def fake_health(_port):
        return {
            "healthy": True,
            "port": 0,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 100,  # never moves
        }

    monkeypatch.setattr(lock_mod, "check_proxy_health", fake_health)
    # raising=True (default): _fire_synthetic_request is real code now, so if
    # it's ever renamed this monkeypatch fails loud instead of silently
    # creating a dead attribute (CodeRabbit gate-10).
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True)


def test_unlock_restores_original_env_after_bind_fail(
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lock-fail → unlock → original .env restored byte-for-byte. Sentinel
    cleared of the DEGRADED state by unlock so status no longer warns."""
    from worthless.cli.commands import lock as lock_mod

    _patch_proxy_for_bind_fail(monkeypatch, lock_mod)
    wl_home = openclaw_present["home"] / ".worthless"
    cli_env = {
        "WORTHLESS_KEYRING_BACKEND": "null",
        "WORTHLESS_HOME": str(wl_home),
    }

    original_content = env_file.read_text()

    # Lock — exits 91 (bind-confirmation refusal)
    lock_result = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert lock_result.exit_code == 91, (
        f"setup: lock must exit 91 in this fixture. Got {lock_result.exit_code}: "
        f"{lock_result.output}"
    )
    # .env was rewritten — confirms we're testing real recovery, not no-op
    assert env_file.read_text() != original_content
    # Sentinel records the DEGRADED state
    sentinel = json.loads(sentinel_path(wl_home).read_text())
    assert sentinel["status"] == "partial" and sentinel["openclaw"] == "failed"

    # Unlock — must restore original .env byte-for-byte
    unlock_result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
    assert unlock_result.exit_code == 0, (
        f"unlock must succeed from bind-fail state. Got {unlock_result.exit_code}: "
        f"{unlock_result.output}"
    )
    assert env_file.read_text() == original_content, (
        "unlock must restore the .env byte-for-byte — the user's only clean "
        "recovery from a bind-confirmation failure"
    )

    # Sentinel after unlock no longer reports partial+failed
    sentinel_after = json.loads(sentinel_path(wl_home).read_text())
    assert sentinel_after["status"] == "ok", (
        f"unlock must clear the DEGRADED sentinel. Got: {sentinel_after!r}"
    )

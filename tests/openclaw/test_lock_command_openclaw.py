"""Phase 2.b — ``worthless lock`` integration with apply_lock().

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` §"Phase 2.b"
+ AC1 (no-OpenClaw byte-identical), AC10 (.env success + OpenClaw failure
→ exit 0), AC11 (lock-core never rolls back).

These tests drive ``worthless.cli.commands.lock`` end-to-end via the Typer
CliRunner. They sandbox HOME so detect() probes the tmp_path-rooted
workspace, not the developer's real ``~/.openclaw/``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    """A .env with one fake OpenAI key — enough to exercise lock-core."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME / USERPROFILE inside tmp_path so apply_lock's detect()
    cannot see the developer's real ``~/.openclaw/`` during the test run.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Pre-stage ~/.openclaw/ with workspace + valid openclaw.json."""
    openclaw_dir = sandboxed_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # Avoid project-local openclaw.json from pytest's cwd.
    monkeypatch.chdir(sandboxed_home)
    return {"home": sandboxed_home, "workspace": workspace, "config_path": config_path}


# ---------------------------------------------------------------------------
# AC1: no-OpenClaw host is byte-identical to Phase 1 behavior
# ---------------------------------------------------------------------------


def test_lock_with_no_openclaw_succeeds_unchanged(
    home_dir: WorthlessHome, env_file: Path, sandboxed_home: Path
) -> None:
    """AC1: host without OpenClaw → ``lock`` exits 0 and the .env is
    rewritten with shard-A + BASE_URL exactly like Phase 1. No openclaw.json
    appears anywhere because detect() returns absent.
    """
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    # .env got the standard Phase 1 treatment.
    body = env_file.read_text()
    assert "OPENAI_API_KEY=" in body
    assert "OPENAI_BASE_URL=" in body
    # Crucially: nothing got dropped under ~/.openclaw — detect() returned absent.
    assert not (sandboxed_home / ".openclaw" / "openclaw.json").exists()
    assert not (sandboxed_home / ".openclaw" / "workspace").exists()


# ---------------------------------------------------------------------------
# AC2: OpenClaw present → openclaw.json + skill folder both populated
# ---------------------------------------------------------------------------


def test_lock_with_openclaw_writes_openclaw_json_and_installs_skill(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """AC2: with OpenClaw staged at ~/.openclaw, ``lock`` populates the
    config with the ``openai`` entry (WOR-621 F1: lock rewrites the
    provider's ORIGINAL id, not a ``worthless-*`` decoy) and installs the
    skill folder, in one invocation, with no prompts.
    """
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output

    data = json.loads(openclaw_present["config_path"].read_text(encoding="utf-8"))
    providers = data["models"]["providers"]
    assert "openai" in providers, providers
    assert providers["openai"]["baseUrl"].startswith("http://127.0.0.1:")
    assert providers["openai"]["baseUrl"].endswith("/v1")
    assert providers["openai"]["apiKey"], "shard-A must be in apiKey"

    # Skill folder installed.
    skill_dir = openclaw_present["workspace"] / "skills" / "worthless"
    assert skill_dir.exists()
    assert (skill_dir / "SKILL.md").exists()


# ---------------------------------------------------------------------------
# AC10 + AC11: .env/DB success + OpenClaw failure → exit 0, .env still committed
# ---------------------------------------------------------------------------


def test_lock_with_openclaw_failure_exits_nonzero_and_preserves_env_state(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC10 + AC11 (revised by 2026-05-08 verification gauntlet):
    monkeypatch apply_lock to raise OpenclawIntegrationError → ``worthless
    lock`` exits **73** (EX_CANTCREAT, distinguishable from generic 1)
    AND the .env still has shard-A written.

    L1 preserved: lock-core's ``.env``/DB writes are NOT rolled back
    even though we exit non-zero. The user gets BOTH the binding-contract
    protection of the .env split AND a loud signal that OpenClaw is broken.

    This replaces the prior "exit 0 + surfaced events" behavior, which
    failed the trust contract for users whose CI scripts ignore exit
    codes (verification gauntlet finding by brutus + ux-researcher).
    """
    from worthless.openclaw import errors as openclaw_errors
    from worthless.openclaw import integration

    def _raise(*_: object, **__: object) -> None:
        raise openclaw_errors.OpenclawIntegrationError(
            openclaw_errors.OpenclawErrorCode.SKILL_INSTALL_FAILED,
            "simulated unexpected raise",
        )

    monkeypatch.setattr(integration, "apply_lock", _raise)

    original_key_line = env_file.read_text()
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    # Trust-fix: detected+failed → exit 73, not 0.
    assert result.exit_code == 73, result.output
    new_body = env_file.read_text()
    # AC11/L1: .env state advanced past the original (shard-A and/or
    # BASE_URL added). Lock-core was NOT rolled back.
    assert new_body != original_key_line
    assert "OPENAI_API_KEY=" in new_body


def test_lock_with_openclaw_apply_lock_returns_failure_events_exits_nonzero(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC10 (revised 2026-05-08): when apply_lock returns a result with
    failure events (the contracted path — not raising), ``lock`` exits
    **73** AND lock-core's `.env` writes are preserved.

    Simulates F-XS-40 at the command level: writing openclaw.json blows
    up internally, apply_lock surfaces it as a structured error event,
    lock-core's `.env`/DB writes commit, and then `lock` exits non-zero
    so the user can't miss the partial failure.
    """
    from worthless.openclaw import config as config_mod

    def _exploding_set_provider(*_: object, **__: object) -> None:
        raise OSError("simulated EACCES on openclaw.json")

    monkeypatch.setattr(config_mod, "set_provider", _exploding_set_provider)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    # Trust-fix: detected+failed → exit 73, not 0.
    assert result.exit_code == 73, result.output
    # L1: lock-core preserved its .env write despite OpenClaw failure.
    assert "OPENAI_API_KEY=" in env_file.read_text()


# ---------------------------------------------------------------------------
# SP4: UID mismatch → CLI outputs [FAIL] and exits 73
# ---------------------------------------------------------------------------


def test_lock_with_uid_mismatch_outputs_failure_and_exits_73(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP4: when openclaw.json is owned by a different UID (Docker two-UID
    topology), ``worthless lock`` must:
      - print '[FAIL] OpenClaw integration did NOT complete.'
      - exit 73 (distinguishable from generic error; CI scripts cannot miss it)

    Proves the end-to-end CLI wiring:
    UID mismatch → OpenclawConfigUnreadableError → _emit_openclaw_failure → exit 73.
    """
    real_uid = openclaw_present["config_path"].stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: real_uid + 1)
    # Route Fernet through env so the SP4 geteuid mock does not trip keystore
    # ownership validation on fernet.key (this test targets OpenClaw UID mismatch).
    fernet_env = (home_dir.base_dir / "fernet.key").read_bytes().strip().decode()

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={
            "WORTHLESS_HOME": str(home_dir.base_dir),
            "WORTHLESS_FERNET_KEY": fernet_env,
        },
    )

    assert result.exit_code == 73, (
        f"expected exit 73 on UID mismatch, got {result.exit_code}\n{result.output}"
    )
    assert "[FAIL] OpenClaw" in result.output, (
        f"expected '[FAIL] OpenClaw' in output\n{result.output}"
    )

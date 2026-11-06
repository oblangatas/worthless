"""Phase 2.c — ``worthless unlock`` integration with apply_unlock().

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` §"Phase 2.c"
+ AC1 (no-OpenClaw byte-identical), AC10/L1/L2 (.env success + OpenClaw
failure → exit 0).

These tests drive ``worthless.cli.commands.unlock`` end-to-end via the
Typer CliRunner. They sandbox HOME so ``apply_unlock``'s detect() probes
the tmp_path-rooted workspace, not the developer's real ``~/.openclaw/``.
"""

from __future__ import annotations

import json
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
    """A .env with one fake OpenAI key — exercise the lock+unlock cycle."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME / USERPROFILE inside tmp_path so apply_unlock's detect()
    cannot see the developer's real ``~/.openclaw/``.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Pre-stage ~/.openclaw/ with workspace + valid openclaw.json. ``cd`` into
    sandboxed_home so project-local openclaw.json discovery doesn't pull in
    the developer's tree.
    """
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


# ---------------------------------------------------------------------------
# AC1: no-OpenClaw host is byte-identical to Phase 1 unlock behavior
# ---------------------------------------------------------------------------


def test_unlock_with_no_openclaw_succeeds_unchanged(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
) -> None:
    """AC1 (Phase 2.c): host without OpenClaw → ``unlock`` exits 0 and the
    .env is restored exactly like Phase 1. No openclaw.json appears anywhere
    because detect() returns absent.
    """
    # First lock so unlock has something to do.
    lock_result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert lock_result.exit_code == 0, lock_result.output

    result = runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert result.exit_code == 0, result.output

    body = env_file.read_text()
    assert "OPENAI_API_KEY=" in body
    # Phase 1's unlock removes BASE_URL on restore.
    assert "OPENAI_BASE_URL=" not in body
    # Crucially: nothing got created under ~/.openclaw — detect() returned absent.
    assert not (sandboxed_home / ".openclaw" / "openclaw.json").exists()


# ---------------------------------------------------------------------------
# Phase 2.c happy path: lock+unlock cycle removes both side effects
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="WOR-621 F2 — unlock-restore contract not yet implemented; lock now "
    "rewrites the original entry, unlock cannot yet restore it. Remove when F2 lands.",
)
def test_unlock_with_openclaw_removes_provider_and_skill(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """Phase 2.c: with OpenClaw staged at ~/.openclaw, run ``lock`` then
    ``unlock``: assert the ``worthless-openai`` provider entry is gone AND
    the skill folder is gone.
    """
    lock_result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert lock_result.exit_code == 0, lock_result.output
    # Sanity: lock wired things up.
    mid = json.loads(openclaw_present["config_path"].read_text(encoding="utf-8"))
    assert "worthless-openai" in mid["models"]["providers"]
    skill_dir = openclaw_present["workspace"] / "skills" / "worthless"
    assert skill_dir.exists()

    result = runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert result.exit_code == 0, result.output

    post = json.loads(openclaw_present["config_path"].read_text(encoding="utf-8"))
    assert "worthless-openai" not in post["models"]["providers"]
    assert not skill_dir.exists(), "skill folder must be swept on unlock"


# ---------------------------------------------------------------------------
# AC10/L1/L2: OpenClaw failure during unlock must NOT make unlock-core fail
# ---------------------------------------------------------------------------


def test_unlock_with_openclaw_apply_unlock_failure_exits_nonzero(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L1 + AC10 (revised 2026-05-08): monkeypatch ``apply_unlock`` to
    raise → ``worthless unlock`` exits **73** AND the .env is still
    restored. Symmetric with the lock-side trust-fix.

    L1 preserved: unlock-core's `.env` restoration is NOT rolled back
    even though we exit non-zero. The user gets BOTH the .env recovery
    AND a loud signal that OpenClaw cleanup is incomplete.
    """
    # Set up a locked state first.
    lock_result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert lock_result.exit_code == 0, lock_result.output

    from worthless.openclaw import errors as openclaw_errors
    from worthless.openclaw import integration

    def _raise(*_: object, **__: object) -> None:
        raise openclaw_errors.OpenclawIntegrationError(
            openclaw_errors.OpenclawErrorCode.SKILL_INSTALL_FAILED,
            "simulated unexpected raise from apply_unlock",
        )

    monkeypatch.setattr(integration, "apply_unlock", _raise)

    result = runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    # Trust-fix: detected+failed → exit 73, not 0.
    assert result.exit_code == 73, result.output

    # AC11/L1: .env was still restored (OPENAI_API_KEY back to a real-shape
    # key, no BASE_URL). Unlock-core was NOT rolled back.
    body = env_file.read_text()
    assert "OPENAI_API_KEY=" in body
    assert "OPENAI_BASE_URL=" not in body


# ---------------------------------------------------------------------------
# WOR-1043: --quiet shows the [FAIL] header, so it shows what failed and the fix
# ---------------------------------------------------------------------------


def _raise_from_apply_unlock(detail: str):  # noqa: ANN202
    from worthless.openclaw import errors as openclaw_errors

    def _raise(*_: object, **__: object) -> None:
        raise openclaw_errors.OpenclawIntegrationError(
            openclaw_errors.OpenclawErrorCode.SKILL_INSTALL_FAILED, detail
        )

    return _raise


def _failed_apply_result(openclaw_present: dict[str, Path], **fields: object):  # noqa: ANN202
    """An apply_unlock result for a detected OpenClaw that hit an error."""
    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode, OpenclawIntegrationEvent

    fields.setdefault(
        "events",
        (OpenclawIntegrationEvent(code=OpenclawErrorCode.WRITE_FAILED, level="error", detail="x"),),
    )
    return integration.OpenclawApplyResult(
        detected=True,
        config_path=openclaw_present["config_path"],
        workspace_path=openclaw_present["workspace"],
        skill_path=None,
        **fields,
    )


def _quiet_unlock(home_dir: WorthlessHome, env_file: Path):  # noqa: ANN202
    lock_result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert lock_result.exit_code == 0, lock_result.output
    return runner.invoke(
        app,
        ["--quiet", "unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir), "COLUMNS": "1000"},
    )


def test_quiet_unlock_still_says_how_to_repair_openclaw_after_a_raise(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from worthless.openclaw import integration

    monkeypatch.setattr(
        integration,
        "apply_unlock",
        _raise_from_apply_unlock("simulated unexpected raise from /x\x1b[2J/openclaw.json"),
    )

    result = _quiet_unlock(home_dir, env_file)

    assert result.exit_code == 73, result.output
    assert "[FAIL] OpenClaw cleanup did NOT complete." in result.output
    assert "may not have been restored in ~/.openclaw/openclaw.json" in result.output
    assert "simulated unexpected raise from /x[2J/openclaw.json" in result.output
    assert "\x1b" not in result.output  # a path in the detail can't reach the terminal raw
    assert "Fix:    worthless doctor" in result.output


def test_quiet_unlock_still_names_what_openclaw_left_on_the_proxy(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode, OpenclawIntegrationEvent

    failed = _failed_apply_result(
        openclaw_present,
        providers_skipped=(("openai", "entry changed since lock"),),
        events=(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.WRITE_FAILED,
                level="error",
                detail="disk full at /x\x1b[2J/openclaw.json",
            ),
        ),
    )
    monkeypatch.setattr(integration, "apply_unlock", lambda **_: failed)

    result = _quiet_unlock(home_dir, env_file)

    assert result.exit_code == 73, result.output
    assert "[FAIL] OpenClaw cleanup did NOT complete." in result.output
    assert "`worthless unlock` or `worthless doctor` to repair." in result.output
    assert "skipped openai (entry changed since lock)" in result.output
    assert "openclaw.write_failed — disk full at /x[2J/openclaw.json" in result.output
    assert "\x1b" not in result.output


@pytest.mark.parametrize("path", ["raise", "detected-failed"])
def test_a_fail_block_it_cannot_print_still_marks_the_status_degraded(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    """The sentinel is written before the [FAIL] block. Rich exits on a closed
    stderr, and that must not keep `worthless status` from reporting the failure."""
    from worthless.cli.console import WorthlessConsole
    from worthless.cli.sentinel import is_partial, read_sentinel
    from worthless.openclaw import integration

    failed = _failed_apply_result(openclaw_present)
    monkeypatch.setattr(
        integration,
        "apply_unlock",
        _raise_from_apply_unlock("simulated raise") if path == "raise" else (lambda **_: failed),
    )

    def _closed_stderr(console, message: str) -> None:  # noqa: ANN001
        raise SystemExit(1)  # what Rich does on a broken pipe

    monkeypatch.setattr(WorthlessConsole, "print_failure", _closed_stderr)

    _quiet_unlock(home_dir, env_file)

    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert is_partial(sentinel)

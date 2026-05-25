"""Trust-fix tests — D1+D2 from the 2026-05-08 verification gauntlet.

Five-agent gauntlet (karen, T-C-V, brutus, qa-expert, test-automator) +
three-agent re-stress (brutus #2, ux-researcher, architect-reviewer)
converged on a single P0 finding: today's `worthless lock` exits 0 with
surfaced events even when OpenClaw is detected but the integration
stage failed. Naive user thinks lock succeeded; five minutes later
their agent silently bypasses worthless; attacker who steals .env
drains budget.

This file pins the trust contract:

- TF-01 — sentinel written as ``ok / ok`` on full success
- TF-02 — sentinel written as ``ok / absent`` when OpenClaw not detected
- TF-03 — sentinel written as ``partial / failed`` on detected+failed
- TF-04 — `[OK]` text prefix appears in lock success output
- TF-05 — `[FAIL]` text prefix appears in lock failure output
- TF-06 — lock --json emits the report payload to stdout
- TF-07 — unlock symmetric: sentinel ``ok / ok`` on success
- TF-08 — unlock symmetric: sentinel ``partial / failed`` on failure
- TF-09 — status WARN row + exit 73 on partial sentinel
- TF-10 — status clean (exit 0, no WARN) on ok sentinel
- TF-11 — sentinel write is atomic (mid-write crash leaves prior intact)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.sentinel import is_partial, read_sentinel, sentinel_path, write_sentinel

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures (mirror tests/openclaw/test_lock_command_openclaw.py shapes)
# ---------------------------------------------------------------------------


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
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
# TF-01..TF-03 — sentinel state matrix on lock
# ---------------------------------------------------------------------------


def test_lock_writes_sentinel_ok_on_full_success(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """TF-01: full success → sentinel ``status=ok``, ``openclaw=ok``,
    ``alias_count=1``. Lock-core wrote the .env, OpenClaw stage wrote
    the provider entry — both succeeded.
    """
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None, "sentinel must be written on lock"
    assert sentinel["status"] == "ok"
    assert sentinel["openclaw"] == "ok"
    assert sentinel["alias_count"] >= 1
    assert is_partial(sentinel) is False


def test_lock_writes_sentinel_absent_when_no_openclaw(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
) -> None:
    """TF-02: no OpenClaw on host → sentinel ``status=ok``,
    ``openclaw=absent``, ``alias_count=0`` (no openclaw-side counts).
    No DEGRADED state — the absence isn't a failure.
    """
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert sentinel["status"] == "ok"
    assert sentinel["openclaw"] == "absent"
    assert is_partial(sentinel) is False


def test_lock_writes_sentinel_partial_on_detected_failure(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF-03: OpenClaw detected + integration stage fails → sentinel
    ``status=partial``, ``openclaw=failed``. ``is_partial`` returns True.
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

    assert result.exit_code == 73, result.output
    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert sentinel["status"] == "partial"
    assert sentinel["openclaw"] == "failed"
    assert is_partial(sentinel) is True


# ---------------------------------------------------------------------------
# TF-04..TF-05 — text-prefix accessibility (no glyph-only reliance)
# ---------------------------------------------------------------------------


def test_lock_emits_OK_text_prefix_on_success(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """TF-04: literal ``[OK]`` appears in lock output (carrier for
    monochrome terminals, screen readers, CI log scrapers).
    Color/glyph reinforces but is never the carrier.
    """
    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    # CliRunner combines stdout+stderr into result.output.
    assert "[OK]" in result.output


def test_lock_emits_FAIL_text_prefix_on_detected_failure(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF-05: literal ``[FAIL]`` appears on the detected+failed path.
    User CANNOT mistake the partial-failure state for success even if
    they only skim the output.
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

    assert result.exit_code == 73, result.output
    assert "[FAIL]" in result.output


def test_lock_emits_LOCK_FAILED_summary_on_detected_failure(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF-05b: a final ``LOCK FAILED`` summary line appears AFTER the [OK] key-split
    message so the user cannot mistake the mixed [FAIL]+[OK] output for overall
    success (WOR-551).

    Before this fix the output was:
        [FAIL] OpenClaw integration did NOT complete.
        [OK] 1 key split …
        (exit 73 — but no further text)

    After this fix:
        [FAIL] OpenClaw integration did NOT complete.
        [OK] 1 key split …
        LOCK FAILED — …
        (exit 73)
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

    assert result.exit_code == 73, result.output
    # Final LOCK FAILED summary must appear AFTER the [OK] key-split line.
    ok_pos = result.output.find("[OK]")
    failed_pos = result.output.find("LOCK FAILED")
    assert ok_pos != -1, "expected [OK] key-split line in output"
    assert failed_pos != -1, (
        "expected 'LOCK FAILED' summary after [OK] line; got:\n" + result.output
    )
    assert failed_pos > ok_pos, (
        "LOCK FAILED must appear AFTER the [OK] key-split line so the user "
        "cannot miss the failure; got:\n" + result.output
    )


# ---------------------------------------------------------------------------
# TF-06 — --json flag emits the report payload
# ---------------------------------------------------------------------------


def test_lock_json_flag_propagates_to_sentinel(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """TF-06: lock with global ``--json`` writes the same payload shape
    as the sentinel on disk. The sentinel IS the wire-stable contract;
    --json output and the sentinel must match in shape so doctor / Pi
    consumers can read either.

    Today --json is a global Typer flag (app.py:41). This test pins
    that flag flowing through to the lock command and the sentinel
    payload remaining the source of truth.
    """
    result = runner.invoke(
        app,
        ["--json", "lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert result.exit_code == 0, result.output

    # Sentinel still exists with the same fields a JSON consumer would
    # expect (the report-format wire contract).
    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert set(sentinel.keys()) == {"ts", "status", "openclaw", "alias_count", "events"}


# ---------------------------------------------------------------------------
# TF-07..TF-08 — unlock symmetric
# ---------------------------------------------------------------------------


def test_unlock_writes_sentinel_ok_on_success(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
) -> None:
    """TF-07: lock then unlock → sentinel after unlock is
    ``status=ok``, ``openclaw=ok``. Unlock is the symmetric undo.
    """
    lock_result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert lock_result.exit_code == 0, lock_result.output

    unlock_result = runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert unlock_result.exit_code == 0, unlock_result.output

    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert sentinel["status"] == "ok"
    assert sentinel["openclaw"] == "ok"
    assert is_partial(sentinel) is False


def test_unlock_writes_sentinel_partial_on_detected_failure(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF-08: unlock with apply_unlock raising → sentinel
    ``status=partial``, ``openclaw=failed``. Same trust contract as
    lock: detected+failed must be unmissable.
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
            "simulated unlock-stage raise",
        )

    monkeypatch.setattr(integration, "apply_unlock", _raise)

    unlock_result = runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert unlock_result.exit_code == 73, unlock_result.output

    sentinel = read_sentinel(home_dir.base_dir)
    assert sentinel is not None
    assert sentinel["status"] == "partial"
    assert sentinel["openclaw"] == "failed"


# ---------------------------------------------------------------------------
# TF-09..TF-10 — status command reads sentinel
# ---------------------------------------------------------------------------


def test_status_warns_and_exits_nonzero_on_partial_sentinel(
    home_dir: WorthlessHome,
) -> None:
    """TF-09: pre-stage a partial sentinel → ``worthless status`` emits
    ``[WARN]`` row AND exits 73. Closes the "five minutes later" gap:
    even after a CI script swallowed the original lock exit code, the
    next status invocation MUST tell the user the truth.
    """
    write_sentinel(
        home_dir.base_dir,
        status="partial",
        openclaw="failed",
        alias_count=1,
        events=[
            {
                "code": "openclaw.write_failed",
                "level": "error",
                "detail": "simulated",
            }
        ],
    )

    result = runner.invoke(
        app,
        ["status"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 73, result.output
    assert "[WARN]" in result.output
    assert "OpenClaw" in result.output


def test_status_exits_zero_on_ok_sentinel(
    home_dir: WorthlessHome,
) -> None:
    """TF-10: pre-stage a sentinel with ``status=ok`` → status exits 0
    AND does not emit a [WARN] row. The sentinel says everything is
    healthy; status reflects that.
    """
    write_sentinel(
        home_dir.base_dir,
        status="ok",
        openclaw="ok",
        alias_count=1,
        events=[],
    )

    result = runner.invoke(
        app,
        ["status"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    assert "[WARN]" not in result.output


def test_status_exits_zero_when_sentinel_absent(
    home_dir: WorthlessHome,
) -> None:
    """Status with no prior lock state → exit 0, no [WARN] row.
    Absent sentinel is not a failure — it's "no recent lock state."
    """
    # Make sure no sentinel exists.
    target = sentinel_path(home_dir.base_dir)
    if target.exists():
        target.unlink()

    result = runner.invoke(
        app,
        ["status"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    assert "[WARN]" not in result.output


# ---------------------------------------------------------------------------
# TF-11 — atomic sentinel write
# ---------------------------------------------------------------------------


def test_atomic_sentinel_write_preserves_prior_on_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF-11: simulate ``os.replace`` failing mid-write — the prior
    sentinel content must remain intact (atomic-write contract).
    Same guarantee as Phase 1's ``_atomic_write_json``.
    """
    home = tmp_path / "worthless"
    home.mkdir()

    # Write a known-good sentinel first.
    write_sentinel(
        home,
        status="ok",
        openclaw="absent",
        alias_count=0,
        events=[],
    )
    pre = sentinel_path(home).read_bytes()

    # Now monkeypatch os.replace to raise.
    import worthless.cli.sentinel as sentinel_mod

    def _exploding_replace(*_: object, **__: object) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(sentinel_mod.os, "replace", _exploding_replace)

    with pytest.raises(OSError):
        write_sentinel(
            home,
            status="partial",
            openclaw="failed",
            alias_count=1,
            events=[{"code": "x", "level": "error", "detail": "y"}],
        )

    # Sentinel byte-identical to the pre-failure state.
    assert sentinel_path(home).read_bytes() == pre
    # No leftover .tmp files.
    leftover = list(home.glob(".last-lock-status.json.*.tmp"))
    assert leftover == [], leftover

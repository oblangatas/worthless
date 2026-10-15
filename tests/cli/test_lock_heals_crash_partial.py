"""WOR-958: after an uncatchable kill mid-lock, nothing claims the key is safe.

``lock`` commits shard B + enrollment to the DB, then rewrites ``.env``. A
``kill -9`` between the two leaves the DB saying "locked" while ``.env``
still holds the real key. Restoring the pre-lock ``.env`` bytes after a
completed lock reproduces exactly that on-disk state, deterministically.

``lock --env`` already re-locks it (its shard-A check). Every command that
skips enrolled locations instead reported the real key as protected.
"""

from __future__ import annotations

import json
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome

from tests.cli.conftest import (
    TEST_OPENAI_KEY,
    cli_invoke,
    dotenv_value,
    list_enrollments,
    lock_env,
)


def _crash_partial(env_file: Path, home: WorthlessHome) -> None:
    """DB committed, ``.env`` never rewritten — what ``kill -9`` leaves."""
    original = env_file.read_bytes()
    lock_env(env_file, home)
    env_file.write_bytes(original)


def _unlocks_to_original(env_file: Path, home: WorthlessHome) -> None:
    result = cli_invoke(["unlock", "--env", str(env_file)], home)
    assert result.exit_code == 0, result.output
    assert dotenv_value(env_file, "OPENAI_API_KEY") == TEST_OPENAI_KEY


def test_scan_reports_the_real_key(home_dir: WorthlessHome, env_file: Path) -> None:
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["scan", str(env_file)], home_dir)

    # Was: "All 1 keys are protected", exit 0 — a pre-commit hook passed it.
    assert result.exit_code == 1, result.output
    assert "UNPROTECTED" in result.output, result.output


def test_status_does_not_call_it_protected(home_dir: WorthlessHome, env_file: Path) -> None:
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["status"], home_dir)

    assert "PROTECTED" not in result.output, result.output
    assert "worthless lock" in result.output, result.output


def test_doctor_flags_it(home_dir: WorthlessHome, env_file: Path) -> None:
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["doctor"], home_dir)

    assert "No issues found" not in result.output, result.output
    assert "OPENAI_API_KEY" in result.output and "worthless lock" in result.output, result.output


def test_doctor_json_flags_it(home_dir: WorthlessHome, env_file: Path) -> None:
    """Agents read --json: the same key must show up there."""
    _crash_partial(env_file, home_dir)

    report = json.loads(cli_invoke(["doctor", "--json"], home_dir).output)

    check = next(c for c in report["checks"] if c["check_id"] == "unlocked_keys")
    assert check["status"] == "warn", check
    assert [f["var_name"] for f in check["findings"]] == ["OPENAI_API_KEY"]
    assert check["fixable"] is False, "--fix must never purge an unlocked key"


def test_bare_worthless_warns_and_leaves_env_alone(
    home_dir: WorthlessHome, env_file: Path, monkeypatch
) -> None:
    """Warn, don't lock: locking here would also take keys never shown."""
    _crash_partial(env_file, home_dir)
    before = env_file.read_bytes()
    monkeypatch.chdir(env_file.parent)

    result = cli_invoke(["--yes"], home_dir)
    said = " ".join(result.output.split())  # Rich wraps long lines

    assert "OPENAI_API_KEY" in said and "worthless lock --env .env" in said, result.output
    assert env_file.read_bytes() == before


def test_lock_relocks_it(home_dir: WorthlessHome, env_file: Path) -> None:
    """Guard: already true on main via lock's shard-A check."""
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["lock", "--env", str(env_file)], home_dir)

    assert result.exit_code == 0, result.output
    assert dotenv_value(env_file, "OPENAI_API_KEY") != TEST_OPENAI_KEY
    assert len(list_enrollments(home_dir)) == 1, "re-lock duplicated the enrollment"
    _unlocks_to_original(env_file, home_dir)


def test_healthy_lock_is_left_alone(home_dir: WorthlessHome, env_file: Path) -> None:
    """Shard A must never be mistaken for the real key."""
    lock_env(env_file, home_dir)
    locked = env_file.read_bytes()

    for args in (["lock", "--env", str(env_file)], ["status"], ["doctor"]):
        cli_invoke(args, home_dir)
        assert env_file.read_bytes() == locked, f"{args[0]} rewrote a healthy lock"
    assert "PROTECTED" in cli_invoke(["status"], home_dir).output
    assert "No issues found" in cli_invoke(["doctor"], home_dir).output
    _unlocks_to_original(env_file, home_dir)

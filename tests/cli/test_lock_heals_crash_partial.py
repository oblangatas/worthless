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

import pytest

from worthless.cli.bootstrap import WorthlessHome

from tests.cli.conftest import (
    TEST_ANTHROPIC_KEY,
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
    assert "OPENAI_API_KEY" in result.output, result.output


def test_status_does_not_call_it_protected(home_dir: WorthlessHome, env_file: Path) -> None:
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["status"], home_dir)

    assert "EXPOSED" in result.output, result.output
    assert "PROTECTED" not in result.output, result.output
    assert "worthless lock" in result.output, result.output
    assert result.exit_code == 73, "scripts and agents must see a non-zero exit"


def test_doctor_flags_it(home_dir: WorthlessHome, env_file: Path) -> None:
    _crash_partial(env_file, home_dir)

    result = cli_invoke(["doctor"], home_dir)
    said = " ".join(result.output.split())  # Rich wraps long lines

    assert "No issues found" not in said, result.output
    assert "OPENAI_API_KEY" in said, result.output
    assert f"worthless lock --env {env_file}" in said, result.output


def test_doctor_json_flags_it(home_dir: WorthlessHome, env_file: Path) -> None:
    """Agents read --json: the same key must show up there."""
    _crash_partial(env_file, home_dir)

    report = json.loads(cli_invoke(["doctor", "--json"], home_dir).output)

    check = next(c for c in report["checks"] if c["check_id"] == "unlocked_keys")
    assert check["status"] == "warn", check
    assert [f["var_name"] for f in check["findings"]] == ["OPENAI_API_KEY"]
    assert f"worthless lock --env {env_file}" in check["findings"][0]["remediation"]
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

    assert "OPENAI_API_KEY" in said, result.output
    assert "worthless lock --env .env" in said, result.output
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


@pytest.mark.parametrize("damage", ["unreadable", "not_utf8"])
def test_one_bad_env_does_not_blind_every_command(
    home_dir: WorthlessHome, env_file: Path, damage: str
) -> None:
    """The check reads .env contents: a file it can't read is skipped, never fatal."""
    lock_env(env_file, home_dir)
    if damage == "unreadable":
        env_file.chmod(0)
    else:
        env_file.write_bytes(b"OPENAI_API_KEY=\xff\xfe\n")
    try:
        status = cli_invoke(["status"], home_dir)
        doctor = cli_invoke(["doctor"], home_dir)
    finally:
        env_file.chmod(0o600)

    assert "openai-" in status.output, f"status lost every key:\n{status.output}"
    assert "WRTLS-199" not in doctor.output, f"doctor crashed:\n{doctor.output}"


def test_status_keeps_its_keys_if_the_check_fails(
    home_dir: WorthlessHome, env_file: Path, monkeypatch
) -> None:
    """Cursor: the check is extra — its failure must not empty the key list."""
    lock_env(env_file, home_dir)

    async def _boom(*_a, **_k):
        raise RuntimeError("db hiccup")

    monkeypatch.setattr("worthless.cli.commands.status.find_unlocked", _boom)
    result = cli_invoke(["status"], home_dir)

    assert "openai-" in result.output, result.output
    assert "PROTECTED" in result.output, result.output


def test_a_key_in_an_unsearchable_folder_blinds_nothing(
    home_dir: WorthlessHome, env_file: Path, tmp_path: Path
) -> None:
    """exists()/is_file() raise when a parent folder can't be searched."""
    lock_env(env_file, home_dir)
    other = tmp_path / "proj" / ".env"
    other.parent.mkdir()
    other.write_text(f"ANTHROPIC_API_KEY={TEST_ANTHROPIC_KEY}\n")
    lock_env(other, home_dir)
    other.parent.chmod(0)
    try:
        scan = cli_invoke(["scan", str(env_file)], home_dir)
        status = cli_invoke(["status"], home_dir)
        doctor = cli_invoke(["doctor"], home_dir)
    finally:
        other.parent.chmod(0o700)

    assert scan.exit_code == 0, scan.output
    assert "UNPROTECTED" not in scan.output, scan.output
    assert "openai-" in status.output, f"status lost every key:\n{status.output}"
    assert "WRTLS-199" not in doctor.output, f"doctor crashed:\n{doctor.output}"

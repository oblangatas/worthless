"""A key whose link was deleted by the doctor bug keeps both halves (WOR-959).

v0.3.7–v0.3.14: ``worthless doctor --fix --json`` deleted the enrollment row of
healthy keys. Both halves survived, so the key is recoverable (WOR-937 will
re-link it). Until then nothing may destroy what is left:

* the next ``doctor --fix`` must not delete a ``shard_a/<alias>`` file whose key
  still has its shard row;
* ``unlock`` must not tell the user to delete the values as junk.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from tests.cli.conftest import cli_invoke, list_enrollments, lock_env
from tests.helpers import fake_key
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.doctor.checks import stranded_shards
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository


def _repo(home: WorthlessHome) -> ShardRepository:
    return ShardRepository(str(home.db_path), bytes(home.fernet_key))


def _unlink_like_the_bug(home: WorthlessHome):
    """Delete only the enrollment row, as the doctor bug did. Shards survive."""
    (enrollment,) = list_enrollments(home)
    asyncio.run(_repo(home).delete_enrollment(enrollment.key_alias, enrollment.env_path))
    assert list_enrollments(home) == []
    return enrollment


def _fix(home: WorthlessHome) -> dict:
    return stranded_shards.run(CheckContext(home=home, repo=_repo(home), fix=True, dry_run=False))


def test_fix_keeps_shard_a_whose_key_still_has_its_shard_row(
    home_dir: WorthlessHome, env_file: Path
) -> None:
    lock_env(env_file, home_dir)
    enrollment = _unlink_like_the_bug(home_dir)
    half = home_dir.shard_a_dir / enrollment.key_alias
    half.parent.mkdir(parents=True, exist_ok=True)
    half.write_bytes(b"\x01" * 32)

    result = _fix(home_dir)

    assert half.exists(), "doctor --fix deleted the last copy of a recoverable key's half"
    assert result["fixed"] == []
    (finding,) = result["findings"]
    assert finding["reason"] == "key_still_recoverable", finding


def test_fix_still_removes_a_file_with_no_key_left(home_dir: WorthlessHome) -> None:
    ghost = home_dir.shard_a_dir / "ghost-alias"
    ghost.parent.mkdir(parents=True, exist_ok=True)
    ghost.write_bytes(b"\x00" * 32)

    result = _fix(home_dir)

    assert not ghost.exists()
    assert [f["shard_path"] for f in result["fixed"]] == [str(ghost)]


def test_fix_deletes_nothing_when_shard_rows_cannot_be_read(
    home_dir: WorthlessHome, monkeypatch
) -> None:
    ghost = home_dir.shard_a_dir / "ghost-alias"
    ghost.parent.mkdir(parents=True, exist_ok=True)
    ghost.write_bytes(b"\x00" * 32)

    async def unreadable(self):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ShardRepository, "list_keys", unreadable)
    result = _fix(home_dir)

    assert ghost.exists(), "a failed read turned into a delete"
    assert result["status"] == "error"
    assert result["fixed"] == []


def test_unlock_says_an_unlinked_key_is_probably_recoverable(
    home_dir: WorthlessHome, env_file: Path
) -> None:
    lock_env(env_file, home_dir)
    _unlink_like_the_bug(home_dir)

    result = cli_invoke(["unlock", "--env", str(env_file)], home_dir)
    out = " ".join(result.output.split()).lower()

    assert result.exit_code != 0, result.output
    assert "junk" not in out, result.output
    assert "probably still recoverable" in out, result.output
    assert "don't delete" in out, result.output
    assert 'search "wrtls-102"' in out, result.output


def test_agent_repair_command_keeps_an_unlinked_key_intact(
    home_dir: WorthlessHome, env_file: Path
) -> None:
    """The real command agents run, twice, on the state the bug left."""
    lock_env(env_file, home_dir)
    enrollment = _unlink_like_the_bug(home_dir)
    half = home_dir.shard_a_dir / enrollment.key_alias
    half.parent.mkdir(parents=True, exist_ok=True)
    half.write_bytes(b"\x01" * 32)

    for _ in range(2):
        cli_invoke(["doctor", "--fix", "--yes", "--json"], home_dir)

    assert half.exists(), "the agent repair command deleted a recoverable key's half"
    assert asyncio.run(_repo(home_dir).list_keys()) == [enrollment.key_alias]


def test_unlock_never_tells_a_raw_key_holder_not_to_lock(
    home_dir: WorthlessHome, env_file: Path
) -> None:
    """After a normal unlock the .env holds the raw key. Unlocking again must not
    say "don't re-lock": that would leave a plaintext key unprotected."""
    lock_env(env_file, home_dir)
    assert cli_invoke(["unlock", "--env", str(env_file)], home_dir).exit_code == 0

    result = cli_invoke(["unlock", "--env", str(env_file)], home_dir)
    out = " ".join(result.output.split()).lower()

    assert "probably still recoverable" not in out, result.output
    assert "re-lock, or uninstall" not in out, result.output
    assert "junk" not in out, result.output


def test_recoverable_advice_follows_this_env_not_the_whole_machine(
    home_dir: WorthlessHome, tmp_path: Path
) -> None:
    """One bug-hit key elsewhere on the machine must not make every other project's
    raw keys hear "don't re-lock" (Cursor Bugbot on PR #709)."""
    hit_env = tmp_path / "hit" / ".env"
    raw_env = tmp_path / "raw" / ".env"
    hit_key, raw_key = (fake_key("sk-proj-", seed=s) for s in ("hit-project", "raw-project"))
    for env, key in ((hit_env, hit_key), (raw_env, raw_key)):
        env.parent.mkdir()
        env.write_text(f"OPENAI_API_KEY={key}\n")
        lock_env(env, home_dir)
    hit = next(e for e in list_enrollments(home_dir) if e.env_path == str(hit_env.resolve()))
    asyncio.run(_repo(home_dir).delete_enrollment(hit.key_alias, hit.env_path))
    assert cli_invoke(["unlock", "--env", str(raw_env)], home_dir).exit_code == 0

    raw = " ".join(cli_invoke(["unlock", "--env", str(raw_env)], home_dir).output.split())
    assert "probably still recoverable" not in raw.lower(), raw
    assert "worthless lock --env" in raw, raw

    hit_out = " ".join(cli_invoke(["unlock", "--env", str(hit_env)], home_dir).output.split())
    assert "probably still recoverable" in hit_out.lower(), hit_out

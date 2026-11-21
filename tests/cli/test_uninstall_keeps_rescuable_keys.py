"""Nothing destroys a key that can still be rescued (WOR-1135).

Two ways a key outlives its link to a project, both measured on main bd6e2dbc:

* the v0.3.7–v0.3.14 doctor bug deleted its enrollment row (an "unlinked" key);
* the user moved or renamed the project folder, so the stored ``.env`` path is
  gone (a "moved" key).

Both keys are still whole: Shard A in the project's ``.env``, Shard B in the
DB. On main, ``uninstall --yes`` wipes them silently, and ``lock`` on a
keys-only ``.env`` re-splits Shard A and destroys the key. Operator decisions
(2026-11-15): uninstall refuses; ``revoke --alias`` per key or ``--force`` gets
past; ``--force`` stays a loud last resort.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sqlite3
from pathlib import Path

from tests.cli.conftest import cli_invoke, list_enrollments
from tests.helpers import fake_key
from worthless.cli.bootstrap import WorthlessHome
from worthless.storage.repository import ShardRepository

REFUSED = 103  # ErrorCode.SHARD_STORAGE_FAILED, same as the existing uninstall guard


def _repo(home: WorthlessHome) -> ShardRepository:
    return ShardRepository(str(home.db_path), bytes(home.fernet_key))


def _project(tmp_path: Path, name: str, seed: str) -> Path:
    env = tmp_path / name / ".env"
    env.parent.mkdir()
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', seed=seed)}\n")
    return env


def _lock(env: Path, home: WorthlessHome, *, keys_only: bool = False) -> None:
    args = ["lock", *(["--keys-only"] if keys_only else []), "--env", str(env)]
    result = cli_invoke(args, home)
    assert result.exit_code == 0, f"precondition lock failed:\n{result.output}"


def _unlink_like_the_bug(home: WorthlessHome, env: Path) -> str:
    """Delete only the enrollment row, as the doctor bug did. Returns the alias."""
    (enrollment,) = [e for e in list_enrollments(home) if e.env_path == str(env.resolve())]
    asyncio.run(_repo(home).delete_enrollment(enrollment.key_alias, enrollment.env_path))
    return enrollment.key_alias


def _shard_aliases(home: WorthlessHome) -> list[str]:
    con = sqlite3.connect(home.db_path)
    try:
        return [r[0] for r in con.execute("SELECT key_alias FROM shards")]
    finally:
        con.close()


def _flat(output: str) -> str:
    return " ".join(output.split())


def test_uninstall_refuses_while_a_key_has_no_link(home_dir, tmp_path) -> None:
    env = _project(tmp_path, "app", "unlinked")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)
    before = env.read_text()

    result = cli_invoke(["uninstall", "--yes"], home_dir)
    out = _flat(result.output)

    assert result.exit_code == REFUSED, result.output
    assert home_dir.base_dir.exists(), "uninstall wiped a key that can still be rescued"
    assert _shard_aliases(home_dir) == [alias]
    assert env.read_text() == before
    assert alias in out and "nothing was changed" in out.lower(), result.output


def test_uninstall_refuses_while_a_project_was_moved(home_dir, tmp_path) -> None:
    env = _project(tmp_path, "old-name", "moved")
    _lock(env, home_dir)
    (alias,) = _shard_aliases(home_dir)
    env.parent.rename(tmp_path / "new-name")

    result = cli_invoke(["uninstall", "--yes"], home_dir)
    out = _flat(result.output)

    assert result.exit_code == REFUSED, result.output
    assert home_dir.base_dir.exists(), "uninstall wiped the key of a project that moved"
    assert _shard_aliases(home_dir) == [alias]
    assert alias in out and "moved or was deleted" in out, result.output


def test_refusal_happens_before_any_key_is_restored(home_dir, tmp_path) -> None:
    """A refusal must mean nothing changed: a healthy project stays locked too."""
    healthy = _project(tmp_path, "healthy", "healthy")
    _lock(healthy, home_dir)
    hit = _project(tmp_path, "hit", "hit")
    _lock(hit, home_dir)
    _unlink_like_the_bug(home_dir, hit)
    healthy_before = healthy.read_text()

    result = cli_invoke(["uninstall", "--yes"], home_dir)

    assert result.exit_code == REFUSED, result.output
    assert healthy.read_text() == healthy_before, "restored a key before refusing"


def test_refusal_never_suggests_force(home_dir, tmp_path) -> None:
    env = _project(tmp_path, "app", "no-force")
    _lock(env, home_dir)
    _unlink_like_the_bug(home_dir, env)

    result = cli_invoke(["uninstall", "--yes"], home_dir)

    assert result.exit_code == REFUSED, result.output
    assert "--force" not in result.output, result.output


def test_the_suggested_revoke_command_works(home_dir, tmp_path) -> None:
    """Every command a refusal suggests must run as printed."""
    env = _project(tmp_path, "app", "revoke")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)

    refused = cli_invoke(["uninstall", "--yes"], home_dir)
    match = re.search(r"worthless (revoke --alias \S+)", _flat(refused.output))
    assert match, f"refusal must name a per-key way past:\n{refused.output}"
    assert match.group(1) == f"revoke --alias {alias}"

    revoked = cli_invoke(match.group(1).split(), home_dir)
    assert revoked.exit_code == 0, revoked.output
    assert cli_invoke(["uninstall", "--yes"], home_dir).exit_code == 0


def test_force_names_every_key_it_destroys_even_when_quiet(home_dir, tmp_path) -> None:
    unlinked_env = _project(tmp_path, "hit", "force-hit")
    _lock(unlinked_env, home_dir)
    unlinked = _unlink_like_the_bug(home_dir, unlinked_env)
    moved_env = _project(tmp_path, "old-name", "force-moved")
    _lock(moved_env, home_dir)
    moved = next(a for a in _shard_aliases(home_dir) if a != unlinked)
    shutil.move(str(moved_env.parent), str(tmp_path / "new-name"))

    result = cli_invoke(["--quiet", "uninstall", "--yes", "--force"], home_dir)
    out = _flat(result.output)

    assert result.exit_code == 0, result.output
    assert not home_dir.base_dir.exists()
    assert unlinked in out and moved in out, (
        f"--force must name what it destroyed:\n{result.output}"
    )
    assert "rotate" in out.lower(), result.output


def test_lock_never_resplits_half_of_a_rescuable_keys_only_key(home_dir, tmp_path) -> None:
    """On main, re-locking a keys-only .env whose key lost its link re-splits
    Shard A as if it were a key, overwriting the only copy of it."""
    env = _project(tmp_path, "app", "relock")
    _lock(env, home_dir, keys_only=True)
    alias = _unlink_like_the_bug(home_dir, env)
    before = env.read_text()

    result = cli_invoke(["lock", "--keys-only", "--env", str(env)], home_dir)

    assert result.exit_code != 0, result.output
    assert env.read_text() == before, "lock overwrote half of a rescuable key"
    assert _shard_aliases(home_dir) == [alias], "lock stored a new key"
    assert alias in _flat(result.output), result.output


def test_lock_never_resplits_a_moved_keys_only_project(home_dir, tmp_path) -> None:
    env = _project(tmp_path, "old-name", "relock-moved")
    _lock(env, home_dir, keys_only=True)
    (alias,) = _shard_aliases(home_dir)
    moved = tmp_path / "new-name" / ".env"
    env.parent.rename(moved.parent)
    before = moved.read_text()

    result = cli_invoke(["lock", "--keys-only", "--env", str(moved)], home_dir)

    assert result.exit_code != 0, result.output
    assert moved.read_text() == before, "lock overwrote half of a moved project's key"
    assert _shard_aliases(home_dir) == [alias], "lock stored a new key"


def test_a_moved_copy_of_a_key_still_live_elsewhere_does_not_block(home_dir, tmp_path) -> None:
    """Same key locked in two projects, one moved: uninstall gives the key back
    through the live one. Refusing here would suggest ``revoke --alias``, which
    deletes every record of the key and breaks the live project (Karen, WOR-1135)."""
    live = _project(tmp_path, "live", "shared")
    original = live.read_text()
    _lock(live, home_dir)
    moved = _project(tmp_path, "old-name", "shared")
    _lock(moved, home_dir)
    assert len(set(_shard_aliases(home_dir))) == 1, "precondition: one key, two projects"
    moved.parent.rename(tmp_path / "new-name")

    result = cli_invoke(["uninstall", "--yes"], home_dir)

    assert result.exit_code == 0, result.output
    assert live.read_text() == original, "the live project did not get its key back"
    assert "revoke" not in result.output, result.output


def test_lock_ignores_a_stored_key_it_cannot_decrypt(home_dir, tmp_path) -> None:
    """One stale key from another project (Fernet drift) must not stop every
    later lock of that provider: the guard skips what it can't read (Brutus)."""
    _lock(_project(tmp_path, "good", "good"), home_dir)
    _lock(_project(tmp_path, "stale", "stale"), home_dir)
    stale = next(e.key_alias for e in list_enrollments(home_dir) if "stale" in e.env_path)
    con = sqlite3.connect(home_dir.db_path)
    with con:
        con.execute(
            "UPDATE shards SET shard_b_enc = ? WHERE key_alias = ?", (b"not-a-token", stale)
        )
    con.close()

    result = cli_invoke(["lock", "--env", str(_project(tmp_path, "new", "new"))], home_dir)

    assert result.exit_code == 0, result.output


def _hide_fernet_key(home: WorthlessHome) -> None:
    """As a locked keychain or a WSL box with no secret service looks to uninstall."""
    home.fernet_key_path.unlink()


def test_an_unreadable_fernet_key_does_not_hide_a_rescuable_key(home_dir, tmp_path) -> None:
    """Key names need no decryption (Brutus): the guard must still refuse."""
    env = _project(tmp_path, "app", "no-fernet")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)
    _hide_fernet_key(home_dir)

    result = cli_invoke(["uninstall", "--yes"], home_dir)

    assert result.exit_code == REFUSED, result.output
    assert alias in _flat(result.output), result.output
    assert _shard_aliases(home_dir) == [alias]


def test_force_names_keys_even_when_the_fernet_key_is_unreadable(home_dir, tmp_path) -> None:
    env = _project(tmp_path, "app", "no-fernet-force")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)
    _hide_fernet_key(home_dir)

    result = cli_invoke(["--quiet", "uninstall", "--yes", "--force"], home_dir)

    assert result.exit_code == 0, result.output
    assert alias in _flat(result.output), f"--force must name what it destroyed:\n{result.output}"


def test_plain_unlock_points_at_a_key_that_lost_its_link(home_dir, tmp_path, monkeypatch) -> None:
    env = _project(tmp_path, "app", "plain-unlock")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("DEBUG=1\n")
    monkeypatch.chdir(elsewhere)

    result = cli_invoke(["--quiet", "unlock"], home_dir)
    out = _flat(result.output)

    assert alias in out and "WRTLS-102" in out, result.output
    assert "--force" not in out and "revoke" not in out, result.output
    assert _shard_aliases(home_dir) == [alias]


def test_a_busy_database_refuses_without_offering_force(home_dir, tmp_path, monkeypatch) -> None:
    env = _project(tmp_path, "app", "busy-db")
    _lock(env, home_dir)
    alias = _unlink_like_the_bug(home_dir, env)
    real_connect = sqlite3.connect

    def busy(target, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if str(target).endswith("?mode=ro"):
            raise sqlite3.OperationalError("database is locked")
        return real_connect(target, *args, **kwargs)

    monkeypatch.setattr("worthless.cli.commands.uninstall.sqlite3.connect", busy)
    result = cli_invoke(["uninstall", "--yes"], home_dir)
    out = _flat(result.output)

    assert result.exit_code == 1 and "WRTLS-105" in out, result.output  # same as the restore path
    assert "worthless down" in out and "--force" not in out, result.output
    assert _shard_aliases(home_dir) == [alias]

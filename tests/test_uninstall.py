"""Tests for `worthless uninstall` (WOR-435).

Starts with the mode-clamp safety helper (brutus /merge-ready gate-6 P1):
restore the original mode, but NEVER looser than 0o600 on a file that now
holds the reconstructed real key — no group/other access to a secret.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner()


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (None, None),  # never captured (pre-715) → leave file as-is
        (0o600, 0o600),  # already secure → unchanged
        (0o400, 0o400),  # tighter than 600 (read-only) → preserved exactly
        (0o644, 0o600),  # world-readable → clamped (no group/other read of the key)
        (0o640, 0o600),  # group-readable → clamped
        (0o666, 0o600),  # world-writable → clamped
        (0o700, 0o700),  # owner-only (with exec) → unchanged (no group/other)
        (0o755, 0o700),  # group/other exec+read → clamped to owner-only
    ],
)
def test_secure_restore_mode_clamps_group_and_other(
    original: int | None, expected: int | None
) -> None:
    """secure_restore_mode strips ALL group/other bits — never re-exposes the key.

    The original is preserved when it's already owner-only (incl. tighter
    read-only 0o400); anything granting group/other access is clamped so the
    restored .env (now holding the real key) is owner-only.
    """
    from worthless.cli.commands.uninstall import secure_restore_mode

    assert secure_restore_mode(original) == expected


@pytest.mark.parametrize(
    ("orig", "expected_final"),
    [
        (0o644, 0o600),  # world-readable → clamped owner-only
        (0o640, 0o600),  # group-readable → clamped owner-only
        (0o600, 0o600),  # already secure → unchanged
    ],
)
def test_uninstall_restores_key_and_applies_mode_policy(
    home_dir: WorthlessHome, tmp_path, orig: int, expected_final: int
) -> None:
    """End-to-end: lock a real .env, run `worthless uninstall --yes`, assert the
    real key is back, the mode policy applied, and ~/.worthless wiped.
    """
    from tests.helpers import fake_key

    key = fake_key("sk-")
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    env.chmod(orig)

    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert locked.exit_code == 0, locked.output
    assert (env.stat().st_mode & 0o777) == 0o600  # lock tightened it
    assert key not in env.read_text()  # shard-A, not the real key

    uninst = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert uninst.exit_code == 0, uninst.output
    assert key in env.read_text(), "real key not restored to .env"
    assert (env.stat().st_mode & 0o777) == expected_final, (
        f"mode policy: expected 0o{expected_final:o}, got 0o{env.stat().st_mode & 0o777:o}"
    )
    assert not home_dir.base_dir.exists(), "~/.worthless not wiped"


def test_uninstall_idempotent_second_run_is_clean(home_dir: WorthlessHome, tmp_path) -> None:
    """A second uninstall on an already-clean machine exits 0 (nothing to do)."""
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})
    runner.invoke(app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    second = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert second.exit_code == 0, second.output


def test_uninstall_aborts_wipe_when_a_restore_fails(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """Key-shredder guard: if ANY restore fails, the wipe must NOT run —
    shard-B stays in the DB and ~/.worthless survives for a retry.
    """
    import sqlite3

    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    async def boom(*_a, **_k):
        raise RuntimeError("simulated restore failure")

    monkeypatch.setattr(uninstall_mod, "_unlock_batch", boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, "uninstall must ABORT when a restore fails"
    assert home_dir.base_dir.exists(), "shredder guard FAILED: home wiped despite a failed restore"
    n_shards = (
        sqlite3.connect(str(home_dir.db_path)).execute("SELECT COUNT(*) FROM shards").fetchone()[0]
    )
    assert n_shards >= 1, "shard-B deleted despite the abort"


def test_uninstall_enroll_only_key_warns_but_does_not_block(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """An enroll-only enrollment (env_path IS NULL) must NOT trip the shredder
    guard — it warns and the uninstall still completes (wipe runs).
    """
    import sqlite3

    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    # Seed a separate enroll-only key (no .env) directly in the DB.
    con = sqlite3.connect(str(home_dir.db_path))
    con.execute(
        "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
        "VALUES (?, ?, ?, ?, ?)",
        ("enroll-only-alias", b"x", b"c", b"n", "openai"),
    )
    con.execute(
        "INSERT INTO enrollments (key_alias, var_name, env_path) VALUES (?, ?, NULL)",
        ("enroll-only-alias", "ENROLL_ONLY_KEY"),
    )
    con.commit()
    con.close()

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, f"enroll-only key blocked uninstall: {result.output}"
    assert "enroll-only" in result.output.lower(), "no warning surfaced for the enroll-only key"
    assert not home_dir.base_dir.exists(), "wipe did not run"


def test_uninstall_restores_multiple_envs(home_dir: WorthlessHome, tmp_path) -> None:
    """Two locked .env files are both restored in one uninstall."""
    from tests.helpers import fake_key

    k1, k2 = fake_key("sk-"), fake_key("sk-")
    e1 = tmp_path / "a" / ".env"
    e1.parent.mkdir()
    e1.write_text(f"OPENAI_API_KEY={k1}\n")
    e2 = tmp_path / "b" / ".env"
    e2.parent.mkdir()
    e2.write_text(f"OPENAI_API_KEY={k2}\n")
    for e in (e1, e2):
        runner.invoke(
            app, ["lock", "--env", str(e)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
        )

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    assert k1 in e1.read_text(), "first .env not restored"
    assert k2 in e2.read_text(), "second .env not restored"
    assert not home_dir.base_dir.exists()


def test_uninstall_calls_openclaw_undo_with_restored_aliases(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """uninstall must invoke the OpenClaw symmetric undo with (provider, alias)
    tuples for every restored key — so openclaw.json isn't left pointing at a
    dead proxy. (OpenClaw isn't installed in CI, so we spy on the call.)
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    calls: list[list] = []

    def spy(unlocked, console, home):  # noqa: ANN001, ANN202
        calls.append(list(unlocked))
        return False

    monkeypatch.setattr(uninstall_mod, "_apply_openclaw_unlock", spy)

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1, "uninstall did not call _apply_openclaw_unlock exactly once"
    assert calls[0], "OpenClaw undo called with an empty OcRestore list"
    restore = calls[0][0]
    assert restore.provider and restore.alias, f"bad OcRestore (no provider/alias): {restore!r}"


def test_uninstall_partial_rmtree_message_is_accurate(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """Thermo cosmetic fix: if ~/.worthless can't be fully removed, the final
    message must NOT claim it was removed — it must disclose that files remain.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    # Simulate rmtree leaving the dir behind (e.g. an immutable/locked file).
    monkeypatch.setattr(uninstall_mod.shutil, "rmtree", lambda *a, **k: None)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "remain" in out, "must disclose that ~/.worthless files remain"
    assert "and ~/.worthless removed" not in out, (
        "must NOT claim full removal when it didn't happen"
    )

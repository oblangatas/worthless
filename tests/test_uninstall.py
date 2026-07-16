"""Tests for `worthless uninstall` (WOR-435).

Starts with the mode-clamp safety helper (brutus /merge-ready gate-6 P1):
restore the original mode, but NEVER looser than 0o600 on a file that now
holds the reconstructed real key — no group/other access to a secret.
"""

from __future__ import annotations

import errno
import sqlite3

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode, WorthlessError

runner = CliRunner()


def _op_error(msg: str, *, code: int | None) -> sqlite3.OperationalError:
    """A sqlite3.OperationalError with an optional sqlite_errorcode — 3.11+ sets
    it from the C layer; ``None`` simulates the 3.10 no-attribute case."""
    exc = sqlite3.OperationalError(msg)
    if code is not None:
        exc.sqlite_errorcode = code
    return exc


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (None, None),  # never captured (pre-715) → leave file as-is
        (0o600, 0o600),  # already secure → unchanged
        (0o400, 0o400),  # tighter than 600 (read-only) → preserved exactly
        (0o644, 0o600),  # world-readable → clamped (no group/other read of the key)
        (0o640, 0o600),  # group-readable → clamped
        (0o666, 0o600),  # world-writable → clamped
        (0o700, 0o600),  # owner rwx → exec stripped to the 0o600 floor (worthless-dffx)
        (0o755, 0o600),  # group/other + exec → clamped to the 0o600 floor
    ],
)
def test_secure_restore_mode_clamps_to_0o600_floor(
    original: int | None, expected: int | None
) -> None:
    """secure_restore_mode clamps a restored key-bearing .env to a 0o600 floor.

    Group/other bits AND the owner-execute bit are stripped (a .env is never
    executable), so a loose mode captured at lock time can never re-widen the
    key at rest (worthless-dffx). Modes already at/under 0o600 (incl. read-only
    0o400) are preserved exactly. ``None`` (pre-715, never captured) = leave as-is.
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


def test_uninstall_removes_the_service_unit(home_dir: WorthlessHome, tmp_path, monkeypatch) -> None:
    """WOR-795: uninstall best-effort tears down the launchd/systemd service unit
    (so a KeepAlive unit can't respawn `worthless up` and recreate ~/.worthless),
    and the home is still wiped afterwards.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    calls: list = []

    monkeypatch.setattr(uninstall_mod, "IS_WINDOWS", False)
    monkeypatch.setattr(uninstall_mod, "uninstall_service", lambda home: calls.append(home))  # noqa: ANN001

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1, "uninstall must tear down the service unit exactly once"
    assert not home_dir.base_dir.exists(), "home must still be wiped after service teardown"


def test_uninstall_service_teardown_failure_does_not_block(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """WOR-795: a service-teardown that raises (no unit installed, permission, …)
    is best-effort — it must NOT block the uninstall, same class as stopping the
    daemon. This also covers the no-service no-op path.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    def _boom(home) -> None:  # noqa: ANN001
        raise RuntimeError("no unit / cannot remove")

    monkeypatch.setattr(uninstall_mod, "IS_WINDOWS", False)
    monkeypatch.setattr(uninstall_mod, "uninstall_service", _boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, "a service-teardown error must not block uninstall"
    assert not home_dir.base_dir.exists(), "home must still be wiped despite a teardown error"


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


# --- PR1 hardening (WOR-713 tail) ------------------------------------------


def test_uninstall_tty_human_declining_cancels(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """jlco: at a TTY, declining the top-level confirm cancels cleanly —
    nothing wiped, nothing restored.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    monkeypatch.setattr(uninstall_mod, "_stdin_is_tty", lambda: True)

    key = fake_key("sk-")
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    result = runner.invoke(
        app, ["uninstall"], input="n\n", env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, f"TTY decline should be a clean cancel: {result.output}"
    assert home_dir.base_dir.exists(), "declined uninstall must NOT wipe ~/.worthless"
    assert key not in env.read_text(), "declined uninstall must NOT restore (still shard-A)"


def test_uninstall_non_interactive_without_yes_refuses_cleanly(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """jlco/security gate: a non-interactive caller (no TTY) without --yes must
    get a CLEAN refusal that points at --yes — never a confirm that EOFs into an
    internal error (WRTLS-199), and never a silent wipe.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    monkeypatch.setattr(uninstall_mod, "_stdin_is_tty", lambda: False)

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    result = runner.invoke(app, ["uninstall"], env={"WORTHLESS_HOME": str(home_dir.base_dir)})
    assert result.exit_code != 0, "non-interactive without --yes must refuse"
    out = result.output.lower()
    assert "--yes" in out, "refusal must tell the caller to pass --yes"
    assert "internal error" not in out, "must NOT crash with WRTLS-199"
    assert home_dir.base_dir.exists(), "refusal must NOT wipe ~/.worthless"


def test_uninstall_stops_daemon_before_wipe(home_dir: WorthlessHome, tmp_path, monkeypatch) -> None:
    """fzbi: uninstall stops a running proxy daemon (best-effort) during teardown
    so it isn't left serving against a deleted ~/.worthless.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    calls: list[str] = []
    monkeypatch.setattr(uninstall_mod, "_stop_daemon", lambda home, console: calls.append("stop"))

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    assert calls == ["stop"], "uninstall must call _stop_daemon (best-effort) during teardown"
    assert not home_dir.base_dir.exists(), "wipe must still complete"


def test_uninstall_openclaw_partial_failure_exits_73_but_still_wipes(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """jl13: an OpenClaw-undo partial failure must SURFACE (exit 73) like unlock
    does — but it must NOT block the wipe (best-effort, L1).
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    # Real _apply_openclaw_unlock returns True on detected+failed; simulate it.
    monkeypatch.setattr(
        uninstall_mod, "_apply_openclaw_unlock", lambda unlocked, console, home: True
    )

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 73, f"OpenClaw partial failure must exit 73: {result.output}"
    assert not home_dir.base_dir.exists(), "wipe must still run despite OpenClaw failure"


def test_zero_restore_keys_wipes_plaintext() -> None:
    """gcmp: _zero_restore_keys zeros every held plaintext key in place; tolerates None."""
    from worthless.cli.commands.uninstall import _zero_restore_keys

    class _R:
        pass

    with_key = _R()
    with_key.plaintext_key = bytearray(b"sk-secret-key")
    secretref = _R()
    secretref.plaintext_key = None  # SecretRef branch — nothing to zero

    _zero_restore_keys([with_key, secretref])

    assert with_key.plaintext_key == bytearray(len(b"sk-secret-key")), "key not zeroed"
    assert secretref.plaintext_key is None  # didn't crash on None


def test_uninstall_zeros_keys_when_a_restore_fails(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """gcmp: on the restore-failure path (wipe aborts before the OpenClaw undo
    that normally zeros keys), uninstall must still zero the built restores.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    real = uninstall_mod._zero_restore_keys
    spied: list[list] = []

    def _spy(restores):  # noqa: ANN001, ANN202
        spied.append(list(restores))
        real(restores)

    monkeypatch.setattr(uninstall_mod, "_zero_restore_keys", _spy)

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    # Fail _unlock_batch — the SOLE shred-guarded step (worthless-ftit). A
    # transactional restore failure there routes the file to `failed` →
    # _guard_failed_restores zeroes any keys already built for other files (SR-02)
    # and aborts the wipe. (Post-ftit, _decide_mode/os.chmod are cosmetic and no
    # longer abort, so the injection point moved here from _decide_mode.)
    async def _boom(*_a, **_k):
        raise OSError("simulated restore failure")

    monkeypatch.setattr(uninstall_mod, "_unlock_batch", _boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, "a failed restore must abort the wipe"
    assert home_dir.base_dir.exists(), "shredder guard: home not wiped"
    assert spied, "the abort path must run the key-zeroing guard"


# --- f2ge: symlink .env classification (real symlinks, no mocking) ---------


def test_uninstall_dangling_symlink_env_is_skipped_not_blocked(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """worthless-f2ge: a locked .env replaced by a DANGLING symlink (target
    deleted) classifies as `missing` — the shard-A file is already gone, so
    the wipe proceeds. Real symlink; safe_rewrite's real refusal drives it.
    """
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    env.unlink()
    env.symlink_to(tmp_path / "deleted-target")  # dangling: target does not exist

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, result.output
    assert "nothing to restore" in result.output.lower(), result.output
    assert not home_dir.base_dir.exists(), "a dangling symlink must NOT block the wipe"


def test_uninstall_live_symlink_env_blocks_wipe(home_dir: WorthlessHome, tmp_path) -> None:
    """worthless-f2ge: a locked .env replaced by a LIVE symlink (points at a
    real file) classifies as `failed` — the real key was never written back
    (safe_rewrite refuses symlinks) and shard-A is still live, so the
    key-shredder guard must block the wipe. Real symlink.
    """
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    real_target = tmp_path / "elsewhere.env"
    real_target.write_text("OPENAI_API_KEY=whatever\n")
    env.unlink()
    env.symlink_to(real_target)  # live: target exists

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, "a live symlink must trip the shredder guard"
    assert home_dir.base_dir.exists(), "a live symlink must NOT be wiped"
    assert "could not restore" in result.output.lower(), result.output


# --- ftit: post-restore failures don't false-block / don't silently break OC --


def test_chmod_failure_after_restore_does_not_block_wipe(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """worthless-ftit: on a chmod-hostile filesystem (WSL /mnt/c, FAT, some
    network mounts), a failed mode-tighten AFTER the key is restored must NOT
    abort the uninstall — the key is already back. Simulated by a chmod that
    rejects the .env (the real EPERM/EROFS such mounts raise).
    """
    import errno

    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    key = fake_key("sk-")
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    env.chmod(0o644)  # loose → uninstall will try to clamp it to 0o600
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    real_chmod = uninstall_mod.os.chmod

    def _chmod_hostile(path, mode, *a, **k):  # noqa: ANN001, ANN202 — mimic a chmod-hostile mount
        if str(path).endswith(".env"):
            raise OSError(errno.EPERM, "Operation not permitted")
        return real_chmod(path, mode, *a, **k)

    monkeypatch.setattr(uninstall_mod.os, "chmod", _chmod_hostile)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, f"a cosmetic chmod failure must not abort: {result.output}"
    assert key in env.read_text(), "the real key must be restored despite the chmod failure"
    assert not home_dir.base_dir.exists(), "the wipe must complete"
    assert "tightened" in result.output.lower() or "chmod" in result.output.lower()


def test_openclaw_build_failure_exits_73_and_still_wipes(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """worthless-ftit: if the OpenClaw undo BUILD raises, uninstall must NOT
    false-block (the key IS restored) and must NOT silently exit 0 (openclaw.json
    would still point at the deleted proxy). It surfaces via exit 73 + a
    'run doctor' hint, and the wipe still completes.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    key = fake_key("sk-")
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    async def _build_boom(*_a, **_k):
        raise RuntimeError("openclaw rollback build blew up")

    monkeypatch.setattr(uninstall_mod, "_build_oc_restores", _build_boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 73, (
        f"OpenClaw build failure must surface as exit 73: {result.output}"
    )
    assert key in env.read_text(), "the real key must still be restored"
    assert not home_dir.base_dir.exists(), "the wipe must still complete"
    assert "doctor" in result.output.lower(), "must point the user at `worthless doctor`"


# --- u4hl: never force-wipe a recoverable (busy/locked) install ---------------


@pytest.mark.parametrize(
    ("make_exc", "recoverable"),
    [
        (lambda: _op_error("database is locked", code=5), True),  # SQLITE_BUSY
        (lambda: _op_error("database table is locked", code=6), True),  # SQLITE_LOCKED
        (lambda: _op_error("database is locked", code=None), True),  # 3.10 string-only path
        (lambda: _op_error("no such table: enrollments", code=1), False),  # SQLITE_ERROR → broken
        (lambda: sqlite3.DatabaseError("file is not a database"), False),  # corrupt → broken
        (lambda: WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key at /secret/x"), False),
        (lambda: WorthlessError(ErrorCode.ORPHANED_SHARD_DATA, "gone"), False),
        (lambda: OSError(errno.EACCES, "Permission denied"), False),  # perms → broken
        (lambda: OSError(errno.ECONNREFUSED, "Connection refused"), True),  # IPC sidecar down
    ],
)
def test_is_recoverable_repo_error_classification(make_exc, recoverable) -> None:  # noqa: ANN001
    """worthless-u4hl: the busy-vs-broken discriminator. Recoverable (busy/locked,
    incl. the 3.10 string-only path, and an IPC sidecar-down socket) is never
    force-wiped; everything unrecognized (corrupt, no-such-table, WorthlessError,
    EACCES) stays broken → wipeable via --force.
    """
    from worthless.cli.commands.uninstall import _is_recoverable_repo_error

    assert _is_recoverable_repo_error(make_exc()) is recoverable


@pytest.mark.parametrize("force_flag", [[], ["--force"]])
def test_uninstall_refuses_a_locked_install_never_wipes(
    home_dir: WorthlessHome, tmp_path, monkeypatch, force_flag
) -> None:
    """worthless-u4hl (the P2 data-loss fix): a busy/locked DB is RECOVERABLE —
    uninstall refuses and changes NOTHING, with OR without --force. Injects the
    exact ``database is locked`` OperationalError a held write lock produces,
    driven through the real classifier + refuse path.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    async def _locked(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(uninstall_mod, "_restore_all", _locked)

    result = runner.invoke(
        app, ["uninstall", "--yes", *force_flag], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, "a locked DB must never be wiped"
    assert home_dir.base_dir.exists(), "nothing must be wiped on a recoverable/busy DB"
    n_shards = (
        sqlite3.connect(str(home_dir.db_path)).execute("SELECT COUNT(*) FROM shards").fetchone()[0]
    )
    assert n_shards >= 1, "shard-B must survive — the keys are recoverable"
    out = result.output.lower()
    assert "another process" in out or "worthless down" in out, out


def test_force_wipes_a_really_corrupt_db(home_dir: WorthlessHome, tmp_path) -> None:
    """worthless-u4hl: a genuinely corrupt DB is UNRECOVERABLE — --force still
    wipes it (the escape hatch survives). Real garbage bytes on disk, no mock.
    """
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    home_dir.db_path.write_bytes(b"this is definitely not a sqlite database")  # real corruption

    result = runner.invoke(
        app, ["uninstall", "--yes", "--force"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code == 0, f"--force must wipe a genuinely-broken install: {result.output}"
    assert not home_dir.base_dir.exists(), "the broken install must be wiped"


def test_uninstall_zeros_keys_when_the_mode_confirm_aborts(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """ftit / SR-02: a Ctrl-C `Abort` from the mode-clamp confirm (a RuntimeError,
    NOT an OSError) escapes the cosmetic catch — the restore loop's finally must
    still zero the keys already built into `unlocked` before the abort
    propagates, and nothing may be wiped.
    """
    import typer

    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    runner.invoke(app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    spied: list[list] = []
    real = uninstall_mod._zero_restore_keys

    def _spy(restores):  # noqa: ANN001, ANN202
        spied.append(list(restores))
        real(restores)

    monkeypatch.setattr(uninstall_mod, "_zero_restore_keys", _spy)
    monkeypatch.setattr(
        uninstall_mod,
        "_confirm_uninstall",
        lambda console, *, assume_yes: True,  # noqa: ANN001
    )

    def _abort(*_a, **_k):
        raise typer.Abort()

    monkeypatch.setattr(uninstall_mod, "_decide_mode", _abort)

    result = runner.invoke(app, ["uninstall"], env={"WORTHLESS_HOME": str(home_dir.base_dir)})
    assert result.exit_code != 0, "an aborted uninstall must not silently wipe"
    assert home_dir.base_dir.exists(), "abort before the wipe → home intact"
    assert spied, "SR-02: built restore keys must be zeroed even when the confirm aborts"


@pytest.mark.parametrize("extra", [[], ["--force"]], ids=["no-force", "force"])
@pytest.mark.parametrize(
    "make_busy",
    [
        lambda: _op_error("database is locked", code=5),  # SQLITE_BUSY
        lambda: _op_error("database table is locked", code=6),  # SQLITE_LOCKED
        lambda: _op_error("database is locked", code=None),  # 3.10: no errorcode → string fallback
    ],
    ids=["busy", "locked", "py310-string"],
)
def test_uninstall_refuses_on_a_locked_db_mid_restore(
    home_dir: WorthlessHome,
    tmp_path,
    monkeypatch,
    extra: list[str],
    make_busy,  # noqa: ANN001
) -> None:
    """CodeRabbit / u4hl: a busy/locked DB raised from _unlock_batch mid-restore is
    RECOVERABLE — it re-raises to the refuse path (LOCK_IN_PROGRESS), never routes
    to `failed`. Proven across BUSY(5), LOCKED(6), and the 3.10 string-only path,
    with AND without --force (with --force is the data-loss case: `failed` +
    --force would otherwise wipe recoverable keys).
    """
    import sqlite3

    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    # Prove the refusal comes from the locked-DB path, not a "nothing installed"
    # fallback: the setup lock MUST have succeeded (CodeRabbit).
    assert locked.exit_code == 0, f"setup lock failed, test would prove nothing: {locked.output}"

    async def _busy(*_a, **_k):
        raise make_busy()

    monkeypatch.setattr(uninstall_mod, "_unlock_batch", _busy)

    result = runner.invoke(
        app, ["uninstall", "--yes", *extra], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, f"a locked DB mid-restore must refuse ({extra})"
    # the LOCK_IN_PROGRESS refuse path — NOT a generic crash, NOT a wipe:
    assert "another process" in result.output.lower(), result.output
    assert "keys are safe" in result.output.lower(), result.output
    assert home_dir.base_dir.exists(), "a recoverable lock must NOT be wiped"
    n_shards = (
        sqlite3.connect(str(home_dir.db_path)).execute("SELECT COUNT(*) FROM shards").fetchone()[0]
    )
    assert n_shards >= 1, "shard-B deleted despite the recoverable refuse"


class TestMcpLeftoverReminder:
    """worthless-ify0: after a successful uninstall, name a leftover Worthless MCP
    server entry in the user's editor config so they can remove it — read-only, and
    ONLY when one actually exists (the ~90% who never set it up aren't nagged).
    """

    @staticmethod
    def _uninstall_env(home_dir: WorthlessHome, fake_home) -> dict[str, str]:
        # Isolate HOME (detection reads ~/.cursor/mcp.json + ~/.claude.json) and
        # widen the console so a long tmp path in the reminder isn't wrapped.
        return {
            "WORTHLESS_HOME": str(home_dir.base_dir),
            "HOME": str(fake_home),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "COLUMNS": "1000",
        }

    def test_uninstall_names_the_editor_config_holding_a_worthless_mcp_entry(
        self, home_dir: WorthlessHome, tmp_path, monkeypatch
    ) -> None:
        """Proof of fix: with ~/.cursor/mcp.json referencing `worthless-mcp`, a
        successful uninstall points the user at that exact file to remove.
        """
        from tests.helpers import fake_key

        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)  # Path.cwd()/.mcp.json must NOT exist / false-match here
        fake_home = tmp_path / "home"
        cursor_cfg = fake_home / ".cursor" / "mcp.json"
        cursor_cfg.parent.mkdir(parents=True)
        cursor_cfg.write_text(
            '{"mcpServers":{"worthless":{"command":"npx","args":["-y","worthless-mcp"]}}}'
        )

        env = work / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        locked = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir), "HOME": str(fake_home)},
        )
        assert locked.exit_code == 0, locked.output

        result = runner.invoke(
            app, ["uninstall", "--yes"], env=self._uninstall_env(home_dir, fake_home)
        )
        assert result.exit_code == 0, result.output
        assert "MCP server" in result.output, "no MCP-leftover reminder printed"
        assert str(cursor_cfg) in result.output, "reminder must name the exact config file"

    def test_uninstall_is_silent_about_mcp_when_no_config_references_worthless(
        self, home_dir: WorthlessHome, tmp_path, monkeypatch
    ) -> None:
        """No-noise invariant: with no editor MCP config referencing worthless,
        uninstall says nothing about MCP — no nagging users who never set it up.
        """
        from tests.helpers import fake_key

        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        fake_home = tmp_path / "home"
        fake_home.mkdir()  # empty: no .cursor / .claude.json / .mcp.json

        env = work / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir), "HOME": str(fake_home)},
        )
        result = runner.invoke(
            app, ["uninstall", "--yes"], env=self._uninstall_env(home_dir, fake_home)
        )
        assert result.exit_code == 0, result.output
        assert "MCP server" not in result.output, "no-noise: MCP reminder must stay silent"

    def test_uninstall_does_not_remind_about_mcp_when_it_refuses(
        self, home_dir: WorthlessHome, tmp_path, monkeypatch
    ) -> None:
        """Placement: the reminder rides the post-wipe path only. A refused
        uninstall (non-interactive, no --yes) exits 1 and wipes nothing, so even
        with a worthless MCP entry present, no reminder prints.
        """
        from tests.helpers import fake_key

        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        fake_home = tmp_path / "home"
        cursor_cfg = fake_home / ".cursor" / "mcp.json"
        cursor_cfg.parent.mkdir(parents=True)
        cursor_cfg.write_text(
            '{"mcpServers":{"worthless":{"command":"npx","args":["-y","worthless-mcp"]}}}'
        )

        env = work / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir), "HOME": str(fake_home)},
        )
        # No --yes + non-interactive stdin (CliRunner) → uninstall REFUSES; nothing wiped.
        refused = runner.invoke(app, ["uninstall"], env=self._uninstall_env(home_dir, fake_home))
        assert refused.exit_code == 1, refused.output
        assert home_dir.base_dir.exists(), "a refused uninstall must not wipe"
        assert "MCP server" not in refused.output, "reminder must not fire on a refused uninstall"

    def test_uninstall_survives_a_crashing_mcp_check(
        self, home_dir: WorthlessHome, tmp_path, monkeypatch
    ) -> None:
        """The MCP reminder is advisory: if the scan itself raises (deleted cwd,
        unresolvable HOME), it must NOT flip a completed wipe to a failure.
        """
        import worthless.cli.commands.uninstall as uninstall_mod
        from tests.helpers import fake_key

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        runner.invoke(
            app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
        )

        def _boom(*_a, **_k):
            raise RuntimeError("HOME unresolvable / cwd gone")

        monkeypatch.setattr(uninstall_mod, "_mentions_worthless_mcp", _boom)

        result = runner.invoke(
            app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
        )
        assert result.exit_code == 0, result.output  # an advisory crash must not fail the uninstall
        assert not home_dir.base_dir.exists(), "the wipe must still have completed"

    def test_uninstall_names_a_project_scoped_mcp_json_in_the_cwd(
        self, home_dir: WorthlessHome, tmp_path, monkeypatch
    ) -> None:
        """Proof of fix (cwd branch): a project-scoped ./.mcp.json referencing
        worthless-mcp is detected and named too — not only the ~/.cursor path.
        """
        from tests.helpers import fake_key

        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        mcp_cfg = work / ".mcp.json"
        mcp_cfg.write_text(
            '{"mcpServers":{"worthless":{"command":"npx","args":["-y","worthless-mcp"]}}}'
        )
        fake_home = tmp_path / "home"
        fake_home.mkdir()  # empty: isolate the cwd branch (no ~/.cursor / ~/.claude.json)

        env = work / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir), "HOME": str(fake_home)},
        )
        result = runner.invoke(
            app, ["uninstall", "--yes"], env=self._uninstall_env(home_dir, fake_home)
        )
        assert result.exit_code == 0, result.output
        assert "MCP server" in result.output, "cwd .mcp.json must be detected"
        assert str(mcp_cfg) in result.output, "reminder must name the cwd .mcp.json"

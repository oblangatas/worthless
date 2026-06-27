"""`worthless uninstall` ROBUSTNESS contract (WOR-713 PR2) — RED-first TDD.

Live "fuck around and find out" found two real bugs the existing 23
``tests/test_uninstall.py`` tests miss. These tests encode the operator's
decisions as the contract; the implementation lands AFTER this file, so every
test here is expected to FAIL (RED) until then.

The two bugs, and the decisions that fix them:

BUG-1 — A BROKEN INSTALL CANNOT BE REMOVED.
    With ``.bootstrapped`` present but ``fernet.key`` deleted (or
    ``worthless.db`` corrupted), opening the repo raises ``WRTLS-102`` (no
    Fernet key) / a DB error, and ``uninstall`` refuses — so a half-dead
    install is un-removable. Decision: WITHOUT ``--force`` refuse cleanly and
    tell the user to re-run with ``--force`` (never a WRTLS-199 crash); WITH
    ``--force`` wipe the remains anyway, warning that keys could not be
    restored.

BUG-2 — A DELETED PROJECT (.env gone) ABORTS UNINSTALL FOREVER.
    An enrollment row whose ``.env`` file was deleted is indistinguishable, to
    the current key-shredder guard, from a restore that FAILED (real risk).
    So uninstall aborts (``WRTLS-103, nothing wiped``) and can never finish.
    Decision: a MISSING ``.env`` (nothing to lose) is a skip+warn, NOT a block
    — the wipe still runs. A restore that genuinely FAILS (``.env`` present,
    reconstruction raised) still blocks WITHOUT ``--force`` and is overridden
    WITH ``--force``.

These map to the seam the docstring of ``uninstall._run_uninstall`` already
names: "if any .env can't be restored, nothing is wiped". The fix has to make
that guard distinguish "file missing" from "restore failed", and add a
``--force`` escape hatch for the broken-repo and failed-restore paths.

Run:  WORTHLESS_KEYRING_BACKEND=null uv run pytest \
        tests/test_uninstall_robustness.py -p no:benchmark -q
"""

from __future__ import annotations

import sqlite3

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers — seed broken / orphaned states on top of the bootstrapped home_dir.
# ---------------------------------------------------------------------------


def _lock_one(home_dir: WorthlessHome, tmp_path, *, prefix: str = "sk-") -> tuple[str, object]:
    """Lock a single fresh ``.env`` and return ``(real_key, env_path)``.

    Mirrors the setup every ``tests/test_uninstall.py`` test uses so the
    robustness tests start from the same known-good locked state.
    """
    from tests.helpers import fake_key

    key = fake_key(prefix)
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert locked.exit_code == 0, locked.output
    return key, env


def _seed_missing_env_enrollment(home_dir: WorthlessHome, missing_path: str) -> None:
    """Insert a shard + enrollment whose ``env_path`` points at a file that
    does NOT exist (a project the user deleted).

    Distinct from the ``env_path IS NULL`` enroll-only case already covered by
    ``test_uninstall_enroll_only_key_warns_but_does_not_block``: here the row
    DOES carry an ``env_path``, but the file behind it is gone. Pre-fix this
    trips the key-shredder guard exactly like a real restore failure.

    Seed pattern lifted from that existing test (direct sqlite INSERT into
    ``shards`` + ``enrollments``).
    """
    con = sqlite3.connect(str(home_dir.db_path))
    con.execute(
        "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
        "VALUES (?, ?, ?, ?, ?)",
        ("ghost-alias", b"x", b"c", b"n", "openai"),
    )
    con.execute(
        "INSERT INTO enrollments (key_alias, var_name, env_path) VALUES (?, ?, ?)",
        ("ghost-alias", "GHOST_KEY", missing_path),
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Contract 1 — missing .env (file deleted, row remains) is a SKIP, not a BLOCK.
# Fixes BUG-2. With --yes the wipe MUST still run.
# ---------------------------------------------------------------------------


def test_uninstall_missing_env_file_skips_and_still_wipes(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 1 / BUG-2: an enrollment whose ``.env`` was deleted (file gone,
    row present) must SKIP+WARN and NOT block — ``~/.worthless`` is still wiped
    with ``--yes``.

    Pre-fix the missing file is collected as a ``failed`` restore, the
    key-shredder guard fires, and uninstall aborts ``WRTLS-103`` with nothing
    wiped — a deleted project makes uninstall impossible. There is nothing to
    lose here (no real key sits in a file that's gone), so the only correct
    action is to remove the dead row on wipe.
    """
    missing = tmp_path / "deleted-project" / ".env"  # never created
    _seed_missing_env_enrollment(home_dir, str(missing))

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    assert result.exit_code == 0, f"a missing .env must NOT block the wipe (BUG-2): {result.output}"
    out = result.output.lower()
    assert "ghost" in out or "missing" in out or "skip" in out, (
        f"uninstall must surface a skip/warn for the missing .env, got: {result.output}"
    )
    assert not home_dir.base_dir.exists(), "wipe did not run despite the missing .env being skipped"


def test_uninstall_missing_env_does_not_count_as_failed_restore(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 1 / BUG-2 (sharper): the missing-``.env`` row must NOT appear on
    the FAILED-restore path. The abort message ("could not be restored",
    "Aborting uninstall") must NOT be printed for a file that never existed.

    This pins the exact mis-classification: the guard must tell "file missing
    (nothing to lose)" apart from "restore failed (real risk)".
    """
    missing = tmp_path / "deleted-project" / ".env"
    _seed_missing_env_enrollment(home_dir, str(missing))

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    out = result.output.lower()
    assert "aborting uninstall" not in out, (
        f"missing .env wrongly triggered the failed-restore abort: {result.output}"
    )
    assert "could not be restored" not in out, (
        f"missing .env wrongly reported as a failed restore: {result.output}"
    )


def test_uninstall_missing_env_mixed_with_healthy_env_restores_then_wipes(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 1 / BUG-2 (mixed): one healthy locked ``.env`` PLUS one
    deleted-project row. The healthy file must be restored to its real key and
    the dead row skipped — the whole uninstall still completes and wipes.

    The realistic shape: a user locked two projects, deleted one off disk, then
    runs uninstall. Losing the ability to restore the surviving project just
    because a sibling row is orphaned would be the worst outcome.
    """
    key, env = _lock_one(home_dir, tmp_path)
    missing = tmp_path / "deleted-project" / ".env"
    _seed_missing_env_enrollment(home_dir, str(missing))

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    assert result.exit_code == 0, result.output
    assert key in env.read_text(), "the surviving project's real key was not restored"
    assert not home_dir.base_dir.exists(), "wipe did not run"


# ---------------------------------------------------------------------------
# Contract 2 — BROKEN install (can't open the repo) + NO --force → REFUSE.
# Fixes BUG-1. Refusal must be CLEAN (points at --force, never WRTLS-199),
# and the home must SURVIVE.
# ---------------------------------------------------------------------------


def test_uninstall_missing_fernet_key_without_force_refuses_cleanly(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 2 / BUG-1: ``.bootstrapped`` present but ``fernet.key`` deleted
    → ``uninstall`` (no ``--force``) must REFUSE cleanly: exit != 0, home
    survives, message points at ``--force``, and crucially NO WRTLS-199
    internal-error crash.

    Pre-fix opening the repo reads ``home.fernet_key``, which raises
    ``WRTLS-102`` (KEY_NOT_FOUND) under the null keyring — the user is told the
    install is broken but given no way to remove it. ``--yes`` is supplied so
    the refusal is about the broken repo, not the confirm gate.
    """
    _lock_one(home_dir, tmp_path)
    (home_dir.base_dir / "fernet.key").unlink()  # break the install

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    assert result.exit_code != 0, "a broken install must be refused without --force"
    out = result.output.lower()
    assert "--force" in out, "the refusal must tell the user to re-run with --force"
    assert "internal error" not in out, "must NOT crash with WRTLS-199 on a broken install"
    assert "wrtls-199" not in out, "must NOT surface the generic WRTLS-199 envelope"
    assert home_dir.base_dir.exists(), "refusal must NOT wipe a broken install's home"


def test_uninstall_corrupt_db_without_force_refuses_cleanly(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 2 / BUG-1 (DB variant): a corrupted ``worthless.db`` → refuse
    cleanly without ``--force``. Exit != 0, home survives, message points at
    ``--force``, no WRTLS-199 crash.

    Same operator decision as the missing-key case, exercised through the other
    way a repo open can fail: the SQLite file is no longer a valid database.
    """
    _lock_one(home_dir, tmp_path)
    home_dir.db_path.write_bytes(b"this is not a sqlite database\x00\xff garbage")

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    assert result.exit_code != 0, "a corrupt DB must be refused without --force"
    out = result.output.lower()
    assert "--force" in out, "the refusal must tell the user to re-run with --force"
    assert "internal error" not in out, "must NOT crash with WRTLS-199 on a corrupt DB"
    assert home_dir.base_dir.exists(), "refusal must NOT wipe on a corrupt DB"


# ---------------------------------------------------------------------------
# Contract 3 — BROKEN install + --force → WIPE the remains.
# Fixes BUG-1 escape hatch. Home gone, exit 0, output warns keys not restored.
# ---------------------------------------------------------------------------


def test_uninstall_missing_fernet_key_with_force_wipes_and_warns(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CONTRACT 3 / BUG-1: broken install (``fernet.key`` gone) + ``--force``
    → wipe the remains. ``~/.worthless`` is removed, exit 0, and the output
    WARNS it could not restore keys (the user accepted that by passing
    ``--force``).
    """
    _lock_one(home_dir, tmp_path)
    (home_dir.base_dir / "fernet.key").unlink()

    result = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, f"--force must wipe a broken install: {result.output}"
    assert not home_dir.base_dir.exists(), "--force did not remove ~/.worthless"
    out = result.output.lower()
    assert "could not" in out or "not restore" in out or "unable" in out, (
        f"--force wipe must warn that keys could not be restored, got: {result.output}"
    )


def test_uninstall_corrupt_db_with_force_wipes(home_dir: WorthlessHome, tmp_path) -> None:
    """CONTRACT 3 / BUG-1 (DB variant): corrupt ``worthless.db`` + ``--force``
    → wipe succeeds, home gone, exit 0.
    """
    _lock_one(home_dir, tmp_path)
    home_dir.db_path.write_bytes(b"corrupt-not-sqlite\x00")

    result = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, f"--force must wipe past a corrupt DB: {result.output}"
    assert not home_dir.base_dir.exists(), "--force did not remove ~/.worthless on a corrupt DB"


# ---------------------------------------------------------------------------
# Contract 4 — .env present but reconstruction FAILS + NO --force → BLOCK.
# This is the EXISTING key-shredder guard and MUST be preserved (regression
# fence so the BUG-2 fix doesn't accidentally weaken the real-risk path).
# ---------------------------------------------------------------------------


def test_uninstall_real_restore_failure_without_force_still_blocks(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """CONTRACT 4: a GENUINE restore failure (``.env`` present, ``_unlock_batch``
    raises) must STILL block without ``--force`` — exit != 0, home survives,
    shard-B retained for a retry.

    This is the case where there IS something to lose (a real key would be
    stranded), so the key-shredder guard is correct to abort. The BUG-2 fix
    (skip a MISSING file) must not bleed into this path.
    """
    import worthless.cli.commands.uninstall as uninstall_mod

    _lock_one(home_dir, tmp_path)

    async def boom(*_a, **_k):
        raise RuntimeError("simulated reconstruction failure")

    monkeypatch.setattr(uninstall_mod, "_unlock_batch", boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )

    assert result.exit_code != 0, "a real restore failure must still block without --force"
    assert home_dir.base_dir.exists(), "shredder guard FAILED: home wiped despite a real failure"
    con = sqlite3.connect(str(home_dir.db_path))
    try:
        n_shards = con.execute("SELECT COUNT(*) FROM shards").fetchone()[0]
    finally:
        con.close()
    assert n_shards >= 1, "shard-B deleted despite the abort — real key now unrecoverable"


# ---------------------------------------------------------------------------
# Contract 5 — same as 4 but WITH --force → wipe anyway + warn, exit 0.
# ---------------------------------------------------------------------------


def test_uninstall_real_restore_failure_with_force_wipes_and_warns(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """CONTRACT 5: ``.env`` present but reconstruction fails + ``--force`` →
    wipe anyway. Exit 0, ``~/.worthless`` gone, output warns the key could not
    be restored.

    ``--force`` is the operator explicitly accepting the loss of the
    unrestorable key in exchange for getting Worthless off the machine.
    """
    import worthless.cli.commands.uninstall as uninstall_mod

    _lock_one(home_dir, tmp_path)

    async def boom(*_a, **_k):
        raise RuntimeError("simulated reconstruction failure")

    monkeypatch.setattr(uninstall_mod, "_unlock_batch", boom)

    result = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, f"--force must wipe past a failed restore: {result.output}"
    assert not home_dir.base_dir.exists(), (
        "--force did not remove ~/.worthless after a failed restore"
    )
    out = result.output.lower()
    assert "could not" in out or "not restore" in out or "unable" in out, (
        f"--force wipe must warn the key could not be restored, got: {result.output}"
    )


def test_uninstall_force_still_zeros_keys_on_failed_restore(
    home_dir: WorthlessHome, tmp_path, monkeypatch
) -> None:
    """CONTRACT 5 (SR-02 fence): even when ``--force`` wipes past a failed
    restore, any reconstructed plaintext key built before the failure must be
    zeroed — ``--force`` must not regress the SR-02 zeroing the abort path got
    (bead worthless-gcmp).

    Breaks ``os.chmod`` only during uninstall so a restore is built then fails
    AFTER reconstruction (mirrors ``test_uninstall_zeros_keys_when_a_restore_fails``),
    then asserts ``_zero_restore_keys`` still ran under ``--force``.
    """
    import worthless.cli.commands.uninstall as uninstall_mod

    _lock_one(home_dir, tmp_path)

    spied: list[list] = []
    real = uninstall_mod._zero_restore_keys

    def _spy(restores):  # noqa: ANN001, ANN202
        spied.append(list(restores))
        real(restores)

    monkeypatch.setattr(uninstall_mod, "_zero_restore_keys", _spy)

    def _boom(*_a, **_k):
        raise OSError("simulated chmod failure")

    monkeypatch.setattr(uninstall_mod.os, "chmod", _boom)

    result = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, f"--force must complete the wipe: {result.output}"
    assert spied, "--force path must still zero built restore keys (SR-02)"


# ---------------------------------------------------------------------------
# Cross-cutting — --force on a HEALTHY install behaves like a normal uninstall.
# Guards against --force becoming a "skip restore entirely" footgun.
# ---------------------------------------------------------------------------


def test_uninstall_force_on_healthy_install_still_restores_keys(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """CROSS-CUTTING: ``--force`` on a HEALTHY install must STILL restore real
    keys before wiping — ``--force`` is an escape hatch for broken states, not
    a "skip the restore" switch. A user who reflexively adds ``--force`` must
    not silently lose their keys.
    """
    key, env = _lock_one(home_dir, tmp_path)

    result = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    assert key in env.read_text(), "--force on a healthy install must still restore the real key"
    assert not home_dir.base_dir.exists(), "wipe did not run"

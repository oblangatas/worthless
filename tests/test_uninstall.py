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

    # Force a restore failure AFTER the OcRestores are built (so `unlocked` holds
    # the keys to zero) but before the wipe. Fail _decide_mode, which runs right
    # after _build_oc_restores — deterministic across platforms and Python
    # versions. (Earlier this booped os.chmod, but chmod is only called when a
    # mode clamp is needed, which depends on the captured original_mode — that
    # platform-variance was the py3.13-only CI failure.)
    def _boom(*_a, **_k):
        raise OSError("simulated restore failure")

    monkeypatch.setattr(uninstall_mod, "_decide_mode", _boom)

    result = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert result.exit_code != 0, "a failed restore must abort the wipe"
    assert home_dir.base_dir.exists(), "shredder guard: home not wiped"
    assert spied, "uninstall must zero built restore keys on the failure path"

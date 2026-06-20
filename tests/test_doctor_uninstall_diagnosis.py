"""`worthless doctor` must DIAGNOSE the un-removable broken states (WOR-713 PR2).

RED-first. ``doctor`` is the operator's escape hatch: when ``uninstall`` refuses
a broken install (BUG-1) or has to skip an orphaned enrollment (BUG-2), the user
needs ``doctor`` to (a) name the problem and (b) point at the fix —
``worthless uninstall --force``.

Two diagnoses are required:

7a. ``fernet.key`` MISSING while enrollments exist (the BUG-1 broken install).
    Today ``doctor --json`` reads ``read_fernet_key(home.base_dir)`` at the top
    of ``_doctor_run_json`` BEFORE any check runs, so on a key-missing home the
    command itself crashes (WRTLS-102) — doctor can't even diagnose the state it
    exists to diagnose. The ``fernet_drift`` check only fires when BOTH a keyring
    entry AND a file are present and differ, so a flat-out MISSING key with live
    enrollments is currently un-surfaced. The fix must report it and recommend
    ``worthless uninstall --force``.

7b. ORPHANED enrollments — ``env_path`` set but the file is gone (the BUG-2
    deleted-project state). The ``orphan_db`` check already FINDS these; this
    test additionally pins that the recommendation surfaced for them includes
    ``worthless uninstall --force`` as a way to get fully unstuck (not only the
    surgical ``doctor --fix`` purge).

The implementation (a new check, or extending the existing ones) is the
operator's call — these tests assert the OBSERVABLE JSON contract, not a
specific check_id, so either approach can turn them green.

Run:  WORTHLESS_KEYRING_BACKEND=null uv run pytest \
        tests/test_doctor_uninstall_diagnosis.py -p no:benchmark -q
"""

from __future__ import annotations

import json
import sqlite3

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

# mix_stderr=False so result.stdout is PURE JSON: the one-time AS-IS warranty
# banner is written to stderr (notice.py), and a real agent reads --json off
# stdout only. Mixing the streams would fold the banner into the JSON parse.
runner = CliRunner(mix_stderr=False)


def _lock_one(home_dir: WorthlessHome, tmp_path) -> None:
    """Lock a fresh ``.env`` so the DB carries a live enrollment + shard."""
    from tests.helpers import fake_key

    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    assert locked.exit_code == 0, locked.output


def _seed_missing_env_enrollment(home_dir: WorthlessHome, missing_path: str) -> None:
    """Insert an enrollment whose ``env_path`` points at a deleted file."""
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


def _run_doctor_json(home_dir: WorthlessHome):
    """Invoke ``worthless doctor --json`` and parse the single JSON document."""
    result = runner.invoke(
        app, ["doctor", "--json"], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
    )
    return result


def _all_text(doc: dict) -> str:
    """Flatten the whole JSON envelope to a lowercase string for substring
    assertions — lets the implementation surface the recommendation in a
    ``summary``, a ``findings[].recommendation``, or any other field without
    over-constraining the exact key.
    """
    return json.dumps(doc).lower()


# ---------------------------------------------------------------------------
# 7a — fernet.key missing while enrollments exist.
# ---------------------------------------------------------------------------


def test_doctor_json_does_not_crash_when_fernet_key_missing(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """7a (BUG-1): ``doctor --json`` must NOT crash with WRTLS-102/199 when
    ``fernet.key`` is gone but enrollments remain — it must still emit a valid
    JSON document a machine can parse.

    Pre-fix ``_doctor_run_json`` calls ``read_fernet_key`` before any check, so
    a key-missing home raises ``KEY_NOT_FOUND`` and no JSON is produced — the
    diagnostic tool is unusable in exactly the state it should diagnose.
    """
    _lock_one(home_dir, tmp_path)
    (home_dir.base_dir / "fernet.key").unlink()

    result = _run_doctor_json(home_dir)

    # A parseable JSON document must be on stdout regardless of the key state.
    doc = json.loads(result.stdout)
    assert "checks" in doc, f"doctor --json did not emit a checks envelope: {result.stdout!r}"
    out = result.output.lower()
    assert "internal error" not in out, "doctor --json must not crash with WRTLS-199"


def test_doctor_json_reports_missing_fernet_key_with_enrollments(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """7a (BUG-1): the missing-``fernet.key``-with-enrollments state must be
    SURFACED as a non-ok finding that recommends ``worthless uninstall --force``.

    This is the diagnosis that tells a stuck user how to get unstuck: the key
    is unrecoverable, the locked secrets can't be restored, so the only path
    forward is a forced removal.
    """
    _lock_one(home_dir, tmp_path)
    (home_dir.base_dir / "fernet.key").unlink()

    result = _run_doctor_json(home_dir)
    doc = json.loads(result.stdout)

    assert doc.get("ok") is False, f"missing fernet key with enrollments must be ok=False: {doc}"

    flat = _all_text(doc)
    assert "fernet" in flat, f"no finding mentions the missing Fernet key: {doc}"
    assert "uninstall --force" in flat, (
        f"doctor must recommend `worthless uninstall --force` for an unrecoverable "
        f"key state, got: {doc}"
    )


# ---------------------------------------------------------------------------
# 7b — orphaned enrollment (env_path file deleted).
# ---------------------------------------------------------------------------


def test_doctor_json_reports_orphaned_enrollment(home_dir: WorthlessHome, tmp_path) -> None:
    """7b (BUG-2): an enrollment whose ``env_path`` file was deleted must be
    surfaced by ``doctor --json`` as a non-ok finding naming that alias.

    The ``orphan_db`` check already finds these; this pins the JSON contract so
    a machine can detect the deleted-project state programmatically.
    """
    missing = tmp_path / "deleted-project" / ".env"  # never created
    _seed_missing_env_enrollment(home_dir, str(missing))

    result = _run_doctor_json(home_dir)
    doc = json.loads(result.stdout)

    assert doc.get("ok") is False, f"an orphaned enrollment must be ok=False: {doc}"
    flat = _all_text(doc)
    assert "ghost-alias" in flat, f"the orphaned enrollment alias is not surfaced: {doc}"


def test_doctor_json_recommends_uninstall_force_for_orphans(
    home_dir: WorthlessHome, tmp_path
) -> None:
    """7b (BUG-2): for orphaned enrollments, ``doctor --json`` must offer
    ``worthless uninstall --force`` as a route to a clean machine — not only the
    surgical ``doctor --fix`` purge.

    A user who wants Worthless GONE (not just tidied) needs to be told the
    forced-uninstall path works here too.
    """
    missing = tmp_path / "deleted-project" / ".env"
    _seed_missing_env_enrollment(home_dir, str(missing))

    result = _run_doctor_json(home_dir)
    doc = json.loads(result.stdout)

    flat = _all_text(doc)
    assert "uninstall --force" in flat, (
        f"doctor must recommend `worthless uninstall --force` for orphaned enrollments, got: {doc}"
    )


# ---------------------------------------------------------------------------
# 7c — the HUMAN path: plain `worthless doctor` (no --json) must also survive a
# missing fernet key, not crash WRTLS-102. The human debugging a broken install
# is exactly who needs the diagnosis.
# ---------------------------------------------------------------------------


def test_doctor_text_mode_survives_missing_fernet_key(home_dir: WorthlessHome, tmp_path) -> None:
    """7c (BUG-1, human path): `worthless doctor` (text mode) on a key-missing
    install must NOT crash and must point the user at `uninstall --force`.
    """
    _lock_one(home_dir, tmp_path)
    (home_dir.base_dir / "fernet.key").unlink()

    result = runner.invoke(app, ["doctor"], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    assert result.exit_code == 0, f"text doctor must exit 0 on a broken install: {result.output}"
    # print_warning goes to stderr; the module runner is mix_stderr=False, so
    # combine both streams to assert on what the human actually sees.
    out = (result.stdout + (result.stderr or "")).lower()
    assert "wrtls-102" not in out, f"text doctor crashed on a missing key: {out}"
    assert "internal error" not in out, f"text doctor crashed with WRTLS-199: {result.output}"
    assert "uninstall --force" in out, (
        f"text doctor must point a stuck human at `uninstall --force`, got: {result.output}"
    )


def test_doctor_text_mode_survives_corrupt_db(home_dir: WorthlessHome, tmp_path) -> None:
    """7c (BUG-1, human path, DB variant): text `worthless doctor` on a corrupt
    DB must NOT crash (WRTLS-103) and must point the human at `uninstall --force`.
    """
    _lock_one(home_dir, tmp_path)
    home_dir.db_path.write_bytes(b"corrupt-not-sqlite\x00\xff garbage")

    result = runner.invoke(app, ["doctor"], env={"WORTHLESS_HOME": str(home_dir.base_dir)})

    assert result.exit_code == 0, f"text doctor must exit 0 on a corrupt DB: {result.output}"
    out = (result.stdout + (result.stderr or "")).lower()
    assert "wrtls-103" not in out, f"text doctor crashed on a corrupt DB: {out}"
    assert "internal error" not in out, f"text doctor crashed with WRTLS-199: {out}"
    assert "uninstall --force" in out, (
        f"text doctor must point a stuck human at `uninstall --force`, got: {out}"
    )


# ---------------------------------------------------------------------------
# 7d — the MACHINE path: `worthless doctor --json` must ALSO survive a corrupt
# DB, not just a missing key. An agent scripting --json on a broken install is
# exactly who needs a parseable diagnosis, not a WRTLS-103 crash on stderr.
# ---------------------------------------------------------------------------


def test_doctor_json_survives_corrupt_db(home_dir: WorthlessHome, tmp_path) -> None:
    """7d (BUG-1, machine path, DB variant): `worthless doctor --json` on a
    corrupt DB must NOT crash (WRTLS-103) and must still emit valid JSON with
    ``ok=False`` that recommends ``worthless uninstall --force``.

    Pre-fix ``_doctor_run_json`` called ``get_home()`` OUTSIDE its try/except,
    so a corrupt DB raised WRTLS-103 before any JSON was produced — the very
    state ``--json`` exists to diagnose crashed the machine-facing tool.
    """
    _lock_one(home_dir, tmp_path)
    home_dir.db_path.write_bytes(b"corrupt-not-sqlite\x00\xff garbage")

    result = _run_doctor_json(home_dir)

    # A parseable JSON document must be on stdout despite the corrupt DB.
    doc = json.loads(result.stdout)
    assert "checks" in doc, f"doctor --json did not emit a checks envelope: {result.stdout!r}"
    assert doc.get("ok") is False, f"a corrupt DB must be ok=False: {doc}"
    out = result.output.lower()
    assert "wrtls-103" not in out, f"doctor --json crashed on a corrupt DB: {out}"
    assert "internal error" not in out, "doctor --json must not crash with WRTLS-199"

    flat = _all_text(doc)
    assert "uninstall --force" in flat, (
        f"doctor --json must recommend `worthless uninstall --force` for a corrupt DB, got: {doc}"
    )

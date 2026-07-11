"""Tests for bootstrap — first-run ~/.worthless/ initialization."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from worthless.cli import bootstrap as boot
from worthless.cli.bootstrap import (
    WorthlessHome,
    _init_db,
    _shard_rows_present,
    acquire_lock,
    check_stale_lock,
    ensure_home,
    resolve_home,
)
from worthless.cli.errors import ErrorCode, WorthlessError


@pytest.fixture(autouse=True)
def _force_file_fallback():
    """Force file fallback in all bootstrap tests for hermetic behavior."""
    with patch("worthless.cli.keystore.keyring_available", return_value=False):
        yield


def _insert_shard_row(base: Path) -> None:
    """Insert one real ``shards`` row (creates a minimal table if none exists).

    ``CREATE TABLE IF NOT EXISTS`` is a no-op against the real schema, so this
    works both on a bare directory (no DB yet) and on a fully-bootstrapped home.
    """
    conn = sqlite3.connect(str(base / "worthless.db"))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS shards "
        "(key_alias TEXT PRIMARY KEY, shard_b_enc BLOB, commitment BLOB, nonce BLOB, provider TEXT)"
    )
    conn.execute(
        "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
        "VALUES ('t', X'00', X'00', X'00', 'openai')"
    )
    conn.commit()
    conn.close()


def _empty_db(base: Path) -> None:
    """Create a real, valid, EMPTY DB (the actual schema, zero rows).

    Uses the production ``_init_db`` so ``ensure_home``'s own idempotent
    ``_init_db`` call afterwards is a no-op — a hand-rolled fake-shaped table
    would make that later call raise WRTLS-103 and mask the real assertion.
    """
    _init_db(WorthlessHome(base_dir=base))


class TestEnsureHome:
    def test_creates_directory_structure(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        assert home.base_dir.exists()
        assert home.shard_a_dir.exists()
        assert home.db_path.exists()
        assert home.fernet_key_path.exists()

    def test_directory_permissions(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        mode = home.base_dir.stat().st_mode
        assert stat.S_IMODE(mode) == 0o700

    def test_fernet_key_permissions(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        mode = home.fernet_key_path.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_idempotent(self, tmp_path: Path):
        base = tmp_path / ".worthless"
        home1 = ensure_home(base_dir=base)
        key1 = home1.fernet_key
        home2 = ensure_home(base_dir=base)
        key2 = home2.fernet_key
        # Key should not change on second call
        assert key1 == key2

    def test_fernet_key_is_valid(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        # Should not raise
        f = Fernet(home.fernet_key)
        ct = f.encrypt(b"test")
        assert f.decrypt(ct) == b"test"

    def test_worthless_home_properties(self, tmp_path: Path):
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        assert home.db_path == tmp_path / ".worthless" / "worthless.db"
        assert home.fernet_key_path == tmp_path / ".worthless" / "fernet.key"
        assert home.shard_a_dir == tmp_path / ".worthless" / "shard_a"
        assert home.lock_file == tmp_path / ".worthless" / ".lock-in-progress"

    def test_fernet_key_path_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        custom_path = tmp_path / "secrets" / "fernet.key"
        monkeypatch.setenv("WORTHLESS_FERNET_KEY_PATH", str(custom_path))
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        assert home.fernet_key_path == custom_path

    def test_fernet_key_written_to_custom_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir(mode=0o700)
        custom_path = secrets_dir / "fernet.key"
        monkeypatch.setenv("WORTHLESS_FERNET_KEY_PATH", str(custom_path))

        home = ensure_home(base_dir=tmp_path / ".worthless")
        assert custom_path.exists()
        assert home.fernet_key_path == custom_path
        # Default location should NOT have fernet.key
        assert not (tmp_path / ".worthless" / "fernet.key").exists()

    def test_custom_fernet_path_missing_dir_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv(
            "WORTHLESS_FERNET_KEY_PATH", str(tmp_path / "nonexistent" / "fernet.key")
        )
        with pytest.raises(WorthlessError) as exc_info:
            ensure_home(base_dir=tmp_path / ".worthless")
        assert "WORTHLESS_FERNET_KEY_PATH" in str(exc_info.value)
        assert "does not exist" in str(exc_info.value)


class TestInitDbMigration:
    """Regression tests for _init_db forward-only migrations."""

    def test_upgrade_adds_decoy_hash_column(self, tmp_path: Path):
        """_init_db on an old DB (enrollments without decoy_hash) must add the column."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        home.base_dir.mkdir(mode=0o700, parents=True)

        # Create old-schema DB without decoy_hash
        conn = sqlite3.connect(str(home.db_path))
        conn.executescript("""
            CREATE TABLE shards (
                key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL,
                commitment BLOB NOT NULL, nonce BLOB NOT NULL,
                provider TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE spend_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, key_alias TEXT NOT NULL,
                tokens INTEGER NOT NULL, model TEXT, provider TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE enrollment_config (
                key_alias TEXT PRIMARY KEY, spend_cap REAL,
                rate_limit_rps REAL NOT NULL DEFAULT 100.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_alias TEXT NOT NULL REFERENCES shards(key_alias) ON DELETE CASCADE,
                var_name TEXT NOT NULL, env_path TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(key_alias, var_name, env_path)
            );
        """)
        conn.commit()
        conn.close()

        _init_db(home)

        conn = sqlite3.connect(str(home.db_path))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(enrollments)").fetchall()}
        conn.close()
        assert "decoy_hash" in columns

    def test_fresh_db_has_decoy_hash(self, tmp_path: Path):
        """_init_db on a fresh DB creates enrollments with decoy_hash."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        home.base_dir.mkdir(mode=0o700, parents=True)

        _init_db(home)

        conn = sqlite3.connect(str(home.db_path))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(enrollments)").fetchall()}
        conn.close()
        assert "decoy_hash" in columns

    def test_upgrade_schema_matches_fresh(self, tmp_path: Path):
        """Upgraded DB schema must converge to the same state as a fresh install."""

        def _get_schema(db_path):
            conn = sqlite3.connect(db_path)
            tables = {}
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall():
                cols = {
                    (row[1], row[2])
                    for row in conn.execute(f"PRAGMA table_info({name})").fetchall()
                }
                tables[name] = cols
            indexes = sorted(
                row[1]
                for row in conn.execute(
                    "SELECT * FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                if row[1] is not None
            )
            conn.close()
            return tables, indexes

        # Fresh DB
        fresh_home = WorthlessHome(base_dir=tmp_path / "fresh" / ".worthless")
        fresh_home.base_dir.mkdir(mode=0o700, parents=True)
        _init_db(fresh_home)
        fresh_tables, fresh_indexes = _get_schema(str(fresh_home.db_path))

        # Upgraded DB (old schema without decoy_hash)
        upgrade_home = WorthlessHome(base_dir=tmp_path / "upgrade" / ".worthless")
        upgrade_home.base_dir.mkdir(mode=0o700, parents=True)
        conn = sqlite3.connect(str(upgrade_home.db_path))
        conn.executescript("""
            CREATE TABLE shards (
                key_alias TEXT PRIMARY KEY, shard_b_enc BLOB NOT NULL,
                commitment BLOB NOT NULL, nonce BLOB NOT NULL,
                provider TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE spend_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, key_alias TEXT NOT NULL,
                tokens INTEGER NOT NULL, model TEXT, provider TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE enrollment_config (
                key_alias TEXT PRIMARY KEY, spend_cap REAL,
                rate_limit_rps REAL NOT NULL DEFAULT 100.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_alias TEXT NOT NULL REFERENCES shards(key_alias) ON DELETE CASCADE,
                var_name TEXT NOT NULL, env_path TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(key_alias, var_name, env_path)
            );
        """)
        conn.commit()
        conn.close()
        _init_db(upgrade_home)
        upgrade_tables, upgrade_indexes = _get_schema(str(upgrade_home.db_path))

        # Schemas must match
        assert fresh_tables == upgrade_tables, (
            f"Column mismatch:\nfresh={fresh_tables}\nupgrade={upgrade_tables}"
        )
        assert fresh_indexes == upgrade_indexes, (
            f"Index mismatch:\nfresh={fresh_indexes}\nupgrade={upgrade_indexes}"
        )


class TestLocking:
    def test_acquire_lock(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        with acquire_lock(home):
            assert home.lock_file.exists()
        assert not home.lock_file.exists()

    def test_lock_prevents_double_acquire(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        with acquire_lock(home):
            with pytest.raises(WorthlessError) as exc_info:
                with acquire_lock(home):
                    pass  # pragma: no cover
            assert exc_info.value.code.value == 105  # LOCK_IN_PROGRESS

    def test_stale_lock_cleanup(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        # Create a lock file and backdate it > 5 minutes
        home.lock_file.touch()
        old_time = time.time() - 400
        os.utime(home.lock_file, (old_time, old_time))
        # Should remove stale lock without error
        check_stale_lock(home)
        assert not home.lock_file.exists()

    def test_fresh_lock_raises(self, tmp_path: Path):
        home = ensure_home(base_dir=tmp_path / ".worthless")
        home.lock_file.touch()
        with pytest.raises(WorthlessError):
            check_stale_lock(home)


class TestShardRowsPresent:
    """WOR-716: the cheap row-emptiness probe that gates every detection decision."""

    def test_no_db_file_returns_false(self, tmp_path: Path):
        base = tmp_path / ".worthless"
        base.mkdir()
        assert _shard_rows_present(WorthlessHome(base_dir=base)) is False

    def test_empty_tables_return_false(self, tmp_path: Path):
        base = tmp_path / ".worthless"
        base.mkdir()
        _empty_db(base)
        assert _shard_rows_present(WorthlessHome(base_dir=base)) is False

    def test_real_row_returns_true(self, tmp_path: Path):
        base = tmp_path / ".worthless"
        base.mkdir()
        _insert_shard_row(base)
        assert _shard_rows_present(WorthlessHome(base_dir=base)) is True

    def test_corrupt_db_still_present_fails_closed_true(self, tmp_path: Path):
        """A present-but-unreadable DB is fail-closed True — never let corruption
        masquerade as 'empty' and trigger a silent key regeneration."""
        base = tmp_path / ".worthless"
        base.mkdir()
        (base / "worthless.db").write_bytes(b"this is not a sqlite database at all")
        assert _shard_rows_present(WorthlessHome(base_dir=base)) is True

    def test_db_vanishes_mid_read_returns_false(self, tmp_path: Path, monkeypatch):
        """A DB deleted mid-read (a concurrent uninstall's rmtree) is 'gone',
        not 'corrupt' — return False so a bystander process isn't hard-blocked
        with a false orphaned-data diagnosis during an ordinary uninstall."""
        base = tmp_path / ".worthless"
        base.mkdir()
        db = base / "worthless.db"
        db.write_text("placeholder so the top-level exists() check passes")
        home = WorthlessHome(base_dir=base)

        def _boom(*_a, **_k):
            db.unlink()  # simulate the concurrent rmtree finishing during our read
            raise sqlite3.DatabaseError("database disk image is malformed")

        monkeypatch.setattr(boot.sqlite3, "connect", _boom)
        assert _shard_rows_present(home) is False

    def test_opens_exactly_one_connection(self, tmp_path: Path, monkeypatch):
        """Bounded DB cost (WOR-716 panel, brutus's cost-honesty finding):
        one connection per call, not a hidden fan-out."""
        base = tmp_path / ".worthless"
        base.mkdir()
        _insert_shard_row(base)
        home = WorthlessHome(base_dir=base)
        count = {"n": 0}
        real_connect = boot.sqlite3.connect

        def _counting(*a, **k):
            count["n"] += 1
            return real_connect(*a, **k)

        monkeypatch.setattr(boot.sqlite3, "connect", _counting)
        assert _shard_rows_present(home) is True
        assert count["n"] == 1


class TestHalfUninstalledDetection:
    """WOR-716: ``ensure_home`` detects a half-uninstalled machine (a stale
    ``.bootstrapped`` marker whose DB/key partially survived a failed uninstall)
    instead of crashing later or silently minting a new key over orphaned rows.
    """

    def test_marker_absent_with_real_rows_raises_orphaned(self, tmp_path: Path):
        """The headline guard: real shard rows but no marker means the key that
        encrypted them is gone — mint a fresh one and they orphan forever.
        Refuse (before any mint)."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        _insert_shard_row(base)  # rows, but NO .bootstrapped marker
        with pytest.raises(WorthlessError) as exc:
            ensure_home(base_dir=base)
        assert exc.value.code == ErrorCode.ORPHANED_SHARD_DATA

    def test_marker_absent_no_rows_proceeds_as_fresh(self, tmp_path: Path):
        """True fresh-install regression guard: no marker, no rows → normal mint."""
        home = ensure_home(base_dir=tmp_path / ".worthless")
        assert home.bootstrapped_marker.exists()
        assert home._adoption_note is None
        assert home.fernet_key  # minted, readable

    def test_provably_keyless_marker_is_silently_adopted(self, tmp_path: Path):
        """Marker present, no rows, no env/file key (keyring off in this file =
        provably keyless) → self-heal: unlink+rewrite the marker, mint a key,
        set the disclosure note."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        base.joinpath(".bootstrapped").write_text("")
        _empty_db(base)  # empty rows, and no fernet.key file → provably keyless
        home = ensure_home(base_dir=base)
        assert home._adoption_note is not None
        assert "stale" in home._adoption_note.lower()
        assert home.bootstrapped_marker.exists()  # rewritten after _init_db
        assert home.fernet_key  # freshly minted, readable

    def test_reenroll_after_adopt_is_not_misdiagnosed(self, tmp_path: Path):
        """The bug brutus caught: after a silent adopt, a normal re-enrollment
        (rows now exist) must NOT read as a broken install on the next call."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        base.joinpath(".bootstrapped").write_text("")
        _empty_db(base)
        first = ensure_home(base_dir=base)
        assert first._adoption_note is not None  # adopted
        _insert_shard_row(base)  # user re-enrolls → real rows now exist
        second = ensure_home(base_dir=base)
        assert second._adoption_note is None, "healthy re-enrolled install misdiagnosed"
        assert second.fernet_key  # key still readable

    def test_marker_present_no_rows_key_in_file_no_adopt(self, tmp_path: Path):
        """A cheap on-disk key present → not keyless → no adopt, marker untouched,
        key unchanged."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        base.joinpath(".bootstrapped").write_text("")
        _empty_db(base)
        key = Fernet.generate_key()
        kf = base / "fernet.key"
        kf.write_bytes(key)
        kf.chmod(0o600)
        home = ensure_home(base_dir=base)
        assert home._adoption_note is None
        assert bytes(home.fernet_key) == key  # unchanged, not re-minted

    def test_rows_present_key_gone_defers_to_property_raising_orphaned(self, tmp_path: Path):
        """Marker present + real rows + key gone → ensure_home does NOT raise
        (fast path); the danger surfaces at the natural lazy key access."""
        base = tmp_path / ".worthless"
        ensure_home(base_dir=base)  # real bootstrap (real schema + file key)
        _insert_shard_row(base)  # add a real row
        (base / "fernet.key").unlink()  # key now gone everywhere (keyring off)
        ensure_home(base_dir=base)  # must NOT raise — rows present → fast path
        fresh = WorthlessHome(base_dir=base)  # cold cache
        with pytest.raises(WorthlessError) as exc:
            _ = fresh.fernet_key
        assert exc.value.code == ErrorCode.ORPHANED_SHARD_DATA

    def test_concurrent_ensure_home_on_adopt_state_is_safe(self, tmp_path: Path):
        """Two real threads race ``ensure_home`` on a provably-keyless adopt
        state (``threading.Barrier(2)``, the pattern proven by
        ``test_concurrent_first_read_triggers_one_keychain_call``). Any failure
        must be a clean LOCK_IN_PROGRESS; the final state is a single readable
        key + marker present + zero orphaned rows."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        base.joinpath(".bootstrapped").write_text("")
        _empty_db(base)

        barrier = threading.Barrier(2)
        results: list[WorthlessHome] = []
        errors: list[WorthlessError] = []

        def worker(_: object) -> None:
            barrier.wait()
            try:
                results.append(ensure_home(base_dir=base))
            except WorthlessError as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=2) as ex:
            list(ex.map(worker, range(2)))

        for e in errors:
            assert e.code == ErrorCode.LOCK_IN_PROGRESS, f"unexpected error: {e}"
        assert len(results) >= 1, "at least one ensure_home must succeed"
        final = ensure_home(base_dir=base)
        assert final.bootstrapped_marker.exists()
        assert final.fernet_key  # exactly one consistent, readable key
        assert _shard_rows_present(final) is False  # nothing orphaned

    def test_ensure_home_respects_a_held_lock_on_adopt_path(self, tmp_path: Path):
        """Deterministic lock proof: while the lock is held, the adopt path's
        ``acquire_lock`` refuses cleanly rather than making a bad decision."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        base.joinpath(".bootstrapped").write_text("")
        _empty_db(base)  # provably-keyless → adopt path tries to acquire the lock
        with acquire_lock(WorthlessHome(base_dir=base)):
            with pytest.raises(WorthlessError) as exc:
                ensure_home(base_dir=base)
            assert exc.value.code == ErrorCode.LOCK_IN_PROGRESS

    def test_orphaned_message_never_offers_recovery(self):
        """SR-04/05: never promise key recovery — only rotation + --force."""
        low = boot._MSG_ORPHANED_SHARD_DATA.lower()
        assert "recover" not in low
        assert "rotate" in low
        assert "uninstall --force" in low

    def test_resolve_home_propagates_orphaned(self, tmp_path: Path, monkeypatch):
        """resolve_home must NOT swallow ORPHANED into None — a half-uninstalled
        machine must never read as 'nothing installed here'."""
        base = tmp_path / ".worthless"
        base.mkdir(mode=0o700)
        _insert_shard_row(base)  # rows, no marker → ensure_home raises ORPHANED
        monkeypatch.setenv("WORTHLESS_HOME", str(base))
        with pytest.raises(WorthlessError) as exc:
            resolve_home()
        assert exc.value.code == ErrorCode.ORPHANED_SHARD_DATA

    def test_resolve_home_still_returns_none_when_absent(self, tmp_path: Path, monkeypatch):
        """Unchanged behavior: a genuinely-absent install is still None."""
        monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "not-installed"))
        assert resolve_home() is None

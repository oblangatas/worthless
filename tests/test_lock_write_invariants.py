"""WOR-646 guard tests for the shards/enrollment write paths.

A 3-lens pre-mortem of the Part-2 atomic write surfaced two catastrophic paths
with NO existing coverage, plus a drift risk from the duplicated SQL:

* **R1 — shard-A leak.** Every write path must store ``shard_a_enc = NULL``;
  shard-A lives only client-side (.env). A path that persisted it server-side
  would defeat the whole key-split. Nothing asserted this.
* **R2 — CASCADE wipe.** Re-locking a key from a *second* ``.env`` path must NOT
  delete the first path's enrollment. The protection is the ``ON CONFLICT DO
  UPDATE`` (never ``INSERT OR REPLACE``) choice — guarded only by comments.
* **R3 — SQL drift.** The shards-UPSERT and enrollment/config INSERTs are copied
  across methods; a future edit could change one copy and not the others.

These are behavioral/structural guards, test-only, independent of the SQL text
where possible.
"""

from __future__ import annotations

import inspect
import re

import aiosqlite
import pytest

from worthless.storage.repository import ShardRepository

from tests.conftest import stored_shard_from_split

_BASE_URL = "https://api.openai.com/v1"
# Routing metadata is stored verbatim; these tests inspect rows / enrollment
# survival, not reconstruction, so any non-empty charset is valid here.
_PREFIX = "sk-"
_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


# ---------------------------------------------------------------------------
# R1 — shard_a_enc must be NULL on every write path (no server-side shard-A)
# ---------------------------------------------------------------------------


class TestShardAEncNeverPersisted:
    @pytest.mark.asyncio
    async def test_shard_a_enc_null_and_routing_cols_set_on_all_write_paths(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        sr = sample_split_result
        shard = stored_shard_from_split(sr)

        await repo.store_enrolled(
            "p-store",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/a/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
        )
        await repo.upsert_locked_shard(
            "p-upsert",
            shard,
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
        )
        await repo.upsert_locked_shard_and_enroll(
            "p-atomic",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/b/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
        )

        async with aiosqlite.connect(tmp_db_path) as db:
            db.row_factory = aiosqlite.Row
            rows = await (
                await db.execute("SELECT key_alias, shard_a_enc, charset, base_url FROM shards")
            ).fetchall()

        seen = {r["key_alias"] for r in rows}
        assert {"p-store", "p-upsert", "p-atomic"} <= seen
        for r in rows:
            assert r["shard_a_enc"] is None, (
                f"{r['key_alias']}: shard_a_enc persisted server-side — key-split defeated"
            )
            # Routing columns must be populated or the proxy can't reconstruct.
            assert r["charset"] is not None, f"{r['key_alias']}: NULL charset"
            assert r["base_url"] is not None, f"{r['key_alias']}: NULL base_url"


# ---------------------------------------------------------------------------
# R2 — re-lock from a second env_path must NOT CASCADE-wipe the first enrollment
# ---------------------------------------------------------------------------


class TestSecondEnvPathDoesNotWipeFirst:
    @pytest.mark.asyncio
    async def test_relock_from_second_env_path_keeps_first_enrollment(
        self,
        repo: ShardRepository,
        sample_split_result,
    ) -> None:
        sr = sample_split_result
        shard = stored_shard_from_split(sr)

        # Enroll the alias from env_path A (creates the shared shards row).
        await repo.store_enrolled(
            "multi",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/a/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
        )
        # Re-lock the SAME alias from env_path B via the atomic path (write_config
        # =False mirrors the re-lock branch). The shards row is patched in place;
        # the env_path A enrollment must survive (no INSERT OR REPLACE CASCADE).
        await repo.upsert_locked_shard_and_enroll(
            "multi",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/b/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
            write_config=False,
        )

        enrollments = await repo.list_enrollments("multi")
        paths = {e.env_path for e in enrollments}
        assert paths == {"/a/.env", "/b/.env"}, (
            f"re-lock from a second env_path wiped the first enrollment: {paths!r}"
        )


# ---------------------------------------------------------------------------
# R3 — drift guard: the duplicated statements must stay identical
# ---------------------------------------------------------------------------


def _norm_stmt(fn, pattern: str) -> str:
    """Return the whitespace-normalised SQL literal matched by *pattern* in *fn*.

    Compares the SQL across methods immune to source line-wrapping. A drifted
    copy (e.g. a column added to one method but not the other) changes the
    normalised string and trips the assertion.
    """
    src = inspect.getsource(fn)
    matches = re.findall(pattern, src, re.DOTALL)
    assert matches, f"pattern not found in {fn.__qualname__}"
    return re.sub(r"\s+", " ", matches[0]).strip()


class TestSqlDriftGuard:
    def test_shards_upsert_identical_across_methods(self) -> None:
        pat = r"INSERT INTO shards.*?oc_rollback_mac\s*=\s*excluded\.oc_rollback_mac"
        a = _norm_stmt(ShardRepository.upsert_locked_shard, pat)
        b = _norm_stmt(ShardRepository.upsert_locked_shard_and_enroll, pat)
        assert a == b, "shards UPSERT SQL drifted between the two methods"

    def test_enrollment_insert_identical_across_methods(self) -> None:
        pat = r"INSERT OR IGNORE INTO enrollments.*?VALUES \(\?, \?, \?, \?\)"
        store = _norm_stmt(ShardRepository.store_enrolled, pat)
        add = _norm_stmt(ShardRepository.add_enrollment, pat)
        atomic = _norm_stmt(ShardRepository.upsert_locked_shard_and_enroll, pat)
        assert store == add == atomic, "enrollments INSERT drifted across methods"

    def test_config_insert_identical_across_methods(self) -> None:
        pat = r"INSERT OR IGNORE INTO enrollment_config.*?VALUES \(\?, \?, \?\)"
        store = _norm_stmt(ShardRepository.store_enrolled, pat)
        atomic = _norm_stmt(ShardRepository.upsert_locked_shard_and_enroll, pat)
        assert store == atomic, "enrollment_config INSERT drifted across methods"


# ---------------------------------------------------------------------------
# Non-vacuous rollback proof: a failure AFTER the shards INSERT but BEFORE
# COMMIT must leave NO shard row. (Pins the atomicity against the
# BEGIN-IMMEDIATE-under-default-isolation concern — confirms close-without-commit
# discards the in-flight INSERT rather than committing an orphan.)
# ---------------------------------------------------------------------------


class TestAtomicWriteRollsBackMidTransaction:
    @pytest.mark.asyncio
    async def test_failure_after_shard_insert_leaves_no_row(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import worthless.storage.repository as repo_mod

        shard = stored_shard_from_split(sample_split_result)

        # _perm_bits is evaluated as an argument to the enrollments INSERT —
        # i.e. AFTER the shards INSERT has already executed inside the open
        # transaction, but before COMMIT. Raising here exercises the exact
        # mid-transaction failure window the orphan bug lived in.
        def _boom(_mode: object) -> int:
            raise RuntimeError("fail mid-transaction, after the shards INSERT")

        monkeypatch.setattr(repo_mod, "_perm_bits", _boom)

        with pytest.raises(RuntimeError):
            await repo.upsert_locked_shard_and_enroll(
                "rollback-probe",
                shard,
                var_name="OPENAI_API_KEY",
                env_path="/a/.env",
                prefix=_PREFIX,
                charset=_CHARSET,
                base_url=_BASE_URL,
            )

        async with aiosqlite.connect(tmp_db_path) as db:
            n = (
                await (
                    await db.execute(
                        "SELECT count(*) FROM shards WHERE key_alias = 'rollback-probe'"
                    )
                ).fetchone()
            )[0]
        assert n == 0, (
            "shards INSERT was NOT rolled back when the transaction failed before "
            "COMMIT — the atomicity guarantee is broken"
        )


# ---------------------------------------------------------------------------
# Routing-metadata validation + spend_cap branch (the atomic method rejects
# NULL routing columns up front, and honours an explicit spend cap).
# ---------------------------------------------------------------------------


class TestAtomicWriteValidatesAndConfigures:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("override", "missing"),
        [
            ({"prefix": None}, "prefix"),
            ({"charset": None}, "charset"),
            ({"base_url": None}, "base_url"),
        ],
        ids=["prefix", "charset", "base_url"],
    )
    async def test_none_routing_metadata_is_rejected(
        self,
        repo: ShardRepository,
        sample_split_result,
        override: dict,
        missing: str,
    ) -> None:
        shard = stored_shard_from_split(sample_split_result)
        kwargs = {"prefix": _PREFIX, "charset": _CHARSET, "base_url": _BASE_URL, **override}
        with pytest.raises(ValueError, match=missing):
            await repo.upsert_locked_shard_and_enroll(
                "validate", shard, var_name="OPENAI_API_KEY", env_path="/a/.env", **kwargs
            )

    @pytest.mark.asyncio
    async def test_explicit_spend_cap_is_written(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        shard = stored_shard_from_split(sample_split_result)
        await repo.upsert_locked_shard_and_enroll(
            "capped",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/a/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
            spend_cap=4242,
        )
        async with aiosqlite.connect(tmp_db_path) as db:
            row = await (
                await db.execute(
                    "SELECT spend_cap FROM enrollment_config WHERE key_alias = 'capped'"
                )
            ).fetchone()
        assert row is not None and row[0] == 4242


# ---------------------------------------------------------------------------
# brutus finding (worthless-exx5): the superseded-enrollment cleanup runs
# OUTSIDE the atomic Pass-1 transaction and is NOT covered by the compensating
# unwind. An interrupt during a key-rotation re-lock can orphan the OLD alias's
# shard. xfail until exx5 folds the cleanup into the transaction (or registers
# the superseded aliases for unwind).
# ---------------------------------------------------------------------------


class TestSupersededCleanupInterruptOrphan:
    @pytest.mark.xfail(
        reason="WOR-646 worthless-exx5: _delete_superseded_location_enrollments "
        "commits outside the atomic transaction; not yet covered by the unwind.",
        strict=False,
    )
    @pytest.mark.asyncio
    async def test_interrupt_during_superseded_cleanup_orphans_old_shard(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import worthless.cli.commands.lock as lock_mod

        shard = stored_shard_from_split(sample_split_result)
        # An OLD alias enrolled at (var, path) — superseded once a NEW alias locks
        # the same var/path during a rotation re-lock.
        await repo.store_enrolled(
            "old-alias",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/a/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
        )

        # Interrupt mid-cleanup: the superseded SHARD delete fails AFTER its
        # enrollment row was already deleted (separate commits, no transaction).
        async def _boom(_alias: str) -> None:
            raise RuntimeError("interrupt during superseded shard delete")

        monkeypatch.setattr(repo, "delete_enrolled", _boom)

        with pytest.raises(RuntimeError):
            await lock_mod._delete_superseded_location_enrollments(
                repo, alias="new-alias", var_name="OPENAI_API_KEY", env_path="/a/.env"
            )

        async with aiosqlite.connect(tmp_db_path) as db:
            shards = {
                r[0] for r in await (await db.execute("SELECT key_alias FROM shards")).fetchall()
            }
        enrolled = {e.key_alias for e in await repo.list_enrollments()}
        orphans = shards - enrolled
        assert not orphans, (
            f"superseded-cleanup interrupt orphaned the old alias's shard: {orphans!r}"
        )

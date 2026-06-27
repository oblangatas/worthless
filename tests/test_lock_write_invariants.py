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
        # The shards UPSERT is still inline in TWO methods (y8ir deduped only the
        # enrollment/config INSERTs — never the shards statements, which differ:
        # UPSERT here vs INSERT OR IGNORE in store_enrolled). Text-identity guard
        # stays for the pair that remains duplicated.
        pat = r"INSERT INTO shards.*?oc_rollback_mac\s*=\s*excluded\.oc_rollback_mac"
        a = _norm_stmt(ShardRepository.upsert_locked_shard, pat)
        b = _norm_stmt(ShardRepository.upsert_locked_shard_and_enroll, pat)
        assert a == b, "shards UPSERT SQL drifted between the two methods"


# ---------------------------------------------------------------------------
# R3 (y8ir): the enrollment/config INSERTs are now single-sourced in
# _exec_enrollment_insert / _exec_config_insert. The old source-identity
# (inspect.getsource) drift tests are moot — there is one copy. Replace them
# with a BEHAVIORAL guard: drive every write path with identical inputs and
# assert byte-identical rows. This survives a future re-inline or signature
# change that a "they call one helper" structural check would miss.
# ---------------------------------------------------------------------------


class TestWritePathsProduceIdenticalRows:
    @pytest.mark.asyncio
    async def test_enrollment_row_identical_across_write_paths(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        shard = stored_shard_from_split(sample_split_result)
        common = {
            "var_name": "OPENAI_API_KEY",
            "env_path": "/x/.env",
            "original_mode": 0o640,
        }
        # Same enrollment inputs through all three write paths (distinct aliases
        # so they coexist in one DB). store_enrolled + atomic also write a shard.
        await repo.store_enrolled(
            "via-store", shard, prefix=_PREFIX, charset=_CHARSET, base_url=_BASE_URL, **common
        )
        await repo.upsert_locked_shard_and_enroll(
            "via-atomic",
            shard,
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
            write_config=False,
            **common,
        )
        # add_enrollment writes only the enrollment row, so its alias needs an
        # existing shard first (the enrollments→shards FK) — exactly how the
        # re-lock-from-another-path caller uses it.
        await repo.upsert_locked_shard(
            "via-add", shard, prefix=_PREFIX, charset=_CHARSET, base_url=_BASE_URL
        )
        await repo.add_enrollment("via-add", **common)

        async with aiosqlite.connect(tmp_db_path) as db:
            db.row_factory = aiosqlite.Row
            rows = {
                r["key_alias"]: (r["var_name"], r["env_path"], r["original_mode"])
                for r in await (
                    await db.execute(
                        "SELECT key_alias, var_name, env_path, original_mode FROM enrollments"
                    )
                ).fetchall()
            }
        assert rows["via-store"] == rows["via-atomic"] == rows["via-add"], (
            f"enrollment row diverged across write paths: {rows!r}"
        )
        assert rows["via-store"] == ("OPENAI_API_KEY", "/x/.env", 0o640)

    @pytest.mark.asyncio
    async def test_config_row_identical_across_write_paths(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        shard = stored_shard_from_split(sample_split_result)
        # The two config-writing paths (store_enrolled, atomic write_config=True)
        # with identical spend_cap/token_budget inputs must produce identical rows.
        await repo.store_enrolled(
            "cfg-store",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/x/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
            spend_cap=1234,
            token_budget_daily=77,
        )
        await repo.upsert_locked_shard_and_enroll(
            "cfg-atomic",
            shard,
            var_name="OPENAI_API_KEY",
            env_path="/y/.env",
            prefix=_PREFIX,
            charset=_CHARSET,
            base_url=_BASE_URL,
            write_config=True,
            spend_cap=1234,
            token_budget_daily=77,
        )

        async with aiosqlite.connect(tmp_db_path) as db:
            db.row_factory = aiosqlite.Row
            rows = {
                r["key_alias"]: (r["spend_cap"], r["token_budget_daily"])
                for r in await (
                    await db.execute(
                        "SELECT key_alias, spend_cap, token_budget_daily FROM enrollment_config"
                    )
                ).fetchall()
            }
        assert rows["cfg-store"] == rows["cfg-atomic"] == (1234, 77), (
            f"enrollment_config row diverged across write paths: {rows!r}"
        )


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
# exx5 (brutus finding on PR #363): the superseded-enrollment cleanup used to
# run as TWO separate commits (delete_enrollment, then a conditional
# delete_enrolled) OUTSIDE the atomic Pass-1 transaction, and was not covered by
# the compensating unwind. An interrupt during a key-rotation re-lock could
# orphan the OLD alias's shard. The fix folds the cleanup into its OWN
# BEGIN IMMEDIATE … COMMIT (delete_superseded_enrollment_atomic). These tests
# pin: rollback-on-interrupt (no orphan), happy-path removal, and the
# conditional that keeps a shard still used by another env_path.
# ---------------------------------------------------------------------------


async def _enroll_old_alias(repo: ShardRepository, shard, *, env_path: str) -> None:
    """Enroll ``old-alias`` at *env_path* — the alias a rotation re-lock supersedes."""
    await repo.store_enrolled(
        "old-alias",
        shard,
        var_name="OPENAI_API_KEY",
        env_path=env_path,
        prefix=_PREFIX,
        charset=_CHARSET,
        base_url=_BASE_URL,
    )


async def _orphans(tmp_db_path: str, repo: ShardRepository) -> set[str]:
    """Shards-table rows with no enrollment — the orphan exx5 closes."""
    async with aiosqlite.connect(tmp_db_path) as db:
        shards = {r[0] for r in await (await db.execute("SELECT key_alias FROM shards")).fetchall()}
    enrolled = {e.key_alias for e in await repo.list_enrollments()}
    return shards - enrolled


class TestSupersededCleanupInterruptOrphan:
    @pytest.mark.asyncio
    async def test_interrupt_at_commit_rolls_back_no_orphan(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Interrupt the atomic cleanup at COMMIT → both rows survive, no orphan.

        Simulates a SIGINT landing mid-cleanup by making the transaction's
        ``commit`` raise: the connection closes with the DELETEs uncommitted, so
        SQLite rolls them back. The old alias is left FULLY intact (a harmless
        duplicate the next lock reconciles) — never a half-deleted orphan.
        """
        shard = stored_shard_from_split(sample_split_result)
        await _enroll_old_alias(repo, shard, env_path="/a/.env")

        async def _boom_commit(_self) -> None:
            raise RuntimeError("interrupt at commit during superseded cleanup")

        # Patch AFTER setup so store_enrolled's own commit succeeds first.
        monkeypatch.setattr(aiosqlite.Connection, "commit", _boom_commit)

        with pytest.raises(RuntimeError):
            await repo.delete_superseded_enrollment_atomic("old-alias", env_path="/a/.env")

        monkeypatch.undo()  # restore commit for the assertion reads
        # Rollback restored BOTH rows: enrollment present AND shard present.
        assert {e.env_path for e in await repo.list_enrollments("old-alias")} == {"/a/.env"}
        assert not await _orphans(tmp_db_path, repo), "interrupt orphaned the old shard"

    @pytest.mark.asyncio
    async def test_cleanup_removes_both_rows_no_orphan(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        """Happy path: a normal rotation re-lock fully removes the superseded alias."""
        import worthless.cli.commands.lock as lock_mod

        shard = stored_shard_from_split(sample_split_result)
        await _enroll_old_alias(repo, shard, env_path="/a/.env")

        await lock_mod._delete_superseded_location_enrollments(
            repo, alias="new-alias", var_name="OPENAI_API_KEY", env_path="/a/.env"
        )

        assert await repo.list_enrollments("old-alias") == []
        assert not await _orphans(tmp_db_path, repo)

    @pytest.mark.asyncio
    async def test_cleanup_keeps_shard_with_sibling_enrollment(
        self,
        repo: ShardRepository,
        sample_split_result,
        tmp_db_path: str,
    ) -> None:
        """Conditional: clearing one env_path keeps a shard still used by another.

        old-alias is enrolled at BOTH /a/.env and /b/.env (one shared shard).
        Superseding it at /a/.env must drop that enrollment but KEEP the shard —
        an unconditional shard delete would CASCADE-wipe the live /b/.env lock.
        """
        shard = stored_shard_from_split(sample_split_result)
        await _enroll_old_alias(repo, shard, env_path="/a/.env")
        await repo.add_enrollment("old-alias", var_name="OPENAI_API_KEY", env_path="/b/.env")

        shard_removed = await repo.delete_superseded_enrollment_atomic(
            "old-alias", env_path="/a/.env"
        )

        assert shard_removed is False, "shard wrongly deleted while /b/.env still uses it"
        assert {e.env_path for e in await repo.list_enrollments("old-alias")} == {"/b/.env"}
        assert not await _orphans(tmp_db_path, repo)

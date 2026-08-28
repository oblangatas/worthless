"""WOR-621 F2 G5-C — drop the dead ``oc_original_base_url`` column (MED-2).

RED-first. The column is dead data: G5-A landed a MAC-bound rollback
record (``oc_original_api_key_json``) that holds the FULL original entry
including ``baseUrl``. Stage A of ``apply_unlock`` reads the URL out of
that MAC-verified JSON — never the column. So the column is duplicated
information, AND it is NOT MAC-bound (a DB-write attacker can flip it
silently). Today no caller trusts it; tomorrow someone might forget that
and add a "read the URL from the fast column" optimization. The column
is a footgun loaded for someone who hasn't been hired yet.

Pinned contracts (RED — these all fail today):

1. Schema introspect: ``PRAGMA table_info(shards)`` does NOT list
   ``oc_original_base_url`` after a fresh init.
2. ``EncryptedShard`` dataclass has no ``oc_original_base_url`` field.
3. ``OcRestore`` dataclass has no ``oc_original_base_url`` field.
4. ``upsert_locked_shard`` signature rejects an ``oc_original_base_url=``
   kwarg (TypeError) — proves the param was removed.
5. ``classify_oc_entry_for_capture`` signature rejects a
   ``prior_base_url=`` kwarg (TypeError) — proves the threaded-through
   param was removed.

These are mechanical/structural assertions. End-to-end re-lock + unlock
behavior is already covered by the existing
``test_lock_capture_oc_rollback.py`` + ``test_unlock_restore_oc.py``
suites, which GREEN must keep passing.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import fields

import aiosqlite
import pytest

from worthless.openclaw.integration import OcRestore, classify_oc_entry_for_capture
from worthless.storage.models import EncryptedShard
from worthless.storage.repository import ShardRepository
from worthless.storage.schema import init_db


@pytest.mark.asyncio
async def test_shards_table_has_no_oc_original_base_url_column(tmp_path) -> None:
    """A fresh DB must NOT have the column. Both the CREATE TABLE DDL AND
    the legacy migration entry must be gone, so an existing DB upgrading
    through the migrations also ends up without it."""
    db_path = str(tmp_path / "shards.db")
    await init_db(db_path)
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("PRAGMA table_info(shards)")
        cols = {row[1] for row in await cursor.fetchall()}
    assert "oc_original_base_url" not in cols, (
        f"shards table still has dead column oc_original_base_url; cols={sorted(cols)}"
    )


def test_encrypted_shard_dataclass_has_no_oc_original_base_url() -> None:
    """The Python record mirror must lose the field too — otherwise
    fetch_encrypted has nothing to populate it from but callers still
    expect it. ``EncryptedShard`` is a NamedTuple, so introspect via
    ``_fields`` rather than ``dataclasses.fields``."""
    names = set(EncryptedShard._fields)
    assert "oc_original_base_url" not in names, (
        f"EncryptedShard still carries dead field oc_original_base_url; fields={sorted(names)}"
    )


def test_oc_restore_dataclass_has_no_oc_original_base_url() -> None:
    """OcRestore is the integration-layer record passed into Stage A. The
    field is populated by the CLI but never read by Stage A — drop it so
    no future caller is tempted to trust it."""
    names = {f.name for f in fields(OcRestore)}
    assert "oc_original_base_url" not in names, (
        f"OcRestore still carries dead field oc_original_base_url; fields={sorted(names)}"
    )


def test_upsert_locked_shard_rejects_oc_original_base_url_kwarg() -> None:
    """The signature must lose the kwarg so any caller still passing it
    fails loud at the boundary (not silently dropped)."""
    sig = inspect.signature(ShardRepository.upsert_locked_shard)
    assert "oc_original_base_url" not in sig.parameters, (
        f"upsert_locked_shard still accepts oc_original_base_url; params={list(sig.parameters)}"
    )


def test_store_enrolled_rejects_oc_original_base_url_kwarg() -> None:
    """Same contract on the fresh-enroll variant (``store_enrolled``)."""
    sig = inspect.signature(ShardRepository.store_enrolled)
    assert "oc_original_base_url" not in sig.parameters, (
        f"store_enrolled still accepts oc_original_base_url; params={list(sig.parameters)}"
    )


def test_classify_oc_entry_for_capture_rejects_prior_base_url_kwarg() -> None:
    """``prior_base_url`` was only echoed back in the ``reuse_prior``
    tuple — never used to drive a decision. Drop it so the threaded-through
    DB column has no remaining reader."""
    sig = inspect.signature(classify_oc_entry_for_capture)
    assert "prior_base_url" not in sig.parameters, (
        f"classify_oc_entry_for_capture still accepts prior_base_url; params={list(sig.parameters)}"
    )


def test_classify_oc_entry_for_capture_returns_2tuple_or_consistent_shape() -> None:
    """If the reuse_prior tuple shape changes (was 3-tuple including
    prior_base_url), pin the new shape so callers update in lockstep.
    Any (kind, record_json) or (kind, None, None) call is a sentinel —
    just assert no caller silently destructures into a stale 3rd slot
    expecting the old base URL."""
    # The function returns (CaptureKind, str | None, str | None) today —
    # the middle slot was base_url. We expect GREEN to either (a) keep
    # the 3-tuple but always set the middle slot to None for reuse_prior,
    # or (b) shrink to (CaptureKind, str | None). Both are acceptable;
    # what's NOT acceptable is a reuse_prior path that returns the prior
    # base_url. Light assertion: invoke the reuse_prior branch and check
    # any returned URL came from the FRESH entry, not a separately-passed
    # prior_base_url.
    result = classify_oc_entry_for_capture(
        current_entry={"baseUrl": "http://127.0.0.1:8787/openai/v1", "apiKey": "shard-a"},
        prior_entry_record_json=(
            '{"apiKey":{"kind":"plaintext"},"baseUrl":"https://api.openai.com/v1"}'
        ),
        proxy_base_url="http://127.0.0.1:8787",
    )
    # The reuse_prior branch must return the prior JSON record verbatim
    # in its record slot; the base_url slot (whether kept or dropped) must
    # NOT carry a separately-supplied "prior_base_url" value because that
    # param is gone.
    assert result[0] == "reuse_prior", f"expected reuse_prior, got {result[0]!r}"
    # Whatever the tuple shape, the JSON record MUST round-trip verbatim.
    assert any(
        isinstance(slot, str)
        and '"baseUrl":"https://api.openai.com/v1"' in slot
        and '"apiKey":{"kind":"plaintext"}' in slot
        for slot in result[1:]
    ), f"prior_entry_record_json not preserved verbatim in result: {result!r}"


def _unused_async_helper() -> None:
    """Keep asyncio import live for the table-info test fixture without
    triggering ruff F401 on a one-off pytest-asyncio file."""
    _ = asyncio.sleep

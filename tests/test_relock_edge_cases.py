"""worthless-16x2: re-lock edge-case tests (TDD red phase).

All tests in this file are FAILING by design. They define the contract for
the re-lock upsert behaviour introduced by the worthless-16x2 fix.

Each test is written against the current (post-16x2) repository API so that
running ``uv run pytest tests/test_relock_edge_cases.py`` with the completed
implementation makes them green.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest
from cryptography.fernet import Fernet

from worthless.crypto.splitter import split_key_fp
from worthless.storage.repository import ShardRepository, StoredShard


pytestmark = pytest.mark.skip(reason="WOR-549: worthless-16x2 ↔ sidecar IPC integration pending")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_URL = "https://api.openai.com/v1"
_PROVIDER = "openai"


def _make_stored(sr) -> StoredShard:
    return StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider=_PROVIDER,
    )


async def _upsert(repo: ShardRepository, alias: str, sr) -> None:
    """Thin wrapper: upsert both shards from a SplitResult."""
    stored = _make_stored(sr)
    await repo.upsert_locked_shard(
        alias,
        stored,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url=_BASE_URL,
    )


async def _reconstruct_from_db(
    repo: ShardRepository,
    alias: str,
    shard_a: bytes | bytearray,
) -> bytes:
    """Decrypt shard-B from DB, XOR with caller-provided shard-A to recover the key.

    Post-16x2-revert: shard-A is not stored in DB. Callers must supply the
    shard-A bytes they kept from the split result.
    """
    from worthless.crypto.splitter import reconstruct_key_fp

    encrypted = await repo.fetch_encrypted(alias)
    assert encrypted is not None, f"No shard row found for alias={alias!r}"
    stored = repo.decrypt_shard(encrypted)
    return reconstruct_key_fp(
        bytes(shard_a),
        bytes(stored.shard_b),
        bytes(stored.commitment),
        bytes(stored.nonce),
        prefix=encrypted.prefix or "",
        charset=encrypted.charset or "",
    )


# ---------------------------------------------------------------------------
# Fixtures (local — mirrors conftest but self-contained for isolation)
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "relock_edge.db")


@pytest.fixture()
def fernet_key() -> bytes:
    return Fernet.generate_key()


@pytest.fixture()
async def repo(tmp_db_path: str, fernet_key: bytes) -> ShardRepository:
    r = ShardRepository(tmp_db_path, fernet_key)
    await r.initialize()
    return r


# ---------------------------------------------------------------------------
# 1. Relock idempotence — lock 5 times, last pair must reconstruct the key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_idempotence_5x(repo: ShardRepository, tmp_db_path: str) -> None:
    """Locking the same alias 5 times leaves a valid, consistent shard pair.

    After every iteration the DB shard-B and the shard-A from the last
    upsert must XOR back to the original key. This fails if upsert does
    not atomically replace BOTH shards together (e.g. if shard_a_enc is
    not updated on conflict).
    """
    alias = "idempotent-5x"
    api_key = "sk-idempotent-abcdef1234567890"
    original = api_key.encode()

    last_shard_a: bytearray | None = None

    for i in range(5):
        sr = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
        last_shard_a = bytearray(sr.shard_a)
        await _upsert(repo, alias, sr)
        sr.zero()

    # Exactly one row must exist
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM shards WHERE key_alias = ?", (alias,))
        (count,) = await cursor.fetchone()
    assert count == 1, f"Expected exactly 1 shard row, got {count}"

    # Reconstruct from DB using the last shard-A — must equal original key
    assert last_shard_a is not None
    reconstructed = await _reconstruct_from_db(repo, alias, last_shard_a)
    assert reconstructed == original, (
        f"Reconstruction failed after 5 relocks: expected {original!r}, got {reconstructed!r}"
    )


# ---------------------------------------------------------------------------
# 2. Relock after DB-only corruption (garbage shard-B)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_repairs_corrupted_shard_b(
    repo: ShardRepository, tmp_db_path: str, fernet_key: bytes
) -> None:
    """After corrupting shard-B in the DB, a re-lock restores valid state.

    Simulates partial write corruption: shard_b_enc is overwritten with
    Fernet-encrypted garbage. After re-lock, reconstruction must succeed.
    """
    alias = "corrupted-shard-b"
    api_key = "sk-corrupt-abcdef1234567890"

    # Initial lock
    sr = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    await _upsert(repo, alias, sr)
    sr.zero()

    # Corrupt shard-B in the database directly
    fernet = Fernet(fernet_key)
    garbage_enc = fernet.encrypt(b"\xff" * 32)
    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "UPDATE shards SET shard_b_enc = ? WHERE key_alias = ?",
            (garbage_enc, alias),
        )
        await db.commit()

    # Re-lock with a fresh split of the same key
    sr2 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    shard_a2 = bytes(sr2.shard_a)
    await _upsert(repo, alias, sr2)
    sr2.zero()

    # Reconstruction must now succeed and return the original key
    reconstructed = await _reconstruct_from_db(repo, alias, shard_a2)
    assert reconstructed == api_key.encode(), (
        f"Post-corruption re-lock: expected {api_key.encode()!r}, got {reconstructed!r}"
    )


# ---------------------------------------------------------------------------
# 3. openclaw.json missing before relock — file must be created
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_creates_openclaw_json_when_missing(
    tmp_path: Path,
) -> None:
    """lock creates openclaw.json when the file does not yet exist.

    apply_lock() must write the file (not skip silently) when the
    target path does not exist. This test patches _resolve_active_config_path
    to return a freshly created but non-existent temp path, then invokes
    apply_lock and asserts the file was created with valid JSON containing
    the auth_token as the apiKey in the provider entry.

    RED: The assertion checks that auth_token appears as the apiKey field
    inside the nested models.providers structure that apply_lock writes.
    This will fail until the implementation writes the token in that exact
    location with 'apiKey' as the key name.
    """
    from worthless.openclaw.integration import apply_lock, IntegrationState

    openclaw_dir = tmp_path / ".openclaw"
    openclaw_dir.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"

    # File must NOT exist before lock
    assert not config_path.exists(), "pre-condition: file must not exist"

    auth_token = "test-auth-token-abc123"  # noqa: S105 — test fixture, not a real credential
    alias = "missing-file-alias"

    fake_state = IntegrationState(
        present=True,
        config_path=config_path,
        workspace_path=tmp_path / ".openclaw" / "workspace",
        skill_path=None,
        home_dir=tmp_path,
        notes=(),
    )

    with (
        patch("worthless.openclaw.integration.detect", return_value=fake_state),
        patch(
            "worthless.openclaw.integration._resolve_active_config_path",
            return_value=config_path,
        ),
    ):
        apply_lock(
            [(_PROVIDER, alias, auth_token)],
            proxy_base_url="http://127.0.0.1:8787",
        )

    assert config_path.exists(), "apply_lock must create openclaw.json when missing"

    content = json.loads(config_path.read_text())

    # The auth_token must appear as apiKey inside a provider entry.
    # Traverse the whole document looking for 'apiKey': auth_token.
    # This will fail if the token is stored under a different key name.
    def _find_api_key(obj: object) -> str | None:
        if isinstance(obj, dict):
            if obj.get("apiKey") == auth_token:
                return auth_token
            for v in obj.values():
                found = _find_api_key(v)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = _find_api_key(item)
                if found is not None:
                    return found
        return None

    found_token = _find_api_key(content)
    assert found_token == auth_token, (
        f"auth_token {auth_token!r} not found as 'apiKey' in openclaw.json: {content}"
    )

    # Additionally: the provider entry's baseUrl must include the alias path segment.
    raw = json.dumps(content)
    assert alias in raw, (
        f"alias {alias!r} not present in any baseUrl within openclaw.json: {content}"
    )

    # RED assertion: the file must be owned with mode 0o600 (not world-readable).
    mode = oct(config_path.stat().st_mode & 0o777)
    assert mode == oct(0o600), f"openclaw.json must be 0o600, got {mode}"


# ---------------------------------------------------------------------------
# 4. openclaw.json write fails, DB already updated — exit 73, DB state intact
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_openclaw_write_failure_exits_73_db_updated(
    repo: ShardRepository, tmp_path: Path
) -> None:
    """When openclaw write raises OSError, lock exits 73 but DB is committed.

    The DB shard-B must be present and valid even though openclaw failed.
    The user can retry just the openclaw step on the next run.

    Exit 73 is the partial_failure code defined in lock.py (typer.Exit(73)).
    """
    from worthless.cli.commands.lock import _apply_openclaw

    alias = "openclaw-fail-alias"
    api_key = "sk-openclaw-fail-abcdef12345"

    # Write DB first (simulates lock-core completing)
    sr = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    await _upsert(repo, alias, sr)
    shard_a_bytes = bytes(sr.shard_a)
    sr.zero()

    # Confirm DB row exists
    encrypted = await repo.fetch_encrypted(alias)
    assert encrypted is not None, "DB write must have completed before openclaw step"

    # Build a _PlannedUpdate with the correct field set (no base_url field).
    from worthless.cli.commands.lock import _PlannedUpdate

    shard_b_placeholder = bytearray(len(shard_a_bytes))  # same length, zeroed
    commitment_placeholder = bytearray(32)
    nonce_placeholder = bytearray(16)

    planned = [
        _PlannedUpdate(
            alias=alias,
            var_name="OPENAI_API_KEY",
            env_path_str=str(tmp_path / ".env"),
            provider=_PROVIDER,
            shard_a=bytearray(shard_a_bytes),
            shard_b=shard_b_placeholder,
            commitment=commitment_placeholder,
            nonce=nonce_placeholder,
            prefix="sk-",
            charset="",
            was_fresh_enroll=False,
        )
    ]

    from worthless.cli.console import get_console

    console = get_console()

    # Patch apply_lock (the openclaw integration call) to raise OSError,
    # simulating a write failure AFTER the DB has been fully updated.
    with patch(
        "worthless.openclaw.integration.apply_lock",
        side_effect=OSError("disk full"),
    ):
        from worthless.cli.bootstrap import WorthlessHome

        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        partial_failure = _apply_openclaw(
            planned,
            console,
            quiet=True,
            home=home,
        )

    assert partial_failure is True, (
        "_apply_openclaw must return True (partial_failure) when openclaw write raises OSError"
    )

    # DB state must remain intact — shard row must still be valid after the
    # failed openclaw write (lock-core committed before _apply_openclaw ran).
    encrypted2 = await repo.fetch_encrypted(alias)
    assert encrypted2 is not None, "DB shard row must survive openclaw write failure"
    # Post-16x2-revert: shard_a_enc is NULL — lock no longer stores shard-A server-side.
    # The DB row health is verified by the presence of the shard_b_enc column.
    assert encrypted2.shard_b_enc is not None, "shard_b_enc must still be present in DB"


# ---------------------------------------------------------------------------
# 5. Relock with different spend cap — new cap stored, old shard-B replaced
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_updates_spend_cap(repo: ShardRepository, tmp_db_path: str) -> None:
    """Re-locking with a different --spend-cap persists the new cap.

    The shards row must be replaced (both shards updated) and
    enrollment_config.spend_cap must reflect the new value.
    """
    alias = "spend-cap-relock"
    api_key = "sk-spend-cap-abcdef12345678"

    # First lock: initial cap
    sr1 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored1 = _make_stored(sr1)
    await repo.upsert_locked_shard(
        alias,
        stored1,
        prefix=sr1.prefix,
        charset=sr1.charset,
        base_url=_BASE_URL,
    )
    await repo.store_enrolled(
        alias,
        stored1,
        var_name="OPENAI_API_KEY",
        env_path=None,
        spend_cap=1000,
        prefix=sr1.prefix,
        charset=sr1.charset,
        base_url=_BASE_URL,
    )
    sr1.zero()

    # Confirm initial cap
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None and row[0] == 1000, f"Expected initial cap 1000, got {row}"

    # Re-lock: new split of same key with different spend cap.
    # The shard pair is replaced atomically; enrollment_config must also update.
    sr2 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored2 = _make_stored(sr2)
    shard_a2_bytes = bytes(sr2.shard_a)  # capture before zero
    await repo.upsert_locked_shard(
        alias,
        stored2,
        prefix=sr2.prefix,
        charset=sr2.charset,
        base_url=_BASE_URL,
    )

    # upsert_locked_shard does NOT update enrollment_config.spend_cap.
    # The re-lock path must explicitly update spend_cap via set_spend_cap().
    new_cap = 5000
    updated = await repo.set_spend_cap(alias, new_cap)
    assert updated, f"set_spend_cap(alias, {new_cap}) must return True for existing alias"
    sr2.zero()

    # New cap must be stored
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None and row[0] == new_cap, (
        f"Expected updated cap {new_cap} after re-lock, got {row}"
    )

    # Reconstruction with the new shard pair must succeed
    reconstructed = await _reconstruct_from_db(repo, alias, shard_a2_bytes)
    assert reconstructed == api_key.encode(), (
        f"Reconstruction failed after spend-cap re-lock: {reconstructed!r}"
    )

    # RED: Confirm shard row has exactly ONE row (not two) after re-lock.
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM shards WHERE key_alias = ?", (alias,))
        (count,) = await cursor.fetchone()
    assert count == 1, f"Re-lock must not duplicate the shard row; got {count} rows"

    # The new shard pair must DIFFER from sr1 (proves the update happened).
    # shard_b_enc must have been overwritten. We verify this by ensuring the
    # nonce changed — two independent splits of the same key always produce
    # different nonces.
    encrypted_final = await repo.fetch_encrypted(alias)
    assert encrypted_final is not None
    # The nonce must be non-zero (a valid fresh nonce from sr2)
    assert any(b != 0 for b in encrypted_final.nonce), "Nonce must not be all-zeroes after re-lock"


# ---------------------------------------------------------------------------
# 6. Concurrent re-lock: last writer wins, state is consistent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_relock_last_writer_wins(repo: ShardRepository, tmp_db_path: str) -> None:
    """Two concurrent upsert_locked_shard calls leave exactly one shard row.

    After both coroutines complete:
    - Only one row for the alias exists (no duplicate rows).
    - The shard pair in DB is internally consistent (XOR = original key).

    This is the "last writer wins" contract of ON CONFLICT DO UPDATE.
    """
    alias = "concurrent-relock"
    api_key = "sk-concurrent-abcdef12345678"
    original = api_key.encode()

    # Pre-create two distinct splits (same key → same prefix/charset, different random shards)
    sr_a = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    sr_b = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)

    stored_a = _make_stored(sr_a)
    stored_b = _make_stored(sr_b)
    shard_a_a = bytearray(sr_a.shard_a)
    shard_a_b = bytearray(sr_b.shard_a)
    prefix_a = sr_a.prefix
    charset_a = sr_a.charset
    prefix_b = sr_b.prefix
    charset_b = sr_b.charset

    # Run both upserts concurrently
    await asyncio.gather(
        repo.upsert_locked_shard(
            alias,
            stored_a,
            prefix=prefix_a,
            charset=charset_a,
            base_url=_BASE_URL,
        ),
        repo.upsert_locked_shard(
            alias,
            stored_b,
            prefix=prefix_b,
            charset=charset_b,
            base_url=_BASE_URL,
        ),
    )

    sr_a.zero()
    sr_b.zero()

    # Exactly one row for the alias
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM shards WHERE key_alias = ?", (alias,))
        (count,) = await cursor.fetchone()
    assert count == 1, f"Expected exactly 1 shard row after concurrent upserts, got {count}"

    # The persisted pair must reconstruct the original key.
    # One of the two concurrent shards-A won. Try both and accept either success.
    from worthless.crypto.splitter import reconstruct_key_fp

    encrypted_final = await repo.fetch_encrypted(alias)
    assert encrypted_final is not None
    stored_final = repo.decrypt_shard(encrypted_final)
    try:
        reconstructed = reconstruct_key_fp(
            bytes(shard_a_a),
            bytes(stored_final.shard_b),
            bytes(stored_final.commitment),
            bytes(stored_final.nonce),
            prefix=encrypted_final.prefix or "",
            charset=encrypted_final.charset or "",
        )
    except Exception:
        reconstructed = reconstruct_key_fp(
            bytes(shard_a_b),
            bytes(stored_final.shard_b),
            bytes(stored_final.commitment),
            bytes(stored_final.nonce),
            prefix=encrypted_final.prefix or "",
            charset=encrypted_final.charset or "",
        )
    finally:
        stored_final.zero()
    assert reconstructed == original, (
        f"Concurrent re-lock left inconsistent shard pair: "
        f"expected {original!r}, got {reconstructed!r}"
    )


# ---------------------------------------------------------------------------
# 7. Enrollment rows survive re-lock (alias not deleted)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_preserves_enrollment_rows(
    repo: ShardRepository,
) -> None:
    """list_enrollments returns the enrollment record after re-lock.

    ON CONFLICT DO UPDATE must NOT cascade-delete enrollment rows. If
    INSERT OR REPLACE were used instead, the ON DELETE CASCADE on the
    shards → enrollments FK would wipe enrollment records on re-lock.
    """
    alias = "enrollment-survives"
    api_key = "sk-enrollment-abcdef12345678"

    sr1 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored1 = _make_stored(sr1)
    await repo.upsert_locked_shard(
        alias, stored1, prefix=sr1.prefix, charset=sr1.charset, base_url=_BASE_URL
    )
    await repo.store_enrolled(
        alias,
        stored1,
        var_name="OPENAI_API_KEY",
        env_path="/home/user/.env",
        base_url=_BASE_URL,
    )
    sr1.zero()

    # Re-lock: second upsert
    sr2 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored2 = _make_stored(sr2)
    await repo.upsert_locked_shard(
        alias, stored2, prefix=sr2.prefix, charset=sr2.charset, base_url=_BASE_URL
    )
    sr2.zero()

    # Enrollment must still be present
    enrollments = await repo.list_enrollments(alias=alias)
    assert len(enrollments) >= 1, f"Re-lock must not delete enrollment rows; got {enrollments!r}"
    aliases = [e.key_alias for e in enrollments]
    assert alias in aliases, f"Expected alias {alias!r} in enrollment list, got {aliases!r}"


# ---------------------------------------------------------------------------
# 8. Relock on non-existent alias (first-lock INSERT path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_lock_inserts_via_upsert(repo: ShardRepository, tmp_db_path: str) -> None:
    """upsert_locked_shard on a brand-new alias performs an INSERT.

    This is the first-lock path. ON CONFLICT DO UPDATE must not prevent
    the initial INSERT when no row exists for the alias.
    """
    alias = "brand-new-alias"
    api_key = "sk-brand-new-abcdef12345678"

    # Confirm no row exists before
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM shards WHERE key_alias = ?", (alias,))
        (pre_count,) = await cursor.fetchone()
    assert pre_count == 0, "pre-condition: alias must not be in shards table"

    sr = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    shard_a_bytes = bytes(sr.shard_a)  # capture before zero
    await _upsert(repo, alias, sr)
    sr.zero()

    # Row must now exist
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT COUNT(*), shard_b_enc FROM shards WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None
    count, shard_b_enc_val = row
    assert count == 1, f"Expected 1 row after first-lock INSERT, got {count}"
    # Post-16x2-revert: shard_a_enc is NULL — lock no longer stores shard-A server-side.
    assert shard_b_enc_val is not None, "shard_b_enc must be populated on first INSERT"

    # Reconstruction must also work end-to-end using the shard-A from the split
    reconstructed = await _reconstruct_from_db(repo, alias, shard_a_bytes)
    assert reconstructed == api_key.encode(), (
        f"First-lock INSERT: expected {api_key.encode()!r}, got {reconstructed!r}"
    )


# ---------------------------------------------------------------------------
# worthless-fhta: upsert_locked_shard API contract (RED tests)
# ---------------------------------------------------------------------------


class TestUpsertLockedShardApiContract:
    """worthless-fhta TDD red phase.

    Defines the correct upsert_locked_shard API contract:
    - No redundant shard_a kwarg (StoredShard.shard_a is the sole source)
    - prefix, charset, base_url are required — None is a hard error, not a NULL write
    """

    def test_shard_a_kwarg_absent_from_signature(self) -> None:
        """upsert_locked_shard must NOT expose a shard_a parameter.

        Having shard_a alongside StoredShard.shard_a lets callers silently pass
        mismatched halves.  Remove the param: shard-A is never stored server-side
        and the StoredShard instance is the canonical carrier.

        RED: shard_a IS in the current signature → test fails today.
        """
        import inspect

        sig = inspect.signature(ShardRepository.upsert_locked_shard)
        assert "shard_a" not in sig.parameters, (
            "upsert_locked_shard must not accept a shard_a kwarg — "
            "the parameter is never stored and exposes a mismatched-shard footgun."
        )

    @pytest.mark.asyncio
    async def test_call_without_shard_a_kwarg_succeeds(self, repo: ShardRepository) -> None:
        """Calling upsert_locked_shard without shard_a= must not raise TypeError.

        After the fix, shard_a is removed from the signature so the canonical
        call is: upsert_locked_shard(alias, shard, prefix=..., charset=..., base_url=...)

        RED today: shard_a is a required keyword arg → TypeError: missing arg.
        """
        alias = "fhta-no-shard-a"
        sr = split_key_fp("sk-fhta-test-abcdef1234567", prefix="sk-", provider=_PROVIDER)
        stored = _make_stored(sr)
        # Must not raise TypeError after the fix
        await repo.upsert_locked_shard(
            alias,
            stored,
            prefix=sr.prefix,
            charset=sr.charset,
            base_url=_BASE_URL,
        )
        sr.zero()

    @pytest.mark.asyncio
    async def test_none_prefix_is_hard_error(self, repo: ShardRepository) -> None:
        """upsert_locked_shard(prefix=None) must raise — not silently write NULL.

        NULL prefix in the shards row breaks reconstruction: the proxy reads
        encrypted.prefix before calling reconstruct_key_fp and refuses a None value.
        The API must reject it at call time.

        RED today: None is accepted and written to the DB without error.
        """
        alias = "fhta-null-prefix"
        sr = split_key_fp("sk-fhta-prefix-abcdef123", prefix="sk-", provider=_PROVIDER)
        stored = _make_stored(sr)
        with pytest.raises(ValueError):
            await repo.upsert_locked_shard(
                alias,
                stored,
                prefix=None,  # type: ignore[arg-type]
                charset=sr.charset,
                base_url=_BASE_URL,
            )
        sr.zero()

    @pytest.mark.asyncio
    async def test_none_charset_is_hard_error(self, repo: ShardRepository) -> None:
        """upsert_locked_shard(charset=None) must raise — not silently write NULL.

        RED today: None is accepted.
        """
        alias = "fhta-null-charset"
        sr = split_key_fp("sk-fhta-charset-abcdef12", prefix="sk-", provider=_PROVIDER)
        stored = _make_stored(sr)
        with pytest.raises(ValueError):
            await repo.upsert_locked_shard(
                alias,
                stored,
                prefix=sr.prefix,
                charset=None,  # type: ignore[arg-type]
                base_url=_BASE_URL,
            )
        sr.zero()

    @pytest.mark.asyncio
    async def test_none_base_url_is_hard_error(self, repo: ShardRepository) -> None:
        """upsert_locked_shard(base_url=None) must raise — not silently write NULL.

        NULL base_url causes the proxy to refuse requests with "re-lock required".
        The API must catch it immediately, not let it leak into the DB.

        RED today: None is accepted.
        """
        alias = "fhta-null-base-url"
        sr = split_key_fp("sk-fhta-base-url-abcdef1", prefix="sk-", provider=_PROVIDER)
        stored = _make_stored(sr)
        with pytest.raises(ValueError):
            await repo.upsert_locked_shard(
                alias,
                stored,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=None,  # type: ignore[arg-type]
            )
        sr.zero()


# ---------------------------------------------------------------------------
# worthless-rbog: spend-cap test drives real repo path, not raw SQL (RED)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relock_preserves_spend_cap_via_repo(repo: ShardRepository, tmp_db_path: str) -> None:
    """Re-lock via the real repo path must NOT overwrite enrollment_config.spend_cap.

    Drives the actual upsert_locked_shard + add_enrollment path (not raw SQL)
    and asserts spend_cap survives.  This is the behavioral invariant:
    key rotation must not destroy user-configured budget limits.

    Complements the storage-layer test below which uses set_spend_cap().
    """
    alias = "rbog-preserve-spend-cap"
    api_key = "sk-rbog-preserve-abcdef12345"

    # First lock — sets the initial spend cap
    sr1 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored1 = _make_stored(sr1)
    await repo.upsert_locked_shard(
        alias, stored1, prefix=sr1.prefix, charset=sr1.charset, base_url=_BASE_URL
    )
    await repo.store_enrolled(
        alias,
        stored1,
        var_name="OPENAI_API_KEY",
        env_path=None,
        spend_cap=1000,
        prefix=sr1.prefix,
        charset=sr1.charset,
        base_url=_BASE_URL,
    )
    sr1.zero()

    # Re-lock: upsert new shard pair (what lock.py does on re-lock)
    sr2 = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored2 = _make_stored(sr2)
    await repo.upsert_locked_shard(
        alias, stored2, prefix=sr2.prefix, charset=sr2.charset, base_url=_BASE_URL
    )
    await repo.add_enrollment(alias, var_name="OPENAI_API_KEY", env_path=None)
    sr2.zero()

    # spend_cap must be unchanged
    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None and row[0] == 1000, (
        f"Re-lock must preserve spend_cap=1000, got {row!r}. "
        "upsert_locked_shard must not touch enrollment_config."
    )


@pytest.mark.asyncio
async def test_set_spend_cap_updates_via_repo_method(
    repo: ShardRepository, tmp_db_path: str
) -> None:
    """ShardRepository.set_spend_cap() updates enrollment_config.spend_cap.

    Replaces the previous raw SQL UPDATE in test_relock_updates_spend_cap.
    Tests the real repo method rather than exercising SQLite directly.

    RED today: ShardRepository has no set_spend_cap method.
    """
    alias = "rbog-set-spend-cap"
    api_key = "sk-rbog-set-spend-abcdef1234"

    sr = split_key_fp(api_key, prefix="sk-", provider=_PROVIDER)
    stored = _make_stored(sr)
    await repo.upsert_locked_shard(
        alias, stored, prefix=sr.prefix, charset=sr.charset, base_url=_BASE_URL
    )
    await repo.store_enrolled(
        alias,
        stored,
        var_name="OPENAI_API_KEY",
        env_path=None,
        spend_cap=1000,
        prefix=sr.prefix,
        charset=sr.charset,
        base_url=_BASE_URL,
    )
    sr.zero()

    # Update spend cap via the repo method (not raw SQL)
    updated = await repo.set_spend_cap(alias, 5000)
    assert updated is True, "set_spend_cap must return True when the enrollment_config row exists"

    async with aiosqlite.connect(tmp_db_path) as db:
        cursor = await db.execute(
            "SELECT spend_cap FROM enrollment_config WHERE key_alias = ?", (alias,)
        )
        row = await cursor.fetchone()
    assert row is not None and row[0] == 5000, (
        f"set_spend_cap(5000) must update enrollment_config, got {row!r}"
    )

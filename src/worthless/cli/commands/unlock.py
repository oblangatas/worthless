"""Unlock command -- reconstruct keys from shards, restore .env, clean up.

Transactional across N keys: either every alias is reconstructed and
``.env`` is fully rewritten with plaintext + BASE_URLs removed, or
nothing changes. Mirrors the lock pipeline in ``commands/lock.py``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import typer
from dotenv import dotenv_values

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import WorthlessHome, acquire_lock, get_home
from worthless.cli.console import get_console

# 8rqs Phase 8 moved _PROVIDER_ENV_MAP from wrap.py into lock.py
# (wrap is now a passthrough; lock owns BASE_URL ownership). HF4 on main
# pre-dated that move and still imported from wrap.py — that import would
# fail at module-load post-merge. Importing from the new home, lock.py.
from worthless.cli.commands.lock import _PROVIDER_ENV_MAP

# scan_env_keys is used by HF4's per-key messaging logic (the
# "no DB row here" hard-error path further down in this module).
from worthless.cli.dotenv_rewriter import rewrite_env_keys, scan_env_keys
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.orphans import format_orphan_error
from worthless.crypto.reconstruction import reconstruct_key, reconstruct_key_fp
from worthless.crypto.types import zero_buf
from worthless.exceptions import ShardTamperedError
from worthless.openclaw import integration as _openclaw_integration
from worthless.openclaw.errors import OpenclawIntegrationError
from worthless.storage.repository import (
    EnrollmentRecord,
    EncryptedShard,
    ShardRepository,
    StoredShard,
)

logger = logging.getLogger(__name__)


_RECOVERY_LABEL = "<recovery>"


def _db_missing_after_completed_bootstrap() -> tuple[bool, Path]:
    """Return whether an initialized Worthless home has lost its SQLite DB."""
    env_home = os.environ.get("WORTHLESS_HOME")
    base = Path(env_home) if env_home else Path.home() / ".worthless"
    db_path = base / "worthless.db"
    return (base / ".bootstrapped").exists() and not db_path.exists(), db_path


def _format_restored_line(p: _PlannedRestore) -> str:
    """Per-key audit line emitted after a successful restore (HF4)."""
    where = str(p.env_path) if p.env_path is not None else _RECOVERY_LABEL
    return f"[OK] Restored {p.var_name or p.alias} ({p.provider}, alias {p.alias}) → {where}"


def _unrecognised_shards(env: Path) -> list[str]:
    """Var names in *env* that look like LLM provider keys but are not enrolled.

    Used by both unlock branches to discriminate "legitimate empty state"
    (warn + exit 0) from "shard-shape values copied from another machine
    with no DB row here" (HF4 hard error). Reuses scan_env_keys so the
    entropy + KEY_PATTERN guards apply — a low-entropy placeholder like
    ``sk-aaaa…`` will not trigger a false-positive hard error.
    """
    return [var_name for var_name, _value, _provider in scan_env_keys(env)]


async def _resolve_enrollment(
    alias: str,
    repo: ShardRepository,
    env_path: Path | None,
) -> EnrollmentRecord | None:
    """Find the enrollment for *alias*, raising on ambiguity."""
    env_str = str(env_path.resolve()) if env_path else None
    if env_str:
        return await repo.get_enrollment(alias, env_str)

    all_enrollments = await repo.list_enrollments(alias)
    if len(all_enrollments) > 1:
        paths = ", ".join(e.env_path or "<direct>" for e in all_enrollments)
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"Alias {alias!r} is enrolled in multiple env files ({paths}). "
            f"Specify --env to choose which to unlock.",
        )
    return all_enrollments[0] if all_enrollments else None


def _load_shard_a(
    encrypted: EncryptedShard,
    env_path: Path | None,
    var_name: str | None,
    home: WorthlessHome,
    alias: str,
) -> bytearray:
    """Load shard-A from .env (format-preserving) or disk (legacy)."""
    if encrypted.prefix is not None and encrypted.charset is not None:
        if not (env_path and env_path.exists() and var_name):
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                f"Cannot unlock {alias}: shard-A is in .env but no valid env_path",
            )
        parsed = dotenv_values(env_path)
        shard_a_value = parsed.get(var_name)
        if shard_a_value is None:
            # Canonical orphan wording lives in ``cli.orphans`` so the same
            # string surfaces in doctor + unlock + future HF5 status/scan.
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                format_orphan_error(
                    EnrollmentRecord(key_alias=alias, var_name=var_name, env_path=str(env_path))
                ),
            )
        return bytearray(shard_a_value.encode("utf-8"))

    # Legacy: shard_a is a file on disk
    shard_a_path = home.shard_a_dir / alias
    if not shard_a_path.exists():
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"Shard A not found for alias: {alias}",
        )
    return bytearray(shard_a_path.read_bytes())


def _reconstruct(
    encrypted: EncryptedShard,
    shard_a: bytearray,
    stored: StoredShard,
) -> bytearray:
    """Reconstruct the original key from shards (raises ShardTamperedError on bad HMAC)."""
    if encrypted.prefix is not None and encrypted.charset is not None:
        return reconstruct_key_fp(
            shard_a,
            stored.shard_b,
            stored.commitment,
            stored.nonce,
            encrypted.prefix,
            encrypted.charset,
        )
    return reconstruct_key(shard_a, stored.shard_b, stored.commitment, stored.nonce)


@dataclass(eq=False)
class _PlannedRestore:
    """One alias's in-flight unlock plan — built pass-1, consumed by pass-2/3.

    WOR-621 F2 G4: the ``oc_*`` trio is captured from the encrypted shard
    row at pass-1 time so it survives pass-3's row delete. The CLI later
    builds an :class:`OcRestore` from these fields + a freshly-read plaintext
    key (from the just-restored .env) and passes the list to
    ``integration.apply_unlock``. Legacy rows + ``relock_no_prior`` rows
    carry all three as ``None`` — Stage A fail-safe-skips them.
    """

    alias: str
    provider: str
    enrollment: EnrollmentRecord | None
    var_name: str | None
    env_path: Path | None
    key_buf: bytearray = field(repr=False)
    # G5-C: original baseUrl lives INSIDE oc_original_api_key_json (the
    # MAC-bound source of truth); Stage A parses it from there.
    oc_original_api_key_json: str | None = None
    oc_rollback_mac: str | None = None
    # WOR-640: the inert shard-A being retired by this unlock. Captured pass-1
    # (while live), recorded into the decoy tripwire at pass-3 (after the .env
    # is safely restored) so an aborted unlock never retires a still-active
    # value. ponytail: shard-A is the inert half — plaintext in .env by design.
    shard_a_value: str | None = field(default=None, repr=False)

    def zero(self) -> None:
        # Per CodeRabbit nitpick: reuse the imported `zero_buf` helper
        # rather than allocating a new bytes object. Slice-assignment leaves
        # the previous secret material live until GC; zero_buf wipes in-place
        # immediately, matching the pattern used in _pass1_reconstruct.
        zero_buf(self.key_buf)


async def _pass1_reconstruct(
    aliases: list[str],
    home: WorthlessHome,
    repo: ShardRepository,
    env_path: Path | None,
    planned_out: list[_PlannedRestore],
) -> None:
    """Reconstruct + verify every alias in memory. No .env or DB writes.

    Mutates *planned_out* so the caller's ``finally`` can zero buffers
    even if a later alias raises. On any failure the partial buffers
    are zeroed by the caller; nothing is written to disk.
    """
    for alias in aliases:
        encrypted = await repo.fetch_encrypted(alias)
        if encrypted is None:
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                f"Shard B not found in DB for alias: {alias}",
            )

        stored = await repo.decrypt_shard(encrypted)
        shard_a: bytearray | None = None
        try:
            enrollment = await _resolve_enrollment(alias, repo, env_path)
            var_name = enrollment.var_name if enrollment else None

            shard_a = _load_shard_a(encrypted, env_path, var_name, home, alias)
            try:
                key_buf = _reconstruct(encrypted, shard_a, stored)
            except ShardTamperedError as exc:
                label = var_name or alias
                raise WorthlessError(
                    ErrorCode.KEY_NOT_FOUND,
                    f"Cannot unlock {label}: locked .env value was modified after lock "
                    "(commitment mismatch). Restore the locked value, re-lock from the "
                    "original raw key, or run `worthless doctor` for recovery guidance.",
                ) from exc
            planned_out.append(
                _PlannedRestore(
                    alias=alias,
                    provider=encrypted.provider,
                    enrollment=enrollment,
                    var_name=var_name,
                    env_path=env_path,
                    key_buf=key_buf,
                    # G4: lift the captured pair off the encrypted row HERE
                    # so it survives _pass3_db_cleanup's row delete. The
                    # CLI later MAC-verifies + builds an OcRestore from
                    # this snapshot + the just-restored plaintext from .env.
                    # G5-C: dropped the dead third element (oc_original_base_url).
                    oc_original_api_key_json=encrypted.oc_original_api_key_json,
                    oc_rollback_mac=encrypted.oc_rollback_mac,
                    # WOR-640: snapshot the inert shard-A before it is zeroed so
                    # pass-3 can retire it into the decoy tripwire.
                    shard_a_value=shard_a.decode("utf-8"),
                )
            )
        finally:
            if shard_a is not None:
                zero_buf(shard_a)
            stored.zero()


def _batch_restore_env(env_path: Path, planned: list[_PlannedRestore]) -> None:
    """One ``rewrite_env_keys`` call: restore plaintext + drop BASE_URLs."""
    updates: dict[str, str] = {}
    removals: set[str] = set()
    for p in planned:
        if p.var_name is None:
            continue
        # Per CodeRabbit nitpick: fail loudly on duplicate var_name rather
        # than silently overwrite. Two PlannedRestore entries pointing at the
        # same env var would mean DB inconsistency or planning bug — losing
        # one plaintext silently is worse than aborting the whole batch.
        assert p.var_name not in updates, (
            f"duplicate planned restore for env var {p.var_name} "
            f"(planned aliases: {[entry.alias for entry in planned]})"
        )
        updates[p.var_name] = p.key_buf.decode("utf-8")
        base_url_var = _PROVIDER_ENV_MAP.get(p.provider)
        if base_url_var:
            removals.add(base_url_var)

    if not updates and not removals:
        return

    rewrite_env_keys(env_path, updates, removals=removals or None)


async def _pass3_db_cleanup(
    repo: ShardRepository, home: WorthlessHome, planned: list[_PlannedRestore]
) -> None:
    """Delete enrollments + shards. Runs only after .env rewrite succeeds.

    A crash between rewrite and cleanup leaves orphan DB rows the user
    can re-process by re-running ``worthless unlock`` (idempotent: the
    next run finds the .env already plaintext, the alias still in DB,
    and treats it as a fresh unlock attempt).
    """
    for p in planned:
        enrollment_env = p.enrollment.env_path if p.enrollment else None
        remaining = await repo.list_enrollments(p.alias)
        await repo.delete_enrollment(p.alias, enrollment_env)
        remaining = [e for e in remaining if e.env_path != enrollment_env]
        if not remaining:
            # WOR-640: the shard-A is invalidated only when its LAST enrollment
            # is gone (the shard row is deleted just below). One alias can be
            # enrolled in several .env files, all sharing the same shard-A —
            # retiring it while another .env still uses it would 401 that live
            # traffic. Done post-.env-restore so an aborted unlock never retires
            # a still-active value.
            if p.shard_a_value is not None:
                await repo.record_retired_decoy(p.shard_a_value)
            (home.shard_a_dir / p.alias).unlink(missing_ok=True)
            await repo.delete_enrolled(p.alias)


def _print_recovery_keys(planned: list[_PlannedRestore], console) -> None:
    """Print keys for aliases with no env_path (recovery mode)."""
    for p in planned:
        if p.env_path is not None and p.var_name is not None:
            continue
        if p.var_name:
            console.print_warning(f"No .env file at {p.env_path}. Printing key for recovery:")
            sys.stdout.write(f"{p.var_name}={p.key_buf.decode('utf-8')}\n")
        else:
            console.print_warning(f"No enrollment for {p.alias}. Printing key for recovery:")
            sys.stdout.write(f"{p.alias}={p.key_buf.decode('utf-8')}\n")
    sys.stdout.flush()


async def _unlock_batch(
    aliases: list[str],
    home: WorthlessHome,
    repo: ShardRepository,
    env_path: Path | None,
) -> list[_PlannedRestore]:
    """Transactional multi-alias unlock.

    Returns the planned restores so the caller can emit per-key audit output
    (HF4 / worthless-5u6y). The returned objects have ``key_buf`` already
    zeroed by this function's ``finally`` block; only metadata (alias,
    var_name, provider, env_path) is safe to read post-return.
    """
    console = get_console()
    planned: list[_PlannedRestore] = []
    try:
        await _pass1_reconstruct(aliases, home, repo, env_path, planned)
        if not planned:
            return planned

        env_writers = [p for p in planned if p.env_path is not None and p.var_name is not None]
        if env_writers:
            # Refuse pass-3 if the .env we were supposed to restore into is gone.
            # Otherwise we'd zero plaintext, drop DB rows, and never write or print
            # the key — silent permanent loss.
            if env_path is None or not env_path.exists():
                raise WorthlessError(
                    ErrorCode.KEY_NOT_FOUND,
                    f"Cannot restore plaintext to missing .env at {env_path}; "
                    f"refusing to delete DB rows. Re-create the file (touch it) "
                    f"or pass --env pointing at the correct path, then re-run.",
                )
            _batch_restore_env(env_path, env_writers)

        _print_recovery_keys(planned, console)

        await _pass3_db_cleanup(repo, home, planned)
        return planned
    finally:
        for p in planned:
            p.zero()


async def _build_oc_restores(
    planned: list[_PlannedRestore],
    repo: ShardRepository,
    console,  # noqa: ANN001 — Console type is opaque from this layer
) -> list[_openclaw_integration.OcRestore]:
    """WOR-621 F2 G4 — build :class:`OcRestore` per planned restore.

    Runs AFTER ``_unlock_batch`` (so the .env has been restored to
    plaintext) and BEFORE ``_apply_openclaw_unlock`` (which calls
    ``integration.apply_unlock``). Per planned restore:

    * Skip rows with no captured record (legacy pre-G3 or
      ``relock_no_prior``). Stage A fail-safe-skips them anyway.
    * For rows with a captured record: do a shape-only parse here so we
      can decide ``plaintext`` vs ``secretref`` (drives whether to re-read
      the plaintext key from the .env). The G2 MAC tamper-bind is NOT
      enforced here — that gate lives in Stage A as of G5-A (Gap 3a) so
      no caller can bypass it. We just compute ``recomputed_mac`` via the
      same fernet-keyed
      :meth:`ShardRepository._compute_decoy_hash` and pass both
      ``expected_mac`` (from the DB) and ``recomputed_mac`` through the
      ``OcRestore`` for Stage A to constant-time-compare.
    * For ``plaintext``: re-read the key from the just-restored .env
      (``var_name``); pass-2 wrote it moments ago. Build a fresh owned
      bytearray that Stage A's ``finally`` zeroes after use.
    * For ``secretref``: ``plaintext_key=None``; Stage A writes the ref
      pointer verbatim — NEVER downgraded to plaintext.
    """
    restores: list[_openclaw_integration.OcRestore] = []
    for p in planned:
        record = p.oc_original_api_key_json
        if record is None:
            # No captured record (pre-G3 row or relock_no_prior). Stage A
            # will fail-safe-skip; nothing to parse, nothing to warn.
            restores.append(
                _openclaw_integration.OcRestore(
                    provider=p.provider,
                    alias=p.alias,
                    oc_original_api_key_json=None,
                    plaintext_key=None,
                )
            )
            continue

        # G5-A: the MAC tamper-bind gate now lives in Stage A. The CLI
        # only computes the recompute (async — Stage A is sync) and threads
        # both values through the OcRestore. Legacy rows pass both as None
        # and fall back to shape-only validation per the G1 docstring.
        # ``is not None`` (not truthy) matches the parser's contract verbatim
        # at integration.py:159 — an empty-string MAC would otherwise
        # silently downgrade the gate to shape-only.
        expected_mac = p.oc_rollback_mac
        recomputed_mac = (
            await repo._compute_decoy_hash(record) if expected_mac is not None else None
        )

        # Shape-only parse here so we can route plaintext-vs-secretref.
        # Stage A re-runs the full parse with MAC args; that's the
        # load-bearing check. INVARIANT: the same ``record`` object is
        # passed to BOTH this parse and the OcRestore.oc_original_api_key_json
        # field below — Stage A re-parses the identical string, so the two
        # parses cannot disagree. If the record is structurally invalid we
        # surface it now (saves the .env re-read on the plaintext branch)
        # and let Stage A's identical refusal fire as the canonical event.
        try:
            parsed = _openclaw_integration._parse_oc_rollback_entry_record(record)
        except ValueError as exc:
            console.print_warning(
                f"OpenClaw {p.provider!r} rollback record is malformed "
                f"({exc}); leaving entry on the proxy."
            )
            restores.append(
                _openclaw_integration.OcRestore(
                    provider=p.provider,
                    alias=p.alias,
                    oc_original_api_key_json=None,
                    plaintext_key=None,
                )
            )
            continue

        kind = parsed["apiKey"]["kind"]
        plaintext_key: bytearray | None = None
        if kind == "plaintext":
            # Read the key back from the just-restored .env. pass-2 wrote
            # the reconstructed plaintext moments ago. If the .env is gone
            # (recovery mode / user deleted it) we can't restore the OC
            # plaintext branch — fall through fail-safe.
            if p.env_path is not None and p.env_path.exists() and p.var_name:
                parsed_env = dotenv_values(p.env_path)
                value = parsed_env.get(p.var_name)
                if value is not None:
                    plaintext_key = bytearray(value.encode("utf-8"))
            if plaintext_key is None:
                console.print_warning(
                    f"OpenClaw {p.provider!r}: cannot re-read plaintext key "
                    "from restored .env; leaving entry on the proxy."
                )
                restores.append(
                    _openclaw_integration.OcRestore(
                        provider=p.provider,
                        alias=p.alias,
                        oc_original_api_key_json=None,
                        plaintext_key=None,
                    )
                )
                continue

        restores.append(
            _openclaw_integration.OcRestore(
                provider=p.provider,
                alias=p.alias,
                oc_original_api_key_json=record,
                plaintext_key=plaintext_key,
                expected_mac=expected_mac,
                recomputed_mac=recomputed_mac,
            )
        )
    return restores


def _apply_openclaw_unlock(
    restores: list[_openclaw_integration.OcRestore],
    console,  # noqa: ANN001 — Console type is opaque from this layer
    home: WorthlessHome,
) -> bool:
    """OpenClaw symmetric undo + sentinel write. Returns ``partial_failure``.

    Symmetric with ``lock.py::_apply_openclaw``. Per L1: never rolls back
    unlock-core. Per L2 (revised 2026-05-08 by the verification gauntlet):
    detected+failed returns True so the caller raises ``typer.Exit(73)``
    AFTER unlock-core's `.env` restoration commits.

    Returns:
        True if detected+failed (caller should exit non-zero post-commit).
        False if all succeeded OR OpenClaw was not detected on this host.

    Side effects:
        Writes ``$WORTHLESS_HOME/last-lock-status.json`` so ``worthless
        status`` reports DEGRADED state across terminal sessions.
    """
    if not restores:
        # Nothing to undo on the OpenClaw side — also nothing to record.
        return False
    # G4 MED-1 (post-review security follow-up): Stage A zeros
    # ``plaintext_key`` per-iteration in its ``finally`` (integration.py:1397).
    # That covers the happy path, but ``apply_unlock`` can return BEFORE Stage A
    # runs at all (no OpenClaw detected; symlinked config; pre-Stage-A raise) —
    # in those paths the reconstructed real-key bytearrays would live in heap
    # until GC. Wrap the whole function body so every restore's key gets a
    # final zeroing pass on every exit. ``zero_buf`` on an already-zeroed
    # bytearray is idempotent, so this doesn't double-zero or fight Stage A.
    try:
        try:
            result = _openclaw_integration.apply_unlock(restores=restores)
        except OpenclawIntegrationError as exc:
            logger.warning("openclaw apply_unlock raised unexpectedly: %s", exc)
            _emit_openclaw_unlock_failure(console, home, len(restores), str(exc))
            return True
        except Exception as exc:  # noqa: BLE001 — last-resort guard for L1
            logger.warning("openclaw apply_unlock raised unexpectedly: %s", exc)
            _emit_openclaw_unlock_failure(console, home, len(restores), str(exc))
            return True

        # ---- Classify the result ---------------------------------------------
        if not result.detected:
            # No OpenClaw on this host — record absent, no UI noise.
            _write_unlock_sentinel(home, status="ok", openclaw="absent", alias_count=0, events=())
            return False

        # Trust-fix classification lives on OpenclawApplyResult.has_failure
        # (single-sourced — see integration.py docstring).
        # WOR-621 F2 G4: ``providers_set`` carries the providers Stage A actually
        # RESTORED to their pre-lock entries (G1 renamed the field's semantic
        # accordingly). The CLI copy reflects the real action — "restored", not
        # "removed" (decoy-era wording deferred from G1 review).
        if not result.has_failure:
            if result.providers_set:
                console.print_success(
                    f"[OK] OpenClaw: restored {len(result.providers_set)} provider(s)"
                )
                for provider_name in result.providers_set:
                    console.print_hint(f"   • {provider_name}")
            if result.skill_installed:
                console.print_hint("   • ~/.openclaw/workspace/skills/worthless/ — removed")
            _write_unlock_sentinel(
                home,
                status="ok",
                openclaw="ok",
                alias_count=len(result.providers_set),
                events=tuple(e.to_dict() for e in result.events),
            )
            return False

        # Detected + failed: trust-failure path.
        console.print_failure("[FAIL] OpenClaw cleanup did NOT complete.")
        console.print_warning(
            "   Your .env is restored, but the original OpenClaw provider entries"
        )
        console.print_warning("   may not have been restored in ~/.openclaw/openclaw.json — re-run")
        console.print_warning("   `worthless unlock` or `worthless doctor` to repair.")
        for name, reason in result.providers_skipped:
            console.print_warning(f"   skipped {name} ({reason})")
        for event in result.events:
            if event.level == "error":
                console.print_warning(f"   {event.code.value} — {event.detail}")
        _write_unlock_sentinel(
            home,
            status="partial",
            openclaw="failed",
            alias_count=len(result.providers_set),
            events=tuple(e.to_dict() for e in result.events),
        )
        return True
    finally:
        # Idempotent zeroing safety net (SR-02). Stage A already zeros on
        # the happy path; this catches early-returns + pre-Stage-A raises.
        for r in restores:
            if r.plaintext_key is not None:
                zero_buf(r.plaintext_key)


def _emit_openclaw_unlock_failure(
    console,  # noqa: ANN001
    home: WorthlessHome,
    alias_count: int,
    detail: str,
) -> None:
    """Print [FAIL] block + write partial sentinel for the unexpected-raise path."""
    console.print_failure("[FAIL] OpenClaw cleanup did NOT complete.")
    console.print_warning("   Your .env is restored, but the original OpenClaw provider entries")
    console.print_warning(
        "   may not have been restored in ~/.openclaw/openclaw.json — repair via:"
    )
    console.print_warning(f"   detail: {detail}")
    console.print_warning("")
    console.print_warning("   Fix:    worthless doctor")
    _write_unlock_sentinel(
        home,
        status="partial",
        openclaw="failed",
        alias_count=alias_count,
        events=({"code": "openclaw.unexpected_raise", "level": "error", "detail": detail},),
    )


def _write_unlock_sentinel(
    home: WorthlessHome,
    *,
    status: str,
    openclaw: str,
    alias_count: int,
    events: tuple[dict[str, str], ...],
) -> None:
    """Best-effort sentinel write. Failure is logged + swallowed."""
    try:
        from worthless.cli.sentinel import write_sentinel

        write_sentinel(
            home.base_dir,
            status=status,
            openclaw=openclaw,
            alias_count=alias_count,
            events=list(events),
        )
    except OSError as exc:
        logger.warning("sentinel write failed: %s", exc)
    except Exception as exc:  # noqa: BLE001 — sentinel is best-effort
        logger.warning("sentinel write failed unexpectedly: %s", exc)


def register_unlock_commands(app: typer.Typer) -> None:
    """Register the unlock command on the Typer app."""

    @app.command()
    @error_boundary
    def unlock(
        alias: str | None = typer.Option(
            None, "--alias", "-a", help="Specific alias to unlock (default: all)"
        ),
        env: Path | None = typer.Option(
            None,
            "--env",
            "-e",
            help="Path to .env file (default: ./.env if present)",
        ),
    ) -> None:
        """Restore original API keys from shards.

        Transactional: on any HMAC verification failure, .env is left
        byte-identical and DB rows are not deleted.
        """
        console = get_console()
        db_was_missing, missing_db_path = _db_missing_after_completed_bootstrap()
        home = get_home()

        # Detect whether the user passed --env explicitly. The HF4
        # discriminator (raise on shard-shape values without DB rows)
        # only fires when the user named a path — running ``unlock``
        # from a directory with someone else's .env should not surprise-
        # error the user with HF4's hard hint. Per worthless-pnn2.
        explicit_env = env is not None
        if env is None:
            env = Path(".env")

        def _raise_unrecognised_shards() -> None:
            # HF4 (worthless-5u6y): if the .env contains values that look
            # like LLM provider keys but have no matching DB row here, the
            # user has unrecoverable shard-A values — fail loudly. Otherwise
            # the .env is genuinely empty and the caller's "no enrolled
            # keys" warning is correct.
            #
            # Pnn2: only run this discriminator when the user explicitly
            # named --env. With the default (CWD ./.env), we cannot tell
            # whether shard-shape values belong to a different project the
            # user is just visiting; warning + exit 0 is the safer default.
            if not explicit_env:
                return
            unrecognised = _unrecognised_shards(env)
            if not unrecognised:
                return
            if db_was_missing:
                raise WorthlessError(
                    ErrorCode.KEY_NOT_FOUND,
                    f"Local Worthless database is missing at {missing_db_path}. "
                    f"This locked .env cannot be restored from this home because "
                    f"the enrollment records are gone. Restore the database from "
                    f"backup, recover on the original machine, or replace "
                    f"{', '.join(unrecognised)} with raw key(s) and run "
                    f"`worthless lock --env {env}` again.",
                )
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                f"No enrollment found for shard-shape value(s) in {env}: "
                f"{', '.join(unrecognised)}. If this .env was copied from "
                f"another machine, those values are unrecognised shards "
                f"here — re-lock from the original machine, or remove "
                f"them manually if they are junk.",
            )

        # Returns True iff the OpenClaw cleanup stage hit detected+failed
        # (Phase 2.c trust-fix per spec L2 revised 2026-05-08). Caller
        # raises typer.Exit(73) AFTER unlock-core's .env restoration
        # commits. False = full success or OpenClaw absent.
        async def _unlock_async() -> bool:
            async with open_repo(home) as repo:
                await repo.initialize()
                # Trust-fix: collect (provider, alias) tuples from `planned`
                # for OpenClaw symmetric undo. Drives _apply_openclaw_unlock
                # at the end.
                planned: list[_PlannedRestore] = []

                if alias:
                    planned = await _unlock_batch([alias], home, repo, env)
                    if not planned:
                        # If a typo'd --alias points at a .env full of shard-shape
                        # values, silent success is the worst possible feedback.
                        _raise_unrecognised_shards()
                        console.print_warning(f"Alias not found or no keys restored: {alias}.")
                        return False
                    console.print_success(_format_restored_line(planned[0]))
                else:
                    env_str = str(env.resolve())
                    all_enrollments = await repo.list_enrollments()
                    aliases = sorted(
                        {e.key_alias for e in all_enrollments if e.env_path == env_str}
                    )
                    if not aliases:
                        _raise_unrecognised_shards()
                        console.print_warning("No enrolled keys found.")
                        return False

                    planned = await _unlock_batch(aliases, home, repo, env)
                    for p in planned:
                        console.print_success(_format_restored_line(p))
                    n = len(planned)
                    if n > 1:
                        # Per-key lines already covered N=1; only emit the summary
                        # when there's something to count.
                        console.print_success(f"[OK] {n} key(s) restored.")

                # Phase 2.c: OpenClaw symmetric undo. Per L1: NEVER aborts
                # unlock-core success. Per L2 (revised 2026-05-08): detected+failed
                # returns True so the caller raises typer.Exit(73) AFTER
                # unlock-core's .env restoration commits.
                # WOR-621 F2 G4: build real OcRestore records — MAC-verify the
                # captured rollback record, then read the plaintext key back
                # from the just-restored .env (or pass None for the secretref
                # branch). Stage A fail-safe-skips anything we couldn't verify
                # so the entry stays on the proxy rather than getting a
                # synthetic/tampered restore.
                restores = await _build_oc_restores(planned, repo, console)
                return _apply_openclaw_unlock(restores, console, home)

        with acquire_lock(home):
            partial_failure = asyncio.run(_unlock_async())

        # Trust-fix (2026-05-08): symmetric with lock — exit non-zero AFTER
        # unlock-core has restored the .env. Sentinel already updated by
        # _apply_openclaw_unlock; the [FAIL] block already printed.
        if partial_failure:
            raise typer.Exit(code=73)

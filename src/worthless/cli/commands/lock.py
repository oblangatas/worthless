"""Lock command -- scan .env, split keys (format-preserving), store shards."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import stat
import sys
from dataclasses import dataclass
from typing import NamedTuple
from pathlib import Path

import typer

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import WorthlessHome, acquire_lock, get_home
from worthless.cli.code_scanner import scan_for_hardcoded_provider_urls
from worthless.cli.commands.scan import _format_code_findings_human
from worthless.cli.process import resolve_port
from worthless.cli.console import WorthlessConsole, get_console
from worthless.cli.scanner import scan_source_for_hardcoded_provider_urls
from worthless.cli.dotenv_rewriter import (
    rewrite_env_keys,
    scan_env_keys,
)
from worthless.cli.errors import (
    ErrorCode,
    UnsafeReason,
    UnsafeRewriteRefused,
    WorthlessError,
    error_boundary,
    sanitize_exception,
)
from worthless.cli.key_patterns import CANONICAL_KEY_VAR_RE, detect_prefix
from worthless.cli.keystore import keyring_available
from worthless.cli.providers import lookup_by_name, lookup_by_url
from worthless.crypto.reconstruction import (
    _verify_commitment,  # noqa: PLC2701 — intentional internal use for re-lock guard
)
from worthless.crypto.splitter import (
    derive_shard_a_fp,
    reconstruct_key_fp,
    split_key_fp,
)
from worthless.crypto.types import zero_buf
from worthless.exceptions import ShardTamperedError
from worthless.openclaw import audit as _oc_audit
from worthless.openclaw import integration as _openclaw_integration
from worthless.openclaw.errors import OpenclawIntegrationError
from worthless.storage.repository import ShardRepository, StoredShard

logger = logging.getLogger(__name__)

# Map of supported wire protocols → canonical fallback env var name.
# Used only when the user's API-key var doesn't follow the ``<NAME>_API_KEY``
# convention. After 8rqs, ``wrap`` no longer owns this — lock has the only
# remaining consumer (plus ``unlock`` which imports it), so the map lives here.
#
# Keys here are WIRE PROTOCOLS (``openai``, ``anthropic``), NOT registry
# provider names. Post-HF1, ``detect_provider`` can return registry names
# like ``openrouter`` / ``groq`` / ``together`` that all speak the
# ``openai`` wire protocol. ``_pass1_db_writes`` translates the detected
# registry name to its protocol via ``lookup_by_name`` before checking
# this map. ``worthless-9t74`` will promote that translation into a
# structural ``provider name`` vs ``protocol`` separation post-merge.
# sanitise_for_message (from _oc_audit) covers C0/C1 + bidi overrides + BOM —
# a strict superset of the old _CTRL_RE; no separate regex needed here.

_PROVIDER_ENV_MAP: dict[str, str] = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
}

_SUPPORTED_PROTOCOLS = frozenset(_PROVIDER_ENV_MAP.keys())
_ALIAS_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _shard_b_storage_label() -> str:
    """Human label for where the non-.env shard lives."""
    return "your system keystore" if keyring_available() else "a local key file"


def _make_alias(provider: str, api_key: str) -> str:
    """Deterministic alias: provider + first 8 hex chars of sha256(key)."""
    digest = hashlib.sha256(bytearray(api_key.encode())).hexdigest()[:8]  # nosec B303 -- non-cryptographic fingerprint
    return f"{provider}-{digest}"


def _proxy_base_url(alias: str) -> str:
    """Build the proxy BASE_URL for a given alias.

    Reads ``WORTHLESS_PROXY_HOST`` from the environment so Docker and LAN
    deployments can write ``host.docker.internal`` (or any reachable hostname)
    into openclaw.json instead of the loopback address.
    """
    host = os.environ.get("WORTHLESS_PROXY_HOST", "127.0.0.1")
    return f"http://{host}:{resolve_port(None)}/{alias}/v1"


def _derive_base_url_var(var_name: str, provider: str) -> str:
    """Derive the corresponding ``*_BASE_URL`` variable name for a key var.

    Convention: ``OPENROUTER_API_KEY`` → ``OPENROUTER_BASE_URL``. Falls
    back to the canonical ``_PROVIDER_ENV_MAP`` mapping when the key var
    name doesn't end in ``_API_KEY``.
    """
    if var_name.endswith("_API_KEY"):
        return var_name[: -len("_API_KEY")] + "_BASE_URL"
    return _PROVIDER_ENV_MAP.get(provider, "OPENAI_BASE_URL")


def _resolve_upstream_base_url(
    base_url_var: str, env_values: dict[str, str | None], provider: str
) -> str:
    """Pick the upstream URL for the DB row.

    Prefers the user's explicit ``*_BASE_URL`` value from ``.env`` when set
    AND when that URL is in the provider registry. Otherwise falls back to
    the bundled registry default for the provider.

    Refuses unregistered user URLs (M3 / Blocker #1): an attacker who can
    write to .env should not be able to redirect the proxy at an arbitrary
    upstream. worthless-rzi1 (P1 follow-up) adds per-request re-validation
    to close the post-lock-tamper variant; worthless-8fbg adds RFC1918 /
    loopback hardening. See seam 2 in worthless-8rqs design notes.
    """
    user_value = env_values.get(base_url_var)
    if user_value:
        if lookup_by_url(user_value) is None:
            raise WorthlessError(
                ErrorCode.INVALID_INPUT,
                f"unknown upstream URL {user_value!r} from {base_url_var}. "
                "Register it first: 'worthless providers register --name <n> "
                "--url <url> --protocol openai|anthropic'.",
            )
        return user_value
    entry = lookup_by_name(provider)
    if entry is None:  # pragma: no cover — provider is validated above
        return "https://api.openai.com/v1"
    return entry.url


@dataclass(eq=False)
class _PlannedUpdate:
    """One key's in-flight lock plan — built pass-1, consumed by hook + unwind."""

    alias: str
    var_name: str
    env_path_str: str
    provider: str
    shard_a: bytearray
    shard_b: bytearray
    commitment: bytearray
    nonce: bytearray
    prefix: str
    charset: str
    was_fresh_enroll: bool
    # 8rqs Phase 7: per-enrollment base_url plumbing. ``base_url_var`` is the
    # .env variable name to write the local proxy URL to (e.g.
    # ``OPENROUTER_BASE_URL`` for ``OPENROUTER_API_KEY``); preserves the
    # user's naming convention rather than forcing OPENAI_BASE_URL.
    base_url_var: str = ""

    def zero(self) -> None:
        for buf in (self.shard_a, self.shard_b, self.commitment, self.nonce):
            buf[:] = b"\x00" * len(buf)


def _build_verify_hook(planned: list[_PlannedUpdate]):
    """Return a zero-arg hook that raises on any shard round-trip failure.

    Fires inside ``safe_rewrite`` after the tmp fsync but before the atomic
    rename — see ``safe_rewrite._hook_before_replace``. Raising aborts the
    rename, leaving ``.env`` byte-identical.
    """

    def _hook() -> None:
        for p in planned:
            reconstructed: bytearray | None = None
            try:
                reconstructed = reconstruct_key_fp(
                    p.shard_a,
                    p.shard_b,
                    p.commitment,
                    p.nonce,
                    p.prefix,
                    p.charset,
                )
            except ShardTamperedError:
                # from None: drop traceback chain holding shard-material locals.
                raise UnsafeRewriteRefused(UnsafeReason.VERIFY_FAILED) from None
            except ValueError as exc:
                raise WorthlessError(
                    ErrorCode.SHARD_STORAGE_FAILED,
                    sanitize_exception(exc, generic="shard reconstruction malformed"),
                ) from None
            except Exception:  # noqa: BLE001 — preserve opaque refusal contract
                raise UnsafeRewriteRefused(UnsafeReason.VERIFY_FAILED) from None
            finally:
                if reconstructed is not None:
                    zero_buf(reconstructed)

    return _hook


async def _select_unlocked_keys(
    repo: ShardRepository,
    scanned: list[tuple[str, str, str]],
    enrollments: list,
    env_str: str,
) -> list[tuple[str, str, str]]:
    """Drop enrolled locations only when the current value is still shard-A.

    ``scan_env_keys`` cannot tell whether an enrolled ``VAR`` still contains
    the protected shard-A or whether the user pasted a new raw key into the
    same location. For re-lock, we must suppress the former and process the
    latter.
    """
    by_location: dict[tuple[str, str], list] = {}
    for enrollment in enrollments:
        if enrollment.env_path:
            by_location.setdefault((enrollment.var_name, enrollment.env_path), []).append(
                enrollment
            )

    candidates: list[tuple[str, str, str]] = []
    for var_name, value, provider in scanned:
        location_enrollments = by_location.get((var_name, env_str), [])
        if not location_enrollments:
            candidates.append((var_name, value, provider))
            continue

        still_protected = False
        for enrollment in location_enrollments:
            encrypted = await repo.fetch_encrypted(enrollment.key_alias)
            if encrypted is None or encrypted.prefix is None or encrypted.charset is None:
                continue
            stored = await repo.decrypt_shard(encrypted)
            shard_a = bytearray(value.encode("utf-8"))
            reconstructed: bytearray | None = None
            try:
                reconstructed = reconstruct_key_fp(
                    shard_a,
                    stored.shard_b,
                    stored.commitment,
                    stored.nonce,
                    encrypted.prefix,
                    encrypted.charset,
                )
                still_protected = True
                break
            except (ShardTamperedError, ValueError, KeyError, UnicodeDecodeError, IndexError):
                # UnicodeDecodeError: corrupt UTF-8 shard bytes in DB row.
                # IndexError: mismatched shard lengths past the explicit check.
                # Both are safe-fail — treat the enrollment as not still-protected
                # and let the caller re-lock the key.
                continue
            finally:
                zero_buf(shard_a)
                if reconstructed is not None:
                    zero_buf(reconstructed)
                stored.zero()

        if not still_protected:
            candidates.append((var_name, value, provider))

    return candidates


async def _delete_superseded_location_enrollments(
    repo: ShardRepository,
    *,
    alias: str,
    var_name: str,
    env_path: str,
) -> None:
    """Remove stale enrollments for a var/path after a rotated key is locked."""
    enrollments = await repo.list_enrollments()
    stale_aliases = {
        e.key_alias
        for e in enrollments
        if e.var_name == var_name and e.env_path == env_path and e.key_alias != alias
    }
    for stale_alias in stale_aliases:
        await repo.delete_enrollment(stale_alias, env_path)
        if not await repo.list_enrollments(stale_alias):
            await repo.delete_enrolled(stale_alias)


async def _pass1_db_writes(
    repo: ShardRepository,
    candidates: list[tuple[str, str, str]],
    env_str: str,
    token_budget_daily: int | None,
    planned_out: list[_PlannedUpdate],
    env_values: dict[str, str | None],
) -> None:
    """Do every DB write; append each ``_PlannedUpdate`` to *planned_out*.

    MUTATES *planned_out* so partial-failure paths still expose the
    bytearrays the caller's ``finally`` needs to zero.

    *env_values* is the parsed ``.env`` (from ``dotenv_values``) so we can
    read the user's existing ``*_BASE_URL`` value at lock time and store
    that as the upstream URL in the DB.
    """
    for var_name, value, detected_provider in candidates:
        # Translate registry-name → wire-protocol. Post-HF1,
        # ``detect_provider`` returns registry names like ``openrouter``
        # for OpenAI-protocol-compatible services. Lock's downstream uses
        # (alias building, _PROVIDER_ENV_MAP fallback, _SUPPORTED_PROTOCOLS
        # gate, DB ``provider`` column for proxy adapter dispatch) all
        # need the WIRE PROTOCOL, not the registry name.
        #
        # Pre-HF1, detect_provider only returned ``openai``/``anthropic``,
        # so name == protocol and this translation was a no-op. Post-HF1
        # we MUST resolve via the registry or OpenRouter keys would be
        # silently skipped, leaving the plaintext key in .env (the exact
        # leak 8rqs is meant to close). worthless-9t74 will promote this
        # into a structural separation of name/protocol post-merge.
        registry_entry = lookup_by_name(detected_provider)
        protocol = registry_entry.protocol if registry_entry else detected_provider

        if protocol not in _SUPPORTED_PROTOCOLS:
            get_console().print_warning(
                f"Skipping {var_name}: wire protocol {protocol!r} not yet "
                f"supported (detected provider: {detected_provider!r})"
            )
            continue

        # Use the wire protocol for everything downstream so adapter
        # dispatch in the proxy picks the right format, and so the alias
        # namespace stays stable across pre- and post-HF1 enrollments.
        provider = protocol

        base_url_var = _derive_base_url_var(var_name, provider)

        # M4 (Blocker #2): warn on non-canonical var names. Apps that read
        # MY_OPENAI_KEY directly (instead of OPENAI_API_KEY) and construct
        # the SDK client without base_url= will fall through to the real
        # provider — bypassing the proxy and leaking shard-A on the wire.
        # Soft warning per product-manager review; worthless-v5sy adds
        # --strict for CI/team policy. See seam 5 in worthless-8rqs notes.
        if not CANONICAL_KEY_VAR_RE.match(var_name):
            get_console().print_warning(
                f"env var {var_name!r} doesn't match the canonical "
                f"'<PROVIDER>_API_KEY' pattern. lock will set "
                f"{base_url_var}, but if your app reads {var_name} "
                f"without auto-detecting {base_url_var}, requests will "
                f"bypass the proxy and send shard-A upstream. Rename to "
                f"follow <PROVIDER>_API_KEY to silence this warning."
            )

        upstream_base_url = _resolve_upstream_base_url(base_url_var, env_values, provider)

        alias = _make_alias(provider, value)

        # Cross-path collision check: if this alias is already enrolled from a
        # DIFFERENT .env path, the new shard-B upsert will replace the old one —
        # making the original enrollment's shard-A unable to reconstruct. Warn
        # so the user can decide whether to unlock the original path first.
        existing_enrollments = await repo.list_enrollments(alias)
        for existing in existing_enrollments:
            if existing.env_path and existing.env_path != env_str:
                get_console().print_warning(
                    f"Warning: alias '{alias}' already enrolled from "
                    f"{existing.env_path} — re-locking from a different "
                    "path will break that enrollment."
                )
                break  # one warning per alias is sufficient

        db_shard = await repo.fetch_encrypted(alias)

        if db_shard is not None:
            if not db_shard.prefix or not db_shard.charset:
                raise WorthlessError(
                    ErrorCode.SHARD_STORAGE_FAILED,
                    f"Alias {alias!r} predates format-preserving split. "
                    "Run `worthless unlock --all` then re-lock this .env.",
                )
            stored_decrypted = await repo.decrypt_shard(db_shard)
            verify_payload = bytearray(value.encode("utf-8"))
            try:
                try:
                    _verify_commitment(
                        verify_payload,
                        stored_decrypted.commitment,
                        stored_decrypted.nonce,
                    )
                except ShardTamperedError as exc:
                    raise WorthlessError(
                        ErrorCode.SHARD_STORAGE_FAILED,
                        f"Alias {alias!r} exists but {var_name} does not match "
                        "the originally-locked key (commitment mismatch).",
                    ) from exc

                derived_shard_a = derive_shard_a_fp(
                    value,
                    stored_decrypted.shard_b,
                    db_shard.prefix,
                    db_shard.charset,
                )
                # INSERT OR REPLACE keeps shard_a_enc in sync with the auth token
                # written to openclaw.json.  INSERT OR IGNORE would leave the old
                # shard_b in DB on re-lock, causing XOR reconstruction to fail permanently.
                await repo.upsert_locked_shard(
                    alias,
                    stored_decrypted,
                    prefix=db_shard.prefix,
                    charset=db_shard.charset,
                    base_url=db_shard.base_url or upstream_base_url,
                )
                await repo.add_enrollment(alias, var_name=var_name, env_path=env_str)
                await _delete_superseded_location_enrollments(
                    repo,
                    alias=alias,
                    var_name=var_name,
                    env_path=env_str,
                )
                planned_out.append(
                    _PlannedUpdate(
                        alias=alias,
                        var_name=var_name,
                        env_path_str=env_str,
                        provider=provider,
                        shard_a=derived_shard_a,
                        shard_b=bytearray(stored_decrypted.shard_b),
                        commitment=bytearray(stored_decrypted.commitment),
                        nonce=bytearray(stored_decrypted.nonce),
                        prefix=db_shard.prefix,
                        charset=db_shard.charset,
                        was_fresh_enroll=False,
                        base_url_var=base_url_var,
                    )
                )
            finally:
                zero_buf(verify_payload)
                stored_decrypted.zero()
            continue

        # Fresh enroll
        try:
            prefix = detect_prefix(value, provider)
        except ValueError:
            prefix = ""
        sr = split_key_fp(value, prefix, provider)
        try:
            stored = StoredShard(
                shard_b=sr.shard_b,
                commitment=sr.commitment,
                nonce=sr.nonce,
                provider=provider,
            )
            # store_enrolled() handles enrollment rows; upsert_locked_shard()
            # writes the shards row with shard_a_enc included from the first lock.
            await repo.upsert_locked_shard(
                alias,
                stored,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=upstream_base_url,
            )
            await repo.store_enrolled(
                alias,
                stored,
                var_name=var_name,
                env_path=env_str,
                token_budget_daily=token_budget_daily,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=upstream_base_url,
            )
            planned_out.append(
                _PlannedUpdate(
                    alias=alias,
                    var_name=var_name,
                    env_path_str=env_str,
                    provider=provider,
                    shard_a=bytearray(sr.shard_a),
                    shard_b=bytearray(sr.shard_b),
                    commitment=bytearray(sr.commitment),
                    nonce=bytearray(sr.nonce),
                    prefix=sr.prefix,
                    charset=sr.charset,
                    was_fresh_enroll=True,
                    base_url_var=base_url_var,
                )
            )
            await _delete_superseded_location_enrollments(
                repo,
                alias=alias,
                var_name=var_name,
                env_path=env_str,
            )
        finally:
            sr.zero()


def _batch_rewrite(
    env_path: Path,
    planned: list[_PlannedUpdate],
    keys_only: bool,
    existing_env_keys: set[str],
) -> None:
    """One ``safe_rewrite`` call for every planned update + BASE_URL changes."""
    updates: dict[str, str] = {p.var_name: p.shard_a.decode("utf-8") for p in planned}
    additions: dict[str, str] = {}
    if not keys_only:
        # When multiple keys share the same base_url_var slot (e.g. both
        # OPENAI_API_KEY and API_KEY derive OPENAI_BASE_URL), the canonical
        # <PREFIX>_API_KEY name wins regardless of file order. Without this,
        # a non-canonical key's alias can claim the slot and the canonical
        # key's shard-A gets routed to the wrong alias → 401. (worthless-sb8v)
        slot_winner: dict[str, _PlannedUpdate] = {}
        for p in planned:
            if not p.base_url_var:
                continue
            existing = slot_winner.get(p.base_url_var)
            canonical_var = p.base_url_var[: -len("_BASE_URL")] + "_API_KEY"
            if existing is None or p.var_name == canonical_var:
                slot_winner[p.base_url_var] = p

        for slot, p in slot_winner.items():
            local_proxy = _proxy_base_url(p.alias)
            if slot in existing_env_keys:
                updates[slot] = local_proxy
            elif slot not in updates:
                additions[slot] = local_proxy
                sys.stderr.write(
                    f"worthless: added {slot}={local_proxy} to {env_path} (was missing)\n"
                )
                sys.stderr.flush()

    rewrite_env_keys(
        env_path,
        updates,
        additions=additions or None,
        _hook_before_replace=_build_verify_hook(planned),
    )


async def _compensating_unwind(
    repo: ShardRepository, planned: list[_PlannedUpdate]
) -> list[Exception]:
    """Best-effort rollback of pass-1 DB writes. Returns list of failures."""
    errors: list[Exception] = []
    for p in reversed(planned):
        try:
            await repo.delete_enrollment(p.alias, p.env_path_str)
            if p.was_fresh_enroll:
                # Fresh-enroll created this shard + its only enrollment in this
                # same pass — delete_enrollment above just removed the last one.
                await repo.delete_enrolled(p.alias)
        except Exception as exc:  # noqa: BLE001 — keep unwinding subsequent aliases
            logger.debug("Unwind failed for alias %s", p.alias, exc_info=True)
            errors.append(exc)
    return errors


def _apply_openclaw(
    planned: list[_PlannedUpdate],
    console,  # noqa: ANN001 — Console type is opaque from this layer
    quiet: bool,
    home: WorthlessHome,
) -> bool:
    """OpenClaw integration call + sentinel write. Returns ``partial_failure``.

    Per L1 in ``engineering/research/openclaw-WOR-431-phase-2-spec.md``:
    failures here NEVER roll back lock-core. Per L2 (revised 2026-05-08
    by the verification gauntlet): when OpenClaw is **detected** AND the
    integration stage fails, the user is in a false-invariant state ("lock
    succeeded but my agent traffic isn't gated"). Caller (`_lock_keys`)
    raises ``typer.Exit(73)`` AFTER lock-core's `.env`/DB writes are
    fully committed — the binding contract is preserved, but the user
    learns about the partial failure unmissably.

    Returns:
        True if detected+failed (caller should exit non-zero post-commit).
        False if all succeeded OR OpenClaw was not detected on this host.

    Side effects:
        Writes ``$WORTHLESS_HOME/last-lock-status.json`` so ``worthless
        status`` can report DEGRADED state across terminal sessions.
        Sentinel write failure is itself best-effort (logged, swallowed).
    """
    # Each alias gets its own shard-A (format-preserving split value) as the
    # apiKey in openclaw.json. The agent sends shard-A as Bearer on each request;
    # the proxy validates via commitment check (no stable token needed).
    triples: list[tuple[str, str, str]] = [
        (p.provider, p.alias, p.shard_a.decode("utf-8")) for p in planned
    ]
    # Plumb the SAME port lock just used for .env's BASE_URL vars so
    # openclaw.json's baseUrl matches a non-default --port. Without this,
    # users on non-default ports got a wrong baseUrl in openclaw.json
    # while .env's BASE_URL was correct (split-brain proxy URL).
    # Also honour WORTHLESS_PROXY_HOST so all-container Docker deployments
    # write the Docker-internal service name (e.g. "proxy") instead of
    # 127.0.0.1, which is unreachable inside the openclaw container.
    _proxy_host = os.environ.get("WORTHLESS_PROXY_HOST", "127.0.0.1")
    proxy_base_url = f"http://{_proxy_host}:{resolve_port(None)}"
    try:
        result = _openclaw_integration.apply_lock(
            planned_updates=triples, proxy_base_url=proxy_base_url
        )
    except OpenclawIntegrationError as exc:
        # apply_lock's contract is "never raise". If it does, treat as
        # detected+failed (we don't know which, but the user is in a
        # genuinely broken state — surface it loudly).
        logger.warning("openclaw apply_lock raised unexpectedly: %s", exc)
        _emit_openclaw_failure(console, quiet, home, len(planned), str(exc))
        return True
    except Exception as exc:  # noqa: BLE001 — last-resort guard for L1
        logger.warning("openclaw apply_lock raised unexpectedly: %s", exc)
        _emit_openclaw_failure(console, quiet, home, len(planned), str(exc))
        return True

    # ---- Classify the result ---------------------------------------------
    if not result.detected:
        # No OpenClaw on this host — sentinel reflects "absent", not failure.
        _write_lock_sentinel(home, status="ok", openclaw="absent", alias_count=0, events=())
        return False

    # Trust-fix classification lives on OpenclawApplyResult.has_failure
    # (single-sourced — see integration.py docstring). Lock + unlock both
    # call this property.
    if not result.has_failure:
        # Fully successful integration — record OK + enumerate to user.
        if not quiet:
            console.print_success("[OK] OpenClaw integration:")
            for provider_name in result.providers_set:
                console.print_hint(
                    f"   • ~/.openclaw/openclaw.json — added provider '{provider_name}'"
                )
            if result.skill_installed:
                console.print_hint("   • ~/.openclaw/workspace/skills/worthless/ — installed skill")
            console.print_hint("   • Undo: worthless unlock")
        _write_lock_sentinel(
            home,
            status="ok",
            openclaw="ok",
            alias_count=len(result.providers_set),
            events=tuple(e.to_dict() for e in result.events),
        )
        return False

    # Detected + failed: the trust-failure path. Print [FAIL] block, write
    # sentinel as partial. Caller raises typer.Exit(73) after lock-core's
    # .env/DB writes finish committing.
    if not quiet:
        console.print_failure("[FAIL] OpenClaw integration did NOT complete.")
        console.print_warning("   Your .env is locked, but OpenClaw is still calling the")
        console.print_warning("   provider directly with the unsplit key.")
        for name, reason in result.providers_skipped:
            console.print_warning(f"   skipped {name} ({reason})")
        for event in result.events:
            if event.level == "error":
                console.print_warning(f"   {event.code.value} — {event.detail}")
        console.print_warning("")
        console.print_warning("   Fix:       worthless doctor")
        console.print_warning("   Roll back: worthless unlock")
    _write_lock_sentinel(
        home,
        status="partial",
        openclaw="failed",
        alias_count=len(result.providers_set),
        events=tuple(e.to_dict() for e in result.events),
    )
    return True


_CI_ENV_VARS = (
    # Broadly adopted de-facto standard (GitHub Actions, CircleCI, Travis, etc.)
    "CI",
    # Platform-specific vars for systems that don't always set CI=true
    "GITHUB_ACTIONS",  # GitHub Actions
    "GITLAB_CI",  # GitLab CI/CD
    "CI_SERVER",  # GitLab (alternative)
    "TF_BUILD",  # Azure Pipelines
    "CODEBUILD_BUILD_ID",  # AWS CodeBuild
    "BITBUCKET_BUILD_NUMBER",  # Bitbucket Pipelines
    "TEAMCITY_VERSION",  # TeamCity (attaches a real PTY — must be checked explicitly)
    "CIRCLECI",  # CircleCI (sets CI=true too, belt-and-suspenders)
)


def _scan_prompt_is_tty() -> bool:
    """Patchable TTY check — extracted so tests can override without touching sys.stdin.

    Returns False in known CI environments even when stdin appears to be a TTY
    (some CI systems attach a pseudo-TTY), ensuring prompts are never shown there.
    """
    if any(os.environ.get(v) for v in _CI_ENV_VARS):
        return False
    return hasattr(sys.stdin, "isatty") and sys.stdin.isatty()


def _maybe_prompt_code_scan(cwd: Path) -> None:
    """After successful enrollment, offer to scan source for hardcoded URLs.

    Contract:
    - Only called when count > 0 (keys were enrolled).
    - Scans from Path.cwd() (consistent with ``worthless scan --code``) so
      monorepos and non-default --env paths all get a full-project scan.
    - TTY  + findings → interactive "Scan now? [Y/n]"; Y prints findings.
    - non-TTY + findings → one-line warning to stderr (no prompt).
    - Zero findings → completely silent.
    - User pressing Ctrl-C at the prompt → treated as "no", exits cleanly.
    - Any other exception → swallowed; lock exit code is never affected.
    """
    try:
        findings = scan_for_hardcoded_provider_urls([cwd])
        if not findings:
            return
        count = len(findings)
        noun = "URL" if count == 1 else "URLs"
        summary = f"Found {count} hardcoded provider {noun} that will bypass the proxy."
        if _scan_prompt_is_tty():
            confirmed = typer.confirm(f"\n{summary} Scan now?", default=True)
            if not confirmed:
                return
            typer.echo(_format_code_findings_human(findings), err=True)
            typer.echo(
                "\nRun `worthless scan --code` at any time to see this again with fix"
                " instructions.",
                err=True,
            )
        else:
            typer.echo(
                f"\nWarning: {summary} Run `worthless scan --code` for details and"
                " fix instructions.",
                err=True,
            )
    except typer.Abort:
        # User pressed Ctrl-C at the "Scan now?" prompt — lock already succeeded,
        # treat this as a polite "no thanks" rather than an error.
        return
    except Exception:  # noqa: BLE001
        logger.debug("_maybe_prompt_code_scan raised, skipping", exc_info=True)


def _emit_openclaw_failure(
    console,  # noqa: ANN001
    quiet: bool,
    home: WorthlessHome,
    alias_count: int,
    detail: str,
) -> None:
    """Print [FAIL] block + write partial sentinel for the unexpected-raise path.

    Used when ``apply_lock`` raises despite contracting not to. Mirrors the
    in-line FAIL block above — we don't know exactly what failed, but the
    user is in a genuinely broken state and must be told loudly.
    """
    if not quiet:
        console.print_failure("[FAIL] OpenClaw integration did NOT complete.")
        console.print_warning("   Your .env is locked, but OpenClaw is still calling the")
        console.print_warning("   provider directly with the unsplit key.")
        console.print_warning(f"   detail: {detail}")
        console.print_warning("")
        console.print_warning("   Fix:       worthless doctor")
        console.print_warning("   Roll back: worthless unlock")
    _write_lock_sentinel(
        home,
        status="partial",
        openclaw="failed",
        alias_count=alias_count,
        events=({"code": "openclaw.unexpected_raise", "level": "error", "detail": detail},),
    )


def _write_lock_sentinel(
    home: WorthlessHome,
    *,
    status: str,
    openclaw: str,
    alias_count: int,
    events: tuple[dict[str, str], ...],
) -> None:
    """Best-effort sentinel write. Failure is logged + swallowed."""
    try:
        from worthless.cli.sentinel import write_sentinel  # noqa: PLC0415 — deferred import avoids circular dep at module load

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


def _print_lock_result(
    console: WorthlessConsole,
    fresh_count: int,
    relock_count: int,
    env_path: Path,
    home_base_dir: Path,
) -> None:
    """Emit the post-lock user-facing summary (called only when quiet=False)."""
    if fresh_count or relock_count:
        if fresh_count:
            # [OK] text prefix is the accessibility carrier — color/glyph
            # reinforce but are never the sole signal (monochrome, CI logs,
            # screen readers).
            noun = "key" if fresh_count == 1 else "keys"
            console.print_success(
                f"[OK] {fresh_count} {noun} split between this machine and "
                f"{_shard_b_storage_label()} — {env_path.name} no longer contains "
                f"a usable secret."
            )
        if relock_count:
            noun = "key" if relock_count == 1 else "keys"
            console.print_success(f"[OK] {relock_count} {noun} still protected.")
        env_home = os.environ.get("WORTHLESS_HOME")
        if env_home and home_base_dir.resolve() != (Path.home() / ".worthless").resolve():
            typer.echo(
                f"Warning: using non-default home {home_base_dir} (WORTHLESS_HOME is set)", err=True
            )
        if fresh_count:
            console.print_hint(
                "Next: run `worthless wrap <command>` or `worthless up` for daemon mode"
            )
        _maybe_prompt_code_scan(Path.cwd())
    else:
        console.print_warning("No unprotected API keys found.")


def _openclaw_audit_preflight() -> _oc_audit.AuditGateHandle | None:
    """Run OpenClaw secrets audit pre-flight before worthless lock writes.

    Returns None if OpenClaw is not detected on this host or binary is not
    available (gate skipped, _apply_openclaw handles the partial-failure path).
    Raises typer.Exit(73) if blocking plaintext findings are present.
    Raises typer.Exit(87) on subprocess failure or unknown finding codes.
    """
    state = _openclaw_integration.detect()
    if not state.present:
        return None

    try:
        openclaw_bin = _oc_audit.resolve_openclaw_bin()
    except _oc_audit.AuditGateError as exc:
        if os.environ.get("WORTHLESS_OPENCLAW_BIN"):
            # Explicit path configured but broken → hard fail
            typer.echo(f"worthless lock: openclaw audit gate failed: {exc}", err=True)
            raise typer.Exit(code=87) from exc
        # Binary not found in PATH → skip gate, let _apply_openclaw surface it
        logger.debug("openclaw audit gate skipped: %s", exc)
        return None

    try:
        result, classification = _oc_audit.run_and_classify(openclaw_bin)
    except _oc_audit.AuditGateError as exc:
        typer.echo(f"worthless lock: openclaw audit gate failed: {exc}", err=True)
        raise typer.Exit(code=87) from exc

    if classification.unknown_codes:
        typer.echo(
            f"worthless lock: openclaw audit returned unknown finding codes "
            f"{', '.join(classification.unknown_codes)} — exit 87",
            err=True,
        )
        raise typer.Exit(code=87)

    if classification.blocking:
        typer.echo(_oc_audit.format_gate_error_message(classification.blocking), err=True)
        raise typer.Exit(code=73)

    return _oc_audit.AuditGateHandle(
        openclaw_bin=openclaw_bin,
        pre_hashes=_oc_audit.snapshot_hashes(result.files_scanned),
    )


def _openclaw_audit_postflight(gate: _oc_audit.AuditGateHandle) -> None:
    """Post-flight TOCTOU re-audit after lock-core write commits.

    Skips the second subprocess entirely if file hashes are unchanged since
    pre-flight (covers the 99.99% case where no external process touched the
    OpenClaw config during the lock write).

    Raises typer.Exit(87) if new blocking findings appeared since pre-flight,
    indicating the OpenClaw config was modified between the two audit passes.

    Recovery note: if this raises, ``_batch_rewrite`` has already committed
    shard-A values to the .env, but ``_compensating_unwind`` (in the caller's
    except block) rewinds the DB rows. The .env may therefore contain shard-A
    values while DB rows are gone. Re-running ``worthless lock`` recovers: the
    next pre-flight will see the same shard-A values as a PLAINTEXT_FOUND for
    ``worthless-openai`` (allowlisted) and proceed normally once the user
    fixes the OpenClaw plaintext that caused this exit.
    """
    post_hashes = _oc_audit.snapshot_hashes(gate.pre_hashes.keys())
    if post_hashes == gate.pre_hashes:
        # Files unchanged — no need to re-run the 30s subprocess.
        return

    try:
        _, post_class = _oc_audit.run_and_classify(gate.openclaw_bin)
    except _oc_audit.AuditGateError as exc:
        typer.echo(f"worthless lock: post-flight audit failed: {exc}", err=True)
        raise typer.Exit(code=87) from exc

    if post_class.unknown_codes:
        typer.echo(
            f"worthless lock: post-flight audit returned unknown codes "
            f"{', '.join(post_class.unknown_codes)} — exit 87",
            err=True,
        )
        raise typer.Exit(code=87)

    if post_class.blocking:
        detail = _oc_audit.format_gate_error_message(post_class.blocking)
        typer.echo(
            f"worthless lock: state changed between pre-flight and post-flight "
            f"— new plaintext detected, re-run worthless lock.\n{detail}",
            err=True,
        )
        raise typer.Exit(code=87)


def _lock_keys(
    env_path: Path,
    home: WorthlessHome,
    provider_override: str | None = None,
    token_budget_daily: int | None = None,
    quiet: bool = False,
    keys_only: bool = False,
    allow_hardcoded_urls: bool = False,
) -> int:
    """Transactional multi-key lock.

    Pass-1 does every DB write and builds a ``_PlannedUpdate`` list. A single
    ``rewrite_env_keys`` call then updates ``.env`` atomically, with a verify
    hook that reconstructs every shard before the rename commits. On any
    failure the DB writes are unwound so the system is consistent either way.
    """
    console = get_console()

    if not env_path.exists():
        raise WorthlessError(ErrorCode.ENV_NOT_FOUND, f"File not found: {env_path}")
    if env_path.is_symlink():
        raise WorthlessError(ErrorCode.ENV_NOT_FOUND, f"Refusing to follow symlink: {env_path}")

    bypass_findings = scan_source_for_hardcoded_provider_urls(env_path.parent)
    if bypass_findings:
        header = "worthless: hardcoded provider URLs detected — these bypass the proxy:"
        detail_lines = [header]
        for f in bypass_findings:
            safe_file = _oc_audit.sanitise_for_message(f.file)
            safe_url = _oc_audit.sanitise_for_message(f.url)
            detail_lines.append(f"  {safe_file}:{f.line}  {safe_url}  ({f.provider})")
        findings_text = "\n".join(detail_lines)

        if allow_hardcoded_urls:
            console.print_warning(findings_text)
            console.print_warning(
                "Proceeding with --allow-hardcoded-urls. Ensure these are not "
                "active production code paths that bypass the proxy."
            )
        elif sys.stdin.isatty():
            console.print_warning(findings_text)
            if not typer.confirm(
                "\nThese URLs will bypass the proxy. Are these intentional "
                "(e.g. test fixtures or docs)? Proceed anyway?",
                default=False,
            ):
                raise WorthlessError(ErrorCode.SCAN_ERROR, "Aborted.", exit_code=1)
        else:
            raise WorthlessError(
                ErrorCode.SCAN_ERROR,
                findings_text + "\nIf this is intentional (e.g. test fixtures), re-run with "
                "--allow-hardcoded-urls to bypass this check.",
                exit_code=1,
            )

    if not quiet:
        console.print_hint(f"Scanning {env_path} for API keys...")

    class _LockResult(NamedTuple):
        total: int
        fresh_count: int
        partial_failure: bool

    async def _lock_async() -> _LockResult:
        from dotenv import dotenv_values  # noqa: PLC0415 — local import keeps test surface tight

        async with open_repo(home) as repo:
            await repo.initialize()

            env_str = str(env_path.resolve())
            all_enrollments = await repo.list_enrollments()

            raw_scanned = scan_env_keys(env_path)
            scanned = await _select_unlocked_keys(
                repo,
                raw_scanned,
                all_enrollments,
                env_str,
            )
            if not scanned:
                return _LockResult(total=len(raw_scanned), fresh_count=0, partial_failure=False)

            # Snapshot .env so _pass1 can pull *_BASE_URL values into the DB row.
            env_values = dict(dotenv_values(env_path))

            candidates = [
                (var_name, value, provider_override or detected_provider)
                for var_name, value, detected_provider in scanned
            ]
            existing_env_keys = set(env_values.keys())

            # #210 OpenClaw secrets-audit gate: pre-flight runs BEFORE any
            # DB/.env write so blocking plaintext findings abort the lock with
            # zero side effects (gate-before-write). Orthogonal to the
            # sidecar-IPC repo above — placement here is load-bearing.
            _oc_gate = _openclaw_audit_preflight()

            planned: list[_PlannedUpdate] = []
            try:
                if not quiet:
                    # HF2 UX: name the keys so the user knows exactly which env
                    # vars are being touched — prior "Protecting N key(s)..."
                    # was opaque about which secrets just changed.
                    key_names = ", ".join(var_name for var_name, _, _ in candidates)
                    console.print_hint(f"  Protecting {key_names}...")
                # 8rqs Phase 7: env_values flows through so _pass1_db_writes can
                # read each key's matching *_BASE_URL from .env at lock time.
                await _pass1_db_writes(
                    repo, candidates, env_str, token_budget_daily, planned, env_values
                )
                if not planned:
                    return _LockResult(total=0, fresh_count=0, partial_failure=False)
                _batch_rewrite(env_path, planned, keys_only, existing_env_keys)
                if _oc_gate is not None:
                    _openclaw_audit_postflight(_oc_gate)
                # Phase 2.b: OpenClaw magic. Per L1 in
                # engineering/research/openclaw-WOR-431-phase-2-spec.md, this
                # NEVER rolls back lock-core success. Per L2 (revised 2026-05-08
                # by the verification gauntlet): detected+failed returns
                # partial_failure=True so the caller can raise typer.Exit(73)
                # AFTER lock-core's .env/DB writes are fully committed.
                partial_failure = _apply_openclaw(planned, console, quiet, home)
                fresh_count = sum(1 for p in planned if p.was_fresh_enroll)
                return _LockResult(
                    total=len(planned), fresh_count=fresh_count, partial_failure=partial_failure
                )
            except Exception:
                if planned:
                    unwind_errors = await _compensating_unwind(repo, planned)
                    if unwind_errors:
                        console.print_warning(
                            f"Database may contain {len(unwind_errors)} stale row(s); "
                            "run `worthless unlock --all` to reconcile."
                        )
                raise
            finally:
                for p in planned:
                    p.zero()

    result = asyncio.run(_lock_async())
    relock_count = result.total - result.fresh_count

    if result.fresh_count and env_path.exists():
        current = env_path.stat().st_mode
        if current & (stat.S_IRWXG | stat.S_IRWXO):
            env_path.chmod(current & ~(stat.S_IRWXG | stat.S_IRWXO))

    if not quiet:
        _print_lock_result(console, result.fresh_count, relock_count, env_path, home.base_dir)

    # Trust-fix (2026-05-08 verification gauntlet): when OpenClaw was
    # detected on this host AND the integration stage failed, the user is
    # in a false-invariant state — .env is locked, but their agent traffic
    # is not gated. Surface this LOUDLY by exiting non-zero AFTER the
    # lock-core writes have committed (L1 binding contract preserved).
    # Exit code 73 = EX_CANTCREAT (POSIX), distinguishable from 1.
    # The [FAIL] block is already printed by _apply_openclaw; this final
    # LOCK FAILED line disambiguates the mixed [FAIL]+[OK] output so the
    # user cannot mistake a partial failure for overall success (WOR-551).
    if result.partial_failure:
        console.print_failure(
            "LOCK FAILED — .env key is split but OpenClaw integration did not complete.\n"
            "Your agent traffic is NOT gated through the Worthless proxy.\n"
            "Run `worthless doctor` to diagnose, `worthless unlock` to roll back."
        )
        raise typer.Exit(code=73)

    return result.fresh_count + relock_count


def _enroll_single(
    alias: str,
    key: str,
    provider: str,
    home: WorthlessHome,
) -> None:
    """Enroll a single key (no .env scanning).

    Write order: DB first — matching _lock_keys pattern.
    Compensation on failure: clean up the DB row.
    """
    if not _ALIAS_RE.match(alias):
        raise WorthlessError(ErrorCode.SCAN_ERROR, f"Invalid alias: {alias!r}")

    try:
        prefix = detect_prefix(key, provider)
    except ValueError:
        prefix = ""

    sr = split_key_fp(key, prefix, provider)

    async def _enroll_async():
        async with open_repo(home) as repo:
            await repo.initialize()

            existing = await repo.fetch_encrypted(alias)
            if existing is not None:
                raise WorthlessError(
                    ErrorCode.SCAN_ERROR,
                    f"Alias {alias!r} is already enrolled",
                )

            stored = StoredShard(
                shard_b=sr.shard_b,
                commitment=sr.commitment,
                nonce=sr.nonce,
                provider=provider,
            )
            # 8rqs: enroll falls back to the registry default URL — _enroll_single
            # is the no-.env path so there's no user var to read.
            registry_default = lookup_by_name(provider)
            base_url = registry_default.url if registry_default else None
            await repo.store_enrolled(
                alias,
                stored,
                var_name=alias,
                env_path=None,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=base_url,
            )

    try:
        asyncio.run(_enroll_async())
    except WorthlessError:
        raise
    except Exception as exc:
        raise WorthlessError(
            ErrorCode.SHARD_STORAGE_FAILED,
            sanitize_exception(exc, generic="failed to enroll key"),
        ) from exc
    finally:
        sr.zero()

    console = get_console()
    console.print_success(f"Enrolled {alias} ({provider}).")


def register_lock_commands(app: typer.Typer) -> None:
    """Register lock and enroll commands on the Typer app."""

    @app.command()
    @error_boundary
    def lock(
        env: Path = typer.Option(Path(".env"), "--env", "-e", help="Path to .env file"),
        provider: str | None = typer.Option(
            None, "--provider", "-p", help="Override provider auto-detection"
        ),
        token_budget_daily: int | None = typer.Option(
            None, "--token-budget-daily", help="Daily token budget limit"
        ),
        keys_only: bool = typer.Option(
            False, "--keys-only", help="Only rewrite API keys (skip BASE_URL)"
        ),
        allow_hardcoded_urls: bool = typer.Option(
            False,
            "--allow-hardcoded-urls",
            help=(
                "Proceed even if source files contain hardcoded provider URLs. "
                "Use when the URLs are intentional (e.g. test fixtures). "
                "A warning is always printed."
            ),
        ),
    ) -> None:
        """Protect API keys in a .env file."""
        # Pre-announce the macOS Keychain dialog so users aren't surprised by a
        # system prompt mid-command. The dialog labels itself "python3.10" not
        # "worthless"; without this hint, first-time users panic and click Deny.
        # Per HF2 (worthless-mnlp) the prompt fires at most once per invocation
        # (cache + lock + probe-via-property collapse 3+ → 1).
        if sys.platform == "darwin" and keyring_available():
            console = get_console()
            console.print_hint(
                "macOS may ask once to access your Keychain — click 'Always Allow' "
                "so we don't ask again."
            )
        home = get_home()
        with acquire_lock(home):
            _lock_keys(
                env,
                home,
                provider_override=provider,
                token_budget_daily=token_budget_daily,
                keys_only=keys_only,
                allow_hardcoded_urls=allow_hardcoded_urls,
            )

    @app.command()
    @error_boundary
    def enroll(
        alias: str = typer.Option(..., "--alias", "-a", help="Key alias"),
        key: str | None = typer.Option(
            None,
            "--key",
            "-k",
            help="API key (use --key-stdin instead to avoid shell history)",
        ),
        key_stdin: bool = typer.Option(False, "--key-stdin", help="Read API key from stdin"),
        provider: str = typer.Option(..., "--provider", "-p", help="Provider name"),
    ) -> None:
        """Enroll a single API key (scripting/CI primitive)."""
        home = get_home()

        if key_stdin:
            actual_key = sys.stdin.readline().strip()
            if not actual_key:
                raise WorthlessError(ErrorCode.KEY_NOT_FOUND, "No key provided on stdin")
        elif key:
            actual_key = key
        else:
            raise WorthlessError(ErrorCode.KEY_NOT_FOUND, "Provide --key or --key-stdin")

        with acquire_lock(home):
            _enroll_single(alias, actual_key, provider, home)

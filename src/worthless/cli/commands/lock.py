"""Lock command -- scan .env, split keys (format-preserving), store shards."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass
from typing import NamedTuple
from pathlib import Path

import typer

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import WorthlessHome, acquire_lock, get_home
from worthless.cli.code_scanner import scan_for_hardcoded_provider_urls
from worthless.cli.commands.scan import (
    SCAN_TIME_BUDGET_S,
    _format_code_findings_human,
    _format_lock_block_human,
)
from worthless.cli.process import check_proxy_health, resolve_port
from worthless.cli.console import WorthlessConsole, get_console
from worthless.cli.scanner import SkippedFile, scan_source_for_hardcoded_provider_urls
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
from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.keystore import (
    _fernet_file_bytes,
    keyring_available,
    sync_fernet_for_launchd,
)
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
from worthless.openclaw import config as _openclaw_config_mod
from worthless.openclaw import integration as _openclaw_integration
from worthless.openclaw.errors import OpenclawErrorCode, OpenclawIntegrationError
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


def _detect_already_locked_env(env_values: dict[str, str | None]) -> str | None:
    """worthless-ftmg — return the offending var name if the .env is already locked.

    A successful ``worthless lock`` always writes ``*_BASE_URL`` pointing at
    the local Worthless proxy. A subsequent ``lock`` against that same .env
    would re-read the shard-A in the key field as if it were a fresh plaintext
    key, split it, and overwrite both halves — destroying the only path back
    to the original real key.

    We refuse this scenario one preflight earlier: scan the parsed env_values
    for any ``*_BASE_URL`` whose host:port matches our proxy. If found, the
    caller raises ``ErrorCode.ENV_ALREADY_LOCKED`` and points the user at
    ``worthless unlock`` (clean exit) or ``worthless doctor`` (recovery from
    a half-state).

    Detection is intentionally narrow: ONLY the host:port signal. A foreign
    proxy on the same port is the worst-case false positive (we refuse; the
    user changes ``WORTHLESS_PORT`` or stops the foreign service).
    Higher-coverage commitment-scan detection is filed as a follow-up
    (approach B in worthless-ftmg).
    """
    proxy_host = os.environ.get("WORTHLESS_PROXY_HOST", "127.0.0.1")
    proxy_port = resolve_port(None)
    # SONAR python:S5332 hotspot: these are LOOPBACK proxy URL prefixes used
    # for host:port matching, not network endpoints. The worthless proxy
    # binds 127.0.0.1 by design (see WOR-621 plan + security-reviewer
    # signoff: "loopback http acceptable; SSRF guards apply to server-side
    # outbound only"). HTTPS is meaningless on loopback. NOSONAR.
    proxy_netloc_prefixes = (
        f"http://{proxy_host}:{proxy_port}/",  # NOSONAR python:S5332 — loopback proxy
        # Loopback aliases — ``127.0.0.1`` and ``localhost`` resolve to the
        # same socket, so an entry written by one match still binds to the
        # other. Catch both regardless of how WORTHLESS_PROXY_HOST is set.
        f"http://127.0.0.1:{proxy_port}/",  # NOSONAR python:S5332 — loopback proxy
        f"http://localhost:{proxy_port}/",  # NOSONAR python:S5332 — loopback proxy
    )
    for var_name, value in env_values.items():
        if not (var_name.endswith("_BASE_URL") and isinstance(value, str)):
            continue
        normalised = value.rstrip("/") + "/"
        if any(normalised.startswith(prefix) for prefix in proxy_netloc_prefixes):
            return var_name
    return None


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
    base_url_var: str, env_values: dict[str, str | None], registry_name: str
) -> str:
    """Pick the upstream URL for the DB row.

    Prefers the user's explicit ``*_BASE_URL`` value from ``.env`` when set
    AND when that URL is in the provider registry. Otherwise falls back to
    the bundled registry default for the provider.

    ``registry_name`` MUST be the registry name (e.g. ``openrouter``), NOT
    the wire protocol (e.g. ``openai``). OpenRouter speaks the OpenAI
    dialect, so its protocol is ``openai`` — but its upstream lives at
    ``openrouter.ai``. Passing the wire protocol here looked up the OpenAI
    URL and forwarded OpenRouter keys to ``api.openai.com`` → HTTP 401
    (PR #276 thermo-nuclear review; live-container regression).

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
    entry = lookup_by_name(registry_name)
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
    """Remove stale enrollments for a var/path after a rotated key is locked.

    exx5/WOR-646: each stale alias's enrollment + now-unreferenced shard is
    removed in ONE atomic transaction (``delete_superseded_enrollment_atomic``),
    so a SIGINT mid-cleanup on a rotation re-lock can't strand the old alias's
    ``shards`` row (enrollment gone, shard not). The stale set is computed
    first; the "any enrollment left for this alias?" check that gates the shard
    delete runs inside the transaction, not here.
    """
    enrollments = await repo.list_enrollments()
    stale_aliases = {
        e.key_alias
        for e in enrollments
        if e.var_name == var_name and e.env_path == env_path and e.key_alias != alias
    }
    for stale_alias in stale_aliases:
        await repo.delete_superseded_enrollment_atomic(stale_alias, env_path=env_path)


def _capture_original_mode(env_str: str) -> int | None:
    """The ``.env``'s permission bits (``0o777``) before lock tightens it.

    WOR-715: recorded so ``worthless uninstall`` (WOR-435) can restore the
    original permissions, not just the contents. ``None`` on stat failure
    (file vanished, EACCES on the dir) = "mode unknown — leave the file
    as-is at restore" rather than crashing the whole lock.
    """
    try:
        return Path(env_str).stat().st_mode & 0o777
    except OSError:
        return None


async def _decide_oc_capture(
    *,
    repo: ShardRepository,
    oc_config: dict | None,
    proxy_base_url: str,
    provider: str,
    prior_record: str | None,
) -> tuple[str | None, str | None]:
    """G3 capture decision for one provider → (oc_record, oc_mac).

    Bridges the pure sync classifier in
    :mod:`worthless.openclaw.integration` with the async MAC computation
    on :class:`ShardRepository` and the operator-facing warning channel.

    Returns the pair threaded into :meth:`ShardRepository.upsert_locked_shard`
    (and :meth:`store_enrolled` on fresh enrollments). Both values are
    ``None`` on the no-capture branches:

    * ``no_entry`` — no openclaw.json entry for this provider yet.
    * ``relock_no_prior`` — entry is already proxy-shaped but the DB has
      no prior record, so capturing shard-A as "the original" would let
      unlock declare a fake success. Emits a CLI warning.

    G5-C: the original ``baseUrl`` lives INSIDE ``oc_record`` (the
    MAC-bound source of truth), so we don't return a separate base-URL
    slot any more. Stage A unlock parses the URL out of the JSON record.

    The MAC is computed in-process via the same fernet-derived HMAC
    (:meth:`ShardRepository._compute_decoy_hash`) the G2 tamper-bind
    uses. Caller pattern: no new crypto, no master-key oracle.
    """
    current_entry = None
    if oc_config is not None:
        providers = oc_config.get("models", {}).get("providers", {})
        candidate = providers.get(provider)
        if isinstance(candidate, dict):
            current_entry = candidate

    kind, _base_url, record_json = _openclaw_integration.classify_oc_entry_for_capture(
        current_entry,
        prior_entry_record_json=prior_record,
        proxy_base_url=proxy_base_url,
    )

    if kind == "relock_no_prior":
        get_console().print_warning(
            f"OpenClaw {provider!r} entry is already proxy-shaped with no "
            "stored rollback record (relock_no_prior); leaving rollback "
            "columns unset. Run `worthless unlock` first if you want the "
            "original captured."
        )
        return (None, None)

    if record_json is None:
        # 'no_entry' branch — nothing on disk to capture, no MAC to compute.
        return (None, None)

    mac = await repo._compute_decoy_hash(record_json)
    return (record_json, mac)


def _read_openclaw_providers_for_capture() -> dict | None:
    """Read openclaw.json once for G3 rollback capture.

    Returns the parsed config dict (so the caller can look up each
    provider entry by name), or ``None`` if OpenClaw is absent, the
    file is missing, or any read error fires. Capture is best-effort:
    a failure here lets lock-core proceed without a rollback record
    (unlock will fail-safe-skip later), which is strictly safer than
    aborting the lock or crashing in pass1.
    """
    state = _openclaw_integration.detect()
    if not state.present:
        return None
    try:
        config_path = _openclaw_integration._resolve_active_config_path(state, state.home_dir)
        return _openclaw_config_mod.read_config(config_path)
    except Exception:  # noqa: BLE001 — fail-safe: missing rollback row is acceptable
        return None


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

    WOR-621 F2 G3: reads openclaw.json once at the top + per-candidate
    classifies the current entry against the prior shards-row record
    (via :func:`integration.classify_oc_entry_for_capture`). The rollback
    pair (``oc_original_api_key_json``, ``oc_rollback_mac``) rides into
    the DB on the existing :meth:`ShardRepository.upsert_locked_shard`
    write so a crash between here and ``_apply_openclaw`` still leaves
    a row unlock can roll back from (SM-2: StashDB → Rewrite). G5-C
    dropped the dead third element (``oc_original_base_url``) — the
    original URL lives inside the MAC-bound JSON record.
    """
    # WOR-715: capture the .env's pre-lock permission bits ONCE, here in
    # pass-1, BEFORE pass-2 (``_batch_rewrite``) rewrites the file via
    # ``safe_rewrite`` and forces it to 0o600. During pass-1 the file is still
    # untouched, so this is the true original mode — capturing any later would
    # read the already-tightened 0o600 and silently record the wrong value.
    original_mode = _capture_original_mode(env_str)
    # G3: snapshot openclaw.json BEFORE we touch the DB. We classify each
    # provider against this snapshot so a concurrent OpenClaw write doesn't
    # poison our capture, and so the DB write is the first mutation.
    oc_config = _read_openclaw_providers_for_capture()
    oc_proxy_base_url = _openclaw_integration._resolve_proxy_base_url()

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

        # Resolve the upstream URL by the REGISTRY NAME (detected_provider, e.g.
        # "openrouter"), not the wire PROTOCOL (provider, e.g. "openai"). They
        # diverge for OpenAI-dialect-compatible services: OpenRouter's protocol
        # is "openai" but its upstream is openrouter.ai. Using the protocol here
        # mailed OpenRouter keys to api.openai.com → 401 (PR #276 review).
        upstream_base_url = _resolve_upstream_base_url(base_url_var, env_values, detected_provider)

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
                # G3 capture (re-lock branch): the row already exists so the
                # prior rollback record (if any) lives on db_shard. The classifier
                # decides whether to reuse it, refuse to overwrite with shard-A
                # ('relock_no_prior'), or — if the entry was untouched since the
                # last unlock — re-capture as 'new'.
                (
                    oc_capture_record,
                    oc_capture_mac,
                ) = await _decide_oc_capture(
                    repo=repo,
                    oc_config=oc_config,
                    proxy_base_url=oc_proxy_base_url,
                    provider=provider,
                    prior_record=db_shard.oc_original_api_key_json,
                )
                # WOR-646 Part 2: record the planned update BEFORE any DB write,
                # then commit the in-place shard UPDATE + enrollment as ONE
                # transaction. An interrupt before the commit rolls the UPDATE
                # back wholesale (clean); after it, the row is already in
                # ``planned`` for the unwind. The upsert is ON CONFLICT DO UPDATE
                # (NOT INSERT OR REPLACE) so sibling enrollments aren't
                # CASCADE-wiped; INSERT OR IGNORE would strand the old shard_b.
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
                await repo.upsert_locked_shard_and_enroll(
                    alias,
                    stored_decrypted,
                    var_name=var_name,
                    env_path=env_str,
                    prefix=db_shard.prefix,
                    charset=db_shard.charset,
                    base_url=db_shard.base_url or upstream_base_url,
                    original_mode=original_mode,
                    write_config=False,
                    oc_original_api_key_json=oc_capture_record,
                    oc_rollback_mac=oc_capture_mac,
                )
                await _delete_superseded_location_enrollments(
                    repo,
                    alias=alias,
                    var_name=var_name,
                    env_path=env_str,
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
            # G3 capture (fresh-enroll branch): no prior row, so prior_* are
            # None. The classifier will return 'new' for a genuine original
            # entry, 'relock_no_prior' if the user managed to leave openclaw.json
            # already proxy-shaped without a DB row (legacy), or 'no_entry' if
            # the provider has no entry at all yet.
            (
                oc_capture_record,
                oc_capture_mac,
            ) = await _decide_oc_capture(
                repo=repo,
                oc_config=oc_config,
                proxy_base_url=oc_proxy_base_url,
                provider=provider,
                prior_record=None,
            )
            # WOR-646 Part 2: record the planned update BEFORE the DB write, then
            # write the shard + enrollment (+ config) as ONE atomic transaction.
            # An interrupt before the commit leaves no row; after it, the row is
            # already in ``planned`` for the unwind. Closes the orphan-shard
            # window the prior two-commit sequence (upsert_locked_shard then
            # store_enrolled) exposed under a real SIGINT.
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
            await repo.upsert_locked_shard_and_enroll(
                alias,
                stored,
                var_name=var_name,
                env_path=env_str,
                prefix=sr.prefix,
                charset=sr.charset,
                base_url=upstream_base_url,
                original_mode=original_mode,
                token_budget_daily=token_budget_daily,
                write_config=True,
                oc_original_api_key_json=oc_capture_record,
                oc_rollback_mac=oc_capture_mac,
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


def _fire_synthetic_request(host: str, port: int, alias: str) -> bool:
    """WOR-658: send one minimal request to the proxy's dedicated
    bind-confirmation endpoint so the in-memory ``bind_probe_count``
    counter increments.

    Returns ``True`` iff the request reached the proxy's handler (got an HTTP
    response, any status). Returns ``False`` on network/connection errors —
    those mean the proxy couldn't be reached at all, so the counter delta
    cannot be interpreted as evidence either way and ``_confirm_bind`` will
    classify the result as ``skipped`` rather than ``fail``.

    The endpoint ``/_bind_probe/{alias}`` is intentionally public on the
    worthless proxy (no auth, no body) — its only purpose is to bump the
    probe counter and return 204. A 1 s timeout caps the bind-confirmation
    cost so a hung proxy can't stall ``worthless lock``.

    HEAD over GET keeps the probe payload-free while still hitting the same
    handler.
    """
    # Local import keeps lock.py's module-load cost untouched on the cold
    # path (lock is in the hot CLI path; bind-confirmation only runs after
    # a successful OpenClaw rewrite).
    import httpx  # noqa: PLC0415

    # NOSONAR python:S5332 — loopback-only probe; TLS is not provisioned at
    # this layer and the proxy refuses non-loopback origins for /_bind_probe
    # (see proxy/app.py: ``bind_probe`` returns 403 unless request.client.host
    # is the local loopback range). Same shape as the long-standing
    # ``check_proxy_health`` call at ``cli/process.py``.
    url = f"http://{host}:{port}/_bind_probe/{alias}"  # NOSONAR
    try:
        with httpx.Client(timeout=1.0) as client:
            client.head(url)
    except (httpx.HTTPError, OSError):
        return False
    return True


def _coerce_counter(value: object) -> int:
    """Best-effort widen of ``check_proxy_health()``'s ``requests_proxied``.

    The healthz JSON is loosely-typed (``dict[str, object]``-shaped at the
    Python boundary). We accept ``int`` directly, parse numeric strings (any
    older proxy that surfaced the count as a string still works), and fall
    back to 0 for anything else so bind-confirmation can't crash lock just
    because a future schema change altered the type.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject by intent
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _classify_bind_per_alias(
    aliases: list[str],
    before_aliases: dict[str, object],
    after_aliases: dict[str, object],
    *,
    delta: int,
    reached: int,
) -> dict[str, object]:
    """WOR-650 follow-up: per-alias bind verdict.

    Pass iff EVERY confirmed alias's own probe count moved — so on a
    multi-provider lock a tick for one alias can't be mistaken for another's
    (the global counter can't tell them apart). Honest scope: this proves the
    proxy acknowledged a probe for each alias, NOT that each provider's rewrite
    is a working route — the probe hits ``/_bind_probe``, not the real
    ``/{alias}/v1`` path, so a typo'd baseUrl could still pass here; end-to-end
    routing is proven by the live e2e tests. Mirrors :func:`_confirm_bind`'s
    skip reasons so the per-alias path classifies restart / unreachable
    identically; the only new verdict is a ``fail`` that names the aliases
    whose probe did NOT register.
    """
    if delta < 0:
        # Proxy bounced between the before/after reads (its in-memory counters
        # reset to 0). That's inconclusive REGARDLESS of per-alias staleness —
        # the restart signal wins, so we never manufacture a 'fail' against a
        # moving target. Without this, an alias mix of previously-counted +
        # fresh entries would fall through to 'fail' on a bounced proxy.
        return {
            "status": "skipped",
            "reason": "proxy_restarted",
            "delta": delta,
            "aliases": aliases,
            "reached": reached,
        }
    not_routing = [
        a
        for a in aliases
        if _coerce_counter(after_aliases.get(a)) <= _coerce_counter(before_aliases.get(a))
    ]
    if not not_routing:
        return {"status": "pass", "delta": delta, "aliases": aliases, "reached": reached}
    if len(not_routing) == len(aliases):
        # Nothing ticked and the proxy didn't restart — if nothing even reached
        # it, that's inconclusive (same shape _confirm_bind uses for the global
        # counter so callers/sentinel readers see consistent reasons).
        if reached == 0:
            return {
                "status": "skipped",
                "reason": "synthetic_unreachable",
                "delta": delta,
                "aliases": aliases,
                "reached": reached,
            }
    # Proxy was reachable but one or more confirmed aliases didn't tick — those
    # rewrites aren't routing. The silent-bypass class we refuse to pass.
    return {
        "status": "fail",
        "delta": delta,
        "aliases": aliases,
        "reached": reached,
        "not_routing": not_routing,
    }


def _confirm_bind(
    planned: list[_PlannedUpdate],
    *,
    host: str,
    port: int,
) -> dict[str, object]:
    """WOR-658 bind-confirmation. Prove the rewritten OpenClaw entry actually
    routes through the proxy by firing one synthetic request per alias and
    observing the proxy's ``requests_proxied`` counter.

    Returns a result block suitable for the sentinel:
    * ``status == "pass"`` — counter incremented by at least 1; the rewrite
      is in the path.
    * ``status == "fail"`` — counter did not move; the rewrite is NOT routing,
      lock must refuse to claim success (silent-bypass class, WOR-514).
    * ``status == "skipped"`` — proxy unhealthy at the before- or after-read,
      OR there was nothing to confirm (no aliases). Inconclusive, not a fail.
    """
    aliases = [p.alias for p in planned]
    if not aliases:
        return {
            "status": "skipped",
            "reason": "no_aliases",
            "delta": 0,
            "aliases": [],
            "reached": 0,
        }

    try:
        before_health = check_proxy_health(port)
    except Exception:  # noqa: BLE001 — bind-confirmation must never crash lock
        return {
            "status": "skipped",
            "reason": "proxy_check_raised_before",
            "delta": 0,
            "aliases": aliases,
            "reached": 0,
        }
    if not before_health.get("healthy"):
        return {
            "status": "skipped",
            "reason": "proxy_unhealthy_before",
            "delta": 0,
            "aliases": aliases,
            "reached": 0,
        }
    # WOR-658 squatter-resistance: missing ``bind_probe_count`` on the
    # ``/healthz`` body means the responder isn't a worthless proxy. Don't
    # interpret real-traffic ticks (requests_proxied) as proof of routing
    # — a foreign service answering /healthz could have any counter shape.
    if "bind_probe_count" not in before_health:
        return {
            "status": "skipped",
            "reason": "proxy_unrecognised",
            "delta": 0,
            "aliases": aliases,
            "reached": 0,
        }
    before = _coerce_counter(before_health.get("bind_probe_count"))

    reached = 0
    for alias in aliases:
        try:
            if _fire_synthetic_request(host, port, alias):
                reached += 1
        except Exception:  # noqa: BLE001 — never crash lock from this layer
            logger.debug("bind-confirmation fire raised for %s", alias, exc_info=True)

    try:
        after_health = check_proxy_health(port)
    except Exception:  # noqa: BLE001
        return {
            "status": "skipped",
            "reason": "proxy_check_raised_after",
            "delta": 0,
            "aliases": aliases,
            "reached": reached,
        }
    if not after_health.get("healthy"):
        return {
            "status": "skipped",
            "reason": "proxy_unhealthy_after",
            "delta": 0,
            "aliases": aliases,
            "reached": reached,
        }
    # CodeRabbit gate-10 finding: re-check the field on the AFTER read. If
    # BEFORE had ``bind_probe_count`` but AFTER doesn't (responder swap /
    # restart-to-a-different-server mid-call), ``_coerce_counter(None)`` would
    # silently become 0 and ``delta = 0 - before`` would look like a large
    # negative — misclassified as ``proxy_restarted``. Classify the missing
    # field as its own ``proxy_unrecognised_after`` skip so the verdict names
    # the real condition instead of guessing "restart".
    if "bind_probe_count" not in after_health:
        return {
            "status": "skipped",
            "reason": "proxy_unrecognised_after",
            "delta": 0,
            "aliases": aliases,
            "reached": reached,
        }
    after = _coerce_counter(after_health.get("bind_probe_count"))

    delta = after - before

    # WOR-650 follow-up: when the proxy reports per-alias counts, base the
    # verdict on THEM — the global delta only proves "a probe reached the
    # proxy", not "THIS alias's rewrite routes". Older proxies omit the field;
    # fall back to the global tri-state below.
    before_aliases = before_health.get("bind_probe_aliases")
    after_aliases = after_health.get("bind_probe_aliases")
    if isinstance(before_aliases, dict) and isinstance(after_aliases, dict):
        return _classify_bind_per_alias(
            aliases,
            before_aliases,
            after_aliases,
            delta=delta,
            reached=reached,
        )

    # Tri-state classify (global counter — older proxy without per-alias data):
    # * delta > 0                    → pass (counter moved; the request reached
    #                                  the counter via the rewritten alias path)
    # * reached == 0 AND delta == 0  → skipped: every fire failed at the
    #                                  network layer, so the proxy never saw
    #                                  the synthetic request. We can't tell
    #                                  whether the rewrite routes — only that
    #                                  the test harness didn't.
    # * reached >  0 AND delta == 0  → fail: the proxy received the request
    #                                  but did NOT count it. That's the
    #                                  silent-bypass class (WOR-514) we care
    #                                  about — the rewritten entry isn't
    #                                  routing through Worthless.
    if delta > 0:
        return {
            "status": "pass",
            "delta": delta,
            "aliases": aliases,
            "reached": reached,
        }
    if delta < 0:
        # WOR-658 / Gate-3 chaos-engineer finding: the in-memory probe
        # counter resets to 0 on proxy restart. If the proxy restarts
        # between the before- and after-reads, ``after < before`` and
        # the delta is large-negative. That's inconclusive (the proxy
        # was probably fine — it just bounced), NOT a fail. Surfacing
        # this as ``skipped`` keeps lock honest: we can't tell from
        # this single observation whether the rewrite routes, and we
        # refuse to manufacture a fail verdict against a moving target.
        return {
            "status": "skipped",
            "reason": "proxy_restarted",
            "delta": delta,
            "aliases": aliases,
            "reached": reached,
        }
    if reached == 0:
        return {
            "status": "skipped",
            "reason": "synthetic_unreachable",
            "delta": delta,
            "aliases": aliases,
            "reached": reached,
        }
    return {
        "status": "fail",
        "delta": delta,
        "aliases": aliases,
        "reached": reached,
    }


def _finalise_openclaw_success(
    planned: list[_PlannedUpdate],
    result,  # noqa: ANN001 — OpenclawApplyResult is opaque from this layer
    console,  # noqa: ANN001 — Console type is opaque from this layer
    quiet: bool,
    home: WorthlessHome,
    *,
    proxy_host: str,
) -> int:
    """WOR-658: finalise the success branch of ``_apply_openclaw``.

    Runs bind-confirmation, writes the sentinel with the correct paired
    ``status``/``openclaw`` state, prints the user-visible result block,
    and returns the exit code (0 on success, 91 on bind-fail).

    WOR-650 follow-up: if an unrecognized entry was left in place (adoption
    declined / DB snapshot unavailable without --adopt), the header is
    ``[WARN]`` not ``[OK]`` and the sentinel is DEGRADED — but the exit code
    stays 0 (the interactive user made that choice; it isn't a lock error).

    Extracted so ``_apply_openclaw`` stays under the project's xenon
    complexity ceiling — the bind-confirmation classify branches push it
    over otherwise.
    """
    # WOR-650 follow-up: an entry left in place (interactive decline, or DB
    # snapshot unavailable without --adopt) means lock REWIRED .env to the
    # proxy but did NOT neutralize a foreign openclaw.json entry — that
    # provider's agent traffic still escapes Worthless. Both skip paths append
    # the same reason, so it's the one honest signal that something survived.
    # The output must NOT read as a clean [OK] when this happened.
    adoption_skipped = any(
        reason == "unrecognized_not_adopted" for _, reason in result.providers_skipped
    )

    if not quiet:
        if adoption_skipped:
            console.print_warning(
                "[WARN] OpenClaw integration incomplete — an entry was left in place:"
            )
        else:
            console.print_success("[OK] OpenClaw integration:")
        for provider_name in result.providers_set:
            console.print_hint(f"   • ~/.openclaw/openclaw.json — added provider '{provider_name}'")
        if result.skill_installed:
            console.print_hint("   • ~/.openclaw/workspace/skills/worthless/ — installed skill")
        console.print_hint("   • Undo: worthless unlock")
        # WOR-650: tell the user when an unrecognized entry was adopted or
        # skipped. The detail strings already name the benign cause and the
        # --adopt remedy; on the normal recognized/real-key path there are no
        # adoption events so this is silent.
        for event in result.events:
            if event.code in _ADOPTION_EVENT_CODES:
                console.print_hint(f"   • {event.detail}")

    # WOR-658: fire a self-test probe at the proxy for each written alias. A
    # "fail" here means the proxy didn't acknowledge the probe — the entry
    # almost certainly isn't reaching a live worthless proxy. Honest scope:
    # this checks proxy reachability + per-alias acknowledgment, NOT that
    # OpenClaw's rewrite is a working route (see _classify_bind_per_alias); the
    # live e2e tests prove actual routing.
    #
    # WOR-650 follow-up: confirm ONLY the providers we actually wrote. A
    # skipped (unadopted) provider's entry still points elsewhere, so probing
    # its alias would tick the counter and read as a (misleading) "pass".
    set_providers = set(result.providers_set)
    confirmed_planned = [p for p in planned if p.provider in set_providers]
    bind_confirmation = _confirm_bind(confirmed_planned, host=proxy_host, port=resolve_port(None))
    # Bind-fail is a partial-success state at the trust layer:
    # lock-core wrote the .env + DB, but the OpenClaw config isn't
    # routing. ``openclaw="failed"`` (paired with ``status="partial"``)
    # makes ``is_partial()`` fire so ``worthless status`` reports
    # DEGRADED across sessions — the very failure mode WOR-658 was
    # built to make visible.
    bind_failed = bind_confirmation["status"] == "fail"
    # DEGRADED when routing couldn't be proven (bind-fail) OR an entry was left
    # in place (adoption skip). Either way the protection is incomplete, so the
    # cross-session sentinel must say so — the same partial/failed pair
    # ``is_partial()`` already recognises, so no schema change. ``worthless
    # status`` then reports "your agent traffic may NOT be gated" until cleared.
    degraded = bind_failed or adoption_skipped
    _write_lock_sentinel(
        home,
        status="partial" if degraded else "ok",
        openclaw="failed" if degraded else "ok",
        alias_count=len(result.providers_set),
        events=tuple(e.to_dict() for e in result.events),
        bind_confirmation=bind_confirmation,
    )
    if bind_failed:
        if not quiet:
            # WOR-658 Fix 12: "test request" reads to a non-engineer; the
            # term "synthetic" survives only in code identifiers, never the
            # user-facing string. Regression-guarded in
            # tests/openclaw/test_lock_bind_confirmation.py.
            console.print_failure(
                "[FAIL] Bind-confirmation: test request did not "
                "reach the proxy. The rewritten OpenClaw entry is NOT "
                "routing — do NOT trust this lock."
            )
            console.print_warning(
                "   Recover: restart OpenClaw + re-run `worthless lock`, "
                "or `worthless unlock` to roll back. "
                "`worthless doctor` will tell you which."
            )
        # Exit code 91 = bind-confirmation refusal. Distinct from
        # 87 (CONFIG_UNREADABLE: infra blocked before any write) and
        # 73 (OpenClaw integration partial-fail). Wrapping scripts can
        # now branch on "lock didn't write" (87) vs "lock wrote but
        # routing is broken" (91).
        return 91

    # WOR-658 Fix 9: surface inconclusive skipped states with a [WARN] so
    # the user knows lock didn't actually prove routing. Without this the
    # silent-bypass class (WOR-514) still hides behind a green [OK].
    bind_status = bind_confirmation["status"]
    bind_reason = bind_confirmation.get("reason")
    if not quiet and bind_status == "skipped" and bind_reason and bind_reason != "no_aliases":
        console.print_warning(
            f"[WARN] Bind-confirmation inconclusive ({bind_reason}) — "
            "routing wasn't proven. Run `worthless doctor` to investigate."
        )
    return 0


def _openclaw_proxy_base_url() -> tuple[str, str]:
    """``(proxy_host, proxy_base_url)`` for OpenClaw config writes.

    Single-sourced so the WOR-650 consent preview and the actual write agree
    on the URL. Honours ``WORTHLESS_PROXY_HOST`` (all-container Docker writes
    the service name, not 127.0.0.1) and the resolved ``--port``.
    """
    proxy_host = os.environ.get("WORTHLESS_PROXY_HOST", "127.0.0.1")
    # NOSONAR python:S5332 — loopback proxy: the host is constrained to local
    # endpoints by _validate_proxy_base_url, and only shard-A (inert without
    # shard-B) ever transits. Matches the suppression on the health-probe URL.
    return proxy_host, f"http://{proxy_host}:{resolve_port(None)}"  # NOSONAR python:S5332


_ADOPTION_EVENT_CODES = frozenset(
    {
        OpenclawErrorCode.PROVIDER_ADOPTED_UNRECOGNIZED,
        OpenclawErrorCode.PROVIDER_ADOPTION_SKIPPED,
        OpenclawErrorCode.PROVIDER_RECOGNITION_UNAVAILABLE,
    }
)


def _resolve_adoption_policy(
    planned: list[_PlannedUpdate],
    *,
    managed_aliases: set[str] | None,
    adopt: bool,
    console,  # noqa: ANN001 — Console type is opaque from this layer
    quiet: bool,
):
    """WOR-650: decide whether to adopt unrecognized OpenClaw proxy entries.

    ``--adopt`` or a non-interactive shell → adopt (the agent/CI path: the
    overwrite neutralizes any planted entry and the structured event is the
    record). Interactive without ``--adopt`` → preview the foreign entries and,
    if any, prompt once. ``managed_aliases is None`` (DB snapshot failed) is
    threaded straight through — :func:`_classify_adoption` renders it as the
    fail-safe ``recognition_unavailable`` state, never as "recognized".
    """
    AdoptionPolicy = _openclaw_integration.AdoptionPolicy
    if adopt or not sys.stdin.isatty():
        return AdoptionPolicy(managed_aliases=managed_aliases, adopt_unrecognized=True)
    _, proxy_base_url = _openclaw_proxy_base_url()
    unrecognized = _openclaw_integration.preview_unrecognized(
        [(p.provider, p.alias, "") for p in planned],
        proxy_base_url=proxy_base_url,
        managed_aliases=managed_aliases,
    )
    if not unrecognized:
        return AdoptionPolicy(managed_aliases=managed_aliases, adopt_unrecognized=False)
    if not quiet:
        names = ", ".join(sorted(set(unrecognized)))
        console.print_warning(
            f"OpenClaw has proxy-shaped entries not created on this machine: {names}. "
            "These may be your own synced config — or left by something else."
        )
    decision = typer.confirm("Route them through Worthless?", default=False)
    return AdoptionPolicy(managed_aliases=managed_aliases, adopt_unrecognized=decision)


def _apply_openclaw(
    planned: list[_PlannedUpdate],
    console,  # noqa: ANN001 — Console type is opaque from this layer
    quiet: bool,
    home: WorthlessHome,
    adoption_policy=None,  # noqa: ANN001 — AdoptionPolicy is opaque from this layer
) -> int:
    """OpenClaw integration call + sentinel write. Returns exit code (0/73/87).

    Per L1 in ``engineering/research/openclaw/WOR-431-phase-2-spec.md``:
    failures here NEVER roll back lock-core. Per L2 (revised 2026-05-08
    by the verification gauntlet): when OpenClaw is **detected** AND the
    integration stage fails, the user is in a false-invariant state ("lock
    succeeded but my agent traffic isn't gated"). Caller (`_lock_keys`)
    raises ``typer.Exit(openclaw_exit)`` AFTER lock-core's `.env`/DB writes
    are fully committed — the binding contract is preserved, but the user
    learns about the partial failure unmissably.

    Returns:
        0  — succeeded or OpenClaw not detected on this host.
        73 — detected + integration failed mid-way (tried, partial fail).
        87 — infra blocked before any write (CONFIG_UNREADABLE / UID mismatch).

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
    _proxy_host, proxy_base_url = _openclaw_proxy_base_url()
    try:
        result = _openclaw_integration.apply_lock(
            planned_updates=triples,
            proxy_base_url=proxy_base_url,
            adoption_policy=adoption_policy,
        )
    except OpenclawIntegrationError as exc:
        # apply_lock's contract is "never raise". If it does, treat as
        # detected+failed (we don't know which, but the user is in a
        # genuinely broken state — surface it loudly).
        logger.warning("openclaw apply_lock raised unexpectedly: %s", exc)
        _emit_openclaw_failure(console, quiet, home, len(planned), str(exc))
        return 73
    except Exception as exc:  # noqa: BLE001 — last-resort guard for L1
        logger.warning("openclaw apply_lock raised unexpectedly: %s", exc)
        _emit_openclaw_failure(console, quiet, home, len(planned), str(exc))
        return 73

    # ---- Classify the result ---------------------------------------------
    if not result.detected:
        # No OpenClaw on this host — sentinel reflects "absent", not failure.
        _write_lock_sentinel(home, status="ok", openclaw="absent", alias_count=0, events=())
        return 0

    # Trust-fix classification lives on OpenclawApplyResult.has_failure
    # (single-sourced — see integration.py docstring). Lock + unlock both
    # call this property.
    if not result.has_failure:
        return _finalise_openclaw_success(
            planned, result, console, quiet, home, proxy_host=_proxy_host
        )

    # Detected + failed: the trust-failure path. Print [FAIL] block, write
    # sentinel as partial. Caller raises typer.Exit(openclaw_exit) after
    # lock-core's .env/DB writes finish committing.
    #
    # Exit code classification:
    #   87 — CONFIG_UNREADABLE: infra blocked before any write (UID mismatch,
    #        chmod 000). The integration was never attempted.
    #   73 — any other failure: integration tried and partially failed.
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
    # CONFIG_UNREADABLE = infra block (never attempted) → 87.
    # All other failures = tried and partially failed → 73.
    if any(e.code == OpenclawErrorCode.CONFIG_UNREADABLE for e in result.events):
        return 87
    return 73


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

    worthless-8vvg: bounded by ``SCAN_TIME_BUDGET_S`` + ``skipped`` collector
    so a hostile or oversized source file can't make ``worthless lock`` hang
    after the lock has already succeeded. This is ADVISORY not blocking —
    unlike the pre-flight scan in ``_lock_keys`` (which fail-closes on a
    non-empty skipped list), this post-lock prompt is opportunistic: the lock
    is already committed, the exit code MUST NOT change, and the user just
    needs to know the source scan was incomplete so they can re-run
    ``worthless scan --code`` manually.
    """
    try:
        skipped: list[SkippedFile] = []
        deadline = time.monotonic() + SCAN_TIME_BUDGET_S
        findings = scan_for_hardcoded_provider_urls([cwd], deadline=deadline, skipped=skipped)
        if skipped:
            # Advisory note ONLY — lock already succeeded; we don't prompt and
            # we don't change the exit code. The user can re-run the scan
            # manually once they fix the underlying cause (oversized file,
            # permission error, slow disk).
            reason_counts: dict[str, int] = {}
            for s in skipped:
                reason_counts[s.reason] = reason_counts.get(s.reason, 0) + 1
            # Sort most-frequent-first, alpha tie-break — matches the
            # rendered "{count} {reason}" reading order and gives a stable
            # output for the same input.
            reason_summary = ", ".join(
                f"{n} {r}" for r, n in sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            )
            typer.echo(
                f"\nNote: post-lock source scan incomplete ({reason_summary}). "
                "Run `worthless scan --code` after addressing the cause for a "
                "full report on hardcoded provider URLs.",
                err=True,
            )
            return
        if not findings:
            return
        count = len(findings)
        noun = "URL" if count == 1 else "URLs"
        summary = f"Found {count} hardcoded provider {noun} that will bypass the proxy."
        if _scan_prompt_is_tty():
            confirmed = typer.confirm(f"\n{summary} Scan now?", default=True)
            if not confirmed:
                return
            typer.echo(_format_code_findings_human(findings, collapse_tests=True), err=True)
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
    # Handler ordering matters: ``typer.Abort`` MUST precede ``except Exception``.
    # ``typer.Abort`` is a subclass of ``click.exceptions.Abort`` → ``RuntimeError``,
    # so the broader catch would otherwise swallow Ctrl-C and we'd lose the
    # "polite no" semantic. A future maintainer reordering these alphabetically
    # would silently break that behaviour.
    except typer.Abort:
        # User pressed Ctrl-C at the "Scan now?" prompt — lock already succeeded,
        # treat this as a polite "no thanks" rather than an error.
        return
    except Exception:  # noqa: BLE001
        # Promoted from debug → warning (sec-eng R1 on PR #264): if the scanner
        # raises BEFORE populating ``skipped`` (e.g. provider-list import error),
        # the advisory is silently dropped — same blind spot as pre-8vvg. WARNING
        # makes broken post-lock scanners observable in support logs without
        # changing user-facing behaviour (lock exit code stays 0 either way).
        logger.warning("_maybe_prompt_code_scan raised, skipping", exc_info=True)


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
    bind_confirmation: dict[str, object] | None = None,
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
            bind_confirmation=bind_confirmation,
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
    openclaw_failed: bool = False,
) -> None:
    """Emit the post-lock user-facing summary (called only when quiet=False).

    ``openclaw_failed`` (WOR-779 honesty): on a partial OpenClaw failure the
    ``.env`` IS split, but agent traffic is NOT gated — so the derived verdict
    is NOT "you're protected". Suppress the verdict headline + the breezy
    closure (the caller's ``LOCK FAILED`` block carries the real,
    worst-component verdict); the factual ``[OK] split`` line still prints.
    """
    if fresh_count or relock_count:
        # WOR-779: the seatbelt click — lead with a plain verdict (Verdict →
        # Proof → Next). The verdict is DERIVED: on a partial OpenClaw failure
        # we must NOT claim "you're protected" above the LOCK FAILED footer.
        total = fresh_count + relock_count
        total_noun = "key" if total == 1 else "keys"
        if not openclaw_failed:
            console.print_success(
                f"🔒 You're protected. {total} {total_noun} locked — a stolen "
                f"{env_path.name} is now worthless to an attacker."
            )
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
        # WOR-779 (CR): the daemon-mode "Next:" cue is a success next-step — keep
        # it off the partial-failure path so nothing above LOCK FAILED reads as OK.
        if fresh_count and not openclaw_failed:
            console.print_hint(
                "Next: run `worthless wrap <command>` or `worthless up` for daemon mode"
            )
        # WOR-779: closure — the "pull anytime" reassurance home. Suppressed on
        # a partial failure — don't reassure when the lock didn't fully succeed.
        if not openclaw_failed:
            console.print_hint("Check anytime with `worthless status`.")
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


def _sync_fernet_after_lock(home: WorthlessHome) -> None:
    """Copy canonical Fernet key to fernet.key after lock (WOR-748).

    Skipped under Docker IPC-only (sidecar owns ``fernet.key``; proxy cannot
    overwrite) and when on-disk ``fernet.key`` disagrees with the canonical
    key already loaded for this lock (WOR-464 — never auto-pick a side).

    Uses the ``home.fernet_key`` cache so lock does not fire a second
    keyring read (HF2 contract).
    """
    if sys.platform not in ("darwin", "linux"):
        return
    if fernet_ipc_only_enabled():
        return

    key = home.fernet_key
    try:
        on_disk = _fernet_file_bytes(home.fernet_key_path)
        if on_disk is not None and on_disk != key:
            logger.debug(
                "Skipping post-lock fernet sync — file bytes differ from canonical key (WOR-464)"
            )
            return
        sync_fernet_for_launchd(home.base_dir, key=key)
    finally:
        zero_buf(key)


def _lock_keys(
    env_path: Path,
    home: WorthlessHome,
    provider_override: str | None = None,
    token_budget_daily: int | None = None,
    quiet: bool = False,
    keys_only: bool = False,
    allow_hardcoded_urls: bool = False,
    adopt: bool = False,
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

    # c5kc-61tw: same fail-closed contract the CLI scan uses — bounded per-file
    # read + wall-clock deadline so a hostile / oversized source file can't hang
    # ``worthless lock`` the way it could hang ``worthless scan`` pre-c5kc.
    # ``skipped`` collects files we couldn't fully scan (truncated / unreadable
    # / timeout); incomplete scan = hard fail BEFORE evaluating bypass_findings,
    # because ``--allow-hardcoded-urls`` can't waive bypass URLs that were
    # never surfaced (we don't know what was in the un-scanned tail).
    bypass_skipped: list[SkippedFile] = []
    bypass_deadline = time.monotonic() + SCAN_TIME_BUDGET_S
    bypass_findings = scan_source_for_hardcoded_provider_urls(
        env_path.parent,
        deadline=bypass_deadline,
        skipped=bypass_skipped,
    )
    # Filter to the HANG-class skips only. ``unreadable`` (permission denied,
    # I/O error) is silently tolerated here because lock's source scan is
    # opportunistic defense-in-depth — vendored binaries, OS-specific files,
    # and dev-only permission quirks are normal and should NOT block a lock.
    # The pre-existing contract (``test_unreadable_source_file_does_not_crash``)
    # is preserved. ``truncated`` / ``timeout`` ARE genuine hang risks (the
    # c5kc-named scenarios) and still fail closed.
    hang_class_skipped = [s for s in bypass_skipped if s.reason != "unreadable"]
    if hang_class_skipped:
        # Lead with the reason summary so the user-facing word ("truncated" /
        # "timeout") lands in the header — downstream message truncation can
        # eat the middle of multi-line messages, but the header stays intact.
        reason_counts: dict[str, int] = {}
        for s in hang_class_skipped:
            reason_counts[s.reason] = reason_counts.get(s.reason, 0) + 1
        reason_summary = ", ".join(f"{n} {r}" for r, n in sorted(reason_counts.items()))
        skip_lines = [
            f"worthless: source scan incomplete ({reason_summary}) — refusing to lock.",
            "An incomplete scan can't prove no hardcoded provider URLs slipped past.",
            "Affected files:",
        ]
        for s in hang_class_skipped:
            # File paths come from our own filesystem walk — but the walk
            # traverses files NAMED BY THE USER'S REPO, which can include
            # attacker-controlled bytes (npm tarball, hostile git clone,
            # supply-chain dep). Strip C0/C1 + bidi overrides + BOM via
            # sanitise_for_message to defeat terminal-escape spoofing and
            # Trojan Source (CVE-2021-42574) attacks against this security-
            # gate error message. The console layer's k82c bracket-escape
            # handles ``[`` and ``]`` separately. Mirrors the same pattern
            # the bypass-findings path below already uses.
            safe_file = _oc_audit.sanitise_for_message(s.file)
            skip_lines.append(f"  {safe_file}  [{s.reason}]")
        skip_lines.append("Resolve the cause (oversized source, permission, slow disk) and re-run.")
        raise WorthlessError(
            ErrorCode.SCAN_ERROR,
            "\n".join(skip_lines),
            exit_code=2,
        )
    if bypass_findings:
        _san = _oc_audit.sanitise_for_message
        if allow_hardcoded_urls:
            console.print_warning(
                _format_lock_block_human(bypass_findings, blocking=False, sanitize=_san)
            )
            console.print_warning("Proceeding with --allow-hardcoded-urls.")
        elif sys.stdin.isatty():
            console.print_warning(
                _format_lock_block_human(bypass_findings, blocking=False, sanitize=_san)
            )
            if not typer.confirm(
                "Are these test fixtures or docs? Proceed anyway?",
                default=False,
            ):
                raise WorthlessError(ErrorCode.SCAN_ERROR, "Aborted.", exit_code=1)
        else:
            raise WorthlessError(
                ErrorCode.SCAN_ERROR,
                _format_lock_block_human(bypass_findings, blocking=True, sanitize=_san),
                exit_code=1,
            )

    if not quiet:
        console.print_hint(f"Scanning {env_path} for API keys...")

    class _LockResult(NamedTuple):
        total: int
        fresh_count: int
        openclaw_exit: int  # 0 = ok, 73 = partial fail, 87 = infra blocked

    async def _lock_async() -> _LockResult:
        from dotenv import dotenv_values  # noqa: PLC0415 — local import keeps test surface tight

        async with open_repo(home) as repo:
            await repo.initialize()

            # WOR-650: snapshot the aliases this machine created (the shards
            # table) BEFORE pass-1 adds this lock's new aliases, so recognition
            # judges the *existing* OpenClaw entry against prior state. None =
            # the snapshot failed → fail-safe recognition_unavailable downstream.
            try:
                managed_aliases: set[str] | None = set(await repo.list_keys())
            except Exception:  # noqa: BLE001 — recognition is best-effort, never blocks lock
                managed_aliases = None

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
                return _LockResult(total=len(raw_scanned), fresh_count=0, openclaw_exit=0)

            # Snapshot .env so _pass1 can pull *_BASE_URL values into the DB row.
            env_values = dict(dotenv_values(env_path))

            # worthless-ftmg: refuse to lock an already-locked .env BEFORE any
            # state mutation. The legitimate idempotent re-lock case (same key
            # value → same alias → DB row matches → commitment passes) already
            # short-circuited via `if not scanned: return` above — anything
            # still in `scanned` here has NO matching DB row. So a *_BASE_URL
            # pointing at our proxy means we'd be about to re-split a value
            # that's already shard-A from a previous lock cycle (DB-nuked,
            # restored-from-backup, container rebuild, etc.) and overwrite
            # both halves. That destroys the only path back to the original
            # real key. Refuse here with zero side effects.
            _already_locked_var = _detect_already_locked_env(env_values)
            if _already_locked_var is not None:
                raise WorthlessError(
                    ErrorCode.ENV_ALREADY_LOCKED,
                    f"This .env is already locked — {_already_locked_var} points at "
                    "the Worthless proxy and the key field doesn't match any stored "
                    "shard. Re-locking now would overwrite shard-A and make your "
                    "original key unrecoverable.\n"
                    "  • To return to the original key: `worthless unlock`\n"
                    "  • To recover from a half-state:  `worthless doctor`\n"
                    "Nothing was changed — your .env, database, and OpenClaw config "
                    "are untouched.",
                    exit_code=ErrorCode.ENV_ALREADY_LOCKED.value,
                )

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

            # F7 (WOR-648 / WOR-621 AC5): proxy health gate, alongside the
            # audit gate above — BEFORE any DB or .env write. Gated on
            # ``_openclaw_integration.detect().present`` because non-OpenClaw
            # users follow a documented ``worthless lock`` → ``worthless wrap``
            # flow: lock writes ``*_BASE_URL`` pointing at the chosen port,
            # then ``wrap`` binds that same port and forwards (the v0.3.4
            # magic-moment contract, pinned by
            # tests/user_flows/test_wrap_magic_moment.py). Requiring the proxy
            # up at lock time would break that journey. For OpenClaw users
            # the gate IS load-bearing: if the proxy is down, the lock
            # would write the OpenClaw provider's baseUrl at a dead proxy
            # and OpenClaw would route there permanently — a half-locked
            # state that strands the key. Aborting here keeps .env, DB, and
            # ~/.openclaw/openclaw.json byte-for-byte unchanged.
            #
            # KNOWN LIMITATION: ``detect()`` can false-negative on hosts
            # that actually do have OpenClaw (foreign-owned ~/.openclaw in
            # Docker shared-vol mode, non-standard home, container off at
            # lock time). Tracked separately — harden detect() or add a
            # raw-fs fallback so the gate fires even when detect() misses.
            if _openclaw_integration.detect().present:
                _probe_port = resolve_port(None)
                if not check_proxy_health(_probe_port)["healthy"]:
                    raise WorthlessError(
                        ErrorCode.PROXY_NOT_RUNNING,
                        f"Worthless proxy is not responding on port {_probe_port}. "
                        "Nothing was changed — your .env, database, and "
                        "~/.openclaw/openclaw.json are untouched. Start the proxy "
                        "(`worthless up`) and re-run `worthless lock`.",
                    )

            planned: list[_PlannedUpdate] = []

            # WOR-646: arm SIGINT/SIGTERM BEFORE Pass-1's first DB write so an
            # interrupt mid-lock unwinds the rows it already created instead of
            # orphaning them. We use the asyncio-native ``add_signal_handler``
            # (NOT ``signal.signal``) because we're inside ``asyncio.run``: a
            # C-level handler would race the loop's wakeup fd and the
            # cancellation wouldn't be seen until an unrelated wakeup — the same
            # reason ``sidecar/__main__.py`` uses ``add_signal_handler``. The
            # handler cancels THIS task, so a ``CancelledError`` surfaces at the
            # next ``await`` inside the try below and is caught alongside
            # ordinary failures, routing through ``_compensating_unwind``.
            #
            # On 3.11+ ``asyncio.Runner`` installs its own SIGINT handler; our
            # ``add_signal_handler`` cleanly overrides it for the lock window
            # and never touches SIGTERM (which the Runner ignores) — so this is
            # the only uniform SIGINT+SIGTERM path across 3.10–3.13.
            loop = asyncio.get_running_loop()
            this_task = asyncio.current_task()
            installed_signals: list[int] = []
            interrupted = False

            def _request_unwind() -> None:
                # One-shot: cancel on the FIRST signal only. The handler stays
                # installed (but inert) through the rollback below, so a mashed
                # Ctrl-C lands here as a no-op instead of re-cancelling the task
                # — or, worse, hitting the default SIGINT disposition that
                # ``remove_signal_handler`` would restore and raising
                # KeyboardInterrupt mid-unwind, orphaning the rows we're
                # deleting. Disarm happens only in ``finally``.
                nonlocal interrupted
                if interrupted or this_task is None:
                    return
                interrupted = True
                this_task.cancel()

            def _disarm_signals() -> None:
                # Idempotent: pop so calling from both the except clause AND the
                # finally (or a partial install) is a safe no-op the second time.
                while installed_signals:
                    sig = installed_signals.pop()
                    try:
                        loop.remove_signal_handler(sig)
                    except (NotImplementedError, RuntimeError, ValueError):
                        pass

            for _sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(_sig, _request_unwind)
                except (NotImplementedError, RuntimeError):
                    # Signal-driven cancellation is unavailable here:
                    #   * Windows ProactorEventLoop (NotImplementedError), or
                    #   * a non-main-thread event loop (RuntimeError) — e.g. the
                    #     MCP ``worthless_lock`` tool runs ``_lock_keys`` via
                    #     ``run_in_executor`` (mcp/server.py).
                    # Python delivers SIGINT/SIGTERM ONLY to the process main
                    # thread, so a worker-thread lock receives NO interrupt at all
                    # — it is NOT true that "default SIGINT → KeyboardInterrupt
                    # still applies" off the main thread. On these paths
                    # crash-safety rests on the atomic Pass-1 transaction
                    # (WOR-646 Part 2), not the signal handler. Real mid-lock
                    # interrupt safety for the MCP path is tracked in worthless-dqzj.
                    # Record only the signals that actually installed so cleanup
                    # can't leak a handler when one of the two raises.
                    continue
                installed_signals.append(_sig)

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
                    return _LockResult(total=0, fresh_count=0, openclaw_exit=0)
                _batch_rewrite(env_path, planned, keys_only, existing_env_keys)
                if _oc_gate is not None:
                    _openclaw_audit_postflight(_oc_gate)
                # Phase 2.b: OpenClaw magic. Per L1 in
                # engineering/research/openclaw/WOR-431-phase-2-spec.md, this
                # NEVER rolls back lock-core success. Per L2 (revised 2026-05-08
                # by the verification gauntlet): detected+failed returns non-zero
                # openclaw_exit so the caller can raise typer.Exit(openclaw_exit)
                # AFTER lock-core's .env/DB writes are fully committed.
                adoption_policy = _resolve_adoption_policy(
                    planned,
                    managed_aliases=managed_aliases,
                    adopt=adopt,
                    console=console,
                    quiet=quiet,
                )
                openclaw_exit = _apply_openclaw(planned, console, quiet, home, adoption_policy)
                fresh_count = sum(1 for p in planned if p.was_fresh_enroll)
                return _LockResult(
                    total=len(planned), fresh_count=fresh_count, openclaw_exit=openclaw_exit
                )
            except (Exception, KeyboardInterrupt, asyncio.CancelledError) as exc:
                # The signal handler is one-shot and stays installed here, so the
                # rollback below runs uninterrupted by a mashed Ctrl-C; ``finally``
                # disarms it. The interrupt types are caught EXPLICITLY (not a
                # bare ``except BaseException``) so ``SystemExit`` keeps
                # propagating. ``typer.Exit`` is a ``RuntimeError`` (an
                # ``Exception``), so — exactly as before this change — it is
                # caught and DOES unwind: the pre-existing post-flight recovery
                # contract (``_openclaw_audit_postflight`` rewinds the DB rows
                # after a ``.env`` commit for a recoverable re-lock). The
                # ``isinstance`` guard below converts ONLY a genuine signal
                # cancellation to ``KeyboardInterrupt``, leaving other exit codes
                # (``typer.Exit`` 73/87, ``WorthlessError``) intact.
                if planned:
                    unwind_errors = await _compensating_unwind(repo, planned)
                    if unwind_errors:
                        console.print_warning(
                            f"Database may contain {len(unwind_errors)} stale row(s); "
                            "run `worthless unlock --all` to reconcile."
                        )
                if isinstance(exc, asyncio.CancelledError):
                    # Surface the signal-driven cancellation as a conventional
                    # interrupt so the CLI exits cleanly instead of dumping an
                    # asyncio ``CancelledError`` traceback — ``error_boundary``
                    # handles ``Exception`` but not ``BaseException``.
                    raise KeyboardInterrupt from None
                raise
            finally:
                # Idempotent backstop: removes handlers on the paths the except
                # clause never runs (success, or an uncaught ``typer.Exit``).
                _disarm_signals()
                for p in planned:
                    p.zero()

    result = asyncio.run(_lock_async())
    relock_count = result.total - result.fresh_count

    if result.fresh_count and env_path.exists():
        current = env_path.stat().st_mode
        if current & (stat.S_IRWXG | stat.S_IRWXO):
            env_path.chmod(current & ~(stat.S_IRWXG | stat.S_IRWXO))

    if not quiet:
        _print_lock_result(
            console,
            result.fresh_count,
            relock_count,
            env_path,
            home.base_dir,
            openclaw_failed=bool(result.openclaw_exit),
        )

    # Trust-fix (2026-05-08 verification gauntlet): when OpenClaw was
    # detected on this host AND the integration stage failed, the user is
    # in a false-invariant state — .env is locked, but their agent traffic
    # is not gated. Surface this LOUDLY by exiting non-zero AFTER the
    # lock-core writes have committed (L1 binding contract preserved).
    # Exit 73 = tried, partial fail (EX_CANTCREAT, POSIX).
    # Exit 87 = infra blocked before any attempt (CONFIG_UNREADABLE / UID mismatch).
    # The [FAIL] block is already printed by _apply_openclaw; this final
    # LOCK FAILED line disambiguates the mixed [FAIL]+[OK] output so the
    # user cannot mistake a partial failure for overall success (WOR-551).
    if result.openclaw_exit:
        console.print_failure(
            "LOCK FAILED — .env key is split but OpenClaw integration did not complete.\n"
            "Your agent traffic is NOT gated through the Worthless proxy.\n"
            "Run `worthless doctor` to diagnose, `worthless unlock` to roll back."
        )
        raise typer.Exit(code=result.openclaw_exit)

    _sync_fernet_after_lock(home)
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
        adopt: bool = typer.Option(
            False,
            "--adopt",
            help=(
                "Take over pre-existing OpenClaw proxy entries not created on "
                "this machine without prompting (e.g. a synced config or reinstall)."
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
                adopt=adopt,
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

"""Doctor command — diagnose and repair stuck DB/.env states (HF7 / worthless-3907).

Currently handles TWO known shapes:

1. Orphan DB enrollments whose ``.env`` line was deleted by the user (HF7).
   The dogfood-discovered stuck state from 2026-04-30:

     worthless unlock -> "No enrolled keys found." (silently skips orphan)
     worthless status -> "Enrolled keys: ... PROTECTED" (lists the orphan)

2. OpenClaw integration drift (Phase 2.d / WOR-431): OpenClaw installed
   after ``worthless lock`` ran, or skill folder gone stale. Doctor
   surfaces skill version mismatches and un-wired providers, and can
   reinstall the skill when ``--fix`` is passed.

``worthless doctor`` is read-only: it lists issues.
``worthless doctor --fix`` repairs what it can (destructive for orphans,
safe for skill reinstall). Prompts unless ``--yes``. ``--dry-run`` shows
the planned action without writing.

Design seams (foreseen extensions, NOT in this PR):

* ``worthless-7db2`` (P3): a SECOND repair shape — partial-state recovery
  when the home dir is intact but the fernet key is missing from every
  source (manual keyring deletion). ``ensure_home`` will surface that
  state and point users here; doctor will need a key-regeneration flow
  guarded against silently destroying access to existing locked secrets.
* ``worthless-57ad`` (P3, post-v0.4): a BYO-key LLM agent diagnoses
  UNKNOWN stuck states using a user-locked enrollment.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import re
import sys
from collections.abc import Coroutine, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

if sys.platform != "win32":
    import fcntl

import typer

from dotenv import dotenv_values
from worthless.cli.bootstrap import WorthlessHome, acquire_lock, get_home, _DEFAULT_BASE
from worthless.cli.platform import read_process_env
from worthless.cli.process import pid_path, read_pid, resolve_port
from worthless.cli.commands.revoke import _revoke_async
from worthless.cli.console import WorthlessConsole, get_console
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.keystore import _SERVICE
from worthless.cli.orphans import FIX_PHRASE, PROBLEM_PHRASE, find_orphans, is_orphan
from worthless.openclaw import integration as _oc_integration
from worthless.openclaw import skill as _oc_skill
from worthless.openclaw.errors import OpenclawIntegrationError
from worthless.openclaw.integration import IntegrationState
from worthless.storage.repository import EnrollmentRecord, ShardRepository
from worthless.crypto.splitter import reconstruct_key_fp

# WOR-456: top-level conditional import so tests can monkeypatch the
# module attribute directly. Local imports inside functions resolve via
# sys.modules cache and bypass test patching.
if sys.platform == "darwin":
    from worthless.cli import keystore_macos as _keystore_macos
else:
    _keystore_macos = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# WOR-456: iCloud-keychain-leak phrases. Local because doctor.py is the only
# consumer; if a third check arrives, extract to a sibling _messages module.
ICLOUD_LEAK_PHRASE = "stored in iCloud Keychain"
ICLOUD_FIX_PHRASE = "worthless doctor --fix"
RECOVERY_IMPORT_PHRASE = "Recovered"
HOME_MISMATCH_PHRASE = "home mismatch"
ALIAS_NOT_IN_DB_PHRASE = "has no shard in the current DB"
_PROXY_ALIAS_URL_RE = re.compile(r"https?://[^/]+/([a-zA-Z0-9_-]+)/v1\b")

# Multi-device safety warning shown in the --fix consent prompt. Verbatim
# substrings are AND-bound by tests so future copy-paste cleanups don't
# silently drop the safety information.
_MULTI_DEVICE_WARNING = (
    "Migrating will:\n"
    "  • Make these keys this-Mac-only on this Mac\n"
    "  • Save a one-time recovery copy in ~/.worthless/recovery/ (mode 0600)\n"
    "  • Within ~30 seconds, the keys will disappear from your other Apple devices\n"
    "\n"
    "If you have Worthless on other Macs, copy the recovery files there before\n"
    "they sync, OR run `worthless doctor` on those Macs to re-import. Without\n"
    "that, locked .env files on other Macs will be unrecoverable until you\n"
    "re-enroll there."
)


def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run *coro* safely regardless of whether an event loop is already running.

    ``asyncio.run()`` raises ``RuntimeError`` when called from within a running
    event loop (e.g. pytest-asyncio test context).  In that case we dispatch to
    a fresh event loop in a worker thread, which is the same pattern used by
    ``worthless.cli.bootstrap`` for ``migrate_db``.
    """
    try:
        asyncio.get_running_loop()
        # Already inside a running loop — spin up a thread with its own loop.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # No running loop — safe to call asyncio.run() directly.
        return asyncio.run(coro)


async def _list_orphans(
    repo: ShardRepository,
) -> tuple[list[EnrollmentRecord], list[EnrollmentRecord]]:
    """Initialize the repo and return ``(all_enrollments, orphans)``.

    Returns both so callers can reuse the already-fetched enrollment list
    without a second ``asyncio.run`` on the same repo (which fails on Linux
    when the event loop is closed between calls).
    """
    await repo.initialize()
    all_enrollments = await repo.list_enrollments()
    return all_enrollments, find_orphans(all_enrollments)


async def _purge_all(
    orphans: list[EnrollmentRecord],
    repo: ShardRepository,
    shard_a_dir: Path,
) -> int:
    """Delete each orphan's enrollment row surgically. If an alias has no
    enrollments left after the delete, also tear down its shard + spend_log
    + config + shard_a file (the full ``_revoke_async`` path).

    CodeRabbit MAJOR (PR #128 review): the previous version called
    ``_revoke_async`` per orphan, which wipes EVERY enrollment for that
    alias — including healthy rows in other ``.env`` files. That's a
    multi-project data-loss bug. Surgical delete by ``(key_alias, env_path)``
    fixes it; per-alias teardown only fires when the alias has nothing left.

    Re-validates the orphan set against the live DB after acquiring the
    lock so stale entries (state shifted between diagnose + confirm) don't
    delete healthy rows.
    """
    current = await repo.list_enrollments()
    still_orphan_keys = {(e.key_alias, e.env_path) for e in find_orphans(current)}

    purged = 0
    aliases_touched: set[str] = set()
    for orphan in orphans:
        if (orphan.key_alias, orphan.env_path) not in still_orphan_keys:
            continue  # state drifted — skip
        if await repo.delete_enrollment(orphan.key_alias, orphan.env_path):
            purged += 1
            aliases_touched.add(orphan.key_alias)

    # For each touched alias: if zero enrollments remain, tear down the
    # alias-level state (shard_b row + spend_log + config + shard_a file).
    after = await repo.list_enrollments()
    aliases_with_remaining = {e.key_alias for e in after}
    for alias in aliases_touched - aliases_with_remaining:
        await _revoke_async(alias, repo, shard_a_dir)

    return purged


def _print_orphan_lines(
    orphans: list[EnrollmentRecord], *, dry_run: bool, show_fix_hint: bool = True
) -> None:
    """One line per orphan, plain English. Phrase tokens come from
    ``worthless.cli.orphans``. ``typer.echo`` because ``WorthlessConsole``
    only exposes semantic methods (success/error/hint/warning).

    ``show_fix_hint`` is False when we're already running ``--fix`` — no
    point telling the user to run the command they just ran.
    """
    suffix = " (dry-run: no changes)" if dry_run else ""
    for e in orphans:
        typer.echo(
            f"  • {PROBLEM_PHRASE} {e.key_alias}: .env line deleted "
            f"({e.var_name} -> {e.env_path}){suffix}"
        )
    if show_fix_hint:
        typer.echo(f"    fix: run `{FIX_PHRASE}`")


_VERSION_LINE = re.compile(r"^Version:\s*(\S+)\s*$", re.MULTILINE)


def _skill_installed_version(skill_dir: Path) -> str | None:
    """Return the ``Version:`` string from the installed SKILL.md, or None.

    Returns None when the dir / file is absent, unreadable, or has no
    Version line. The parse pattern mirrors :func:`worthless.openclaw.skill.current_version`
    so the comparison in :func:`_check_openclaw_section` is apples-to-apples.
    """
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return None
    try:
        body = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _VERSION_LINE.search(body)
    return match.group(1) if match else None


def _check_skill(
    state: IntegrationState,
    *,
    fix: bool,
    dry_run: bool,
) -> tuple[list[str], list[str]]:
    """Check skill install health. Returns ``(issues, fixed_items)``."""
    issues: list[str] = []
    fixed_items: list[str] = []

    if state.workspace_path is None:
        return ["workspace not found — skill check skipped"], []

    skill_dir = state.workspace_path / "skills" / "worthless"
    installed_ver = _skill_installed_version(skill_dir)
    try:
        bundled_ver = _oc_skill.current_version()
    except OpenclawIntegrationError:
        bundled_ver = None

    skill_needs_repair = installed_ver is None or (
        bundled_ver is not None and installed_ver != bundled_ver
    )
    if installed_ver is None:
        issues.append("skill not installed")
    elif skill_needs_repair:
        issues.append(f"skill stale (installed {installed_ver}, bundled {bundled_ver})")

    if fix and skill_needs_repair:
        if dry_run:
            fixed_items.append("[dry-run] would reinstall skill")
        else:
            try:
                _oc_skill.install(state.workspace_path / "skills")
                fixed_items.append("skill reinstalled")
            except (OpenclawIntegrationError, OSError) as exc:
                issues.append(f"skill repair failed: {exc}")

    return issues, fixed_items


def _check_providers(
    state: IntegrationState,
    healthy: list,
    *,
    port: int,
) -> list[str]:
    """Check openclaw.json provider entries for each healthy enrollment.

    Delegates to :func:`worthless.openclaw.integration.health_check` for
    the read logic so the verification rules live in one place (Phase 2.d).

    ``port`` must come from ``resolve_port(None)`` so non-default deployments
    (``WORTHLESS_PORT`` env or ``--port``) are not falsely reported as drift.

    Returns a list of issue strings (empty = all wired correctly).
    """
    expected = [(e.provider, e.key_alias) for e in healthy]
    report = _oc_integration.health_check(state, expected_providers=expected, proxy_port=port)

    fix_hint = "re-run `worthless lock`"
    if report.config_unreadable:
        return [
            f"worthless-{provider} config unreadable — {fix_hint}" for provider, _alias in expected
        ]

    missing_where = (
        "not wired (no openclaw.json)"
        if state.config_path is None
        else "not wired in openclaw.json"
    )
    issues = [f"{name} {missing_where} — {fix_hint}" for name in report.providers_missing]
    issues.extend(
        f"{name} baseUrl mismatch (got {actual!r}, expected {expected_url!r}) — {fix_hint}"
        for name, actual, expected_url in report.providers_drifted
    )
    return issues


def _read_worthless_providers_from_config(config_path: Path) -> dict[str, dict]:
    """Read all ``worthless-*`` provider entries from openclaw.json.

    Handles both the canonical ``models.providers`` schema and the flat
    ``providers`` top-level schema emitted by some OpenClaw versions.

    Returns a mapping of provider_name -> entry dict. Empty on any error.
    """
    try:
        import json as _json

        raw = config_path.read_text(encoding="utf-8").strip()
        if not raw:
            return {}
        data = _json.loads(raw)
        if not isinstance(data, dict):
            return {}
    except Exception:
        return {}

    # Try canonical schema: data["models"]["providers"]
    models = data.get("models")
    if isinstance(models, dict):
        providers = models.get("providers")
        if isinstance(providers, dict):
            return {
                k: v
                for k, v in providers.items()
                if k.startswith("worthless-") and isinstance(v, dict)
            }

    # Fallback: flat data["providers"] (some OpenClaw / test fixtures)
    flat_providers = data.get("providers")
    if isinstance(flat_providers, dict):
        return {
            k: v
            for k, v in flat_providers.items()
            if k.startswith("worthless-") and isinstance(v, dict)
        }

    return {}


_ALIAS_FROM_BASE_URL_RE = re.compile(r"/([^/]+)/v1(?:/|$)")


def _alias_from_base_url(base_url: str) -> str | None:
    """Extract the key alias from a worthless proxy baseUrl.

    ``http://127.0.0.1:8787/openai-stale/v1`` -> ``openai-stale``
    Returns ``None`` when the URL does not match the expected pattern.
    """
    m = _ALIAS_FROM_BASE_URL_RE.search(base_url)
    return m.group(1) if m else None


def _check_openclaw_apikey_consistency(
    state: IntegrationState,
    repo: ShardRepository,
) -> list[str]:
    """Check that openclaw.json apiKey values reconstruct correctly with DB shards.

    Post-16x2-revert: openclaw.json carries shard-A as apiKey. If the DB has
    been updated (re-lock wrote new shard-B + commitment) without updating
    openclaw.json (e.g. crash/revert), the stored apiKey is stale.

    Iterates over worthless-* provider entries in openclaw.json directly
    (not via enrollment rows, which may not exist when upsert_locked_shard was
    called without store_enrolled).

    Returns a list of issue strings (empty = consistent).
    """
    if state.config_path is None:
        return []

    # F-CFG-15: refuse to read through a symlinked config_path.  health_check()
    # records a note for symlinks rather than following them; this function must
    # honour the same boundary so a malicious symlink cannot poison the check.
    if state.config_path.is_symlink():
        return [
            f"openclaw.json at {state.config_path} is a symlink (refused for safety) — "
            "re-run `worthless lock` to regenerate a real config file"
        ]

    providers = _read_worthless_providers_from_config(state.config_path)
    if not providers:
        return []

    issues: list[str] = []
    for provider_name, entry in providers.items():
        api_key_str = entry.get("apiKey", "")
        if not api_key_str:
            continue

        base_url = entry.get("baseUrl", "")
        alias = _alias_from_base_url(base_url)
        if not alias:
            continue

        try:
            encrypted = _run_async(repo.fetch_encrypted(alias))
        except Exception:  # noqa: BLE001 — treat any fetch error as "not found"
            issues.append(
                f"openclaw.json references alias {alias!r} (provider {provider_name!r}) "
                f"but the DB lookup failed — re-run `worthless lock` to fix"
            )
            continue
        if encrypted is None:
            # Alias present in openclaw.json but not in DB — explicit issue
            issues.append(
                f"openclaw.json references alias {alias!r} (provider {provider_name!r}) "
                f"which is not enrolled in the DB — re-run `worthless lock` to fix"
            )
            continue
        if encrypted.prefix is None or encrypted.charset is None:
            continue

        stored = None
        shard_a_buf = None
        try:
            stored = repo.decrypt_shard(encrypted)
            shard_a_buf = bytearray(api_key_str, "utf-8")
            reconstruct_key_fp(
                shard_a_buf,
                stored.shard_b,
                stored.commitment,
                stored.nonce,
                encrypted.prefix,
                encrypted.charset,
            )
            # Reconstruction succeeded — apiKey is consistent with DB
        except Exception:
            issues.append(
                f"openclaw.json apiKey for {provider_name!r} is stale and out of sync "
                f"with DB shards — re-run `worthless lock` to fix"
            )
        finally:
            if shard_a_buf is not None:
                for i in range(len(shard_a_buf)):
                    shard_a_buf[i] = 0
            if stored is not None:
                stored.zero()

    return issues


def _check_openclaw_section(
    enrollments: list[EnrollmentRecord],
    *,
    repo: ShardRepository | None = None,
    fix: bool,
    dry_run: bool,
) -> bool:
    """Check OpenClaw health. Print diagnostics; optionally repair skill.

    Returns True when any issue was found (even if ``--fix`` repaired it).
    Returns False and prints nothing when OpenClaw is absent OR all checks
    pass — caller shows "No issues found." in that case.

    Spec: ``.claude/plans/graceful-dreaming-reef.md`` §"Phase 2.d" /
    test matrix rows U-DOC-01..07.
    """
    state = _oc_integration.detect()
    if not state.present:
        return False

    skill_issues, fixed_items = _check_skill(state, fix=fix, dry_run=dry_run)

    healthy = [e for e in enrollments if not is_orphan(e)]
    port = resolve_port(None)
    provider_issues = _check_providers(state, healthy, port=port)

    # Check openclaw.json apiKey consistency with DB shards (post-16x2-revert).
    # repo=None when called from tests that don't need the consistency check.
    consistency_issues = _check_openclaw_apikey_consistency(state, repo) if repo is not None else []

    all_issues = skill_issues + provider_issues + consistency_issues
    if not all_issues and not fixed_items:
        return False  # all checks passed, stay silent

    typer.echo("\nOpenClaw:")
    for issue in all_issues:
        typer.echo(f"  ✗ {issue}")
    for item in fixed_items:
        typer.echo(f"  ✓ {item}")
    return True


# ---------------------------------------------------------------------------
# WOR-456: iCloud-keychain check + safe migration
# ---------------------------------------------------------------------------


def _list_synced_keychain_entries() -> list[str]:
    """Return list of synced keychain accounts under our service.

    Empty on non-darwin (no Security framework). Empty on darwin too if
    nothing is synced — clean state.

    Signature shape pinned to match WOR-464's future check-registry contract:
    ``() -> list[str]`` of human-identifiers.
    """
    if _keystore_macos is None:
        return []
    try:
        return _keystore_macos.find_synced_entries(_SERVICE)
    except Exception as exc:  # noqa: BLE001
        # SR-04: never include the exception's value-bearing chain in logs.
        # Bare type + status is enough for support.
        logger.debug("find_synced_entries failed: %s", type(exc).__name__)
        return []


def _list_recovery_files(home: WorthlessHome) -> list[Path]:
    """Return ``<account>.recover`` files awaiting import on this Mac.

    These files are written by ``--fix`` on the originating Mac and are
    consumed (imported into local keychain + deleted) by ``worthless doctor``
    on a sibling Mac after the user transfers them across (e.g. via scp).
    """
    if not home.recovery_dir.exists():
        return []
    return sorted(home.recovery_dir.glob("*.recover"))


def _check_home_mismatch(home: WorthlessHome) -> bool:
    """Check if the running proxy uses a different home. Prints and returns True on mismatch."""
    pid_result = read_pid(pid_path(home))
    if pid_result is None:
        return False
    pid, _port = pid_result
    env = read_process_env(pid)
    proxy_home_str = env.get("WORTHLESS_HOME")
    proxy_home = Path(proxy_home_str) if proxy_home_str else _DEFAULT_BASE
    if proxy_home.resolve() == home.base_dir.resolve():
        return False
    typer.echo(f"WARNING: {HOME_MISMATCH_PHRASE}")
    typer.echo(f"  proxy is using: {proxy_home / 'worthless.db'}")
    typer.echo(f"  this shell sees: {home.base_dir / 'worthless.db'}")
    typer.echo("  Fix: unset WORTHLESS_HOME, then restart the proxy.")
    return True


def _check_alias_not_in_db(home: WorthlessHome, enrollments: list[EnrollmentRecord]) -> bool:
    """Returns True when a .env BASE_URL references a proxy alias absent from enrollments.

    Scans enrolled .env paths plus the current working directory's .env (when it
    exists), so users running doctor from their project directory get checked even
    if the .env path was not explicitly recorded at enrollment time.
    """
    known_aliases = {e.key_alias for e in enrollments}
    env_paths: set[Path] = {Path(e.env_path) for e in enrollments if e.env_path}
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        env_paths.add(cwd_env)

    issues = _collect_alias_issues(env_paths, known_aliases, home.db_path.name)
    if not issues:
        return False

    typer.echo(f"WARNING: {len(issues)} .env BASE_URL alias(es) missing from DB:")
    for issue in issues:
        typer.echo(f"  • {issue}")
    return True


def _collect_alias_issues(env_paths: set[Path], known_aliases: set[str], db_name: str) -> list[str]:
    """Scan env_paths for BASE_URL values referencing proxy aliases absent from DB."""
    issues: list[str] = []
    seen: set[str] = set()
    for env_file in env_paths:
        try:
            parsed = dotenv_values(env_file)
        except OSError:
            continue
        for key, value in parsed.items():
            if not key.endswith("_BASE_URL") or not value:
                continue
            m = _PROXY_ALIAS_URL_RE.search(value)
            if m is None:
                continue
            alias = m.group(1)
            if alias in seen or alias in known_aliases:
                continue
            seen.add(alias)
            issues.append(
                f"alias '{alias}' is set in {env_file.name} BASE_URL "
                f"but {ALIAS_NOT_IN_DB_PHRASE} ({db_name})"
            )
    return issues


def _import_recovery_files(files: list[Path]) -> int:
    """Import each recovery file into local-scope keychain. Returns count.

    Idempotent: if the local keychain already has the account, the recovery
    file is stale (this Mac is the originator) and gets removed silently.
    """
    if not files or _keystore_macos is None:
        return 0

    imported = 0
    for f in files:
        account = f.stem  # filename without .recover
        try:
            value_bytes = f.read_bytes()
            existing = _keystore_macos.read_password_local(_SERVICE, account)
            if existing is not None:
                # Stale recovery file — this Mac is the originator, nothing to import.
                f.unlink(missing_ok=True)
                continue
            _keystore_macos.set_password_local(_SERVICE, account, value_bytes.decode("utf-8"))
            f.unlink(missing_ok=True)
            imported += 1
        except Exception as exc:  # noqa: BLE001 - SR-04 scrub
            logger.warning(
                "Failed to import recovery file for %s: %s",
                account,
                type(exc).__name__,
            )
    return imported


def _migrate_synced_keys(usernames: list[str], home: WorthlessHome) -> int:
    """Migrate synced keychain entries to this-device-only.

    Safe ordering (WOR-456 §3): for each username U,
      1. read value via SynchronizableAny
      2. write recovery file (atomic via O_EXCL) with the value
      3. add staging slot ``U.migrating`` non-synced; verify byte-equality
      4. delete the synced original
      5. add canonical ``U`` non-synced; verify byte-equality
      6. delete staging slot

    Each step is independently re-entrant. SIGKILL between any pair leaves
    the user with at minimum the recovery file (after step 2) plus either
    the staging slot or the canonical slot — doctor re-run reconciles.

    Returns count of successfully migrated entries. Aborts the run (returns
    partial count) on KeychainAuthDenied / KeychainUserCancelled — no state
    change occurs after the abort point because the read in step 1 is the
    only place those exceptions can fire.
    """
    if _keystore_macos is None or not usernames:
        return 0

    home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    success = 0
    for username in usernames:
        try:
            _migrate_one(username, home, _keystore_macos)
            success += 1
        except (
            _keystore_macos.KeychainAuthDenied,
            _keystore_macos.KeychainUserCancelled,
        ):
            logger.info("Migration aborted: keychain access denied/cancelled")
            return success
        except Exception as exc:  # noqa: BLE001 - SR-04 scrub
            logger.warning("Migration failed for one entry: %s", type(exc).__name__)
    return success


def _migrate_one(username: str, home: WorthlessHome, keystore_macos) -> None:
    """One migration step for ``username``. See ``_migrate_synced_keys`` doc."""
    # 1. Read value with SynchronizableAny (finds the synced entry).
    value = keystore_macos.read_password_any_scope(_SERVICE, username)
    if value is None:
        # Already migrated or never existed — idempotent no-op.
        return

    # 2. Recovery file (atomic, O_EXCL — refuse to overwrite an existing
    # in-flight recovery from a prior interrupted run).
    recovery = home.recovery_dir / f"{username}.recover"
    if not recovery.exists():
        fd = os.open(str(recovery), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, value.encode("utf-8"))
        finally:
            os.close(fd)

    # 3. Staging slot — non-synced so iCloud doesn't replicate it.
    staging = f"{username}.migrating"
    keystore_macos.set_password_local(_SERVICE, staging, value)

    # 4. Verify byte-equality (NOT string compare — Fernet keys are
    # base64-encoded raw bytes; any unicode normalization corrupts).
    read_back = keystore_macos.read_password_local(_SERVICE, staging)
    if read_back is None or read_back.encode("utf-8") != value.encode("utf-8"):
        raise RuntimeError(
            f"staging-slot byte-equality failed for {username}; aborting before delete"
        )

    # 5. Delete the synced original (queues iCloud tombstone).
    try:
        keystore_macos.delete_password_synced(_SERVICE, username)
    except keystore_macos.KeychainNotFound:
        # Race: another doctor run already deleted it; recovery file persists.
        pass

    # 6. Add canonical non-synced slot.
    keystore_macos.set_password_local(_SERVICE, username, value)
    canonical_check = keystore_macos.read_password_local(_SERVICE, username)
    if canonical_check is None or canonical_check.encode("utf-8") != value.encode("utf-8"):
        raise RuntimeError(
            f"canonical-slot byte-equality failed for {username}; staging slot remains"
        )

    # 7. Cleanup staging.
    try:
        keystore_macos.delete_password_local(_SERVICE, staging)
    except keystore_macos.KeychainNotFound:
        pass


@contextmanager
def _doctor_lock(home: WorthlessHome) -> Iterator[None]:
    """Single-doctor-at-a-time lock via flock on ~/.worthless/.doctor.lock.

    Two concurrent ``worthless doctor --fix`` runs would race the migration
    state-machine — the second sees the synced entry as still-present after
    the first's read (step 1) but before delete (step 5), then proceeds to
    overlap. flock serializes them: the second exits with LOCK_IN_PROGRESS.

    On Windows, flock is unavailable (no iCloud sync either), so the lock
    is a no-op — concurrent runs are harmless there.
    """
    if sys.platform == "win32":
        yield
        return

    lock_path = home.base_dir / ".doctor.lock"
    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[possibly-undefined]
        except BlockingIOError:
            os.close(fd)
            raise WorthlessError(
                ErrorCode.LOCK_IN_PROGRESS,
                "Another `worthless doctor` is running. Wait for it to finish.",
            ) from None
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[possibly-undefined]
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _print_synced_lines(usernames: list[str], *, dry_run: bool) -> None:
    suffix = " (dry-run: no changes)" if dry_run else ""
    for u in usernames:
        typer.echo(f"  • {u}{suffix}")


# ---------------------------------------------------------------------------
# Fix-mode helpers (extracted to keep _doctor_run under xenon max-absolute C)
# ---------------------------------------------------------------------------


def _doctor_confirm(
    orphans: list[EnrollmentRecord],
    synced: list[str],
    yes: bool,
    console: WorthlessConsole,
) -> bool:
    """Build and display the combined confirmation prompt. Returns True if the
    user wants to proceed (or --yes was given). False means abort."""
    if yes:
        return True
    prompt_lines = []
    if orphans:
        prompt_lines.append(f"Delete {len(orphans)} orphan DB row(s) and their shard files.")
    if synced:
        n = len(synced)
        prompt_lines.append(
            f"Migrate {n} keychain entr{'y' if n == 1 else 'ies'} to this-Mac-only."
        )
        prompt_lines.append("")
        prompt_lines.append(_MULTI_DEVICE_WARNING)
    prompt = "\n".join(prompt_lines) + "\nProceed?"
    proceed = typer.confirm(prompt, default=False)
    if not proceed:
        console.print_hint("Cancelled. No changes made.")
    return proceed


def _doctor_apply(
    orphans: list[EnrollmentRecord],
    synced: list[str],
    repo: ShardRepository,
    home: WorthlessHome,
    console: WorthlessConsole,
) -> None:
    """Execute the fix actions (purge orphans + migrate synced keys)."""
    if orphans:
        purged = _run_async(_purge_all(orphans, repo, home.shard_a_dir))
        console.print_success(f"Cleaned up {purged} broken record(s).")

    if synced:
        migrated = _migrate_synced_keys(synced, home)
        if migrated:
            console.print_success(
                f"Migrated {migrated} keychain entr"
                f"{'y' if migrated == 1 else 'ies'} to this-Mac-only. "
                f"Recovery files saved in {home.recovery_dir}."
            )
        else:
            console.print_warning(
                "No entries migrated — keychain access was denied or cancelled. Re-run when ready."
            )


# ---------------------------------------------------------------------------
# Doctor entrypoint
# ---------------------------------------------------------------------------


def _doctor_run(*, fix: bool, yes: bool, dry_run: bool) -> None:
    """Diagnose and (optionally) repair stuck states.

    Four checks, run in order:
      1. Recovery file imports (sibling-Mac coming online with files copied across)
      2. Orphan DB rows (HF7)
      3. OpenClaw integration drift (WOR-431)
      4. iCloud-synced keychain entries (WOR-456)

    A clean state on all four reports ``No issues found.`` and exits 0.
    """
    console = get_console()
    home = get_home()

    with _doctor_lock(home), acquire_lock(home):
        # ----------- check 1: recovery file imports -----------
        # Always run, regardless of --fix flag — recovery is a one-way
        # idempotent operation and should always heal a sibling-Mac.
        recovery_files = _list_recovery_files(home)
        imported = _import_recovery_files(recovery_files) if recovery_files else 0
        if imported:
            console.print_success(
                f"{RECOVERY_IMPORT_PHRASE} {imported} key(s) from a sibling Mac. "
                "Worthless on this Mac is ready."
            )

        # ----------- check 2: orphan DB rows -----------
        repo = ShardRepository(str(home.db_path), home.fernet_key)
        all_enrollments, orphans = _run_async(_list_orphans(repo))
        openclaw_issues = _check_openclaw_section(
            all_enrollments, repo=repo, fix=fix, dry_run=dry_run
        )

        # ----------- check 3: home mismatch -----------
        had_mismatch = _check_home_mismatch(home)

        # ----------- check 4: iCloud-synced keychain entries -----------
        synced = _list_synced_keychain_entries()

        # ----------- check 5: alias-not-in-DB -----------
        had_alias_issues = _check_alias_not_in_db(home, all_enrollments)

        if (
            not orphans
            and not openclaw_issues
            and not synced
            and not had_mismatch
            and not had_alias_issues
        ):
            if not imported:
                console.print_success("No issues found.")
            return

        if orphans:
            plural = "s" if len(orphans) != 1 else ""
            console.print_warning(f"{len(orphans)} broken record{plural} (.env line deleted):")
            _print_orphan_lines(
                orphans,
                dry_run=fix and dry_run,
                show_fix_hint=not fix,
            )

        if synced:
            plural = "s" if len(synced) != 1 else ""
            console.print_warning(
                f"{len(synced)} Worthless key{plural} {ICLOUD_LEAK_PHRASE} "
                "(syncs across your Apple devices). "
                "Worthless keys should stay on this Mac only."
            )
            _print_synced_lines(synced, dry_run=fix and dry_run)
            if not fix:
                typer.echo(f"    fix: run `{ICLOUD_FIX_PHRASE}`")

        if not fix:
            return

        if dry_run:
            console.print_hint(
                "dry-run: no changes made. Re-run with `--fix` (without `--dry-run`) to apply."
            )
            return

        if not _doctor_confirm(orphans, synced, yes, console):
            return

        # Fresh repo instance: asyncio.run() closes the event loop after
        # _list_orphans; reusing the same repo in a second asyncio.run()
        # call fails on Linux. A new instance avoids the closed-loop error.
        fix_repo = ShardRepository(str(home.db_path), home.fernet_key)
        _doctor_apply(orphans, synced, fix_repo, home, console)


def register_doctor_commands(app: typer.Typer) -> None:
    """Register the doctor command on the Typer app."""

    @app.command()
    @error_boundary
    def doctor(
        fix: bool = typer.Option(
            False,
            "--fix",
            help="Repair orphan DB rows (destructive). Prompts unless --yes.",
        ),
        yes: bool = typer.Option(
            False, "--yes", "-y", help="Skip the confirmation prompt for --fix."
        ),
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Show planned actions without writing."
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit a single machine-readable JSON document. Disables prompts.",
        ),
    ) -> None:
        """Diagnose and repair stuck DB/.env states (HF7 / worthless-3907)."""
        if json_output:
            # Local import so the text-mode path stays free of the runner
            # module and the JSON consumers see deterministic output.
            from worthless.cli.commands.doctor.runner import _doctor_run_json

            _doctor_run_json(fix=fix, dry_run=dry_run)
            return
        _doctor_run(fix=fix, yes=yes, dry_run=dry_run)

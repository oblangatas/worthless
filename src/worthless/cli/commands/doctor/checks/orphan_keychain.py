"""WOR-464: orphan-keychain detection.

A "leaked" keyring entry: a ``fernet-key-<digest>`` row in the OS keychain
under our service whose ``<digest>`` doesn't match any worthless home
directory currently on disk. Common cause: uninstalling worthless via
``rm -rf ~/.worthless`` without running ``worthless revoke`` first.

SAFETY: the current install's active keyring username is allowlisted
before any delete proposal. The check WILL refuse to mark its own active
key as orphan even if the home dir scan misses it.

Cross-platform: on Linux/Windows we have no portable "list all entries"
API for arbitrary keyring backends (SecretService / WinCred). The check
returns ``ok`` with ``skipped_reason`` on non-darwin so JSON consumers
see the check ran, not that it disappeared. macOS-only repair via
``ctypes`` Security-framework delete.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.keystore import _SERVICE, _keyring_username, keyring_available

logger = logging.getLogger(__name__)
check_id = "orphan_keychain"

_FERNET_USERNAME_RE = re.compile(r"^fernet-key-[0-9a-f]{12}$")


def _candidate_home_dirs() -> list[Path]:
    """All plausible worthless home dirs on this user account.

    The keystore digest is ``sha256(str(home_dir.resolve()))[:12]`` so we
    need the resolved-path forms. Two locations are covered:

    * ``~/.worthless`` — the default install.
    * ``$WORTHLESS_HOME`` — explicit override.

    Anything else (test fixtures, staging installs) is the user's job to
    not accidentally remove from the keychain. The allowlist policy is
    strict: an entry is orphan ONLY if no candidate matches.
    """
    candidates: list[Path] = []
    try:
        candidates.append((Path.home() / ".worthless").resolve())
    except (OSError, RuntimeError):
        pass
    env_home = os.environ.get("WORTHLESS_HOME")
    if env_home:
        try:
            candidates.append(Path(env_home).resolve())
        except (OSError, RuntimeError):
            pass
    return candidates


def _expected_usernames() -> set[str]:
    """Set of keyring usernames considered LIVE on this machine."""
    return {_keyring_username(p) for p in _candidate_home_dirs()}


def run(ctx: CheckContext) -> CheckResult:
    if sys.platform != "darwin":
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="Orphan-keychain scan is macOS-only.",
            fixable=True,
            fixed=[],
            skipped_reason="non-darwin platform",
        )

    # Skip when the backend is disabled (test fixtures, opted-out users).
    # The real Security framework is the only thing find_all_entries can
    # talk to; calling it in a null-keyring environment is at best a
    # no-op, at worst a segfault on stubbed bindings.
    if not keyring_available():
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="Keyring backend disabled; nothing to scan.",
            fixable=True,
            fixed=[],
            skipped_reason="keyring backend disabled",
        )

    try:
        from worthless.cli import keystore_macos
    except ImportError:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="Keystore native module unavailable.",
            fixable=True,
            fixed=[],
            skipped_reason="keystore_macos import failed",
        )

    try:
        all_accounts = keystore_macos.find_all_entries(_SERVICE)
    except Exception as exc:  # noqa: BLE001 - SR-04 scrub
        logger.debug("find_all_entries failed: %s", type(exc).__name__)
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary="Could not enumerate keychain entries.",
            fixable=True,
            fixed=[],
            skipped_reason=None,
        )

    live = _expected_usernames()
    # The current install's active key MUST be allowlisted — losing it
    # makes locked .env files unreadable. This is the WOR-464 guardrail.
    live.add(_keyring_username(ctx.home.base_dir))

    orphans = [a for a in all_accounts if _FERNET_USERNAME_RE.match(a) and a not in live]

    findings = [{"keychain_account": a} for a in orphans]
    fixed: list[dict] = []
    status = "ok" if not orphans else "warn"

    if ctx.fix and orphans and not ctx.dry_run:
        for account in orphans:
            # Re-check the allowlist at delete-time (defense in depth).
            if account in live:
                continue
            try:
                keystore_macos.delete_password_local(_SERVICE, account)
                fixed.append({"keychain_account": account})
            except keystore_macos.KeychainNotFound:
                # Already gone — count as fixed (idempotent).
                fixed.append({"keychain_account": account})
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to delete orphan keychain entry %s: %s",
                    account,
                    type(exc).__name__,
                )
        if len(fixed) == len(orphans):
            status = "ok"

    n = len(orphans)
    summary = (
        "No orphan keychain entries."
        if n == 0
        else f"{n} orphan keychain entr{'y' if n == 1 else 'ies'} (no matching home dir)"
    )
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )

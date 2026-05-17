"""WOR-464: Fernet key drift between keyring and file fallback.

Both the OS keyring AND the ``~/.worthless/fernet.key`` file exist but
contain DIFFERENT bytes. Either source could be canonical depending on
how the install evolved; auto-picking one risks discarding the only key
that decrypts existing locked secrets.

``fixable`` is hardcoded False. The check emits instructions and
relies on the user to pick a side. This is THE WOR-464 critical
guardrail — never auto-repair drift.
"""

from __future__ import annotations

import logging

import keyring as _keyring

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.keystore import _SERVICE, _keyring_username, keyring_available

logger = logging.getLogger(__name__)
check_id = "fernet_drift"

_INSTRUCTIONS = (
    "Two Fernet keys exist (keyring + file) and they differ. "
    "Worthless will not auto-pick a side — losing the canonical key "
    "makes existing locked secrets unrecoverable.\n"
    "  1. Identify which one decrypts your current secrets (`worthless status`).\n"
    "  2. Back up both values.\n"
    "  3. Delete the non-canonical source manually:\n"
    "     - File:   rm ~/.worthless/fernet.key\n"
    "     - Keyring: see `keyring del worthless <fernet-key-...>`."
)


def run(ctx: CheckContext) -> CheckResult:
    fernet_path = ctx.home.fernet_key_path

    keyring_value: bytes | None = None
    if keyring_available():
        try:
            v = _keyring.get_password(_SERVICE, _keyring_username(ctx.home.base_dir))
            if v is not None:
                keyring_value = v.encode("utf-8")
        except Exception as exc:  # noqa: BLE001 - SR-04
            logger.debug("keyring read failed in fernet_drift: %s", type(exc).__name__)

    file_value: bytes | None = None
    try:
        file_value = fernet_path.read_bytes().strip()
    except FileNotFoundError:
        pass  # file absent — only one source, no drift possible
    except OSError as exc:
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[],
            summary=f"Could not read fernet.key: {type(exc).__name__}",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    if file_value is None or keyring_value is None:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="No Fernet key drift (only one source present).",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    if file_value == keyring_value:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary="Fernet key in keyring matches file (no drift).",
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    return CheckResult(
        check_id=check_id,
        status="error",
        findings=[
            {
                "fernet_key_path": str(fernet_path),
                "keyring_username": _keyring_username(ctx.home.base_dir),
                "instructions": _INSTRUCTIONS,
            }
        ],
        summary="Fernet keys differ between keyring and file — manual fix required.",
        fixable=False,  # CRITICAL: never auto-repair drift.
        fixed=[],
        skipped_reason=None,
    )

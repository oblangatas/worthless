"""WOR-464: Fernet key drift between keyring and file fallback.

Both the OS keyring AND the ``~/.worthless/fernet.key`` file exist but
contain DIFFERENT bytes. Either source could be canonical depending on
how the install evolved; auto-picking one risks discarding the only key
that decrypts existing locked secrets.

``fixable`` is hardcoded False. The check emits instructions and
relies on the user to pick a side. This is THE WOR-464 critical
guardrail — never auto-repair drift.

worthless-saaz: a key the background service can't use is drift too, even
with one source. Each source is checked against every locked key by HMAC
(no plaintext), and the result says which source opens what.
"""

from __future__ import annotations

import asyncio
import hmac
import logging

import keyring as _keyring

from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.key_check import KEY_FIX, aliases_key_cannot_open
from worthless.cli.keystore import _SERVICE, _keyring_username, keyring_available
from worthless.crypto.types import zero_buf

logger = logging.getLogger(__name__)
check_id = "fernet_drift"

_INSTRUCTIONS = (
    "At risk until you choose — two different Fernet keys exist (keyring + file). "
    "Worthless will not auto-pick a side, because losing the right one makes your "
    "existing locked secrets unrecoverable.\n"
    "  1. Find the canonical key — the one your secrets were written under. Try "
    "decrypting a known secret with each, or check `worthless status`.\n"
    "  2. Back up both values.\n"
    "  3. Delete the non-canonical source manually:\n"
    "     - File:   rm ~/.worthless/fernet.key\n"
    "     - Keyring: see `keyring del worthless <fernet-key-...>`."
)


def _cannot_unlock(ctx: CheckContext, key: bytes) -> tuple[int, list[str]]:
    buf = bytearray(key)
    try:
        return asyncio.run(aliases_key_cannot_open(ctx.home.db_path, buf))
    finally:
        zero_buf(buf)


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

    sources = {"file": file_value, "keyring": keyring_value}
    checked: dict[str, tuple[int, list[str]]] = {}
    if not fernet_ipc_only_enabled() and ctx.home.db_path.is_file():
        checked = {name: _cannot_unlock(ctx, v) for name, v in sources.items() if v is not None}

    if (
        file_value is not None
        and keyring_value is not None
        and not hmac.compare_digest(file_value, keyring_value)
    ):
        finding: dict = {
            "fernet_key_path": str(fernet_path),
            "keyring_username": _keyring_username(ctx.home.base_dir),
            "instructions": _INSTRUCTIONS,
        }
        if any(total for total, _ in checked.values()):
            finding["unlocks"] = {
                name: f"{total - len(dead)} of {total}" for name, (total, dead) in checked.items()
            }
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[finding],
            summary="Fernet keys differ between keyring and file — manual fix required.",
            fixable=False,  # CRITICAL: never auto-repair drift.
            fixed=[],
            skipped_reason=None,
        )

    # The background service reads the file first, then the keyring.
    service = "file" if file_value is not None else "keyring"
    total, dead = checked.get(service, (0, []))
    if dead:
        return CheckResult(
            check_id=check_id,
            status="error",
            findings=[
                {
                    "key_source": service,
                    "cannot_unlock": sorted(dead),
                    "instructions": _INSTRUCTIONS,
                }
            ],
            summary=(
                f"The key the background service uses ({service}) can't unlock "
                f"{len(dead)} of your {total} locked key(s). {KEY_FIX}"
            ),
            fixable=False,  # CRITICAL: never auto-repair drift.
            fixed=[],
            skipped_reason=None,
        )

    return CheckResult(
        check_id=check_id,
        status="ok",
        findings=[],
        summary=(
            "Fernet key in keyring matches file (no drift)."
            if file_value is not None and keyring_value is not None
            else "No Fernet key drift (only one source present)."
        ),
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )

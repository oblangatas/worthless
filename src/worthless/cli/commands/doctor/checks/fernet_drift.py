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

import hmac
import logging
from typing import Literal

import keyring as _keyring

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.key_check import KEY_FIX, aliases_key_cannot_open
from worthless.cli.keystore import _SERVICE, _keyring_username, keyring_available

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


def _result(
    status: Literal["ok", "warn", "error"], summary: str, findings: list | None = None
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings or [],
        summary=summary,
        fixable=False,  # CRITICAL: never auto-repair drift.
        fixed=[],
        skipped_reason=None,
    )


def _read_keyring(home) -> bytes | None:  # noqa: ANN001 — WorthlessHome
    if not keyring_available():
        return None
    try:
        value = _keyring.get_password(_SERVICE, _keyring_username(home.base_dir))
    except Exception as exc:  # noqa: BLE001 - SR-04
        logger.debug("keyring read failed in fernet_drift: %s", type(exc).__name__)
        return None
    return value.encode("utf-8") if value is not None else None


def _sources_differ(ctx: CheckContext, checked: dict[str, tuple[int, list[str]]]) -> CheckResult:
    finding: dict = {
        "fernet_key_path": str(ctx.home.fernet_key_path),
        "keyring_username": _keyring_username(ctx.home.base_dir),
        "instructions": _INSTRUCTIONS,
    }
    if any(total for total, _ in checked.values()):
        finding["unlocks"] = {
            name: f"{total - len(dead)} of {total}" for name, (total, dead) in checked.items()
        }
    return _result(
        "error", "Fernet keys differ between keyring and file — manual fix required.", [finding]
    )


def _service_cannot_unlock(service: str, total: int, dead: list[str]) -> CheckResult:
    return _result(
        "error",
        f"The key the background service uses ({service}) can't unlock "
        f"{len(dead)} of your {total} locked key(s). {KEY_FIX}",
        [{"key_source": service, "cannot_unlock": sorted(dead), "instructions": _INSTRUCTIONS}],
    )


def run(ctx: CheckContext) -> CheckResult:
    keyring_value = _read_keyring(ctx.home)
    try:
        file_value: bytes | None = ctx.home.fernet_key_path.read_bytes().strip()
    except FileNotFoundError:
        file_value = None  # file absent — only one source, no drift possible
    except OSError as exc:
        return _result("error", f"Could not read fernet.key: {type(exc).__name__}")

    sources = {"file": file_value, "keyring": keyring_value}
    checked = {
        name: aliases_key_cannot_open(ctx.home, value)
        for name, value in sources.items()
        if value is not None
    }
    both = file_value is not None and keyring_value is not None
    if (
        file_value is not None
        and keyring_value is not None
        and not hmac.compare_digest(file_value, keyring_value)
    ):
        return _sources_differ(ctx, checked)

    # The background service reads the file first, then the keyring.
    service = "file" if file_value is not None else "keyring"
    total, dead = checked.get(service, (0, []))
    if dead:
        return _service_cannot_unlock(service, total, dead)
    return _result(
        "ok",
        "Fernet key in keyring matches file (no drift)."
        if both
        else "No Fernet key drift (only one source present).",
    )

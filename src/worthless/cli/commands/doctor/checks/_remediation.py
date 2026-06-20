"""WOR-753: static fix playbooks, one per doctor ``check_id``.

AI-less and deterministic — these ship in the wheel and are read offline
(no LLM, no API key, no network). ``runner._stamp_remediation`` attaches
them to each finding of a failing check, and ``worthless doctor --explain
<check_id>`` prints them. ``fernet_drift``'s playbook is its existing
``_INSTRUCTIONS`` so there is a single source of truth — do not copy it.
"""

from __future__ import annotations

from worthless.cli.commands.doctor.checks.fernet_drift import _INSTRUCTIONS as _FERNET_DRIFT

PLAYBOOKS: dict[str, str] = {
    # Each playbook LEADS with the plain-language verdict (safe / gone / at risk),
    # glosses any jargon once, then names the one command to run (WOR-778).
    "recovery_import": (
        "No secret at risk — a sibling-Mac recovery file didn't finish importing "
        "(your keys aren't lost). Re-run `worthless doctor` to retry; the import is "
        "idempotent. If it keeps failing, re-export the file from the other Mac."
    ),
    "orphan_db": (
        "This key is gone — its `.env` line was deleted, so it can't be rebuilt from "
        "what's left. Run `worthless doctor --fix` to clear the dead entry, then re-lock "
        "from your original `.env` if you still have it. Your other keys are safe."
    ),
    "openclaw": (
        "A key is exposed — a plaintext key is sitting in OpenClaw's config. Run "
        "`openclaw secrets configure` to move it behind a secure reference. (If the audit "
        "can't run, point `WORTHLESS_OPENCLAW_BIN` at the openclaw binary.)"
    ),
    "icloud_keychain": (
        "Your key isn't lost — this is cleanup. A Fernet key (the secret that encrypts your "
        "keys) is in iCloud Keychain, so it syncs across your Macs. Run "
        "`worthless doctor --fix` to move it to a local-only entry that won't sync."
    ),
    "orphan_keychain": (
        "Your active key is safe. A stray `fernet-key-*` keychain entry is left over from "
        "an install that's gone. Run `worthless doctor --fix` to remove it — your active "
        "key is allowlisted and never touched."
    ),
    "stranded_shards": (
        "Nothing at risk — a shard file (one half of a split key) has no matching database "
        "row, usually from a crash mid-revoke. Run `worthless doctor --fix` to unlink it; "
        "a lone shard is unusable on its own."
    ),
    "fernet_drift": _FERNET_DRIFT,
    "broken_status": (
        "This key is gone — its shard (its half of the split key) is missing, so it can't "
        "be rebuilt. Run `worthless doctor --fix` to clear the dead reference, then restore "
        "it from your original `.env` if you have it. Your other keys are safe."
    ),
    "bind_confirmation": (
        "Your keys are locked (safe at rest), but worthless couldn't confirm the rewritten "
        "OpenClaw entry routes through the proxy. Restart OpenClaw's daemon, then re-run "
        "`worthless lock`. Still unsure? Check the proxy is up (`worthless up`) and "
        "`WORTHLESS_PORT` is set."
    ),
}

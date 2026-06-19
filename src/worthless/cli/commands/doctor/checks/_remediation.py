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
    "recovery_import": (
        "Sibling-Mac recovery files import automatically on each run — no action needed."
    ),
    "orphan_db": (
        "A locked key's `.env` line is gone, so it can't be restored. "
        "Run `worthless doctor --fix` to purge the dead enrollment, then re-lock from "
        "your original `.env` if you still need the key."
    ),
    "openclaw": (
        "See the per-finding `remediation`. Usually: run `openclaw secrets configure` to "
        "migrate plaintext keys, or set `WORTHLESS_OPENCLAW_BIN` to the openclaw binary."
    ),
    "icloud_keychain": (
        "A Fernet key is in iCloud Keychain (it syncs across your Macs). "
        "Run `worthless doctor --fix` to migrate it to a local-only, non-syncing entry."
    ),
    "orphan_keychain": (
        "A leaked `fernet-key-*` keychain entry has no install on disk. "
        "Run `worthless doctor --fix` to remove it — your active key is allowlisted and "
        "never touched."
    ),
    "stranded_shards": (
        "A shard file has no matching DB row (usually a crash mid-revoke). "
        "Run `worthless doctor --fix` to unlink it — a shard is unusable on its own."
    ),
    "fernet_drift": _FERNET_DRIFT,
    "broken_status": (
        "An enrollment's shard is gone, so the key can't be reconstructed. "
        "Run `worthless doctor --fix` to clear the dead reference; restore the key from "
        "your original `.env` if you have it."
    ),
    "bind_confirmation": (
        "After `worthless lock`, the rewritten OpenClaw entry is not proven to route "
        "through the proxy. Restart OpenClaw's daemon (its cached config may still point "
        "at the old URL) or re-run `worthless lock`. If the proof was inconclusive, check "
        "`WORTHLESS_PORT` and that the proxy is up (`worthless up`)."
    ),
}

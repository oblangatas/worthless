---
title: "Troubleshooting"
description: "Action-first guide to every worthless doctor check_id — symptoms, commands, and fixes."
---

# Worthless Troubleshooting

Every `worthless doctor` check has a short, action-first entry here. If
you see one of these symptoms, jump straight to the matching `check_id`
and run the command shown. JSON consumers (CI, agents) can scrape the
same data from `worthless doctor --json`.

## Decision tree

```text
Are you stuck?
  ├── "unlock says no keys, status says PROTECTED"   → orphan_db
  ├── "Worthless asks me to unlock keychain on another Mac"
  │     OR "keychain shows synced Worthless entries"   → icloud_keychain
  ├── moved to a new Mac, want to import old keys      → recovery_import
  ├── "keys appear in keychain but no install left"    → orphan_keychain
  ├── "shard_a files I don't recognise"                → stranded_shards
  ├── "Worthless complains about two Fernet keys"      → fernet_drift
  ├── "PROTECTED enrollment can't be unlocked at all"  → broken_status
  └── OpenClaw provider missing / skill stale          → openclaw
```

Run `worthless doctor` first; it prints the matching `check_id`. For
machine input, prefer `worthless doctor --json`.

## orphan_db

**Symptom:** `worthless unlock` says "No enrolled keys found" but
`worthless status` lists the key as `PROTECTED`. The `.env` line that
referenced the shard was deleted out from under Worthless.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** surgical DELETE of the orphan enrollment row. If the
alias has no other enrollments left, the full per-alias teardown runs
(shard + spend log + config + shard_a file).

**Risk:** none — the orphan is unrecoverable; this just cleans up the
dead reference. The fix re-validates the orphan set after acquiring the
lock, so a multi-project install never loses a healthy enrollment.

## openclaw

**Symptom:** OpenClaw routes calls to the wrong base URL, or
`worthless status` says "skill stale (installed 0.1, bundled 0.3)".
Cause: OpenClaw was installed (or re-installed) after `worthless lock`
ran, so the skill folder + provider wiring drifted.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** reinstalls the bundled skill at the current version.
Provider wiring (`openclaw.json` entries) is repaired by re-running
`worthless lock`, NOT by doctor — doctor only surfaces the drift.

**Risk:** none — skill reinstall is idempotent.

## icloud_keychain

**Symptom (macOS):** Worthless keys are listed in iCloud Keychain on
your Apple ID. They will sync across every device on that Apple ID,
which is not what you want — these keys should stay on this Mac.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** for each synced entry, writes a `<account>.recover`
file under `~/.worthless/recovery/` (mode 0600), adds a non-synced
"staging" entry, verifies byte-equality, deletes the synced original,
then promotes staging to the canonical slot.

**Risk: read the multi-device warning carefully.** Migrating makes the
key this-Mac-only. If you have Worthless on other Macs, copy the
`*.recover` files to those Macs **before iCloud's tombstone propagates
(~30 seconds)** OR re-run `worthless doctor` on each sibling Mac to
import. Without that, locked `.env` files on sibling Macs become
unrecoverable until you re-enroll there.

## recovery_import

**Symptom (macOS):** moved keys from another Mac via the recovery
mechanism above. `~/.worthless/recovery/<account>.recover` files exist
on this Mac but the keys aren't in the local keychain yet.

**Command:**

```bash
worthless doctor
```

**What it does:** unconditionally imports any pending recovery files
into the local-scope keychain (no `--fix` needed — import is
idempotent). Stale recovery files (already in local keychain) are
silently unlinked.

**Risk:** none.

## orphan_keychain

**Symptom (macOS):** the OS keychain contains `fernet-key-<digest>`
entries under the `worthless` service with no matching home dir on
disk. Common cause: uninstalled Worthless via `rm -rf ~/.worthless`
without running `worthless revoke` first.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** deletes the orphan entries from the local keychain.
**The current install's active username is allowlisted** — the check
refuses to delete its own canonical key even if the home-dir scan
misses it. Defense in depth: the allowlist is re-checked at delete
time, not just at scan time.

**Risk:** low. If you have a Worthless install elsewhere (test fixture,
staging dir) and `WORTHLESS_HOME` is not pointing at it during the
`doctor --fix` run, that install's keychain entry COULD be marked
orphan. Run `worthless doctor` (no `--fix`) first and review the
findings — any account you recognise as live, set the matching
`WORTHLESS_HOME` env var and re-run.

## stranded_shards

**Symptom:** `~/.worthless/shard_a/` contains files whose basename
doesn't match any `key_alias` in the DB. Common cause: a crash
mid-revoke that deleted the DB row before unlinking shard_a.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** unlinks the stranded files. Shard A alone is
unusable without the matching Shard B row in the DB, so the file is
guaranteed dead.

**Risk:** none.

## fernet_drift

**Symptom:** both the OS keyring AND `~/.worthless/fernet.key` exist
but contain DIFFERENT bytes. Worthless cannot tell which one decrypts
your existing locked secrets — auto-picking would risk destroying
access.

**Command:** there is no `--fix`. **Manual recovery only.**

1. Run `worthless status` — does it list any PROTECTED enrollments?
2. If yes, try `worthless unlock` to confirm which key actually
   decrypts them. The one that works is canonical.
3. Back up both values (`cp ~/.worthless/fernet.key /tmp/fernet.key.bak`
   and `keyring get worthless <fernet-key-...>` printed to a file).
4. Delete the non-canonical source:
   * File: `rm ~/.worthless/fernet.key`
   * Keyring: `keyring del worthless <fernet-key-...>`
5. Re-run `worthless doctor` to confirm drift is resolved.

**Why no auto-fix:** WOR-464 hardcodes `fixable=False` on this check.
Drift is the only doctor state where the wrong choice silently destroys
data. The user must decide.

## broken_status

**Symptom:** an enrollment row references a `key_alias` whose shard_a
file is missing on disk. The key cannot be reconstructed even with
the correct Fernet key — Shard B alone is information-theoretically
useless.

**Command:**

```bash
worthless doctor --fix
```

**What it does:** surgical delete of the dangling enrollment + shard
rows. The underlying secret is already unrecoverable; this just removes
the dead reference so `worthless status` stops surfacing it.

**Risk:** none — the secret cannot be recovered by any means.

## When in doubt

Run the JSON mode and share the output:

```bash
worthless doctor --json > /tmp/worthless-doctor.json
```

The JSON has stable keys (`schema_version: "1"`) so support tooling
and AI agents can parse it directly.

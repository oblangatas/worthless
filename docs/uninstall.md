---
title: "Uninstall"
description: "How to remove Worthless cleanly — every locked key is restored before anything is deleted."
---

# Uninstall

Removing Worthless is the exact reverse of installing it: **every key you locked is written back to your `.env` before anything is deleted.** You are never left holding a half-key.

```bash
worthless uninstall
```

That single command:

1. **Restores every locked `.env`** to its real key, undoing the lock (the proxy `BASE_URL` line Worthless added is removed too).
2. **Reverts your OpenClaw config** — provider entries are restored to point back at the real provider with the real key.
3. **Stops the running proxy daemon** (default port `8787`) if one is up.
4. **Deletes `~/.worthless/`** (the local database and encryption key) and the encryption key held in your OS keychain.

The order matters: Worthless **restores everything first, verifies it succeeded, then wipes.** If any recoverable key cannot be put back, it stops *before* deleting anything — so an uninstall can never strand a key it was able to recover.

## Flags

| Flag | What it does |
|------|--------------|
| `--yes` | Skip the confirmation prompt. Use this in scripts, CI, and agents. In a non-interactive shell, uninstall refuses without `--yes` rather than guess. |
| `--force` | Proceed even when the install is broken or a key can't be restored. This **widens what gets wiped** — it never skips restoring a key on a healthy install. |

## When the install is broken

If `~/.worthless/` is damaged — the encryption key is gone, or the database is corrupted — the locked keys can no longer be reconstructed. Uninstall refuses and tells you so, instead of crashing:

```bash
$ worthless uninstall
Can't read this Worthless install (the encryption key or database is missing/unreadable).
Re-run with --force to wipe the remains.
```

```bash
$ worthless uninstall --force
Worthless removed. The locked keys were unrecoverable — rotate them at your provider.
```

**`--force` on a broken install does not recover your keys.** It cleans the machine; the keys themselves are lost and must be rotated at the provider.

## When a project was moved or deleted

If you deleted a project whose `.env` was locked, that file is simply skipped with a warning — a missing file is never treated as a failed restore, and it never blocks the uninstall:

```bash
$ worthless uninstall
Skipping a project whose file is gone (its key was already lost with the file)... done.
Worthless removed.
```

## Diagnose first

Not sure what state you're in? `worthless doctor` tells you, and points at the fix:

```bash
worthless doctor          # human-readable
worthless doctor --json   # machine-readable, for agents
```

On a broken install, both report the problem and recommend `worthless uninstall --force` — neither crashes.

## Exit codes

For scripts and agents:

| Code | Meaning |
|------|---------|
| `0` | Uninstall completed. |
| `1` | Refused — confirmation declined, a non-interactive shell without `--yes`, or a broken install without `--force`. |
| `73` | Uninstall completed, but reverting the OpenClaw config partially failed — check `openclaw.json`. |

## See also

- [Recovery](/recovery/) — what to do if your `.env` was corrupted or deleted (Worthless does not back it up).
- [Uninstall contract](/uninstall-contract/) — the line-by-line list of everything Worthless installs and exactly how uninstall removes or restores each item.

---
title: "Uninstall contract"
description: "Exactly what Worthless puts on your machine, and exactly how uninstall removes or restores each item — auditable line by line."
---

# Uninstall contract

Worthless asks you to read its installer before you run it. The uninstaller earns the same trust: **everything Worthless puts on your machine is listed here, with exactly how `worthless uninstall` removes or restores it.** Hand this page to your AI alongside the source and ask it to confirm the two match.

## The ordering guarantee

Uninstall always runs in this order:

1. **Restore all** — reconstruct the real key for every locked `.env` and write it back.
2. **Verify** — confirm every recoverable key was actually restored.
3. **Wipe all** — only now delete the local state and keychain entry.

If step 2 finds a recoverable key that didn't restore, uninstall **stops before any deletion** (override with `--force`, which accepts the loss). A wipe can never run ahead of a successful restore, so uninstall cannot shred a key it was able to recover.

## What gets installed, and how it's removed

| Artifact | Created by | Removed / restored by uninstall |
|----------|-----------|----------------------------------|
| Real API key in your project `.env` | `worthless lock` replaces it with shard A (which looks like a real key) | **Restored** — the real key is written back and the `.env` is returned to its pre-lock state (the proxy `BASE_URL` line is removed) |
| Shard B + enrollment rows + spend log | `worthless lock`, stored in `~/.worthless/worthless.db` | **Deleted** — the entire `~/.worthless/` directory is removed |
| Encryption (Fernet) key in your OS keychain | First `worthless lock` | **Deleted** — removed from the keychain |
| `~/.worthless/fernet.key` (legacy file, pre-keyring installs only) | Older installs | **Deleted** — removed with `~/.worthless/` |
| `~/.worthless/.bootstrapped` marker | First run | **Deleted** — removed with `~/.worthless/` |
| OpenClaw provider entries in `openclaw.json` | `worthless lock` rewrites them to route through the proxy | **Restored** — put back to point at the real provider with the real key |
| Running proxy daemon (default port `8787`) | `worthless up` / `worthless wrap` | **Stopped** before the wipe |
| launchd / systemd service unit (auto-start on boot/login) | `worthless service install` | **Removed** (best-effort, before the wipe) so it can't relaunch the proxy and recreate `~/.worthless` |

## What uninstall does NOT do

Honesty matters as much as the removal itself:

- **It does not back up your `.env`.** Restore happens during uninstall, but Worthless keeps no separate copy. If your `.env` was already corrupted or deleted, see [Recovery](/recovery/).
- **It cannot recover keys from a broken install.** If the encryption key or database is already gone, the keys are unreconstructable. `--force` wipes the remains so the machine is clean, but those keys are lost — rotate them at the provider.
- **It does not touch anything it didn't install.** Providers you manage yourself, unrelated files, and other tools' config are left untouched. Uninstall only reverses what `worthless lock` did.
- **It does not remove the `worthless` program itself.** `worthless uninstall` clears Worthless's *state*; the installed binary stays so you can reinstall or re-lock without re-downloading. Remove it separately with `uv tool uninstall worthless` (or `pipx uninstall worthless`). The `curl worthless.sh/uninstall | sh` one-liner does both — state *and* binary — in one shot, since a website-channel user shouldn't need to know about uv.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Uninstall completed. |
| `1` | Refused — confirmation declined, a non-interactive shell without `--yes`, or a broken install without `--force`. |
| `73` | Uninstall completed, but reverting the OpenClaw config partially failed — check `openclaw.json`. |

## Verify it yourself

```bash
worthless uninstall --help
```

The command is implemented in `src/worthless/cli/commands/uninstall.py` — read it against this table.

## See also

- [Uninstall](/uninstall/) — the step-by-step guide.
- [Recovery](/recovery/) — recovering a `.env` Worthless can't reconstruct.

---
title: "Recovery"
description: "How to recover when your .env is corrupted, deleted, or overwritten."
---

# Recovery

Worthless does not back up your `.env` file. Locking replaces the real key in `.env` with shard A (which looks like a real key) and stores shard B in the local database; if your `.env` is corrupted, deleted, or overwritten, Worthless cannot reconstruct it for you. Keep your own backup — a password manager, an encrypted secrets vault, or a private file kept outside the repo all work. If you have replacement bytes ready, `worthless restore <path>` reads them from stdin and writes them atomically to the target file (e.g. `cat saved.env | worthless restore .env`); this only restores file contents, it does not regenerate keys.

## If your `.env` may have leaked

This is a different problem than file corruption above — your `.env` is intact, but you're worried a copy of it (git history, a CI log, a shared screenshot) got out.

**Re-lock immediately: `worthless lock`.** Re-locking a key that's already locked retires the current shard-A and issues a fresh one. The exposed shard-A is now worthless twice over: it's cryptographically inert alone (as always), and any attempt to replay it against the proxy is refused and logged — see the [retired-key tripwire](/security/#retired-key-tripwire-decoy). This is the actual incident response; nothing else in this document rotates the key.

Re-locking does not require you to know whether the leak was real. If in doubt, re-lock — it costs nothing and stops further replay of the exposed key from that point forward. It does not undo anything that happened before the re-lock.

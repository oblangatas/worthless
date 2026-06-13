---
title: "Install — Solo Developer"
description: "Install Worthless on your laptop in under 90 seconds."
---

# Install — Solo Developer

```bash
pipx install worthless   # or: pip install worthless
cd your-project
worthless
```

That's it. `worthless` (no args) detects keys in `.env`, splits them, starts the proxy. No code changes.

What it does:

1. Scans `.env` (and `.env.local`) for API keys
2. Splits each key into two shards (shard-A stays local, shard-B encrypted in the proxy DB)
3. Replaces the `.env` value with shard-A — format-preserving (same prefix, same length, looks like a real key, useless on its own)
4. Starts the proxy on `localhost:8787`
5. Injects `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` into `.env` so your SDK routes through the proxy

Your existing code works identically. The proxy reconstructs the key only when the rules engine approves the request — blow your spend cap, the key never forms.

## One-line install (curl)

No Python or pipx set up? Install with a single command. The script is version-pinned and verifies a SHA-256 of the download before it runs anything:

```bash
curl -sSL https://worthless.sh | sh
# inspect first: curl -sSL 'https://worthless.sh?explain=1' | less
```

This installs the `worthless` CLI; then `cd your-project && worthless` exactly as above.

## Non-interactive (CI, scripts)

```bash
worthless --yes      # skip the confirmation prompt
worthless --json     # read-only state report, never writes
```

## Install from source

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
```

See the [README quickstart](https://github.com/shacharm2/worthless/blob/main/README.md#quickstart) for the full walkthrough and command reference.

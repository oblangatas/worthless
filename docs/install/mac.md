---
title: "Install — macOS"
description: "Native install on Apple Silicon or Intel Mac, ~90 seconds zero to working proxy."
---

# Install on macOS

Zero to working proxy in ~2 minutes on a fast network. Apple Silicon
(M1/M2/M3/M4) and Intel Macs both supported. macOS 11 (Big Sur) or
newer.

## 0. Prerequisites

```bash
# Confirm macOS version (must be 11+)
sw_vers -productVersion

# Confirm curl + bash present (default on macOS)
command -v curl bash
```

You do NOT need: Homebrew, pyenv, Python pre-installed, Xcode, sudo.
worthless's installer (`uv tool install`) bootstraps everything inside
`~/.local/`.

## 1. Install

```bash
curl -sSL https://worthless.sh | sh
```

The installer drops `uv` and `worthless` into `~/.local/bin/`. **No
keychain popups during install** — the keychain is only touched when
you first lock a key (step 3).

## 2. Verify install

```bash
worthless --version
```

Expected output:

```text
worthless 0.3.8
```

If you see "command not found", `~/.local/bin` isn't on your PATH yet.
The installer printed activation hints for your shell. Either restart
your terminal or run the suggested `export PATH=...` line.

## 3. First lock — expect ONE keychain popup

```bash
cd /path/to/your/project   # one with .env
cat .env
# OPENAI_API_KEY=<your-real-openai-key-here>

worthless
```

What happens:
1. worthless detects the API key in `.env`
2. Prompts: `Lock these keys? [y/N]:` — type `y`
3. **macOS Keychain popup appears once** — it asks whether worthless
   can access "fernet-key" — click **"Always Allow"**
4. Key is split: shard A stays in `.env` (decoy), shard B encrypted in
   `~/.worthless/`
5. `.env` is rewritten (see [README — what `worthless lock` does](/install/#what-worthless-lock-does-to-your-env)) and the proxy spawns on `127.0.0.1:8787`

**Subsequent runs of `worthless` produce zero popups.** The "Always
Allow" you clicked grants the binary permanent ACL trust.

## 4. Point your app at the proxy

If your app already reads `.env` (most do via `dotenv` /
`python-dotenv` / Next.js / etc.), **nothing changes in your code**.
The OpenAI/Anthropic SDK picks up `OPENAI_BASE_URL` automatically and
routes through `127.0.0.1:8787`.

If your app loads env vars another way, point it explicitly:

```python
from openai import OpenAI
client = OpenAI()  # reads OPENAI_API_KEY + OPENAI_BASE_URL from .env
```

## 5. Verify it actually works

See [README — Verify it works](/install/#verify-it-works) for the
SDK snippet. Same on every platform.

## 6. Daily use

| You do | What survives | What you do |
|---|---|---|
| Close terminal | Proxy keeps running (background) | Nothing |
| `worthless down` | Proxy stops | `worthless up` to restart |
| Reboot Mac | **Proxy is gone** | `worthless up` from a terminal |
| Wake from sleep | Proxy keeps running | Nothing |
| Switch projects (`cd`) | Each project's `.env` has its own proxy URL | Nothing — same daemon serves all |

### Why no auto-start? (the reboot gap)

The reboot gap is real. Until WOR-174 ships a launchd LaunchAgent
in v1.1, you manually `worthless up` after every reboot.

If you want a less-manual workaround in the meantime — knowing that
silently auto-spawning a daemon on shell open is a tradeoff — you can
opt in via your shell rc:

```bash
# OPT-IN, NOT recommended unless you understand the tradeoff:
# echo 'worthless up &> /dev/null &' >> ~/.zshrc
```

The proper fix lands when WOR-174 installs a managed LaunchAgent.

## 7. Uninstall (manual, until WOR-435 ships)

```bash
# Stop proxy
worthless down

# Remove binary
uv tool uninstall worthless

# Purge keychain entries (loop drains all)
while security delete-generic-password -s worthless 2>/dev/null; do :; done

# Wipe state
rm -rf ~/.worthless
```

After WOR-435 ships, this becomes one command: `worthless uninstall`.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| "command not found: worthless" | `~/.local/bin` not on PATH | `export PATH="$HOME/.local/bin:$PATH"` or restart terminal |
| Multiple popups during step 3 | Bug — should be 1 | File issue with `worthless --version` + `sw_vers -productVersion` |
| App gets `connection refused` on `127.0.0.1:8787` | Proxy not running | `worthless up` |
| App gets `connection refused` after reboot | Proxy died with the boot — see §6 | `worthless up` |
| Proxy started but `/healthz` reports a different PID | Stale orphan proxy on port 8787 | `worthless down` then `worthless up` (tracked as `worthless-6gkb`) |

## What worthless does NOT defend against

- Your laptop being compromised. If an attacker has root/admin on your
  Mac, they can read shard A from `.env` AND extract the keychain
  entry AND query the proxy directly. worthless raises the bar against
  *exfiltrated `.env` files*, not local-attacker scenarios.
- "Always Allow" widens the trust zone. Once you grant it, **any
  process running as your user can read the keychain entry without
  prompting** — including a malicious dev tool you `npm install`.
  worthless is not a sandbox; it's a leak-mitigation layer.
- Non-LLM secrets. `worthless scan` only flags OpenAI / Anthropic /
  Google / xAI / OpenRouter key prefixes. Use `gitleaks` or
  `trufflehog` for general secret scanning.

## For AI agents

> Human readers can stop here — the YAML below is for AI agents.

Schema documented in [agent-schema.md](/install/agent-schema/).

```yaml
schema_version: 1
platform: macos
commands:
  install: "curl -sSL https://worthless.sh | sh"
  verify: "worthless --version"
  first_lock: "worthless"
  proxy_restart: "worthless up"
expectations:
  install_succeeds_silently: true
  first_lock_keychain_popups: 1
  first_lock_requires_human_interaction: true   # popup needs "Always Allow" click — agent must hand back to human
  subsequent_command_keychain_popups: 0
  proxy_starts_automatically_on_lock: true
  proxy_survives_reboot: false
proxy:
  url_template: "http://127.0.0.1:8787/<alias>/v1"
  port: 8787
limitations:
  - "Manual `worthless up` after every reboot — WOR-174"
  - "First-lock popup requires user to click Always Allow"
  - "uv tool uninstall doesn't purge keychain — WOR-435"
```

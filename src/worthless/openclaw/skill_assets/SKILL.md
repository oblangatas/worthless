---
name: worthless
description: Lock LLM API keys behind a local spend-cap proxy. Run `worthless lock` and OpenAI/Anthropic/OpenRouter traffic routes through the proxy — if the spend cap is hit, the real key never reconstructs.
homepage: https://wless.io
metadata:
  openclaw:
    emoji: 🛡️
    requires:
      bins:
        - worthless
    install:
      - id: local-wheel
        kind: shell
        command: sh -c 'uv tool install /opt/worthless/worthless-*.whl 2>/dev/null || pip install /opt/worthless/worthless-*.whl'
        bins:
          - worthless
        label: Install Worthless (LOCAL WHEEL — dev environments; tries this FIRST so a pre-staged wheel under /opt/worthless wins over published)
      - id: worthless-sh
        kind: shell
        command: curl -sSL https://worthless.sh | sh
        bins:
          - worthless
        label: Install Worthless (worthless.sh — recommended for end users)
      - id: uv
        kind: shell
        command: uv tool install worthless
        bins:
          - worthless
        label: Install Worthless (uv from PyPI)
      - id: pip
        kind: shell
        command: pip install worthless
        bins:
          - worthless
        label: Install Worthless (pip from PyPI)
---

# Worthless — make leaked LLM keys worthless

Version: 1.0.0

**Worthless** splits an LLM API key into two shards with XOR: one stays on
this machine, one is encrypted on a local proxy. Neither half alone calls
the model. Every request goes through the proxy, which enforces a spend cap
*before* it reconstructs the key in memory for a single call, then zeroes
it. Blow the cap and the key never forms — so a leaked `.env` is worthless,
and killing the proxy stops the agent.

## When to use this skill

Use Worthless when the user wants to **protect an LLM API key**, **cap
spend**, or **stop a key from leaking** into env vars, logs, or a stolen
config. Trigger phrases: "protect my key", "lock my OpenAI key", "set a
spend limit", "make my key safe".

**Scope (be honest):** Worthless handles **LLM provider keys only** —
OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-`), OpenRouter (`sk-or-`),
Google (`AIza`), xAI (`xai-`). It does **not** find general secrets (AWS,
GitHub PATs, DB passwords). For a broad secret sweep, recommend gitleaks or
trufflehog instead.

## The magic flow

```bash
worthless lock            # detect keys in .env, split them, point traffic at the proxy
worthless up              # start the local proxy daemon (port 8787 by default)
# ...the agent's LLM calls now route through the proxy and are spend-capped
worthless status          # show what's protected and how much has been spent
```

After `lock`, the real key lives nowhere on disk — only shard-A (inert) is
in `.env`, and `*_BASE_URL` points at the proxy. Stop the proxy and calls
fail: that failure is the protection working.

## Commands

All commands take `--json` for machine-readable output.

- `worthless lock [--env PATH]` — split every detected key; rewrite `.env`
  so the SDK routes through the proxy. The headline command.
- `worthless wrap <command…>` — run a one-off command through an ephemeral
  proxy (e.g. `worthless wrap python main.py`); cleans up on exit.
- `worthless up` — start the persistent local proxy daemon.
- `worthless status [--json]` — what's enrolled, proxy health, spend so far.
- `worthless scan [PATHS…] [--json] [--code]` — find LLM keys in `.env`
  files; `--code` instead finds hardcoded provider base URLs (routing
  bypasses) in source. `scan --json` → `{"schema_version": 2, "findings":
  [...], "orphans": [...]}`; guard with `assert result["schema_version"] >= 2`.
- `worthless doctor [--fix] [--json]` — diagnose and (with `--fix`) repair
  broken enrollments and stale config.

## Spending controls

Set rules per key so a runaway agent can't burn the budget:

- **spend_cap** — hard dollar ceiling; key never reconstructs past it.
- **rate_limit** — requests per window.
- **token_budget** — tokens per window (e.g. daily).
- **time_window** — only allow calls during set hours.

## Agent etiquette

- Confirm with the user before running `worthless lock` — it rewrites
  `.env`. Show what was detected first (`worthless scan --json`).
- If `worthless` isn't on PATH, install it first (the `install` block above):
  `curl -sSL https://worthless.sh | sh` (uv/pip are fallbacks).
- Never print a reconstructed key or shard-A; surface the `--json` error
  `code` on failure, not raw key material.

## Non-interactive use (CRITICAL for agents)

Agents have no stdin — `worthless lock` will hang or fail if it prompts.
**Always pass these flags together when running lock from an agent**, unless
the user explicitly asks for interactive review:

```bash
worthless lock --env <path> --keys-only --allow-hardcoded-urls
```

- `--keys-only` — only protect API keys in the `.env`; skip the
  source-code scan that detects hardcoded provider URLs. Without this,
  `lock` walks the working tree and produces a long list of warnings
  about third-party libraries (e.g. OpenClaw's own bundle in `/tmp/jiti/`)
  that have nothing to do with the user's keys.
- `--allow-hardcoded-urls` — acknowledge any URL warnings non-interactively
  instead of prompting. Belt-and-suspenders alongside `--keys-only`.

If you write the `.env` first, **use `python3 -c`** to write it. Do not
chain `echo "..." > file` with nested `$(cat ...)` or `$(... | python3 -c
"...")` — shell quoting collapses when the agent rewrites the command,
which produces empty files and confusing failures. Example:

```bash
# Right — Python writes the file, no shell quoting risks:
python3 -c 'import os; open("/tmp/t.env","w").write(f"OPENAI_API_KEY={os.environ[\"OPENAI_API_KEY\"]}\n")'

# Wrong — fragile across agent rewrites:
echo "OPENAI_API_KEY=$(cat key.txt)" > /tmp/t.env
```

## Testing & verification

To prove `lock` works without touching a production key, run this exact
recipe. **The fake key must be high-entropy** — Worthless's scanner uses an
entropy threshold (3.9) to ignore placeholder strings like
`sk-proj-faketestkey1234567890`. Low-entropy fakes are silently skipped
(no key locked, no error), which looks like "lock did nothing".

```bash
# 1. Create a throwaway .env with a HIGH-ENTROPY fake key.
python3 -c 'import secrets; print(f"OPENAI_API_KEY=sk-proj-{secrets.token_hex(32)}")' \
  > /tmp/t.env

# 2. Lock it non-interactively.
worthless lock --env /tmp/t.env --keys-only --allow-hardcoded-urls

# 3. Verify the split — the .env now holds shard-A, not the original.
cat /tmp/t.env
#   ↑ OPENAI_API_KEY=<a DIFFERENT sk-proj-... value> = shard-A (inert)
#   ↑ OPENAI_BASE_URL=http://127.0.0.1:8787/<alias>/v1  (added by lock)

# 4. Verify enrollment + proxy health.
worthless status --json
#   ↑ "keys": [{"alias": "openai-...", ...}]   (1 enrollment, not [])
#   ↑ "proxy": {"healthy": true, ...}
```

Success criteria: `OPENAI_API_KEY` value changes (replaced by shard-A),
`OPENAI_BASE_URL` is added pointing at `127.0.0.1:8787`, and
`status --json` reports `keys: [{...}]` (non-empty). If any of those is
missing, lock didn't actually run — most commonly because the fake key
was too low-entropy.

## Programmatic access (MCP)

Worthless also ships an MCP server: `worthless_status()`,
`worthless_lock(env_path)`, `worthless_scan(paths, deep, code)`,
`worthless_spend(alias)` — for agents that prefer tool calls over the CLI.

Full docs: https://docs.wless.io

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
      - id: worthless-sh
        kind: shell
        command: curl -sSL https://worthless.sh | sh
        bins:
          - worthless
        label: Install Worthless (recommended — worthless.sh)
      - id: uv
        kind: shell
        command: uv tool install worthless
        bins:
          - worthless
        label: Install Worthless (uv)
      - id: pip
        kind: shell
        command: pip install worthless
        bins:
          - worthless
        label: Install Worthless (pip)
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

## Programmatic access (MCP)

Worthless also ships an MCP server: `worthless_status()`,
`worthless_lock(env_path)`, `worthless_scan(paths, deep, code)`,
`worthless_spend(alias)` — for agents that prefer tool calls over the CLI.

Full docs: https://docs.wless.io

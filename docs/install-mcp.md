---
title: "Install — Claude Code, Cursor, or Windsurf"
description: "Run the Worthless proxy locally and point your editor's SDK at it."
---

# Install — Claude Code, Cursor, or Windsurf

Worthless ships an MCP server exposing `lock`, `scan`, `status`, and `spend`
tools to AI coding agents. The recommended install path needs only Node 18+;
Python and `uv` are bootstrapped automatically on first run.

## Recommended — npm wrapper via `.mcp.json`

Add this to your editor's MCP config. **Verified on Claude Code** (`.mcp.json`)
**and Cursor** (`~/.cursor/mcp.json` — appears as `worthless` with all 4 tools
enabled under Settings → MCP). Windsurf reads its own config path and is
unverified:

```json
{
  "mcpServers": {
    "worthless": {
      "command": "npx",
      "args": ["-y", "worthless-mcp"]
    }
  }
}
```

Restart your editor. On first launch, `worthless-mcp`:

1. Finds or installs `uv` (one-time, ~5 s).
2. Runs `uvx worthless[mcp]==<pinned-version> mcp` — `uvx` caches the Python
   environment, so subsequent starts are instant.
3. Streams MCP protocol over stdio to the editor.

Total cold-start install time: **< 30 s** on a fresh machine with Node only.
No Python toolchain awareness required.

### Available tools

- `worthless_status()` — running proxy state, protected keys
- `worthless_lock(env_path)` — split the real key, rewrite `.env` with a shard
- `worthless_scan(paths, deep)` — find accidental key exposures
- `worthless_spend(alias)` — per-provider spend readout

> **`worthless_lock` interrupt safety.** Over MCP the lock runs in a worker
> thread, where OS interrupts (SIGINT/SIGTERM) aren't delivered — so the CLI's
> mid-lock rollback-on-Ctrl-C does **not** apply here. Crash-safety still holds
> via atomic writes (an interrupted lock can't leave a half-written key). The
> tool's JSON includes `state_consistent`; if it's `false`, run
> `worthless doctor` to reconcile before trusting the result.

## Alternative — manual CLI install

If you already use `pipx` or want the full CLI (`worthless wrap`,
`worthless up`, proxy mode), install the Python package directly:

```bash
pipx install worthless
# or: curl -sSL https://worthless.sh | sh
worthless lock              # protect your .env keys
worthless wrap claude       # starts proxy + launches Claude Code
```

Then point your editor at the HTTP proxy:

```bash
worthless up -d             # background proxy on :8787
export OPENAI_BASE_URL=http://localhost:8787
export ANTHROPIC_BASE_URL=http://localhost:8787
```

## Cursor

:::tip[MCP tools — verified]
The `worthless-mcp` block above works in Cursor. Drop it into
`~/.cursor/mcp.json`; Cursor connects the server and Settings → MCP shows
**`worthless`, 4 tools enabled** (`worthless_status`, `worthless_scan`,
`worthless_lock`, `worthless_spend`). Verified on macOS.
:::

The section below is a **different** integration — pointing Cursor's *built-in*
AI at the proxy via `OPENAI_BASE_URL` — which we have **not** verified:

:::caution[Untested]
We have **not** verified that Cursor honors a custom `OPENAI_BASE_URL` for its
built-in AI features. These steps mirror the Claude Code approach and are a
reasonable starting point — but treat them as unverified. Tried it? [Open an
issue](https://github.com/shacharm2/worthless/issues) and tell us what happened.
:::

Start the proxy, then configure Cursor's environment:

```bash
worthless up -d
```

In Cursor settings, add:

```
OPENAI_BASE_URL=http://localhost:8787
```

## Windsurf

:::caution[Untested]
Same as Cursor: we have **not** verified that Windsurf honors a custom
`OPENAI_BASE_URL` for its built-in AI. Unverified starting point.
:::

Start the proxy, then configure Windsurf's environment:

```bash
worthless up -d
```

In Windsurf settings, add:

```
OPENAI_BASE_URL=http://localhost:8787
```

## Run the proxy in Docker (alternative)

You don't have to run the proxy locally. The same proxy ships as a signed
container — see [Docker install](/install-docker/). Start it, then point your
editor's `BASE_URL` at the mapped port (`localhost:8787`) exactly as above.

## How it works

1. `worthless lock` splits your API key and replaces `.env` with shard-A (format-preserving, looks like a real key)
2. `worthless up` (or `wrap`) starts a local HTTP proxy on port 8787
3. Your editor's SDK calls hit `localhost:8787` instead of the provider directly
4. The proxy reconstructs the real key in memory, makes the upstream call, and zeros the key

Your editor works identically. Your key is never stored in plaintext.

:::note[Planned: Cloud proxy]
A hosted proxy that eliminates the need to run locally is on the roadmap.
:::

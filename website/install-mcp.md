# Install — Claude Code, Cursor, or Windsurf

```bash
pip install worthless
worthless lock
```

That's it. `worthless lock` injects `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` into your `.env` automatically — your editor picks them up with no further config.

> Worthless is an HTTP proxy, not an MCP server. Your editor talks to AI providers through it via `BASE_URL` — no MCP registration needed.

## Verify

```bash
worthless status
```

```
Enrolled keys:
  anthropic-a1b2c3d4 anthropic  PROTECTED
  openai-a1b2c3d4    openai     PROTECTED

Proxy: running on 127.0.0.1:8787
```

For an additional check in Claude Code, ask: **"What is my current spend cap?"** — if Claude answers with real data from the proxy, routing is working.

For CI or agent scripts, use the machine-readable form:

```bash
worthless status --json   # exits 0 when proxy is healthy, 1 otherwise
```

## Claude Code

Option A — use `wrap` (recommended):

```bash
worthless wrap claude    # starts proxy, injects BASE_URL, launches Claude Code
```

Option B — run the proxy separately:

```bash
worthless up -d          # start proxy in background on port 8787
claude                   # BASE_URL already in .env — no export needed
```

## Cursor

```bash
worthless up -d
```

`OPENAI_BASE_URL` is already in your `.env` from `worthless lock` — Cursor picks it up on launch.

Or use `worthless wrap cursor` to start proxy and editor together.

## Windsurf

```bash
worthless up -d
```

`OPENAI_BASE_URL` is already in your `.env` — Windsurf picks it up on launch.

## How it works

1. `worthless lock` splits your API key and injects `BASE_URL` into `.env`
2. `worthless up` (or `wrap`) starts a local HTTP proxy on port 8787
3. Your editor's SDK calls hit `localhost:8787` instead of the provider directly
4. The proxy reconstructs the real key in memory, makes the upstream call, and zeros the key

Your editor works identically. Your key is never stored in plaintext.

## Undo

```bash
worthless unlock
```

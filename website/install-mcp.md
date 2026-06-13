# Install -- Claude Code, Cursor, or Windsurf

Run the Worthless proxy locally, then point your editor's SDK at it.

> [!NOTE]
> Worthless is an HTTP proxy, not an MCP server. Your editor talks to AI
> providers through it via `BASE_URL` — no MCP registration needed.
> MCP server integration is planned for a future release.

## Prerequisites

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock          # protect your .env keys
```

## Claude Code

Option A — use `wrap` (recommended):

```bash
worthless wrap claude    # starts proxy, injects BASE_URL, launches Claude Code
```

Option B — run the proxy separately:

```bash
worthless up -d          # start proxy in background on port 8787
export OPENAI_BASE_URL=http://localhost:8787
export ANTHROPIC_BASE_URL=http://localhost:8787
claude                   # SDK calls route through the proxy
```

## Cursor

Start the proxy, then configure Cursor's environment:

```bash
worthless up -d
```

In Cursor settings, add:

```
OPENAI_BASE_URL=http://localhost:8787
```

Or use `worthless wrap cursor` if Cursor supports being launched from the command line.

## Windsurf

Start the proxy, then configure Windsurf's environment:

```bash
worthless up -d
```

In Windsurf settings, add:

```
OPENAI_BASE_URL=http://localhost:8787
```

## How it works

1. `worthless lock` splits your API key and replaces `.env` with a decoy
2. `worthless up` (or `wrap`) starts a local HTTP proxy on port 8787
3. Your editor's SDK calls hit `localhost:8787` instead of the provider directly
4. The proxy reconstructs the real key in memory, makes the upstream call, and zeros the key

Your editor works identically. Your key is never stored in plaintext.

> [!NOTE]
> **Planned: Cloud proxy.** A hosted proxy that eliminates the need to run locally
> is planned. Track progress on [GitHub Issues](https://github.com/shacharm2/worthless/issues).

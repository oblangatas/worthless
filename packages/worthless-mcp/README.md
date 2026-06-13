# worthless-mcp

Zero-Python install wrapper for the [Worthless](https://github.com/shacharm2/worthless) MCP server. Thin Node.js shim so Claude Code, Cursor, and Windsurf can auto-install Worthless's MCP tools straight from `.mcp.json` without requiring Python on the host.

## Install

Add to your project's `.mcp.json`:

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

Restart your editor. On first launch the wrapper:

1. Finds or installs [`uv`](https://docs.astral.sh/uv/) (one-time, ~5 s).
2. Runs `uvx worthless[mcp]==<pinned-version> mcp` — the Python env is cached by `uvx`, so subsequent starts are instant.
3. Streams MCP protocol over stdio to the editor.

Cold start on a fresh Node-only machine: **< 30 s**.

## Requirements

- Node.js ≥ 18
- Network access on first run (to fetch `uv` and the Python package)
- macOS, Linux, or Windows

## MCP tools exposed

| Tool | Description |
| --- | --- |
| `worthless_status()` | Proxy state, protected keys, spend caps |
| `worthless_lock(env_path)` | Split the real API key, rewrite `.env` with a shard |
| `worthless_scan(paths, deep)` | Find accidental key exposures in the tree |
| `worthless_spend(alias)` | Per-provider spend readout |

## Flags (for manual invocation)

```bash
npx worthless-mcp --version    # print wrapper version
npx worthless-mcp --help       # show help
npx worthless-mcp              # launch MCP server on stdio
```

## Versioning

This npm package version is pinned 1:1 to the `worthless` PyPI package. The wrapper execs `uvx worthless[mcp]==<this-version> mcp`, so bumping one always bumps the other.

## License

AGPL-3.0 — same as the upstream Python package.

---
title: "What each install path gives you"
description: "Which install paths route your keys, which only add editor tools, and what happens if you stop halfway."
---

# What each install path gives you

Not every install path protects your keys. This page says exactly which does what,
so you can tell whether you're actually covered.

## The table

| Install path | 4 tools in your editor | Proxy running (keys route) | Spend cap enforced |
|---|---|---|---|
| `curl -sSL https://worthless.sh \| sh` then `worthless` | — | **Yes** | **Yes** |
| `pipx install worthless` then `worthless` | — | **Yes** | **Yes** |
| [Docker](/install-docker/) | — | **Yes** (in the container) | **Yes** |
| **Add to Cursor** / **Install in VS Code** / `claude mcp add` / Claude Desktop | **Yes** | **No** | **No** |
| [GitHub Actions](/install-github-actions/) | — | CI-scoped | CI-scoped |

## The part that catches people

The one-click editor buttons install an **MCP server** that exposes four management
tools — `worthless_status`, `worthless_scan`, `worthless_lock`, `worthless_spend`.

That server **cannot start the proxy.** There is no proxy-start tool. Only the CLI
(`worthless`) starts the proxy on `127.0.0.1:8787`.

This matters because `worthless_lock` always writes a `*_BASE_URL` into your `.env`
pointing at the proxy. So if you lock a key from your editor and never start the CLI
proxy:

- your key **is** split (the real key is not sitting in `.env`), **and**
- your app's requests go to `127.0.0.1:8787`, where **nothing is listening**, so they
  fail with a connection error.

You are not silently unprotected — but you are not working either. Start the proxy:

```bash
worthless          # from your project directory
```

Then confirm:

```bash
worthless status   # reports whether the proxy is running, and which keys are protected
```

## Rule of thumb

- **Want your keys protected and your app working?** Install the CLI. That is the path
  that does the work.
- **Want to drive Worthless from your AI editor?** Add the editor tools **on top of** a
  running CLI proxy — not instead of it.

## What this page does not claim

- It does not claim the editor tools are useless — they let an agent scan for exposed
  keys, lock a `.env`, and read spend without you leaving the editor.
- It does not cover whether a specific editor honours a custom `OPENAI_BASE_URL` for its
  own built-in AI features. That is a separate, **unverified** question — see
  [Install for AI editors](/install-mcp/).

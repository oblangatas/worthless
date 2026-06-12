# Worthless

**Make leaked API keys worthless.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)
[![Tests](https://github.com/shacharm2/worthless/actions/workflows/tests.yml/badge.svg)](https://github.com/shacharm2/worthless/actions/workflows/tests.yml)

Your API key is split into two pieces. Neither piece is useful on its own.
Every request goes through a proxy that enforces a hard spend cap **before** the key ever reconstructs.
Budget blown = key never forms = request never reaches the provider.

> Every secrets tool protects the key until your app uses it.
> Worthless protects you **after it leaks**.

## Quickstart

```bash
pipx install worthless
cd your-project
worthless
```

That's it. Worthless detects API keys in your `.env`, splits them, starts a local proxy, and you're protected.

```
$ worthless

  Found 2 API keys:
    OPENAI_API_KEY      openai
    ANTHROPIC_API_KEY   anthropic

  Lock these keys? [y/N] y

  Protecting OPENAI_API_KEY...      done
  Protecting ANTHROPIC_API_KEY...   done

  Starting proxy on 127.0.0.1:8787...   healthy

  Proxy healthy on 127.0.0.1:8787
```

Your code doesn't change. The proxy handles everything.

### Alternative install

```bash
pip install worthless        # in a virtualenv
```

## How it works

1. `worthless lock` splits each API key into two shards using XOR
2. Shard A stays on your machine (encrypted). Shard B goes to the proxy database.
3. Your `.env` is rewritten with a decoy key that looks real but isn't
4. The proxy reconstructs the key only when the rules engine approves the request
5. Spend cap blown? The key never forms. The request never reaches the provider.

## Commands

```bash
worthless              # Auto-detect, lock, start proxy (the magic)
worthless lock         # Lock keys in .env
worthless unlock       # Restore original keys
worthless scan         # Detect exposed keys without locking
worthless status       # Show proxy and key status
worthless up           # Start proxy (foreground)
worthless up -d        # Start proxy (background daemon)
worthless down         # Stop the proxy
worthless wrap <cmd>   # Run a command through the proxy
worthless revoke       # Revoke enrolled keys
```

## Undo everything

```console
$ worthless unlock
1 key(s) restored.
```

Original key is back. No trace.

## Pre-commit hook

```yaml
repos:
  - repo: https://github.com/shacharm2/worthless
    rev: main
    hooks:
      - id: worthless-scan
```

## For AI coding agents

Worthless ships a `SKILL.md` that tells Claude Code, Cursor, and Windsurf what commands are available. Agents use `--json` for structured output:

```bash
worthless status --json
```

## Development

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv sync --extra dev --extra test
uv run pytest
```

## Learn more

- [Protocol](https://docs.wless.io/protocol/) -- technical deep dive
- [Security rules](SECURITY_RULES.md) -- invariants all contributions must preserve
- [SKILL.md](SKILL.md) -- agent discovery file

## Contributing

PRs welcome. Read [SECURITY_RULES.md](SECURITY_RULES.md) first.

## License

[AGPL-3.0](LICENSE)

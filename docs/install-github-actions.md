---
title: "Install — GitHub Actions"
description: "Protect API keys during CI test runs and scan for exposed secrets."
---

# Install -- GitHub Actions

Run Worthless in CI to protect API keys during test runs and scan for exposed secrets.

## Workflow

Add this to `.github/workflows/worthless-ci.yml`, or copy from
[`examples/ci/worthless-ci.yml`](https://github.com/shacharm2/worthless/blob/main/examples/ci/worthless-ci.yml):

```yaml
name: Worthless CI Gate

on:
  push:
    branches: [main]
  pull_request:

jobs:
  protect-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install uv
        uses: astral-sh/setup-uv@v4

      - name: Install worthless
        run: uv pip install worthless --system

      - name: Enroll OpenAI key
        run: echo "$OPENAI_API_KEY" | worthless enroll --alias openai --provider openai --key-stdin
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - name: Run tests through proxy
        run: worthless wrap pytest

      - name: Scan for exposed keys
        run: worthless scan --deep
```

## What this does

1. **Enroll** -- Pipes each API key from GitHub Secrets through stdin to `worthless enroll`. The key is split into shards and stored locally on the ephemeral runner. Secrets never touch disk as a `.env` file.
2. **Wrap** -- Starts an ephemeral proxy on the same port `lock` wrote into `.env` (default 8787, override via `WORTHLESS_PORT`) and runs `pytest` through it. Your test code reads `OPENAI_BASE_URL` from `.env` like any normal app — wrap doesn't synthesise it.
3. **Scan** -- Checks files and environment variables for any exposed (unprotected) keys. Exits non-zero if found.

## Adding more keys

Repeat the enroll step for each provider:

```yaml
      - name: Enroll Anthropic key
        run: echo "$ANTHROPIC_API_KEY" | worthless enroll --alias anthropic --provider anthropic --key-stdin
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The alias is user-chosen -- use `openai-prod`, `openai-test`, etc. for multiple keys from the same provider.

## Alternative: file-based enrollment

If you prefer using a `.env` file, create one from secrets and use `worthless lock`:

```yaml
      - name: Create .env and lock
        run: |
          cat <<'EOF' > .env
          OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }}
          EOF
          worthless lock --env .env
          rm -f .env
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All keys protected, scan clean |
| 1 | Unprotected keys found (scan) or key operation failed |
| 2 | Scan error (invalid config, file access error) |

> [!NOTE]
> **Planned: Hosted proxy in CI.** A hosted proxy service that eliminates the need
> to install Worthless in each CI run is planned for a future release.

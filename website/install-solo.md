# Install — Solo Developer

```bash
pip install worthless
worthless lock
```

Within a few seconds your API keys are split and your proxy is running. No code changes required — your app works identically.

## What `worthless lock` does

Scans `.env`, splits each key into two shards, and injects `BASE_URL` so your SDK routes through the proxy automatically:

```text
Scanning .env for API keys...
  Protecting OPENAI_API_KEY...
  Protecting ANTHROPIC_API_KEY...
worthless: added OPENAI_BASE_URL=http://127.0.0.1:8787/openai-a1b2c3d4/v1 to .env
worthless: added ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic-a1b2c3d4/v1 to .env
[OK] 2 key(s) split between this machine and your system keystore — .env no longer contains a usable secret.
Next: run `worthless wrap <command>` or `worthless up` for daemon mode
```

## Verify

```bash
worthless status
```

```text
Enrolled keys:
  openai-a1b2c3d4    openai     PROTECTED
  anthropic-a1b2c3d4 anthropic  PROTECTED

Proxy: running on 127.0.0.1:8787
```

`PROTECTED` and `Proxy: running` means your keys are protected. Run your app normally.

## How protection works

After `worthless lock`, your API key value in `.env` is replaced with a format-preserving shard — it looks like a real key. An attacker who steals your `.env` gets a dead shard and doesn't even know it. The shard fails silently when used directly against any provider. (`worthless lock` also injects `BASE_URL` entries so your SDK routes through the proxy automatically.)

## Run your app

```bash
# Wrap a single command (proxy starts, wraps your process, exits cleanly):
worthless wrap python your_app.py

# Or run the proxy in the background:
worthless up -d
python your_app.py
```

## Undo

```bash
worthless unlock
```

Restores the original keys to `.env` and removes the proxy enrollment.

---

Installing from source? See the [README quickstart](../README.md#quickstart).

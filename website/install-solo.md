# Install -- Solo Developer

> [!NOTE]
> **Not yet available.** The one-line installer requires a PyPI package and domain
> that are not yet published. Install from source -- see the [GitHub repository](https://github.com/shacharm2/worthless).

## Target-state install (coming soon)

```bash
pip install worthless
worthless lock
worthless wrap python your_app.py
```

This will:

1. Scan your `.env` for API keys
2. Split each key into two shards (one local, one encrypted in the proxy DB)
3. Replace the `.env` value with a format-correct decoy
4. Start a local proxy on `localhost:8787`
5. Inject `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` so your SDK routes through the proxy

Your existing code works identically. Your key is now split and budget-protected.

## Current install (from source)

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock
worthless wrap python your_app.py
```

See the [README quickstart](https://github.com/shacharm2/worthless#quickstart) for full walkthrough.

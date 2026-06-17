---
title: "Install — Self-Hosted"
description: "Run the Worthless proxy yourself — Docker Compose, cloud, or from source."
---

# Install -- Self-Hosted

Run the Worthless proxy in Docker. The container is fully self-contained —
it generates its own encryption key and stores all shard data internally.

## Quick start (Docker Compose)

```bash
git clone https://github.com/shacharm2/worthless && cd worthless/deploy
cp docker-compose.env.example docker-compose.env
docker compose up -d
```

The proxy starts on `localhost:8787`. Enroll your API keys:

```bash
printf '%s' "${OPENAI_API_KEY:?set OPENAI_API_KEY first}" | docker compose exec -T proxy \
  worthless enroll --alias openai --key-stdin --provider openai
```

Repeat for each key. The container splits and stores the key internally —
the original key never touches disk.

## Cloud deploy

:::note[Planned]
Cloud deployment (Railway, Render) requires a persistent volume at `/data`.
Template configs are in [`deploy/`](https://github.com/shacharm2/worthless/tree/main/deploy)
(`railway.toml`, `render.yaml`), but the enrollment workflow is not yet streamlined.
:::

## From source (no Docker)

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock
worthless up
```

The proxy runs on `localhost:8787`. See the [README](https://github.com/shacharm2/worthless#readme) for the full command reference.

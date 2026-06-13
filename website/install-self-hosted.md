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
echo $OPENAI_API_KEY | docker compose exec -T proxy \
  worthless enroll --alias openai --key-stdin --provider openai
```

Repeat for each key. The container splits and stores the key internally —
the original key never touches disk.

## Cloud deploy

> [!NOTE]
> **Planned** -- Cloud deployment (Railway, Render) requires a persistent
> volume at `/data`. Template configs are in `deploy/` but the enrollment
> workflow is not yet streamlined.
> See the [GitHub repository](https://github.com/shacharm2/worthless) for current install options.

## From source (no Docker)

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock
worthless up
```

The proxy runs on `localhost:8787`. See the [GitHub repository](https://github.com/shacharm2/worthless) for details.

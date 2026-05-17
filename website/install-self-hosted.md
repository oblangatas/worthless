# Install — Self-Hosted (Docker)

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

Repeat for each key. The original key never touches disk.

## Verify

```bash
docker compose exec proxy worthless status
```

```
Enrolled keys:
  openai-a1b2c3d4  openai  PROTECTED

Proxy: running on 0.0.0.0:8787
```

`PROTECTED` and `Proxy: running` means your keys are enrolled and the proxy is serving requests.

Point your app at the proxy:

```bash
export OPENAI_BASE_URL=http://localhost:8787/openai-a1b2c3d4/v1
```

## OpenClaw or other tools running in a container

If your client runs in a container and the Worthless proxy runs on your host, the container needs to reach the host. Set two env vars before locking on the host:

```bash
# Bind the proxy to all interfaces (not just loopback)
export WORTHLESS_HOST=0.0.0.0

# Tell lock to write host.docker.internal into client config files
export WORTHLESS_PROXY_HOST=host.docker.internal

worthless lock
```

Start your client container with host access:

```bash
docker run --rm -it \
  --add-host=host.docker.internal:host-gateway \
  your-client-image
```

> `--add-host=host.docker.internal:host-gateway` is the Linux equivalent of Docker Desktop's built-in `host.docker.internal`. On macOS with Docker Desktop, it resolves automatically.

## Cloud deploy (Railway, Render)

Template configs are in `deploy/`. Mount a persistent volume at `/data` to survive restarts.

See the [README](../README.md) for deployment notes.

## From source (no Docker)

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock
worthless up
```

The proxy runs on `localhost:8787`.

## Undo

```bash
worthless unlock
```

Or stop the container:

```bash
docker compose down
```

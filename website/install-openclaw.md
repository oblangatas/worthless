# Install — OpenClaw

Worthless integrates with OpenClaw automatically when you run `worthless lock`. No separate install step, no MCP server required.

## How it works

`worthless lock` does three things in one shot:

1. Splits your API key and writes Shard A into `.env`
2. Injects a `worthless-<provider>` entry into `~/.openclaw/openclaw.json`
3. Installs the Worthless skill into `~/.openclaw/workspace/skills/worthless/`

After that, every request OpenClaw makes routes through the Worthless proxy — spend cap enforced, key never exposed.

## Quick start (local)

```bash
# Lock your key — OpenClaw config updated automatically
worthless lock
```

That's it. Restart OpenClaw and it picks up the new provider.

## Docker / container setup

If OpenClaw runs in a container and the Worthless proxy runs on your host machine, the container needs to reach the host. Set two env vars before locking:

```bash
# Bind the proxy to all interfaces (not just loopback)
export WORTHLESS_HOST=0.0.0.0

# Tell lock to write host.docker.internal into openclaw.json
export WORTHLESS_PROXY_HOST=host.docker.internal

worthless lock
```

Then start OpenClaw with access to your config:

```bash
docker run --rm -it \
  --add-host=host.docker.internal:host-gateway \
  -v "$HOME/.openclaw:/home/node/.openclaw" \
  ghcr.io/openclaw/openclaw:latest \
  openclaw agent --local --message "hello"
```

> `--add-host=host.docker.internal:host-gateway` is the Linux equivalent of Docker Desktop's built-in `host.docker.internal`. On macOS with Docker Desktop, it resolves automatically.

## All-container setup (docker-compose)

> **Server / cloud deployments only.** This section is for running both services in Docker on a remote server with no host process. If you installed OpenClaw locally, use the [Quick start](#quick-start-local) above instead. A one-command `clawhub install worthless` skill is coming — check [ClawHub](https://clawhub.ai) for availability.

Run the Worthless proxy and OpenClaw in the same Docker network — no worthless process on your host.

**1. Start the proxy first (openclaw comes after)**

```bash
# Download the compose file and env template
curl -sSL https://raw.githubusercontent.com/shacharm2/worthless/main/deploy/docker-compose.yml -o docker-compose.yml
curl -sSL https://raw.githubusercontent.com/shacharm2/worthless/main/deploy/docker-compose.env.example -o docker-compose.env

# Start only the proxy — openclaw must not be running yet when you lock
docker compose up -d
```

**2. Write your key and lock**

```bash
# Write the key into the proxy container's tmpfs — ephemeral, never on disk
printf 'OPENAI_API_KEY=%s\n' "$OPENAI_API_KEY" | \
  docker compose exec -T proxy sh -c 'cat > /tmp/.env'

# Lock: splits the key, stores shard B in the proxy, writes openclaw.json
# with baseUrl=http://proxy:8787 into the shared volume
docker compose exec proxy worthless lock --env /tmp/.env
```

> **Order matters.** Lock must run before OpenClaw starts. Once OpenClaw has started it locks down its config directory and a subsequent `worthless lock` cannot write to it. If you need to re-lock (e.g. to rotate a key), stop openclaw first: `docker compose stop openclaw`, then lock, then `docker compose start openclaw`.

**3. Start OpenClaw**

```bash
# Start openclaw — it reads the provider entry lock just wrote
docker compose --profile openclaw up -d
```

`WORTHLESS_PROXY_HOST=proxy` is pre-set in `docker-compose.yml`, so `worthless lock` writes the Docker-internal hostname into `openclaw.json` automatically — no env var to remember. The key in `/tmp/.env` is replaced with shard A and lives only in tmpfs (reset on container restart).

**4. Send a request through OpenClaw**

```bash
docker compose exec openclaw \
  openclaw agent --local --message "hello"
```

Check the proxy log for a proxied request count increment:

```bash
docker compose logs proxy | grep proxied
```

**What the shared volume does**

Both services mount the same `openclaw-config` volume: the proxy writes to it at `/data/.openclaw`, openclaw reads from it at `/home/node/.openclaw`. The API key never leaves the proxy container.

## Verify it's working

```bash
worthless status
```

Look for `openclaw` in the output — it shows whether the provider entries and skill folder are present.

To test end-to-end, send a request through OpenClaw and check the proxy log for a proxied request count increment.

## Undo

```bash
worthless unlock
```

Removes the `worthless-<provider>` entries from `openclaw.json` and uninstalls the skill folder. Your original providers are untouched.

# Install — OpenClaw

Worthless integrates with OpenClaw automatically when you run `worthless lock`. No separate install step, no MCP server required.

Running worthless as a host process? [Start here](#quick-start-local). Running worthless inside Docker? [Jump to all-container setup](#all-container-setup-docker-compose). OpenClaw in a container but proxy on your host? [Hybrid setup](#openclaw-in-docker-proxy-on-host).

## How it works

`worthless lock` does three things in one shot:

1. Splits your API key and writes Shard A into `.env`
2. Rewrites your existing `models.providers.<provider>` entry in `~/.openclaw/openclaw.json` — `baseUrl` points at the Worthless proxy, `apiKey` becomes an inert shard
3. Installs the Worthless skill into `~/.openclaw/workspace/skills/worthless/`

Your provider keeps its original name. You pick the same model in OpenClaw as before — the difference is that the request now travels through the Worthless proxy, where the spend cap is enforced and the full key is reassembled.

> Providers you signed into with OAuth can't be split, so they still go direct. `worthless doctor` lists them.

## Quick start (local)

```bash
# Lock your key — OpenClaw config updated automatically
worthless lock

# Start the proxy in the background
worthless up -d
```

When you run `lock` in a terminal it offers to install a background service so protection survives closing the terminal and rebooting. Answer `y` and you can skip `worthless up -d`. The default is no. Missed the prompt? Run `worthless service install` any time.

Fully restart OpenClaw — it reads `openclaw.json` only at startup — and use it as usual. Check that requests are flowing with [`worthless status`](#verify-its-working).

### If lock refuses to run

Before writing anything, `worthless lock` asks OpenClaw to audit its own config for plaintext API keys. If it finds any, lock stops:

```
worthless lock aborted: plaintext API keys detected in OpenClaw configuration.
```

Exit code `73`. Fix it by migrating those keys to SecretRefs, then re-run lock:

```bash
openclaw secrets configure
worthless lock
```

Exit code `87` means the audit could not run — usually an OpenClaw too old to have `openclaw secrets audit` (tested with `2026.5.3-1`), or a `WORTHLESS_OPENCLAW_BIN` pointing at a binary that does not exist. Upgrade OpenClaw and try again.

Lock can also exit non-zero *after* your `.env` is already locked — for example when the final re-audit finds something new. Your keys stay locked, but OpenClaw may not be routed through the proxy yet. Run `worthless doctor` before retrying.

The audit is skipped when OpenClaw is not installed, so non-OpenClaw users never see it.

## All-container setup (docker-compose)

> **Cloud / VPS deployments.** Both the Worthless proxy and OpenClaw run as containers in the same Docker network — nothing installed on the host. If you installed OpenClaw locally, use the [Quick start](#quick-start-local) above instead.
>
> Not yet verified end-to-end on a live deployment (WOR-510).

**Before you start:** Lock must run before OpenClaw starts. Once OpenClaw has started it locks down its config directory and a subsequent `worthless lock` cannot write to it. If you need to re-lock (e.g. to rotate a key), stop openclaw first: `docker compose stop openclaw`, then lock, then `docker compose start openclaw`.

**1. Start the proxy first (openclaw comes after)**

```bash
# Create a fresh directory for this deployment
mkdir worthless-deploy && cd worthless-deploy

# Download the compose file and env template
curl -sSL https://raw.githubusercontent.com/oblangatas/worthless/main/deploy/docker-compose.yml -o docker-compose.yml
curl -sSL https://raw.githubusercontent.com/oblangatas/worthless/main/deploy/docker-compose.env.example -o docker-compose.env

# Start only the proxy — openclaw must not be running yet when you lock
docker compose up -d
```

**2. Write your key and lock**

```bash
# Write the key into the proxy container's tmpfs — ephemeral, never on disk
printf 'OPENAI_API_KEY=%s\n' "$OPENAI_API_KEY" | \
  docker compose exec -T proxy sh -c 'cat > /tmp/.env'

# Lock: splits the key, stores shard B in the proxy, rewrites openclaw.json
# with baseUrl=http://proxy:8787 into the shared volume
docker compose exec proxy worthless lock --env /tmp/.env

# Remove the key from tmpfs — shard B is now in the proxy DB
docker compose exec proxy rm /tmp/.env
```

Ignore lock's closing hint about `worthless up` — the proxy container is already serving.

**3. Start OpenClaw**

```bash
docker compose --profile openclaw up -d
```

`WORTHLESS_PROXY_HOST=proxy` is pre-set in `docker-compose.yml`, so lock writes the Docker-internal hostname into `openclaw.json` automatically.

**4. Send a request and confirm it went through the proxy**

```bash
docker compose exec openclaw openclaw agent --local --message "hello"

docker compose exec -e WORTHLESS_PORT=8787 proxy worthless status
```

`Requests proxied` should be `1` or higher.

Both services share the `openclaw-config` volume (proxy at `/data/.openclaw`, openclaw at `/home/node/.openclaw`), so the API key is never written to host disk or container layers.

To undo in this setup, run unlock inside the proxy container: `docker compose exec proxy worthless unlock`.

## OpenClaw in Docker, proxy on host

> Not yet verified end-to-end on a live deployment (WOR-510).

If OpenClaw runs in a container but the Worthless proxy runs on your host machine, the container needs to reach the host. Set two env vars before locking:

```bash
# lan mode binds the proxy to all interfaces (default loopback mode only allows 127.0.0.1)
export WORTHLESS_DEPLOY_MODE=lan

# Tell lock to write host.docker.internal into openclaw.json
export WORTHLESS_PROXY_HOST=host.docker.internal

worthless lock      # answer "no" to the background-service prompt — see below
worthless up -d
```

> **Don't install the background service for this setup.** The service keeps only the port, not `WORTHLESS_DEPLOY_MODE=lan`, so it binds loopback only — the container can't reach it, and it holds port 8787 so `worthless up` can't start. If you already installed it, run `worthless service stop` (or `worthless service uninstall`) first. After a reboot, re-run `WORTHLESS_DEPLOY_MODE=lan worthless up -d`.

> **Firewall:** lan mode exposes the proxy port on all network interfaces. Ensure your firewall restricts inbound access to the proxy port before doing this on a cloud or shared machine.

Then send a request from OpenClaw with access to your config:

```bash
docker run --rm -it \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  --add-host=host.docker.internal:host-gateway \
  -v "$HOME/.openclaw:/home/node/.openclaw" \
  ghcr.io/openclaw/openclaw:2026.5.3-1 \
  openclaw agent --local --message "hello"
```

> `--add-host=host.docker.internal:host-gateway` is the Linux equivalent of Docker Desktop's built-in `host.docker.internal`. On macOS with Docker Desktop, it resolves automatically.

## Verify it's working

```bash
worthless status
```

Before your first message it looks like this:

```
🟢 You're protected — 1 key(s) locked, proxy up.

Enrolled keys:
  openai-a1b2c3d4  openai  PROTECTED

Proxy: running on 127.0.0.1:8787 (mode: up)
Requests proxied: 0
```

To confirm OpenClaw is wired, check that your provider's `baseUrl` points at the proxy:

```bash
grep -B2 -A3 '"baseUrl"' ~/.openclaw/openclaw.json
```

```
      "openai": {
        "baseUrl": "http://127.0.0.1:8787/openai-a1b2c3d4/v1",
```

Send a message from OpenClaw and `Requests proxied` will increment.

## Troubleshooting

Run `worthless doctor` first. It checks your local state and the OpenClaw wiring — including the secrets audit behind exit codes 73 and 87 — and prints the fix. `worthless doctor --fix` repairs what it safely can.

- **Proxy not running after a reboot:** `worthless service status`, then `worthless service start`. No service installed? Run `worthless up -d`.
- **Port 8787 already in use:** `worthless up -d -p 8788`, then re-run `worthless lock` so `openclaw.json` gets the new port.
- **Requests still go direct:** fully restart OpenClaw — it reads `openclaw.json` only at startup.

## Undo

```bash
worthless unlock
```

Restores your original provider entry in `openclaw.json` from the rollback record and removes the skill folder. Providers Worthless never touched are left alone. If you installed the background service, also run `worthless service uninstall`.

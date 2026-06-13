---
title: "Install — Docker"
description: "When your app runs in a container — how the host CLI, Docker image, and host.docker.internal fit together."
---

# Install with Docker

The Docker image is a worthless **server** — not the CLI. The CLI is
always installed natively on your host. The scenarios below spell out
which one you need so the most-common confusion ("can I just `docker
run worthless`?") doesn't happen.

## TL;DR — pick your scenario

| Your setup | What to do | Container URL |
|---|---|---|
| **Solo dev. App runs natively. No Docker.** | Use [mac.md](/install/mac/) / [linux.md](/install/linux/) / [wsl.md](/install/wsl/) | n/a (`127.0.0.1:8787`) |
| **Solo dev. App in container. worthless on host.** | [Scenario A](#scenario-a-your-app-in-docker-worthless-on-host) | `host.docker.internal:8787` |
| **Solo dev. worthless + app in same Compose stack.** | [Scenario B](#scenario-b-both-worthless-and-app-in-the-same-compose-stack) | service-name `worthless:8787` |
| **Team. Shared worthless server (single-tenant).** | [Scenario C](#scenario-c-single-tenant-team-server) | your TLS endpoint |

## Scenario A — your app in Docker, worthless on host

Most common. Your app's Dockerfile / docker-compose.yml runs your
service in a container. worthless lives on your host.

### A.1 Install worthless natively on your host

Follow [mac.md](/install/mac/) / [linux.md](/install/linux/) / [wsl.md](/install/wsl/)
to install the native CLI. For this Docker scenario, do not start the default
loopback proxy yet; you will start it in LAN mode after the `.env` bridge edit.

### A.2 Lock the keys

```bash
cd /path/to/your/project
worthless lock
```

This rewrites your `.env`:

```diff
- OPENAI_API_KEY=<your-real-openai-key-here>
+ OPENAI_API_KEY=<decoy-prefix>...
+ OPENAI_BASE_URL=http://127.0.0.1:8787/<alias>/v1
```

### A.3 Use `host.docker.internal:8787` (not `127.0.0.1`)

**This is the gotcha.** From inside a container, `127.0.0.1` means
"the container itself" — not "the host." Your container can't reach
the host's port 8787 via that address.

Edit `.env` to use Docker's host-bridge address:

| Platform | Replace `127.0.0.1` with |
|---|---|
| Docker Desktop (Mac, Windows, WSL2) | `host.docker.internal` |
| Docker on Linux (no Desktop) | Add `--add-host=host.docker.internal:host-gateway` to your `docker run` (or to the service in docker-compose), then use `host.docker.internal` |

After edit:

```bash
# .env
OPENAI_API_KEY=<decoy-prefix>...
OPENAI_BASE_URL=http://host.docker.internal:8787/<alias>/v1
```

Now start the host proxy. On Linux without Docker Desktop, the host proxy has
to listen on the Docker bridge, not only on host loopback:

```bash
WORTHLESS_DEPLOY_MODE=lan worthless up
```

On Docker Desktop, LAN mode also works for this scenario and avoids accidentally
leaving a loopback-only proxy running from the default `worthless` command.
Keep the default loopback mode for native apps. Use `lan` only for the Docker
app journey where a container must reach the host proxy.

### A.4 Pass the locked .env into the container

If your app reads configuration from environment variables, use Compose
`env_file` (or `docker run --env-file`) so the container receives the rewritten
values:

```yaml
services:
  app:
    image: my-app:latest
    env_file:
      - .env
    extra_hosts:                   # ONLY needed on Linux (no Docker Desktop)
      - "host.docker.internal:host-gateway"
```

If your app loads `.env` from disk with dotenv, bind-mount the file instead:

```yaml
services:
  app:
    image: my-app:latest
    volumes:
      - ./.env:/app/.env:ro
```

### A.5 Verify

From inside the container, use the SDK pattern from
[README — Verify it works](/install/#verify-it-works) (`docker compose exec app python /app/verify.py` etc.).

(Auto-detection of Docker context — so the `.env` URL gets written as
`host.docker.internal` directly without a manual edit — is on the v1.2
roadmap.)

## Scenario B — both worthless and app in the same Compose stack

If you want everything containerized (e.g., for reproducibility),
add the worthless server as a service:

```yaml
# docker-compose.yml
services:
  worthless:
    image: ghcr.io/shacharm2/worthless-proxy:0.3.7
    ports:
      - "8787:8787"   # host:container — exposes for CLI lock-from-host
    environment:
      WORTHLESS_DEPLOY_MODE: lan   # safe default for compose network
    volumes:
      - worthless-data:/data       # persists DB + shard storage

  app:
    image: my-app:latest
    env_file:
      - .env
    depends_on:
      - worthless
    # In compose, services reach each other by name. From `app`,
    # the proxy is at http://worthless:8787 — NOT host.docker.internal.

volumes:
  worthless-data:
```

### B.1 Lock from host (CLI on host targets the compose-side proxy)

The compose port mapping `8787:8787` means the worthless service is
reachable at `127.0.0.1:8787` from your host shell. The host CLI locks
against it:

```bash
worthless
```

`.env` gets rewritten with the host-side URL:

```diff
- OPENAI_API_KEY=<your-real-openai-key-here>
+ OPENAI_API_KEY=<decoy-prefix>...
+ OPENAI_BASE_URL=http://127.0.0.1:8787/<alias>/v1
```

> The container side of your stack will reach the proxy at
> `http://worthless:8787/<alias>/v1` (compose service name) — not
> `127.0.0.1`. After locking, edit `.env` to swap `127.0.0.1` for
> `worthless` so the `app` service can reach the proxy. Auto-detection
> of compose context is tracked for v1.2.

## Scenario C — single-tenant team server

Run a shared worthless instance behind a TLS-terminating reverse proxy.
Today this works as **single-tenant** (one shared enrollment table for
the team) — multi-dev key isolation with per-user auth between CLI and
remote proxy is not in v0.3.7.

```yaml
# docker-compose.yml on the team server box
services:
  worthless:
    image: ghcr.io/shacharm2/worthless-proxy:0.3.7
    ports:
      - "8787:8787"
    environment:
      WORTHLESS_DEPLOY_MODE: public
      # REPLACE with your reverse proxy's actual subnet — e.g.
      # 10.0.1.0/24 for the subnet your Caddy/nginx sits in.
      WORTHLESS_TRUSTED_PROXIES: "<your-private-CIDR>"
    volumes:
      - worthless-data:/data
    # plus TLS termination — Caddy/nginx reverse proxy in front
```

> Multi-tenant team mode (per-dev enrollments, mTLS between CLI and
> remote proxy, dashboard) is on the v0.4 roadmap — see
> WOR-300 / WOR-388. The single-tenant flow above works today but
> assumes your team trusts each other with the shared enrollment
> table.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `worthless` not found in shell | You ran `docker run worthless` thinking that's the CLI | Install natively per [mac.md](/install/mac/) / [linux.md](/install/linux/) |
| App in container: "connection refused" on `127.0.0.1:8787` | `127.0.0.1` from container = container itself | Use `host.docker.internal` (§A.3) |
| Linux: `host.docker.internal` doesn't resolve | No Docker Desktop = no auto host-gateway | Add `--add-host=host.docker.internal:host-gateway` to `docker run` |
| Compose: `worthless:8787` doesn't resolve | Service not in same compose network | Check `docker compose ps` — both must be on the default network |
| Proxy on host responds but every request returns 502 | Proxy can't reach upstream — DNS / network from host | Test with `curl https://api.openai.com/v1/models` from host |
| Deploy mode mismatch warnings on container start | `WORTHLESS_DEPLOY_MODE` not set, defaults to loopback, but you exposed a port | Set `WORTHLESS_DEPLOY_MODE=lan` (or `public` with trusted proxies) |

## What worthless does NOT defend against in Docker setups

- Container escape. If your container runs as root with `--privileged`
  or mounts the host filesystem, attacker-with-container = attacker-
  with-host = full read of `~/.worthless/`.
- Compose secret leakage via env_file. `.env` mounted into the
  container is readable by anything in the container. shard A is
  decoy — but if your container is compromised, attacker has shard A
  and the proxy URL. They still can't reconstruct without server-side
  shard B + cap gate, but the audit log shows the request flow.
- Image supply chain. Use the cosign-signed image (regex must match
  the publish workflow's Fulcio SAN exactly — workflow path is the
  `LOAD-BEARING` filename `publish-docker.yml`):
  ```bash
  cosign verify ghcr.io/shacharm2/worthless-proxy:0.3.7 \
    --certificate-identity-regexp 'https://github.com/shacharm2/worthless/\.github/workflows/publish-docker\.yml@refs/tags/v.*' \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  ```
- `env_file: .env` puts the decoy + proxy URL into the container's
  process env, visible to anyone in the host's `docker` group via
  `docker inspect <container>`. The decoy is harmless; the URL leak is
  fine for `127.0.0.1` and minor for `host.docker.internal`. For
  Scenario C team-server URLs, this matters — restrict `docker` group
  access on shared hosts.

## Why this is more complicated than mac/linux/wsl

Because there are three legitimate setups (host-CLI + container-app,
single compose stack, team-server) and the URL semantics differ across
all three. The CLI doesn't auto-detect which one you're in — you tell
it (or accept the default and edit `.env`).

The v1.2 work tracked under "worthless lock detects Docker context"
will collapse some of this, but won't fully replace the need to
understand which scenario you're in.

## For AI agents

> Human readers can stop here — the YAML below is for AI agents
> installing worthless on a user's behalf.

Schema documented in [agent-schema.md](/install/agent-schema/).
Docker has multiple scenarios — the YAML below covers the most common
("app in container, worthless on host"). Inspect the scenario sections
above for compose-stack and team-server flows.

```yaml
schema_version: 1
platform: docker
scenario: app_in_container_worthless_on_host   # most common; see scenario A
commands:
  install: "curl -sSL https://worthless.sh | sh"   # CLI is ALWAYS native, never `docker run`
  verify: "worthless --version"
  first_lock: "worthless lock"
  proxy_restart: "WORTHLESS_DEPLOY_MODE=lan worthless up"
post_lock_required_step:
  description: "Edit .env to use host.docker.internal:8787 instead of 127.0.0.1:8787 (containers can't reach host loopback)"
  sed_command: "sed -i.bak 's|127.0.0.1:8787|host.docker.internal:8787|' .env"
  linux_extra: "Add `--add-host=host.docker.internal:host-gateway` if no Docker Desktop, and start the host proxy with `WORTHLESS_DEPLOY_MODE=lan worthless up`"
expectations:
  install_succeeds_silently: true
  # Docker itself adds no popup. The host platform's keystore is what fires.
  # Strict YAML readers: substitute the host's value from mac.md / linux.md / wsl.md.
  first_lock_keychain_popups: 0
  first_lock_requires_human_interaction: false   # inherit from host platform's flag (mac=true)
  subsequent_command_keychain_popups: 0
  proxy_starts_automatically_on_lock: true
  proxy_survives_reboot: false
proxy:
  url_template_host: "http://127.0.0.1:8787/<alias>/v1"
  url_template_container: "http://host.docker.internal:8787/<alias>/v1"
  port: 8787
other_scenarios:
  - id: scenario_b_compose_stack
    container_url_template: "http://worthless:8787/<alias>/v1"
  - id: scenario_c_team_server
    container_url_template: "https://<your-tls-endpoint>/<alias>/v1"
limitations:
  - "`worthless lock` writes 127.0.0.1 blindly — manual .env edit required for containers (v1.2 will auto-detect)"
  - "Docker image is server-only; CLI is always native install on host"
  - "`env_file: .env` exposes proxy URL via `docker inspect` — restrict docker group access on shared hosts"
```

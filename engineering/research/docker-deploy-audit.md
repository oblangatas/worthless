# Docker Deployment Architecture Audit

## Finding 1: CRITICAL — PaaS fernet key loss on restart

Dockerfile hardcodes `WORTHLESS_FERNET_KEY_PATH=/secrets/fernet.key`. On Render/Railway (single volume at `/data`), `/secrets` is ephemeral — fernet key lost on restart, all enrolled shards permanently undecryptable.

**Root cause**: Dockerfile ENV bakes a two-volume assumption. PaaS targets mount only one volume.
**Files**: `Dockerfile` (line 27), `deploy/render.yaml`, `deploy/railway.toml`
**Fix**: Remove `WORTHLESS_FERNET_KEY_PATH` from Dockerfile ENV. Default to `$WORTHLESS_HOME/fernet.key`. Let docker-compose.yml set the override via environment block.

## Finding 2: HIGH — Entrypoint migration deletes key from /data on PaaS

Migration logic does `cp /data/fernet.key /secrets/fernet.key && rm /data/fernet.key`. On PaaS where `/secrets` is ephemeral, this **destroys the key**.

**Root cause**: Migration doesn't verify target is persistent.
**Files**: `deploy/entrypoint.sh` (lines 10-14)
**Fix**: Only migrate when `WORTHLESS_FERNET_KEY_PATH` is explicitly set (not the default). This makes migration opt-in via compose, not automatic.

## Finding 3: HIGH — VOLUME declaration creates anonymous volumes

`VOLUME ["/data", "/secrets"]` causes Docker to create anonymous volumes for unmounted paths. On PaaS, `/secrets` gets a throwaway anonymous volume.

**Root cause**: VOLUME instruction in Dockerfile is widely considered an anti-pattern.
**Files**: `Dockerfile` (line 32)
**Fix**: Remove `VOLUME` declaration. Let orchestrators (compose/PaaS) declare mounts.

## Finding 4: MEDIUM — Render/Railway configs reference only /data

PaaS configs have no env var override for fernet key path. After fixing Finding 1, PaaS deployments will correctly default to `/data/fernet.key`, but this should be documented.

**Files**: `deploy/render.yaml`, `deploy/railway.toml`
**Fix**: Add comment noting the default. No env var override needed if Finding 1 is fixed.

## Finding 5: MEDIUM — Misleading fernet key error message

`ProxySettings.validate()` says "WORTHLESS_FERNET_KEY environment variable is required" but Docker uses fd 3, not env var.

**Files**: `src/worthless/proxy/config.py` (line 70)
**Fix**: Update message to mention multiple sources.

## Finding 6: LOW — docker-compose comment overstates volume separation

Comment says separation prevents "single-volume exfiltration from reconstructing API keys" but shard_a and encrypted shard_b are both on /data. Separation only protects fernet.key.

**Files**: `deploy/docker-compose.yml` (lines 12-14)
**Fix**: Correct comment to "Separates the decryption key from the encrypted data."

## Fix Order

1. Findings 1+3: Dockerfile (remove FERNET_KEY_PATH env, remove VOLUME)
2. Finding 2: entrypoint.sh (make migration conditional on explicit env var)
3. Finding 5: config.py error message
4. Finding 6: compose comment accuracy
5. Finding 4: PaaS config comments

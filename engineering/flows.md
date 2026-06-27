# Runtime Flows

## 1. No-argument default flow

Entry: `worthless` with no subcommand

High-level path:

1. `cli/app.py` invokes `run_default`
2. local `.env` files are inspected for candidate keys
3. the user confirms locking unless `--yes` is set
4. lock flow protects discovered keys
5. proxy startup is triggered
6. final health/result output is rendered

This is the highest-level UX path and the one most likely to be used by new users.

## 2. Lock / enroll flow

Entry: `worthless lock`

High-level path:

1. candidate key material is detected from `.env`
2. provider and alias are derived
3. the key is split into shards
4. Shard B is encrypted and stored in SQLite
5. local metadata and shard material are persisted
6. `.env` is rewritten with a decoy value
7. enrollment/config rows are written for later recovery and gating

Important implementation characteristic:

- the flow has intermediate states; DB writes, shard-file writes, and `.env` rewriting do not happen as one opaque step

## 3. Ephemeral wrap flow

Entry: `worthless wrap <cmd>`

High-level path:

1. start a temporary proxy on the same port `lock` wrote into `.env` (default 8787, override via `WORTHLESS_PORT`)
2. spawn the child command with the parent environment unchanged — `lock` already wrote `*_BASE_URL` into the user's `.env`, so the child picks them up via dotenv
3. child SDK/HTTP traffic resolves `*_BASE_URL` from `.env` and reaches the proxy on the bound port
4. on child exit, clean up proxy/process state

Important characteristic:

- `wrap` is a distinct protection mode from daemon mode; it is intentionally short-lived and process-scoped

## 4. Daemon lifecycle flow

Entry: `worthless up`, `worthless up -d`, `worthless down`, `worthless status`

High-level path:

1. `up` validates settings and starts the proxy
2. daemon mode writes PID/log state and backgrounds the process
3. `status` inspects enrolled aliases and proxy health
4. `down` terminates the daemon process tree and cleans up PID state

Important characteristic:

- daemon lifecycle is part of the security model because a stale or unhealthy local proxy changes what traffic is protected and how

## 5. Request handling flow

Entry: any request to the local proxy

High-level path:

1. alias is extracted from the URL path
2. provider-style auth header is parsed for Shard A
3. active rules run before any reconstruction
4. encrypted shard data is fetched from storage
5. shard data is decrypted and the key is reconstructed
6. adapter-specific upstream request is formed
7. upstream response is relayed back to the client
8. usage/spend is extracted and recorded after the response
9. mutable key material is zeroed during cleanup paths

Important characteristics:

- gate-before-reconstruct is the core control path
- upstream metering is post-response, so budget enforcement is best-effort rather than a reservation system
- adapter auth header construction happens in the adapter layer, not in the route handler alone

## 6. Recovery and deletion flows

### Unlock

- reconstructs original keys from stored shard material
- writes plaintext back to `.env` or equivalent output surface
- intentionally reintroduces cleartext as part of recovery

### Revoke

- deletes shard files and related DB state
- is deletion-oriented rather than restoration-oriented
- uses best-effort wipe semantics for local material

## 7. MCP integration flow

The MCP server is not on the hot path for request proxying, but it matters operationally because it exposes control and management surfaces around the same local protection system.

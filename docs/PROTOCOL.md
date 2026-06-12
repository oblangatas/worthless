# Worthless Wire Protocol

> [!NOTE]
> **Pre-release.** This protocol may change before v1.0.

## Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| `x-worthless-key` | Client -> Proxy | Identifies which enrolled key to use for reconstruction |
| `x-worthless-shard-a` | Client -> Proxy | Client's shard (Base64-encoded) for key reconstruction |

When only one key is enrolled per provider, the proxy infers the alias from the request path. The `x-worthless-key` header is only required when multiple keys share a provider.

## Endpoints

| Path | Method | Provider | Status |
|------|--------|----------|--------|
| `/v1/chat/completions` | POST | OpenAI | Streaming + non-streaming |
| `/v1/messages` | POST | Anthropic | Streaming + non-streaming |
| `/healthz` | GET | -- | Liveness probe |
| `/readyz` | GET | -- | Readiness probe (DB connected, keys enrolled) |

All other paths return `401` (anti-enumeration: unknown endpoints do not return `404`).

## Proxy Error Responses

The proxy returns provider-compatible JSON error bodies so SDKs handle them natively.

| Status | Meaning | When |
|--------|---------|------|
| 401 | Authentication required | Missing/invalid alias, missing shard, commitment mismatch |
| 402 | Spend cap exceeded | Cumulative spend exceeds configured cap |
| 429 | Rate limit exceeded | Requests per second exceeded (includes `Retry-After` header) |
| 502 | Gateway error | Upstream provider unreachable |
| 504 | Gateway timeout | Upstream provider timed out |

All `401` responses return an identical body regardless of failure reason (anti-enumeration).

## CLI Error Codes

| Code | Name | Meaning |
|------|------|---------|
| WRTLS-100 | BOOTSTRAP_FAILED | Home directory or database initialization failed |
| WRTLS-101 | ENV_NOT_FOUND | `.env` file not found or is a symlink |
| WRTLS-102 | KEY_NOT_FOUND | No API key found, or shard missing |
| WRTLS-103 | SHARD_STORAGE_FAILED | Failed to write shard to DB or filesystem |
| WRTLS-104 | PROXY_UNREACHABLE | Proxy failed to start or health check timed out |
| WRTLS-105 | LOCK_IN_PROGRESS | Another lock/unlock operation is running |
| WRTLS-106 | SCAN_ERROR | File scan failed or invalid scan configuration |
| WRTLS-107 | PORT_IN_USE | Proxy port already bound by another process |
| WRTLS-108 | WRAP_CHILD_FAILED | Child process failed to start |
| WRTLS-199 | UNKNOWN | Unexpected error |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WORTHLESS_PORT` | `8787` | Proxy listen port |
| `WORTHLESS_DB_PATH` | `~/.worthless/worthless.db` | SQLite database path |
| `WORTHLESS_SHARD_A_DIR` | `~/.worthless/shard_a` | Directory for Shard A files |
| `WORTHLESS_FERNET_KEY` | *(auto-generated)* | Fernet key for encrypting Shard B at rest |
| `WORTHLESS_RATE_LIMIT_RPS` | `100.0` | Default rate limit (requests/second per IP) |
| `WORTHLESS_UPSTREAM_TIMEOUT` | `120.0` | Non-streaming upstream timeout (seconds) |
| `WORTHLESS_STREAMING_TIMEOUT` | `300.0` | Streaming upstream timeout (seconds) |
| `WORTHLESS_ALLOW_INSECURE` | `false` | Allow shard headers over non-TLS (dev only) |

## Security Model

### Shard custody

- **Shard A** stays on the client machine (filesystem). In local mode, the proxy reads it directly from the `shard_a` directory - no network transmission. In remote mode (planned), the client sends Shard A via the `x-worthless-shard-a` header over TLS. A future MPC upgrade will eliminate Shard A transmission entirely, keeping it on the client at all times.
- **Shard B** is encrypted at rest in SQLite using Fernet (AES-128-CBC + HMAC-SHA256). It is decrypted only in memory during key reconstruction.

### Gate before reconstruct

The rules engine (rate limiting, spend caps) evaluates every request *before* Shard B is decrypted. If a rule denies the request, zero key material is touched. This is enforced architecturally -- the reconstruction function is only called after all gates pass.

### Server-side direct call

The reconstructed API key is used for the upstream provider call and immediately zeroed. It never appears in any response body, header, or log. The key exists in memory only for the duration of a single HTTP call.

### Anti-enumeration

All authentication failures return an identical `401` response body. An attacker cannot distinguish between "alias does not exist" and "shard mismatch" from the response alone. Unknown endpoints also return `401` (not `404`) to prevent endpoint discovery.

---
title: "Wire Protocol"
description: "Worthless proxy ↔ reconstruction service wire protocol."
---

# Worthless Wire Protocol

> [!NOTE]
> **Pre-release.** This protocol may change before v1.0.

## Headers

Shard A is delivered to the proxy using standard provider authentication headers:

| Provider | Header | Purpose |
|----------|--------|---------|
| OpenAI | `Authorization: Bearer <shard-A>` | Shard A for key reconstruction |
| Anthropic | `x-api-key: <shard-A>` | Shard A for key reconstruction |

The alias is embedded in the URL path: `/<alias>/v1/chat/completions`. The proxy extracts the alias from the first path segment and uses it to look up the corresponding shard-B. No custom Worthless-specific headers are required.

## Endpoints

| Path | Method | Provider | Status |
|------|--------|----------|--------|
| `/<alias>/v1/chat/completions` | POST | OpenAI | Streaming + non-streaming |
| `/<alias>/v1/messages` | POST | Anthropic | Streaming + non-streaming |
| `/healthz` | GET | -- | Liveness probe |
| `/readyz` | GET | -- | DB connectivity check |

All other paths return `401` (anti-enumeration: unknown endpoints do not return `404`).

## Proxy Error Responses

The proxy returns provider-compatible JSON error bodies so SDKs handle them natively.

| Status | Meaning | When |
|--------|---------|------|
| 401 | Authentication required | Missing/invalid alias, missing shard-A in auth header, commitment mismatch |
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
| `WORTHLESS_FERNET_KEY` | *(auto-generated)* | Fernet key for encrypting Shard B at rest |
| `WORTHLESS_RATE_LIMIT_RPS` | `100.0` | Default rate limit (requests/second per IP) |
| `WORTHLESS_UPSTREAM_TIMEOUT` | `120.0` | Non-streaming upstream timeout (seconds) |
| `WORTHLESS_STREAMING_TIMEOUT` | `300.0` | Streaming upstream timeout (seconds) |
| `WORTHLESS_ALLOW_INSECURE` | `false` | Allow shard-A auth over non-TLS (dev only) |
| `WORTHLESS_UPSTREAM_PROXY` | *(unset: direct)* | Egress proxy for `https://` upstream calls (`http`/`https` URL). `HTTPS_PROXY` and the system proxy are ignored. It can read your real keys only if it inspects TLS and you trust its CA via `WORTHLESS_UPSTREAM_CA_BUNDLE`. See [Egress proxies](/security/#egress-proxies-and-custom-cas) |
| `WORTHLESS_UPSTREAM_CA_BUNDLE` | *(unset: built-in CA list)* | PEM bundle to verify providers against. `SSL_CERT_FILE` is ignored. Anyone holding a key for a CA in it can read your real keys |

## Security Model

### Shard custody

- **Shard A** stays on the client machine in `.env`. It is format-preserving (same prefix, charset, and length as the original key), so the SDK sends it as `Authorization: Bearer <shard-A>` (OpenAI) or `x-api-key: <shard-A>` (Anthropic) on every request. The proxy extracts it from the standard auth header. No server-side shard-A storage exists.
- **Shard B** is encrypted at rest in SQLite using Fernet (AES-128-CBC + HMAC-SHA256). It is decrypted only in memory during key reconstruction.

### Gate before reconstruct

The rules engine (rate limiting, spend caps) evaluates every request *before* Shard B is decrypted. If a rule denies the request, zero key material is touched. This is enforced architecturally -- the reconstruction function is only called after all gates pass.

### Server-side direct call

The reconstructed API key is used for the upstream provider call and immediately zeroed. It never appears in any response body, header, or log. The key exists in memory only for the duration of a single HTTP call.

### Anti-enumeration

All authentication failures return an identical `401` response body. An attacker cannot distinguish between "alias does not exist" and "shard mismatch" from the response alone. Unknown endpoints also return `401` (not `404`) to prevent endpoint discovery.

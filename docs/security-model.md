# Security Model

## Architectural Invariants

Worthless enforces three invariants. Any change that violates them will be rejected.

### 1. Gate before reconstruct

The rules engine (spend cap, rate limit) evaluates every request **before** Shard B is decrypted. If a request is denied, the key is never reconstructed. Zero KMS calls, zero key material touched.

### 2. Transparent routing

Setting `BASE_URL` to the proxy address causes API calls from any HTTP client to route through the proxy. The proxy is invisible to provider SDKs - no wrapper libraries, no code changes beyond one environment variable.

### 3. Server-side only reconstruction

The reconstructed key is used for the upstream API call and never appears in any response to the client. Key material is zeroed from memory immediately after the upstream request is dispatched.

## Anti-Enumeration

All authentication failures - missing alias, unknown alias, missing shard, invalid shard, failed HMAC commitment - return an **identical 401 response body**. This prevents attackers from probing which step of authentication failed or enumerating enrolled keys.

## TLS Enforcement

By default, the proxy rejects requests carrying shard headers over non-TLS connections. For local development, set `WORTHLESS_ALLOW_INSECURE=true`. This flag must never be used in production.

## Known Limitations (Python PoC)

### GC non-determinism

Python's garbage collector does not guarantee when memory is freed. Although Worthless explicitly zeros `bytearray` buffers after use (`key_buf[:] = b'\x00' * len(key_buf)`), the GC may retain copies in internal structures. This is an inherent limitation of the Python runtime.

### Immutable string in HTTP headers

The adapter `prepare_request()` method calls `api_key.decode()` to set the `Authorization` or `x-api-key` header. This creates an immutable `str` copy that cannot be zeroed. The `str` lives until garbage collection. This is unavoidable because HTTP client libraries (httpx) require string headers.

### In-process reconstruction

The Python PoC performs key reconstruction in the same process as the proxy. True memory isolation requires separate processes or containers, planned for the Rust hardening phase.

## Threat Model Scope

Worthless protects against:
- API key exfiltration (GitHub leaks, `.env` exposure, client-side JS)
- Runaway spend from compromised or buggy agents
- Unauthorized usage within a spend/rate budget

Worthless does **not** protect against:
- Full machine compromise (attacker has root on the proxy host)
- Upstream provider outages or billing disputes
- Content safety, prompt injection, or model misuse

This is the same trust boundary as a password manager: if the attacker owns the machine, all bets are off.

## Planned Hardening

- **Rust reconstruction service** - deterministic memory control, `mlock`, `zeroize`, distroless container
- **Process isolation** - reconstruction in a separate process with its own memory space
- **mTLS client certificates** - mutual TLS for proxy authentication

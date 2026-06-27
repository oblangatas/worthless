# Contributor Security Rules

Mandatory invariants for all Worthless code. Every commit, every phase, every
review. Referenced from CLAUDE.md. Verified by `/gsd:verify-work`.

For the threat model (what these rules are defending and what attackers are in
scope), see [docs/security.md](docs/security.md).

## Memory Safety

**SR-01: No immutable types for secrets.**
Never store key material, shards, or reconstructed keys in `str`, `bytes`, or any immutable type. Use `bytearray` (Python) or `zeroize`-backed structs (Rust). Immutable objects linger in GC-managed memory and cannot be wiped.

**SR-02: Explicit memory zeroing.**
The instant an upstream HTTP request is dispatched, overwrite the reconstructed key buffer with zeros. Do not defer to garbage collection. Use `buf[:] = bytearray(len(buf))` (Python — matches `_zero_buf` in `crypto/types.py`) or `zeroize` (Rust). Document any GC limitations in [docs/security.md](docs/security.md).

## Gate Ordering

**SR-03: Check before build.**
The rules engine (spend cap, rate limit, model allowlist) MUST evaluate BEFORE XOR reconstruction runs. If the budget is blown, reject immediately (402/429). The key must never be reconstructed for a denied request. Zero KMS calls, zero key material touched.

## Telemetry

**SR-04: Zero telemetry on secrets.**
The reconstructed key, Shard A, Shard B, nonces, and commitments must NEVER be passed to any logging function, error handler, stack trace, or APM tool. Mask all `Authorization` and `x-api-key` headers in outbound request logs. Override `__repr__` on all crypto dataclasses to redact sensitive fields.

**SR-05: Logging denylist enforcement.**
These patterns must never appear in any log, anywhere:
- API key prefixes: `sk-*`, `anthropic-*`, `AIza*`, `xai-*`
- Certificate private keys
- Base64 strings > 32 chars in a security context
- Prompt or response content
- Raw user IP addresses

## Isolation

**SR-06: Sidecar/isolated execution.**
The reconstruction service runs in an isolated process with its own memory space. The main application (proxy, CLI, MCP server) never has access to the reconstruction service's memory or environment variables. In the Python PoC, reconstruction is in-process but architecturally separated — the Rust hardening phase enforces true process isolation (distroless container).

## Shard Separation

**SR-09: Shard-A never at rest in proxy.**
The proxy process must never have filesystem access, environment variable access, or configuration pointing to shard-A material. Shard-A arrives exclusively via the `Authorization: Bearer` header (OpenAI) or `x-api-key` header (Anthropic) per-request. No `WORTHLESS_SHARD_A_DIR`, no disk fallback, no shard-A directory scanning. Enforced by semgrep rule `sr09-no-shard-a-in-proxy`.

**SR-10: No dual-shard co-location.**
No single process may hold (or have access paths to) both shard-A and shard-B for the same key, except transiently during the reconstruct-call-zero sequence within a single request handler. Configuration that grants a process access to both shard storage locations is a security violation regardless of whether the process reads them.

**SR-11: Client-transport-only for shard-A.**
Shard-A lives in the developer's `.env` file. The SDK reads it as the API key and sends it as `Authorization: Bearer <shard-A>` to the proxy. The proxy extracts it from the header. No server-side shard-A storage of any kind — no files, no database columns containing shard-A values, no environment variables.

**SR-12: Format-preserving split.**
`split_key` must produce shard-A in the same prefix, charset, and length as the original API key. The split operates over the key's character alphabet using modular arithmetic (one-time pad over Z/N), not raw byte XOR. Shard-A must be indistinguishable from a real API key to any observer without shard-B.

## Cryptographic Operations

**SR-07: Constant-time comparisons.**
All secret-dependent comparisons (HMAC verification, share validation) must use constant-time functions (`hmac.compare_digest` in Python, `constant_time_eq` in Rust). Never use `==` on digest bytes.

**SR-08: CSPRNG only.**
All random byte generation uses `secrets.token_bytes()` (Python) or `OsRng` (Rust). The `random` module is banned via Ruff TID251 lint rule. No exceptions.

## Traceability

| Rule | Phase enforced | Requirement |
|------|---------------|-------------|
| SR-01 | Phase 1+ | CRYP-03 |
| SR-02 | Phase 1+ | CRYP-03 |
| SR-03 | Phase 3 | CRYP-05 |
| SR-04 | All phases | Logging denylist |
| SR-05 | All phases | Logging denylist |
| SR-06 | Phase 3+ (full in Rust) | Architecture |
| SR-07 | Phase 1+ | CRYP-02 |
| SR-08 | Phase 1+ | CRYP-04 |
| SR-09 | All phases | Architecture — shard separation |
| SR-10 | All phases | Architecture — shard separation |
| SR-11 | All phases | Architecture — client-transport |
| SR-12 | Phase 1+ | CRYP-01 (format-preserving) |

## Platform Notes

**Windows (experimental):** SR-02 (explicit memory zeroing) is best-effort on Windows. Forced process termination via `TerminateProcess` skips atexit handlers and signal handlers, so key material may persist in process memory until the OS reclaims pages. Graceful shutdown via `worthless down` zeroes key material normally. This is acceptable because Worthless protects against key exfiltration from `.env` files and network transit — not against an attacker with local memory access to the running process (who already has full machine access). The Harden milestone will address this with a Rust reconstruction service using `SecureZeroMemory` and named-event graceful shutdown.

# Security Rules

Mandatory constraints for all Worthless code. Every commit, every phase, every review.
Referenced from CLAUDE.md and checked by the security-reviewer gate + automated verifiers.

Each rule below names **what verifies it**. A rule with no automated verifier is a **gap**
(tracked in §Gaps) — it relies on review/tests only, which is weaker and must be hardened.

## Coverage at a glance

| Rule | Requirement (short) | Verifier | Status |
|------|---------------------|----------|--------|
| SR-01 | `bytearray` for secrets, never `bytes`/`str` | pre-commit `SR-01` + Semgrep `sr01-*` + tests | **Enforced** (static) |
| SR-02 | explicit memory zeroing after use | zeroing helpers + unit tests | ⚠️ Test-only — **no static verifier (gap)** |
| SR-03 | gate (rules engine) before reconstruct | architecture import test + gate tests | Strong-by-design; proof partly heuristic |
| SR-04 | no secrets in logs/errors/repr | repr-redaction + sanitized-error tests | Mixed — `--debug` prints full tracebacks by design |
| SR-05 | logging denylist (`sk-*`, keys, prompts, IPs) | Gitleaks + `.gitleaks.toml` denylist | **Enforced** (static); runtime proof weaker |
| SR-06 | reconstruction isolated from proxy/CLI memory | (Rust sidecar) | ⚠️ **Planned — not in Python PoC (gap)** |
| SR-07 | constant-time compare on digests | pre-commit `SR-07` + Semgrep + tests | **Enforced** (static, heuristic) |
| SR-08 | CSPRNG only; `random` banned | Ruff TID251 + Semgrep `sr08-*` + tests | **Enforced** (strong) |
| SR-09 | shard-A never at rest in proxy | Semgrep `sr09-no-shard-a-in-proxy` + import test | **Enforced** (static) |
| SR-10 | no dual-shard co-location in one process | architecture review | ⚠️ **Manual-only (gap)** |
| SR-11 | shard-A client-transport only (header) | adapter/transport tests | Test-covered |
| SR-12 | format-preserving split (shard-A looks real) | splitter property tests | Test-covered |

## Memory Safety

**SR-01: No immutable types for secrets.** Never store key material, shards, or reconstructed keys in `str`, `bytes`, or any immutable type. Use `bytearray` (Python) or `zeroize`-backed structs (Rust). Immutable objects linger in GC-managed memory and cannot be wiped.

**SR-02: Explicit memory zeroing.** The instant an upstream HTTP request is dispatched, overwrite the reconstructed key buffer with zeros (`key_buf[:] = b'\x00' * len(key_buf)` / `zeroize`). Do not defer to GC. Document GC limitations in the security posture notes.

## Gate Ordering

**SR-03: Check before build.** The rules engine (spend cap, rate limit, model allowlist) MUST evaluate BEFORE XOR reconstruction. Denied request → reject immediately (402/429), zero KMS calls, zero key material touched.

## Telemetry

**SR-04: Zero telemetry on secrets.** Reconstructed key, Shard A/B, nonces, commitments must NEVER reach any logging function, error handler, stack trace, or APM tool. Mask `Authorization` / `x-api-key` headers. Redact sensitive fields in `__repr__` on all crypto dataclasses.

**SR-05: Logging denylist.** Never log: API-key prefixes (`sk-*`, `anthropic-*`, `AIza*`, `xai-*`), certificate private keys, base64 > 32 chars in a security context, prompt/response content, raw user IPs.

## Isolation

**SR-06: Sidecar/isolated execution.** The reconstruction service runs in an isolated process; the proxy/CLI/MCP never has access to its memory or env. Python PoC is in-process but architecturally separated; the Rust hardening phase enforces true process isolation (distroless).

## Cryptographic Operations

**SR-07: Constant-time comparisons.** All secret-dependent comparisons (HMAC verify, share validation) use `hmac.compare_digest` / `constant_time_eq`. Never `==` on digest bytes.

**SR-08: CSPRNG only.** All random byte generation uses `secrets.token_bytes()` / `OsRng`. The `random` module is banned via Ruff TID251. No exceptions.

## Shard Separation

**SR-09: Shard-A never at rest in proxy.** The proxy process must never have filesystem, env-var, or config access to shard-A. Shard-A arrives only via `Authorization: Bearer` (OpenAI) / `x-api-key` (Anthropic) per request. No `WORTHLESS_SHARD_A_DIR`, no disk fallback, no shard-A scanning.

**SR-10: No dual-shard co-location.** No single process may hold (or have access paths to) both shard-A and shard-B for the same key, except transiently during the reconstruct-call-zero sequence within one request handler.

**SR-11: Client-transport-only for shard-A.** Shard-A lives in the developer's `.env`, sent as the API key over the header. No server-side shard-A storage of any kind — no files, no DB columns, no env vars.

**SR-12: Format-preserving split.** `split_key` must produce shard-A in the same prefix, charset, and length as the original key (one-time pad over the key's alphabet, not raw byte XOR). Shard-A must be indistinguishable from a real key without shard-B.

## Gaps — SRs without a strong automated verifier

These rely on review/tests only and must be hardened (each → a tracked follow-up):

- **SR-02 (zeroing):** no static check that a key buffer is zeroed on every exit path. *Proposed verifier:* a Semgrep/AST rule requiring a `[:] = ` zeroing before key buffers go out of scope, or a runtime test asserting buffers are zeroed.
- **SR-06 (isolation):** not implemented in the Python PoC (in-process). *Verifier lands with the Rust sidecar.*
- **SR-10 (dual-shard co-location):** manual review only. *Proposed verifier:* an import/config test asserting no module imports both shard-A transport and shard-B storage.
- **SR-04 partial:** `--debug` prints full tracebacks; confirm no secret can ride a debug traceback.

## Traceability

| Rule | Phase | Requirement |
|------|-------|-------------|
| SR-01/02 | Phase 1+ | CRYP-03 |
| SR-03 | Phase 3 | CRYP-05 |
| SR-04/05 | All | Logging denylist |
| SR-06 | Phase 3+ (Rust) | Architecture |
| SR-07 | Phase 1+ | CRYP-02 |
| SR-08 | Phase 1+ | CRYP-04 |
| SR-09/10/11 | All | Architecture — shard separation |
| SR-12 | Phase 1+ | CRYP-01 |

## Platform Notes

**Windows (experimental):** SR-02 is best-effort. Forced termination (`TerminateProcess`) skips cleanup handlers, so key material may persist in process memory until the OS reclaims pages. Graceful shutdown (`worthless down`) zeroes normally. Acceptable because Worthless protects against `.env`/network exfiltration, not against an attacker with local memory access (who already has machine access). The Harden milestone addresses this with a Rust reconstruction service.

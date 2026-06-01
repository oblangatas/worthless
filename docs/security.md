---
title: "Security Model"
description: "Threat model, architectural invariants, known limitations."
---

# Worthless Security

Threat model, architectural invariants, known limitations, and residual risk for
the Python PoC. This file describes what is real today. Roadmap items live in
Linear ([WOR-257](https://linear.app/plumbusai/issue/WOR-257)).

- To report a vulnerability, see [/SECURITY.md](../SECURITY.md).
- Contributor invariants (the SR-\* rules) live in [../CONTRIBUTING-security.md](../CONTRIBUTING-security.md).
- For the install-time supply chain, see [install-security.md](install-security.md).

## TL;DR

Worthless makes stolen API keys worthless to the thief. The real key is split
into two shards on the client using a format-preserving one-time pad. Neither
half reveals anything alone. Every request passes through a rules engine that
enforces spend caps **before** the key reconstructs. Budget blown = key never
forms = request never reaches the provider.

Three architectural invariants protect this claim. All three are CI-tested and
would break the build if violated.

In the blessed Docker deployment, key reconstruction runs in a **separate sidecar
process under its own Unix user** — the proxy process cannot read the Fernet key
or the reconstructed key, even if an attacker gains code execution inside it.
Bare-metal single-process installs do not have this boundary yet; see
[Process isolation](#process-isolation-the-crypto-sidecar-docker). The Python PoC
has known memory-safety limitations — documented below with a concrete Rust
hardening path.

**This is not a compliance certification.** Worthless has not been audited or
certified under SOC 2, FIPS, ISO 27001, or any other framework.

## Trust boundary

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT BOUNDARY                          │
│                                                                 │
│  Developer machine / CI agent                                   │
│                                                                 │
│  ┌──────────┐    api_key    ┌──────────────┐                    │
│  │  .env    │──────────────>│  split_key() │                    │
│  │  file    │               │  (CLI only)  │                    │
│  └──────────┘               └──────┬───────┘                    │
│                                    │                            │
│                          ┌─────────┴─────────┐                  │
│                          │                   │                  │
│                    Shard A (kept)      Shard B + commitment     │
│                    stored locally      + nonce (sent once)      │
│                                              │                  │
├──────────────────────────────────────────────┼──────────────────┤
│                  NETWORK BOUNDARY             │                  │
│                                              │                  │
│  Enrollment: Shard B + commitment + nonce ───┘                  │
│  Request:    Authorization / x-api-key header (Shard A)         │
│                                                                 │
│  *** Full API key NEVER crosses this boundary ***               │
│  *** Reconstructed key NEVER crosses this boundary ***          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     PROXY BOUNDARY                              │
│                                                                 │
│  ┌───────────────┐   deny (402/429)   ┌─────────────────────┐   │
│  │ Rules Engine  │───────────────────>│ Client gets error   │   │
│  │ (spend cap,   │                    │ Key never forms     │   │
│  │  rate limit,  │                    └─────────────────────┘   │
│  │  allowlist)   │                                              │
│  └───────┬───────┘                                              │
│          │ allow                                                │
│          v                                                      │
├─────────────────────────────────────────────────────────────────┤
│               RECONSTRUCTION BOUNDARY                           │
│                                                                 │
│  ┌──────────────────┐  ┌─────────────────┐  ┌───────────────┐   │
│  │ Fernet decrypt   │─>│ reconstruct_key │─>│ secure_key()  │   │
│  │ (Shard B)        │  │ (modular + HMAC)│  │ context mgr   │   │
│  └──────────────────┘  └─────────────────┘  └───────┬───────┘   │
│                                                     │           │
│            ┌────────────────────────────────────────┘           │
│            │  key_buf (bytearray, zeroed on exit)               │
│            v                                                    │
│  ┌─────────────────┐         ┌──────────────────────────────┐   │
│  │ Upstream call   │────────>│ LLM Provider (OpenAI, etc.)  │   │
│  │ (httpx)         │         └──────────────────────────────┘   │
│  └─────────────────┘                                            │
│                                                                 │
│  *** Reconstructed key NEVER returns to proxy layer ***         │
│  *** Reconstructed key NEVER sent in response ***               │
│  *** key_buf zeroed immediately after dispatch ***              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## The three invariants

### Invariant 1 — Client-side splitting

**Claim.** `split_key` runs exclusively on the client. The server never receives
the full API key or Shard A. The server receives only Shard B, commitment, and
nonce at enrollment time.

**Code.** [`src/worthless/crypto/splitter.py`](../src/worthless/crypto/splitter.py)
exposes `split_key`. Server-side directories are determined by _exclusion_ from
a client allowlist (`{"cli", "crypto"}`) — new packages land in the server
bucket by default.

**Tests.** [`tests/test_invariants.py`](../tests/test_invariants.py):

- `TestSplitKeyNeverServerSide::test_ast_no_split_key_import` — AST scan of every server-side file
- `test_grep_no_split_key_string` — catches dynamic imports (`getattr`, `importlib`)
- `test_no_star_import_in_server_modules` — blocks `from worthless.crypto import *`
- `test_server_files_found` / `test_client_dirs_exist` — guards against vacuously-true tests

**Limitations.** Dynamic imports built from concatenated strings
(`getattr(mod, 'split' + '_key')`) are not caught. Test-time enforcement only —
a developer modifying the test suite would be caught in PR review, not by CI.

### Invariant 2 — Gate before reconstruction

**Claim.** The rules engine (spend cap, rate limit, model allowlist) evaluates
every request **before** XOR reconstruction runs. A denied request results in
zero KMS calls, zero Fernet decryption, and zero key material touched.

**Code.** [`src/worthless/proxy/app.py`](../src/worthless/proxy/app.py) —
`rules_engine.evaluate` runs, early-returns a `Response(...)` on denial, and
only then calls `repo.decrypt_shard`. The repository exposes a two-step API:
`fetch_encrypted()` returns an `EncryptedShard` (ciphertext only), then
`decrypt_shard()` converts it to a `StoredShard`.

**Tests.** [`tests/test_security_properties.py::TestGateBeforeDecrypt`](../tests/test_security_properties.py):

- `test_evaluate_precedes_decrypt_in_proxy_handler` — static analysis: evaluate appears before decrypt_shard in the handler source
- `test_fetch_encrypted_returns_encrypted_type` — `EncryptedShard` exposes ciphertext, not plaintext
- `test_fetch_encrypted_source_has_no_decrypt_calls` — AST scan confirms no decrypt method is called
- `test_gate_deny_prevents_decrypt` (Hypothesis-powered) — denial return precedes decrypt call

**Limitations.** In-process — no hardware boundary between gate and
reconstruction. Source ordering is a heuristic: textual position, not control
flow graph.

### Invariant 3 — Server-side containment

**Claim.** The reconstruction service calls the LLM provider directly. The
reconstructed key is contained within a `secure_key` context manager, never
returns to the proxy layer, never transits the network, and is zeroed
immediately after the upstream HTTP call.

**Code.** [`src/worthless/crypto/splitter.py::secure_key`](../src/worthless/crypto/splitter.py)
is a `contextlib.contextmanager` that yields the key `bytearray` and calls
`_zero_buf(key_buf)` in its `finally`. `_zero_buf` overwrites the buffer
in-place (`buf[:] = bytearray(len(buf))`). The proxy's own `finally` block also
zeros shard material.

**Tests.** [`tests/test_invariants.py`](../tests/test_invariants.py):

- `TestInvariant3ServerSideContainment::test_reconstruct_result_flows_through_secure_key`
- `test_key_not_used_outside_secure_key_block` — `as k` alias never referenced after the with-block exits
- `TestKeyBufZeroedAfterDispatch::test_key_buf_zeroed_proxy_style_flow` — runtime: all zeros after exit
- `test_key_buf_zeroed_on_dispatch_failure` — zeroing happens even when upstream raises

See [Known limitations](#known-limitations-python-poc) for what `secure_key`
does NOT cover in the Python PoC.

## Process isolation: the crypto sidecar (Docker)

*Shipped in [WOR-306](https://linear.app/plumbusai/issue/WOR-306). Applies to the
Docker deployment — the blessed topology for v1.1. Bare-metal `pip` installs run
single-process and do not have this boundary yet.*

In the Docker image, the proxy and the crypto code run as **two different Unix
users in the same container**:

| Process                       | User                          | Holds                          |
| ----------------------------- | ----------------------------- | ------------------------------ |
| Proxy (FastAPI, HTTP ingress) | `worthless-proxy` (uid 10001) | nothing secret                 |
| Crypto sidecar                | `worthless-crypto` (uid 10002)| the Fernet key + reconstruction|

The Fernet key file and the reconstruction code live entirely inside the sidecar.
The proxy never holds the Fernet key, never sees Shard B plaintext, and never sees
the reconstructed key. To do a key operation, the proxy sends a request to the
sidecar over a local Unix-domain socket; the sidecar does the crypto.

**What this buys you.** Code execution in the proxy process — the most exposed
component — no longer reaches key material. The attacker lands on the wrong side
of a kernel-enforced user boundary:

```bash
# The proxy user cannot read the key the sidecar owns:
$ docker exec --user worthless-proxy <ctr> cat /secrets/fernet.key
cat: /secrets/fernet.key: Permission denied
```

**How the boundary is enforced.**

- **Peer-uid authentication.** The sidecar reads the connecting process's uid from
  the kernel (`SO_PEERCRED` on Linux, `getpeereid()` on macOS) and rejects any peer
  that is not the authorized proxy uid. The check runs only on `AF_UNIX` sockets — a
  guard rejects every other socket family before the uid check, so a non-Unix socket
  cannot be authorized as root. (macOS is supported for local development; the
  user-isolation guarantee above is delivered by the Docker deployment, which runs on
  Linux — a macOS bare-metal install is single-process and does not have this boundary.)
- **Filesystem permissions.** Access is gated by owner, group, and mode — not by
  trusting the proxy. The Fernet key file is owned by the crypto user, mode `0400`, so
  the proxy user cannot read it. The socket is created and owned by the crypto user; the
  proxy connects only through the shared `worthless` group and the socket's mode, and
  never owns key material.
- **Fail closed, never fall back.** If the sidecar is unreachable, the request
  returns `503` (`WRTLS-114 SIDECAR_NOT_READY`). The proxy never falls back to
  in-process reconstruction — no code path allows it.

**What this does NOT defend against.** Root (or a container escape) inside the
container can still read both users' memory and files — a compromised _host_ is an
explicit non-goal (see [non-goals](#threat-model-non-goals)). The boundary protects
against a compromised proxy _process_, not a compromised host. The crypto user is a
software boundary, not a hardware enclave; v2.0's Rust/MPC sidecar is the hardening
path.

## Atomic `.env` rewrite (WOR-276 v2)

`worthless lock KEY1 KEY2 ...` must leave the user's `.env` either
fully locked or entirely untouched. Any state in between — half-locked
`.env`, orphan tmp file, stale backup, corrupted shard — is a failure.

The transactional model has no persistent rollback state: there is no
`.bak` file, no RECOVERY.md, no cleartext backup bucket. Recovery
works because the commit point is a single `rename(2)` call that is
either entirely successful or has no effect.

### T-9: In-flight transaction rollback

An attacker or a crash may interrupt `worthless lock` after shard-B
has been persisted to the server but before the `.env` has been
atomically rewritten. The threat is that the user loses access to
their own key: shard-B exists on the server, but shard-A was never
written to `.env`.

**Mitigation.** The `.env` rewrite pipeline is:

1. Open target + grab exclusive `flock`.
2. Build the fully-rewritten `.env` content in memory (all N keys at
   once — no partial-batch state).
3. Write to `.env.tmp-XXXX`, `fsync` the tmp file.
4. **Verify** the reconstructed key (shard-A ⊕ shard-B) in memory
   (see [T-10](#t-10-reconstruction-verify) below) against an
   enrollment-time HMAC. Refuse with `UnsafeReason.VERIFY_FAILED`
   on mismatch.
5. `rename(2)` tmp → final (atomic on POSIX filesystems that
   `fs_check` has admitted — see [`UnsafeReason.FILESYSTEM`](https://github.com/plumbusai/worthless/blob/main/src/worthless/cli/fs_check.py)).
6. `fsync` parent directory.

If the process is killed between steps 1 and 5, the `.env` is
byte-identical to the pre-call state. If killed between 5 and 6, the
rename is durable on any modern journaled filesystem; the parent-dir
`fsync` only flushes the metadata journal entry.

Non-atomic filesystems (CIFS/SMB, NFSv3/v4, FAT, 9P, WSL `/mnt/c`
fuse.drvfs bridge) are refused before the pipeline starts. Users on
those filesystems are told to move their project to a journaled
Linux filesystem (on WSL, `/home` — the Microsoft/VSCode-recommended
path). Ephemeral-backup support for those filesystems is tracked in
[WOR-325](https://linear.app/plumbusai/issue/WOR-325). Set
`WORTHLESS_FORCE_FS=1` to bypass for CI on exotic filesystems.

### T-10: Reconstruction-verify

An attacker who can tamper with the derived shard-A between
derivation and the rewrite (e.g. by swapping the shard-B database
row mid-call, or via a fault-injection attack on the XOR loop) could
cause `worthless lock` to write a corrupted shard-A to `.env` — the
user would then be unable to reconstruct the original key on every
subsequent API call.

**Mitigation.** Before the atomic rename, the CLI reconstructs
`shard_a ⊕ shard_b` in memory and compares an HMAC of the result
against an enrollment-time HMAC stored alongside shard-B. The HMAC
input is length-prefixed and key-bound (see commit 10), so swapping
shard-B for a different key will not produce a matching HMAC.

Memory hygiene: all intermediate secrets (shard-A copy,
reconstructed bytes, HMAC) are held in `bytearray` buffers, `mlock`ed,
zeroed via `ctypes.memset` on function exit, and the process sets
`RLIMIT_CORE=0` + Linux `PR_SET_DUMPABLE=0` so a crash cannot
materialize them in a coredump. The comparison uses
`hmac.compare_digest`.

## Threat model: non-goals

Worthless does **not** protect against:

1. **Compromised client machine.** An attacker with full access to the CLI process can intercept the API key before `split_key` runs. Worthless protects keys _after_ splitting.
2. **Malicious LLM provider.** The provider receives the full API key (that's the point — the request must work).
3. **Side-channel timing attacks on the Python PoC.** HMAC verification uses `hmac.compare_digest` (SR-07), but other operations (XOR loop, allocation) are not constant-time.
4. **Memory forensics on the proxy host.** CPython's GC may retain intermediate copies. See [Known limitations](#known-limitations-python-poc).
5. **Supply chain attacks on Python dependencies.** `pip-audit` runs in CI; no full SBOM or reproducible builds yet.
6. **Compromised proxy _host_.** An attacker with a root shell (or a container escape) on the proxy host can read process memory, attach a debugger, or modify the app. The host is trusted infrastructure. The non-goal is host/root compromise.
7. **Compromised proxy _process_** (application-uid RCE on `worthless-proxy`). The [crypto sidecar](#process-isolation-the-crypto-sidecar-docker) boundary protects a specific scope, not a general one.

   The wall **does** protect:
   - Fernet key shares (`share_a.bin`, `share_b.bin`) from disk exfiltration — the share files are owned by `worthless-crypto`, mode `0400`, on a `0700` directory.
   - Fernet key bytes from in-memory exfiltration via the proxy uid — the key is reconstructed only inside the sidecar's address space.
   - Decrypted shard-B plaintext from persisting in the proxy uid — it transits the proxy in-flight and is zeroed in a `finally` block on every code path.

   The wall **does not** protect:
   - Live in-flight `Authorization: Bearer <shard-A>` headers from a compromised proxy uid that reads requests as they arrive.
   - Key reconstruction itself — a compromised proxy can call the sidecar's IPC `open()` verb at the documented contract, which the sidecar authenticates by uid match. The sidecar does not rate-limit, scope, or per-call audit-alert; legitimate and compromised `open()` calls are indistinguishable at the IPC layer.
   - After-the-fact detection that any specific request reconstructed a key under attacker control. Reconstruction by a compromised proxy looks identical to legitimate traffic in the audit log.

   The rules engine (spend caps, rate limits, token budgets) is in the same blast radius — it runs in the proxy process, on the compromised uid. An attacker who patches it has no further software defense. The architectural hardening path is sidecar-side enforcement on the `open()` verb (per-alias rate limits, alerting on velocity anomalies, audit-log signing) — tracked in [WOR-619](https://linear.app/plumbusai/issue/WOR-619); not currently scheduled for V1.

   The non-goal is proxy-process RCE. The wall's coverage is Fernet-key isolation, not key-reconstruction prevention.
8. **Nation-state adversaries with physical access.** Hardware, cold-boot, and electromagnetic side channels are out of scope.

## Known limitations (Python PoC)

The primary `bytearray` is zeroed after dispatch. The items below all describe
what happens to **intermediate** or **derived** copies the language runtime
creates and that we cannot reach from Python. Each has a `zeroize`-backed Rust
resolution path.

### GC non-determinism

CPython uses refcounting plus a cycle-detecting GC. `_zero_buf` clears the
primary buffer, but intermediate `bytes` from `hmac.new(...).digest()` or XOR
steps linger in the managed heap until GC collects them.

- **Exploit shape.** Code execution in the FastAPI process scanning heap for `sk-*`, `anthropic-*`. Window: milliseconds under normal load; unbounded in theory.
- **Prerequisite.** Code execution in the FastAPI process.
- **Risk.** Medium — requires process-level access; primary buffer IS zeroed.
- **Rust path.** `zeroize` crate: `Zeroize` trait, compiler barrier (`core::ptr::write_volatile`), stack-allocated buffers with deterministic lifetimes.

### No mlock

The OS may swap the key page to disk.

- **Prerequisite.** Physical access or access to the swap partition.
- **Risk.** Low — most cloud VMs use encrypted swap or no swap.
- **Rust path.** `mlock(2)` pins the page; `madvise(MADV_DONTDUMP)` excludes from core dumps.

### No compiler barrier

Optimizers can elide dead stores. CPython's bytecode interpreter doesn't do
this for `bytearray` slice assignment in practice, but there's no formal
guarantee.

- **Risk.** Low — additive to GC non-determinism, not independent.
- **Rust path.** `core::ptr::write_volatile` is guaranteed not to be elided.

### In-process reconstruction (bare-metal only)

**Resolved in Docker** by the crypto sidecar (see
[Process isolation](#process-isolation-the-crypto-sidecar-docker)). This
limitation now applies only to bare-metal single-process installs (`pip install`
without the sidecar), where reconstruction still runs in the FastAPI process with
no OS-level isolation between gate and reconstruction.

- **Exploit shape.** On bare-metal, a vulnerability in any FastAPI dependency could access the reconstruction function or read its memory, bypassing the gate. In Docker, the proxy process runs as a different uid and cannot reach the key.
- **Prerequisite.** Code execution in the FastAPI process (bare-metal); code execution _plus_ root or container-escape (Docker).
- **Risk.** Low in Docker (process-isolated); Medium on bare-metal.
- **Path.** Docker: shipped (two-uid sidecar, WOR-306). v2.0: Rust distroless sidecar with `seccomp` syscall restriction for both topologies.

### `api_key.decode()` creates an immutable `str` copy

In `src/worthless/proxy/app.py`, the reconstructed `bytearray` is decoded to
`str` before being handed to httpx as an Authorization header. Python `str`
objects are immutable and cannot be zeroed — the copy persists until GC.

- **Exploit shape.** Same as GC non-determinism, but with unbounded lifetime in the managed heap.
- **Prerequisite.** Code execution in the FastAPI process.
- **Risk.** Medium — noted in code comments but has no programmatic mitigation in the Python PoC.
- **Rust path.** Rust reconstruction uses stack-allocated byte buffers; the HTTP client accepts byte slices directly — no string conversion.

### Shard B data-at-rest (Fernet)

Shard B is Fernet-encrypted at rest. The Fernet key resides on the proxy
host's filesystem or environment.

- **Prerequisite.** Full shell/root access to the proxy host.
- **Risk.** Low — compromise of the proxy host is an explicit non-goal. Shard B alone cannot reconstruct any key.

### Per-key revocation only

`worthless revoke --alias <alias>` deletes a single key's shards. No bulk
rotation in V1 — a large breach requires manual re-enrollment of each key.

- **Risk.** Medium (operational).
- **Path.** Bulk rotation CLI + API planned for V2.

### No protocol versioning on the shards table

The `shards` table has no `protocol_version` column. The XOR + HMAC-SHA256
scheme is the only supported protocol. Swapping schemes requires a migration
touching every row.

- **Risk.** Low (operational). Rolling upgrades are impossible without a version column.
- **Tracked.** [WOR-257](https://linear.app/plumbusai/issue/WOR-257) epic child.

### Legacy `shard_a_enc` column

The `shards` table includes a column `shard_a_enc` that is `NULL` on every
modern enrollment. It exists for backwards compatibility with the pre-Bearer-auth
era (PR #198, internally codenamed "worthless-16x2"), where both shards were
Fernet-encrypted at rest. The current design places shard-A in the request's
`Authorization: Bearer` header; the proxy's auth code path does not fall back to
`shard_a_enc` even when present.

- **Risk.** Medium until [WOR-615](https://linear.app/plumbusai/issue/WOR-615)
  lands. The invariant ("Bearer is the only auth path") is enforced
  structurally in the proxy code at `src/worthless/proxy/app.py` —
  no fallback branch consumes `stored.shard_a` for authentication. `worthless
  relock` sets the column to `NULL` on every re-lock. **However**, the
  invariant currently relies on code review, not on a CI test. A future
  refactor reintroducing a stored-shard-A fallback would not be caught.
- **Tracked.** [WOR-615](https://linear.app/plumbusai/issue/WOR-615) — adds the
  adversarial regression test, plus a proposed startup assertion that refuses
  to boot the proxy if any row has `shard_a_enc IS NOT NULL`, making the
  precondition machine-checkable. Once WOR-615 lands, this row downgrades to
  Low.

### Windows (experimental)

Forced process termination via `TerminateProcess` skips atexit and signal
handlers, so key material may persist in process memory until the OS reclaims
pages. Graceful shutdown via `worthless down` zeroes normally. Accepted —
Worthless protects against `.env`-exfiltration and network transit, not against
a local attacker who already has the machine.

## Breach scenario: Shard B database compromise

Attacker gains read access to the SQLite database containing encrypted Shard B
values.

- **Immediate impact.** Shard B is Fernet-encrypted. Without the Fernet key, the ciphertext is useless. Commitments and nonces are HMAC parameters, not key material.
- **If the Fernet key is also compromised.** Attacker decrypts all Shard B values. Shard B alone is still useless — Shard A is held on the client and never stored server-side.
- **If both Shard A and Shard B are compromised.** Attacker reconstructs the original API key. This requires compromising both the client (Shard A) and the server (Shard B + Fernet key).

**Response.**

1. Rotate the Fernet key (invalidates all encrypted Shard B values).
2. Re-enroll all affected keys via the CLI (generates new shards).
3. Revoke the compromised API keys at the provider dashboard.
4. No bulk rotation in V1 — re-enroll individually.

## Forensic logging

What is currently logged (from `src/worthless/proxy/app.py`):

| Event                     | Logged?                         | Content                      |
| ------------------------- | ------------------------------- | ---------------------------- |
| Ambiguous alias inference | Yes (`logger.warning`)          | Match count, provider name   |
| Spend recording failure   | Yes (`logger.warning`)          | Alias name only              |
| Gate denials (402/429)    | **No**                          | Returned directly, not logged |
| Enrollment events         | **No**                          | CLI-side only                |
| Upstream success/failure  | **No**                          | —                            |
| Request metadata          | Partial — `spend_log` table only | Alias, tokens, model, provider, timestamp |

**Denylist compliance (SR-05).** Logs contain only alias and provider names —
no keys, shard bytes, commitments, nonces, request/response bodies, or IP
addresses. Upstream error messages are sanitized via `_sanitize_upstream_error`
(OWASP A09:2021).

**Gaps tracked in [WOR-257](https://linear.app/plumbusai/issue/WOR-257).**

- Gate denials are not emitted to the application logger.
- No server-side enrollment audit trail.
- No upstream-call outcome log (even status-code only).
- No CI test that captures logger output and scans it against the denylist — current SR-05 evidence only exercises `_sanitize_upstream_error`.

## Supply chain

- `pip-audit` runs in CI.
- No SBOM, no reproducible builds, no second-reviewer gate on releases.
- Install-time trust roots live in [install-security.md](install-security.md).

## Residual risk summary

| Risk                                           | Severity | Mitigation status                        |
| ---------------------------------------------- | -------- | ---------------------------------------- |
| GC retains intermediate key copies             | Medium   | Primary buffer zeroed; intermediates at GC mercy |
| `api_key.decode()` creates immutable str copy  | Medium   | Gap — `str` cannot be zeroed in Python   |
| Key pages swappable to disk                    | Low      | Planned (Rust `mlock`)                   |
| In-process reconstruction shares memory        | Low (Docker) / Med (bare-metal) | **Shipped** for Docker (two-uid sidecar, WOR-306); bare-metal pending v2.0 Rust sidecar |
| No bulk key rotation                           | Medium   | Planned (V2)                             |
| No protocol versioning for shard schema        | Low      | Gap — [WOR-257](https://linear.app/plumbusai/issue/WOR-257) |
| Fernet key on proxy host                       | Medium   | Accepted (non-goal: compromised proxy)   |
| No gate-denial audit log                       | Medium   | Gap — [WOR-257](https://linear.app/plumbusai/issue/WOR-257) |
| Zeroing may be elided (theoretical)            | Low      | Best-effort (CPython doesn't elide in practice) |

## License

AGPL-3.0. Running an unmodified Worthless proxy internally has no obligation
beyond the standard AGPL terms. Modified versions offered as a network service
must make source available.

## Changelog

| Date       | Change                                                                 |
| ---------- | ---------------------------------------------------------------------- |
| 2026-05-26 | Documented the crypto sidecar (WOR-306): in Docker, key reconstruction runs in a separate Unix user (`worthless-crypto`) the proxy process cannot read. Updated the in-process-reconstruction limitation, non-goal #6, and the residual-risk table to reflect the shipped boundary. |
| 2026-04-24 | Added T-9 (in-flight transaction rollback) + T-10 (reconstruction-verify) for WOR-276 v2. Transactional `.env` rewrite replaces persistent cleartext backups. |
| 2026-04-21 | Consolidated from SECURITY_POSTURE.md, docs/security-model.md, docs/risk-key-material-in-python-memory.md. Stripped confidence-tier prose, hard-cap rule, update-cadence, enterprise-tier marketing, mTLS orphan claim. Refs WOR-235, WOR-257, WOR-262. |
| 2026-04-03 | Initial security posture document (SECURITY_POSTURE.md). Commit `4f79fe6`. |

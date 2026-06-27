# Sidecar Topology: What the Prototype Proves, What v2.0 Inherits

*Internal architecture doc. Audience: sidecar implementers, container/systemd packagers,
v2.0 Rust/MPC reimplementers, security auditors.  Originally landed via WOR-307.
Lives in `engineering/`, not `docs/`, because end users install Worthless via
`curl | sh` / Docker — they never need to know the sidecar exists.*

**Status:** Gate-closing handoff for the Fernet sidecar epic (WOR-306).
**Audience:** sidecar implementers, proxy IPC client authors, container/systemd packagers, and the v2.0 Rust/MPC rewrite.
**Companion:** [`engineering/ipc-contract.md`](ipc-contract.md) (wire format, **frozen for v1.1**).

This document describes what the 3-day prototype built, which invariants are load-bearing, and what a v2.0 Rust/MPC implementation must preserve vs. may freely change.

## 1. What shipped in the prototype

| Layer | File | Verb |
|---|---|---|
| Wire codec | `src/worthless/ipc/framing.py` | `encode_frame` / `read_frame`, 1 MiB cap, `FrameError` hierarchy |
| Peer auth | `src/worthless/ipc/peercred.py` | `get_peer_credentials`, `require_peer_uid`, AF_UNIX guard |
| Envelope | inline in `src/worthless/ipc/client.py` + `src/worthless/sidecar/server.py` | `{v, id, kind, op, deadline_ms, body}` + error codes (no separate `protocol.py` module in v1.1) |
| Async client | `src/worthless/ipc/client.py` | `IPCClient.seal / open / attest`, 2 s default timeout, lock-serialized |
| Async server | `src/worthless/sidecar/server.py` | `start_sidecar(...)`, 0660 socket, peer-uid gate |
| Backend ABC | `src/worthless/sidecar/backends/base.py` | `Backend.seal / open / attest`, `BackendError` |
| Fernet backend | `src/worthless/sidecar/backends/fernet.py` | XOR-share reconstruction, HKDF-bound attest HMAC |
| Entry point | `src/worthless/sidecar/__main__.py` | env-configured bind, SIGTERM handler |
| Container | `docker/sidecar/Dockerfile` | tini PID 1, two uids, socket volume |
| Supervisor | `docker/sidecar/supervise.sh` | starts sidecar as `worthless-crypto`, client as `worthless-proxy` |

Smoke-tested by `tests/docker/test_container_smoke.py` (builds image, runs container, asserts full roundtrip across the uid boundary).

## 2. Platform matrix

The IPC contract deliberately hides these differences behind `framing` + `peercred`. Any platform that provides (a) AF_UNIX stream sockets and (b) a way to read peer uid on an accepted connection is supported.

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Peer uid syscall | `SO_PEERCRED` (`getsockopt`) → `struct ucred{pid,uid,gid}` | `getpeereid()` via libc ctypes → `uid_t, gid_t` (no pid) | **WSL only** in v1.1; native Named Pipes deferred to v2.0+ |
| `sun_path` limit | 108 chars | **104 chars** (governs everything) | N/A |
| Abstract namespace (`\0name`) | Exists but **FORBIDDEN** (bypasses FS ACLs) | N/A | N/A |
| Socket default path | `/var/run/worthless/sidecar.sock` | same | N/A |
| Test socket path | `tempfile.mkdtemp()` + `/s.sock` (always ≤104) | same | N/A |
| Non-AF_UNIX fallback | **Refused** — `require_peer_uid` raises | **Refused** — same guard closes a Darwin auth-bypass | N/A |

The AF_UNIX guard in `peercred.require_peer_uid` rejects any socket whose `family != AF_UNIX` **before** the uid check. On Darwin, `getpeereid()` returns `0` for non-AF_UNIX sockets (TCP, AF_INET6, socketpair(AF_UNIX, SOCK_SEQPACKET)), which would silently authorize any peer as root. Do not remove this guard in v2.0.

## 3. Deployment topologies

All three share the **same IPC contract**. Choice is operational, not protocol.

### 3.1 Single-container (demonstrated, blessed for v1.1)

```text
┌────────── container ─────────────────────────────────┐
│  tini (PID 1)                                        │
│   └─ deploy/start.py (root, briefly — privilege drop)│
│        ├─ worthless-proxy   (uid 10001, gid 10001)   │  ← HTTP in
│        └─ worthless-crypto  (uid 10002, gid 10001)   │  ← binds socket
│                                                      │
│  /run/worthless                       (root:worthless 0770)  │
│  /run/worthless/<pid>/sidecar.sock    (crypto:worthless ~0600/0660) │
└──────────────────────────────────────────────────────┘
```

- WOR-310 contract: `worthless-proxy=10001`, `worthless-crypto=10002`, shared `worthless` group `gid=10001`. `/run/worthless` is `root:worthless` mode `0770`; per-PID dirs and the socket inside are `crypto:worthless`.
- Socket file mode is set by `start_sidecar()` (`0660` so the proxy can connect via shared group); the directory perms (`/run/worthless` 0770, `/run/worthless/<pid>/` 0710 with crypto:worthless) gate which uid can even traverse to the socket inode.
- tini handles PID-1 duties (zombie reaping, SIGTERM forwarding). `deploy/start.py` runs the priv-drop dance + spawns the sidecar before exec'ing uvicorn — no `supervise.sh`. v2.0 may swap in s6-overlay without contract changes.
- Built and exercised by `tests/test_docker_e2e.py` on every `-m docker` run; the two-uid invariant is asserted by `test_runs_as_non_root` (proves `{10001, 10002} ⊆ uids_seen`).

### 3.2 Sidecar-container (documented, optional)

Two containers share `/run/worthless` as a volume. Peer-uid auth still works across the volume — the uid must be allocated consistently (e.g. both images derive from the same base, or both declare `user: 10001` / `user: 10002` in compose). Exposes no extra surface beyond single-container.

### 3.3 systemd-managed (documented, optional)

```text
systemd socket unit          binds /run/worthless/sidecar.sock
      │
      ├─ worthless-sidecar.service  User=worthless-crypto, Group=worthless, socket-activated
      └─ worthless-proxy.service    User=worthless-proxy,  Group=worthless
```

Socket activation + `User=`/`Group=` directives give the same two-uid shape (proxy 10001 + crypto 10002 in shared group `worthless`) without a container runtime. Useful for host installs. The sidecar accepts an already-bound fd via `LISTEN_FDS=1` **in v1.2** — prototype does not implement this yet; v2.0 Rust rewrite should.

## 4. WOR-306 9-row red-team table → test mapping

| # | Attack | Control | Executable evidence |
|---|---|---|---|
| 1 | Proxy RCE reads Fernet key | Key never leaves crypto uid process | `tests/ipc/test_failure_matrix.py::test_bound_socket_is_mode_0660_not_world_accessible` + container two-uid topology in `tests/docker/test_container_smoke.py` |
| 2 | Malicious Python dep in proxy | Only path out is IPC verbs | `tests/ipc/test_failure_matrix.py::test_client_module_has_no_crypto_fallback_path` |
| 3 | `/proc/<proxy-pid>/mem` dump | Key is in crypto process, not proxy | Two-uid container asserts process split; no crypto symbol imported in proxy client (`tests/ipc/test_failure_matrix.py::test_client_module_has_no_crypto_fallback_path`) |
| 4 | Read shared volume | Socket is rendezvous only | Dockerfile `chmod 0770 /run/worthless`, 0660 socket (see row 6) |
| 5 | Cold-boot memory dump (host) | **Out of scope — documented limit** | `engineering/ipc-contract.md` + §7 below |
| 6 | Connect from random uid | `require_peer_uid` | `tests/ipc/test_peercred.py::TestRequirePeerUid::test_disallowed_uid_raises`, `::test_empty_allowlist_always_rejects`, `::test_multi_uid_allowlist`; AF_UNIX bypass closed in `TestGetPeerCredentials::test_raises_on_non_unix_socket` |
| 7 | Malformed IPC payload | `FrameError` + envelope validation | `tests/ipc/test_framing.py` (oversized, truncated, non-map body, missing fields) + `tests/ipc/test_failure_matrix.py::test_connect_to_stale_socket_file_raises_protocol_error` |
| 8 | Sidecar dies mid-request | `IPCProtocolError`, **no fallback** | `tests/ipc/test_failure_matrix.py::test_op_after_transport_closed_raises_protocol_error`, `::test_reconnect_after_server_killed_raises_protocol_error`, `::test_client_module_has_no_crypto_fallback_path` |
| 9 | Container escape | **Out of scope — documented limit** | See §7 |

Additional contract guards not tied to a red-team row: `test_backend_error_message_is_scrubbed_on_wire` (no plaintext/key/share bytes in error strings), `test_client_timeout_raises_ipc_timeout_error_fast` (2 s deadline, §ipc-contract `deadline_ms`).

**Shard-A Bearer + commitment verify via sidecar IPC (WOR-549, PR #250)** — the proxy delivers `Authorization: Bearer <shard-A>` from the agent through to upstream by: (1) extracting shard-A from the header, (2) calling `await ipc.open(shard_b_enc, key_id=alias)` to decrypt shard-B inside the sidecar, (3) XOR'ing the two halves in-process, and (4) verifying commitment via HMAC-SHA256 keyed by the per-row nonce (public, in DB — **not the Fernet key**). The proxy uid never holds Fernet key bytes during any of this. Executable evidence: `tests/test_proxy_auth_16x2.py` (20 tests — token survival, restart, re-lock atomicity), `tests/test_relock_adversarial.py` (6 tests — uniform 401 body across all failure paths, commitment-mismatch never reaches upstream, concurrent re-lock atomicity), `tests/test_relock_attacks.py` (8 tests — bit-flip, truncation, cross-alias, replay, empty/null bytes, corrupt shard-B, anti-enumeration). WOR-465 invariant test `tests/test_proxy_no_fernet_key_read.py` stays green alongside (20/20). Wire-level IPC (framing, peercred, request-id correlation) covered separately by `tests/ipc/*` per rows 6, 7, 8.

## 5. Backend ABC stability contract (for v2.0 Rust/MPC)

The `Backend` ABC in `src/worthless/sidecar/backends/base.py` is the boundary v2.0 reimplements against. The **three verbs and their shapes are frozen**:

```python
class Backend(ABC):
    @abstractmethod
    async def seal(self, plaintext: bytes, context: bytes | None = None) -> bytes: ...
    @abstractmethod
    async def open(self, ciphertext: bytes, context: bytes | None = None, key_id: bytes | None = None) -> bytes: ...
    @abstractmethod
    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes: ...
```

**Locked (breaking to change):**
- Verb names, argument names, argument order.
- Return types (always `bytes`).
- `BackendError` is the only exception a backend may raise across the IPC boundary.
- Backend errors carry a **fixed, information-free message** — no plaintext, key material, share bytes, or wrapped exception text.

**Additive-only (safe to extend without bumping `envelope.v`):**
- New ops may be added; advertise via `backend_caps` in handshake.
- New optional fields in request/response bodies (msgpack skips unknown fields).
- `key_id` semantics opaque — Fernet ignores, KMS/MPC may require.

**Backend-internal (swap freely):**
- Key material shape (XOR shares vs. MPC shares vs. KMS handle).
- `attest` implementation (HKDF-HMAC today; signed blob or MPC commitment later). Proxy verifies via backend-specific verifier, so the evidence format is an implementation detail.
- Session/state management.

**v2.0 Rust rewrite path:** implement the Rust sidecar binding the same `/var/run/worthless/sidecar.sock`, answering the same envelope shape, advertising the same `backend_caps`. The Python proxy IPC client (`worthless.ipc.client.IPCClient`) MUST work against it unchanged — this is the load-bearing property WOR-307 protects.

## 6. Operational invariants the prototype pins

The following are **deliberate** choices; flipping any of them breaks the security claim or the v2.0 path:

1. **Pathname sockets only.** Abstract-namespace (`\0name`) sockets bypass filesystem ACLs and the install-time permission model. Rejected in the framing contract; enforce in any future listener.
2. **0660 socket mode, group-shared.** Enables two-uid single-container. 0600 breaks it. 0666 exposes the socket to world. Enforced in `start_sidecar` + regression-tested.
3. **AF_UNIX guard before uid check.** Closes Darwin `getpeereid` bypass for non-AF_UNIX sockets. `require_peer_uid` raises before authorizing.
4. **No in-process crypto fallback in the proxy client.** Sidecar unreachable → `IPCProtocolError` → caller returns HTTP 503. `test_client_module_has_no_crypto_fallback_path` inspects the client module source to enforce this (no `cryptography` / `fernet` / `hazmat` imports). Do not lazy-import them either.
5. **Crypto-primitive-agnostic verbs.** The IPC client exports `seal` / `open` / `attest`, never `fernet_encrypt` / `fernet_decrypt`. The proxy MUST NOT grow backend-specific IPC methods — if it needs a new verb, add it to the contract and advertise via `backend_caps`.
6. **Wire errors are safe strings.** No peer uid/pid, no key or share bytes, no plaintext/ciphertext, no wrapped exception text. Rich diagnostics go to the sidecar log only.
7. **`envelope.v = 1` is frozen for v1.1.** Bump only for breaking wire changes. New ops are additive (capability negotiation via `backend_caps`).

## 7. Documented limits (explicitly out of scope)

| Limit | Why accepted for v1.1 | Future |
|---|---|---|
| Cold-boot host memory dump reads the key (row 5) | Host compromise = game over; defending against it needs OS-level memory isolation (mlock, SGX, secure enclave) | v1.2 memory hardening (mlock + zero-on-free); v2.0 MPC makes the key never exist in one place |
| Container escape reads crypto memory (row 9) | Single-container topology shares kernel with proxy uid | v1.2 sidecar-container topology blessed; v2.0 separate VM / enclave |
| Native Windows Named Pipes | One platform-specific code path per release cap | v2.0+ |
| Multiple concurrent Fernet keys | Single-key per sidecar keeps the prototype focused | v2.0 via `key_id` (already in wire contract) |
| Socket activation via systemd `LISTEN_FDS` | Prototype binds its own socket | v1.2 or v2.0 Rust rewrite |

## 8. Metrics against the WOR-307 gate

| Gate criterion | Status |
|---|---|
| Clean 3-day build | ✅ (Day 1 framing+peercred; Day 2 server+client+backend; Day 3 container+failure matrix+handoff) |
| `install.sh` under ~300 lines | ⚠️ (336 lines — 12% over the soft cap; no sidecar-driven growth. Delta is from unrelated lock/recovery work in WOR-252.) |
| IPC contract ≤2 revisions | ✅ (1 revision after Day 1.5 expert review: added `deadline_ms`, error-message hygiene clause, `key_id` shape) |
| SO_PEERCRED works on Linux and macOS | ✅ (`tests/ipc/test_peercred.py` green on both) |
| Supervision reliable (no races/zombies) | ✅ (tini reaps; `supervise.sh` cleanup trap; container smoke test green) |
| Failure matrix: sidecar dies → no fallback | ✅ (`test_client_module_has_no_crypto_fallback_path` + transport-closed/reconnect tests) |
| Handoff doc for v2.0 reuse | ✅ (this document) |

## 9. What the claim honestly is — and isn't

An external red-team pass on the product claim (brutus gate, WOR-307 validation round) flagged that the narrow engineering win is easy to over-sell. Canonical phrasing for launch comms + threat model page:

**Safe to claim:**
- *"The Fernet key is not in proxy memory. Offline decryption of at-rest ciphertext requires compromising a second process (different uid, different PID, different address space)."*
- *"A proxy RCE cannot exfiltrate the Fernet key for offline bulk decryption."*
- *"The sidecar IPC contract is designed to survive the v2.0 Rust/MPC rewrite without proxy-side code changes."*

**Must NOT claim (would be materially misleading):**
- ❌ "Your keys are safe even if the proxy is compromised." A proxy with RCE can still call `open` over IPC on every active key for the duration of the compromise window.
- ❌ "Isolated key material." Single-container topology shares a kernel, namespace, and host filesystem volume with the proxy uid.
- ❌ Any comparison to HSM / secure enclave / MPC — not earned until v2.0.
- ❌ "Proxy RCE can't steal keys." It can — one `open` call at a time — just not in bulk and not offline.

**Honest positioning:** this raises the cost of offline decryption of *cold* (at-rest, not currently flowing through the proxy) ciphertext. It does not turn a live-proxy compromise into a non-event. For the full security story users want, v2.0 MPC is load-bearing — v1.1 sidecar is a down-payment, not a finished product.

## 10. Architectural debts the contract freeze bakes in

A round-2 architect-reviewer pass flagged four debts that freezing the v1.1 contract as-is carries into v2.0. Freezing is still the right call (unfreezing would delay the epic for a request/response crypto KMS that doesn't need these features), but the debts should be visible up-front so v2.0 doesn't claim forward-compat it doesn't have.

1. **No `session_id` distinct from `id`.** `id` is per-request correlation. Multi-round MPC protocols need a session token that survives across requests. Today: stuff `session_id` inside `body`. Expected v:2 bump trigger if MPC needs first-class session semantics.
2. **No `stream` / `cancel` kinds.** Only `req` / `resp` / `err`. Long-running MPC rounds with server-driven progress or client-side deadline cancellation can't express either cleanly — proxy's only recourse is TCP close. Expected v:2 bump trigger and the most likely one.
3. **Backend-specific `attest` verifier lives proxy-side.** The wire stays opaque (per §5), but whoever verifies an MPC `attest` bundle needs MPC-aware code in the proxy. The contract is wire-agnostic; the verifier split is not. Plan the proxy-side verifier abstraction before v2.0 lands so this coupling doesn't compound.
4. **Handshake downgrade path unwritten.** `_PROTOCOL_VERSION` is exact-match (server rejects if `1 ∉ client_versions`). A v:2 server accepting v:1 clients is a policy choice, not a spec. Add a "downgrade-on-handshake" clause to the §Versioning section of `engineering/ipc-contract.md` *before* we ever ship v:2.

None of these break v1.1 for its stated workload (Fernet request/response). All four are expected to surface when v2.0 work starts; treat them as known-debt, not discovered-debt.

## §11 — Why the sidecar does not use the OS keyring

The sidecar reads its two Fernet shares from `0600` files at `WORTHLESS_SIDECAR_SHARE_A` and `WORTHLESS_SIDECAR_SHARE_B`. It does not call `keyring`.

Why:

- Headless runtimes (Docker, systemd, launchd; WSL without a D-Bus session counts) return `keyring.backends.fail.Keyring`. The CLI already filters this case via `cli/keystore.py::keyring_available` — applying the same predicate inside the sidecar would always return false.
- Shares are provisioned to disk by the install script (see WOR-311). The two env-var paths ARE the contract; treating them as the only ingress keeps the threat surface inspectable.
- The interactive CLI path (`src/worthless/cli/keystore.py`) is unchanged. Keyring + env-cascade still applies to end-user secrets — only the sidecar opts out.

A future PR adding "load from keyring when share files are missing" is rejected by design. Falling back to a single keyring entry collapses the two-share split into one secret, a strict downgrade of the threat model. Missing share files must be a hard config error (the existing rc=1 path), not a soft fallback.

Adding sidecar keyring support later is a design pass, not a feature flag. Keyring stores one `(service, username)` value; the sidecar deliberately holds two XOR shares so no single artifact reconstructs the key. Re-introducing keyring requires either a new naming convention for share-pair entries or consolidating the threat model — both warrant their own ticket and security review.

*See also: `docs/security.md`, `docs/adversarial/attack-map.md`, and the env-var contract in `src/worthless/sidecar/__main__.py`.*

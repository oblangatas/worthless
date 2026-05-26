# Docker two-uid Fernet sidecar topology

*Originally landed via WOR-310. Mission-driven name; ticket lineage in the footer.*

> "API keys are protected against bulk/offline exfiltration even when the proxy is compromised."

## What ships

A Docker image that runs the Worthless proxy and Fernet sidecar as **two distinct
Linux uids inside one container**, with kernel-enforced isolation against
offline key theft. Even with full RCE in the proxy (read arbitrary memory, send
arbitrary signals, open arbitrary files), the attacker cannot extract the Fernet
key for offline decryption or bulk exfiltration — the kernel rejects ptrace,
`/proc/<pid>/mem`, and `kill(-9)` across the uid wall.

**WOR-465 A4 (shipped):** `fernet.key` is now owned `worthless-crypto:worthless-crypto 0400`
unconditionally — no operator flag required. The Dockerfile sets
`WORTHLESS_FERNET_IPC_ONLY=1` as the default ENV, and the entrypoint enforces
the permission regardless of operator environment. A fail-closed stat check at
container start exits 78 if the storage backend silently drops the chown.

**What this does NOT defend against:** a live proxy RCE can still drive the IPC
to request per-request `seal`/`open` operations on traffic that arrives at the
proxy while the attacker controls it. The threat model WOR-310 closes is
*offline key extraction* (steal the key, walk away with it, decrypt later or
elsewhere); it does not close *online traffic decryption* by an attacker
co-located with the live proxy. The latter is bounded by other v1.1 controls
(spend cap, request audit log, sidecar attest) — see the WOR-313 9-row
red-team table for the full coverage matrix.

## Runtime flag contract

| Flag | Required? | Why |
|---|---|---|
| `--security-opt=no-new-privileges` | **required** for the security claim | Locks NO_NEW_PRIVS at the kernel level. Without it, a future setuid binary on PATH could re-escalate the dropped uid back to root. |
| `--read-only` + `--tmpfs /tmp` | recommended | Container filesystem is immutable. Blocks a class of "write malware to disk" attacks; doesn't affect functionality because writable spots are explicit volumes. |
| `--cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=SETPCAP --cap-add=DAC_OVERRIDE --cap-add=CHOWN --cap-add=FOWNER` | recommended | Drops every Linux capability EXCEPT the six the runtime needs *briefly* during entrypoint bootstrap + priv-drop. SETUID/SETGID for `setres*`/`setgroups`; SETPCAP for `prctl(PR_CAPBSET_DROP)`; DAC_OVERRIDE so root can write into `/data` which is owned by `worthless-proxy` (uid 10001) — without it root is treated as "other" and `mkdir /data/shard_a` hits EACCES; CHOWN for the post-bootstrap re-ownership step; FOWNER for `chmod fernet.key` on a non-root-owned file. The preexec_fn calls `prctl(PR_CAPBSET_DROP, cap)` for cap 0..63 immediately before `setresuid`, so the post-drop process has zero caps — same end-state as `--cap-drop=ALL`. Plain `--cap-drop=ALL` is INCOMPATIBLE with this flow: bootstrap would EACCES on `/data` and the container never becomes healthy. |

Image self-documents via labels:

```sh
docker inspect worthless --format '{{ .Config.Labels }}'
# org.worthless.required-run-flags=--security-opt=no-new-privileges
# org.worthless.recommended-run-flags=--read-only --tmpfs /tmp --cap-drop=ALL
```

## Threat model coverage

| Attack | Defended? | How |
|---|---|---|
| Stolen `.env` (Shard A) | ✅ | XOR-split: Shard A alone reveals nothing. Pre-existing v1.1 claim. |
| RCE in proxy → read Fernet key | ✅ (A4) | `fernet.key` owned `worthless-crypto:worthless-crypto 0400` unconditionally (WOR-465 A4 — no flag required). Kernel rejects `open()` from proxy uid 10001, which is not in gid 10002. Fail-closed stat check at container start exits 78 if chown was silently dropped by the storage backend. Two-uid wall + `PR_SET_DUMPABLE=0` + YAMA `ptrace_scope=1` + NO_NEW_PRIVS + CAPBSET_DROP block the remaining exfiltration paths (ptrace, `/proc/<pid>/mem`, core dump). **Does NOT defend against:** proxy RCE driving live IPC verbs (`seal`/`open`) while the attacker is present — the key cannot be extracted but can be used on chosen plaintexts/ciphertexts for the duration of the compromise. |
| RCE in proxy → kill sidecar | ⚠ partial | `kill()` across uids is blocked by the OS, but proxy can still SIGTERM via the orchestrator if it has socket-level access. Out-of-scope for the in-container claim. |
| Memory-disclosure crash dump | ✅ | `PR_SET_DUMPABLE=0` (Phase A) + `ulimit -c 0` (Phase D) + image-level core-dump suppression. |
| `setuid` binary escalation | ✅ | `prctl(PR_SET_NO_NEW_PRIVS, 1)` in the priv-drop preexec_fn. Locks the bit before uid drops so it applies to the dropped uid. |
| Capability escalation via file caps | ✅ | `prctl(PR_CAPBSET_DROP, cap)` for cap 0..63 in the preexec_fn. Bounding set is empty post-drop. |
| Symlink redirect on rendezvous socket | ✅ | `lstat(socket_path)` post-bind; refuse if not S_ISSOCK. |
| Container escape | ❌ documented limit | Outside the v1.1 claim. Run with strict syscall filtering / gVisor / Kata for that threat model. |
| Cold-boot host memory dump | ❌ documented limit | Host compromise = game over. v1.2 mlock will reduce attack window. |

## Architecture summary

```text
PID 1 (tini)
├── deploy/start.py (root, briefly)
│     ├── _resolve_service_uids() → ServiceUids(10001, 10002, 10001)
│     ├── split_to_tmpfs() → /run/worthless/<pid>/share_{a,b}.bin (root:root 0600)
│     ├── chown shares → worthless-crypto:worthless 10002:10001
│     ├── spawn_sidecar(service_uids=uids)
│     │     └── fork()
│     │           └── preexec_fn:
│     │                 setresgid(10001, 10001, 10001)
│     │                 setgroups([])
│     │                 prctl(PR_SET_NO_NEW_PRIVS, 1)
│     │                 prctl(PR_CAPBSET_DROP, *) for cap 0..63
│     │                 setresuid(10002, 10002, 10002)
│     │                 prctl(PR_SET_DUMPABLE, 0)
│     │           └── exec python -m worthless.sidecar
│     │                 └── assert_hardening_applied() — refuses if NoNewPrivs!=1 or Dumpable!=0
│     │                 └── bind /run/worthless/<pid>/sidecar.sock
│     ├── lstat(socket_path) — assert S_ISSOCK
│     ├── self drop: setresgid → setgroups([]) → setresuid(10001, 10001, 10001)
│     ├── getresuid() != (10001,10001,10001)? → WorthlessError
│     └── execvp(uvicorn) — proxy uid=10001
└── (sidecar PID, separate process tree under tini supervision)
```

## What's NOT in WOR-310

| Deferred to | Why |
|---|---|
| WOR-311 (install.sh) | Bare-metal install never modifies the host (no useradd, no sudo). install.sh path is single-uid by design. Same kernel-level defenses (DUMPABLE=0, YAMA, NO_NEW_PRIVS) protect the in-process work, but no uid wall. |
| WOR-313 (red-team test suite) | The 9-row red-team table executable tests live there. WOR-310 ships the *defenses*; WOR-313 ships the *attacks* that try to break them. |
| WOR-314 (threat model docs) | This file is engineering-internal. The user-facing docs live in WOR-314. |
| WOR-352 (stale-socket race) | Concurrent restart races on `/run/worthless/sidecar.sock`. Documented separately. |
| v1.2 (memory hardening) | mlock + page-protection on Fernet bytes. Not needed for v1.1's threat model (host-compromise = out of scope). |
| v1.2 (Native Windows Named Pipes) | Windows users go via WSL2 + Docker for v1.1. |
| v2.0 (sidecar-in-its-own-container) | True process isolation. v1.1 ships single-container; advanced topology is v2.0. |

## What changed

7 phases (A through F), 6 implemented (F is this doc). 21 commits on
`feature/wor-310-dockerfile`. ~150 unit, property, chaos, order, and real-fork
tests. 2 docker-marked integration tests. 3 expert-review rounds (security,
architect, brutus) with all MUST-FIX findings shipped.

Branch: `feature/wor-310-dockerfile` → PR #137 → `feature/wor-306-fernet-sidecar-epic` → PR #134 → `main`.

## Security checklist

- [x] SR-01 (bytearray for secret material) — preserved through the lifecycle
- [x] SR-02 (zero before exec) — `zero_buf(shard_a/b)` after sidecar reads
- [x] SR-03 (gate before reconstruct) — proxy hard-fails without sidecar (WOR-309)
- [x] SR-04 (no secrets in logs) — verified across all C2 logging paths
- [x] SR-07 (constant-time compare) — N/A for this phase
- [x] SR-08 (CSPRNG only) — Fernet key generation unchanged

## References

- Plan: `~/.claude/plans/parallel-doodling-zephyr.md`
- Linear ticket: WOR-310
- Parent epic: WOR-306 (Fernet sidecar)
- Related: WOR-307 (IPC contract), WOR-308 (sidecar production), WOR-309 (proxy hard-fail), WOR-384 (lifecycle), WOR-465 (Fernet IPC migration — A4 ships unconditional key lockdown)
- Linux kernel docs:
  - [`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html) — `PR_SET_DUMPABLE`, `PR_SET_NO_NEW_PRIVS`, `PR_CAPBSET_DROP`
  - [`setresuid(2)`](https://man7.org/linux/man-pages/man2/setresuid.2.html) — saved-uid lock
  - [Yama LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) — `ptrace_scope`
- BPO-34394: forking from multi-threaded process (single-threaded assertion before spawn)

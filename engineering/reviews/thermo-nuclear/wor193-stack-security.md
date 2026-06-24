# Thermo-Nuclear Security Review — WOR-193 Stack (#288→#292)

**Date:** 2026-06-08
**Scope:** `main...gsd/wor-193-wave3b-adversarial` (51 files, +5374 / −234)
**Branch tip:** `cb53166`
**PRs:** #288, #289, #290, #292

## Executive summary

| Severity | Count | Merge blockers? |
|----------|-------|-----------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 (3 fixed) | — |
| Low | 4 | No |

**Verdict: PASS** (2026-06-08 follow-up) — M1–M3 fixed in branch; see commit after thermo reports.

---

## Medium findings (resolved)

### M1 — Health probe masks service state ✅ FIXED

`detect_proxy_runtime` now consults platform service state **before** health when a unit is installed. STOPPED/FAILED returns `running=False` even if `/healthz` answers on the port.

### M2 — `_service_start_hint` exits 0 ✅ FIXED

Default command now raises `typer.Exit(code=2)` when service is installed-but-stopped/failed (`_raise_if_service_requires_start`). Single `detect_proxy_runtime` call in `_ensure_proxy_running`.

### M3 — Symlink / path normalization ✅ FIXED

`service_paths()` and templates use `home.base_dir.resolve()`. `unit_file_matches_home` matches exact `Environment=WORTHLESS_HOME=` / plist key pair (no substring prefix collision).

---

## Earlier stack items (cleared in #288–#290)

| Finding | Status |
|---------|--------|
| `refuse_foreign_unit` only in `detect_status` | **FIXED** — all mutators in `launchd.py` / `systemd.py` |
| `os.getlogin()` eager eval in systemd | **FIXED** — `_session_user()` lazy fallback (`systemd.py:27-38`) |
| User-flow mocks `start_daemon` | **FIXED** — mocks `detect_proxy_runtime` + `start_supervised_proxy` |
| Bootstrap TOCTOU / Fernet drift | **FIXED** — `_seed_cache_from_advisory_source`, `hmac.compare_digest` |
| Reclaim kill without health PID check | **FIXED** — `poll_health_pid` guard (`up.py:117-120`) |
| Stale socket HELLO-only | **PARTIAL** — `find_sidecar_socket_for_open` uses IPC `open`; `_managed_sidecar_healthy` still HELLO-only (tracked) |
| Bootstrap SR-07 plain compare | **FIXED** — `hmac.compare_digest` at `bootstrap.py:324` |

---

## Low findings

| ID | Topic | Notes |
|----|-------|-------|
| L1 | `_managed_sidecar_healthy` decrypt path | Decrypts when enrollments exist; HELLO-only as no-enrollment fallback (WOR-749 tracks full IPC open on health path) |
| L3 | Reclaim skips kill when `listener_pid != existing_pid` | Safer than blind kill; orphan may persist until manual `down` |
| L4 | Live packs manual-only | L7 scripts not CI — scope honesty, not a code bug |

---

## Cleared areas

- **Foreign unit mutation:** `refuse_foreign_unit` + L3 tests (`TestForeignUnitMutators`, 10 cases).
- **Atomic unit writes:** `atomic_write_text` refuses symlinks.
- **IPC open verification:** `find_sidecar_socket_for_open` + collapsed except tuple.
- **Service-managed Fernet:** `_seed_cache_from_advisory_source` + `WORTHLESS_SERVICE_MANAGED` gate.
- **Managed orphan reclaim:** Sidecar-dead + health-up path kills only PID verified via `poll_health_pid`.
- **Install preflight:** `preflight_service_install` refuses without Fernet.
- **PR #292 CodeRabbit threads (3):** keystore `S_ISREG`, fernet test `chmod(0o644)`, launchd plist positive match — **fixed in branch**; resolve threads on GitHub after green CI.

---

## PR discussion cross-check

- **#292:** 3 CodeRabbit threads addressed in code (items 1–3 above); PR body “Why” updated; pass-2 restores exit 2 + service-before-health + unconditional fernet stat gate.
- **#288–#290:** Merged; residual CodeRabbit nits on older PRs overlap cleared M1–M3 items — not re-opened as new Criticals on #292.

---

## Recommendation

Proceed with **#292 → main** after pass-1 MUST-FIXes land and CI green (#288–#290 already merged). File Medium items as Beads follow-ups; none require blocking this epic.

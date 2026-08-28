# Thermo-Nuclear Code Quality Review — WOR-193 Stack (#288→#292)

**Date:** 2026-06-08
**Scope:** `main...gsd/wor-193-wave3b-adversarial` (51 files, +5374 / −234)
**Branch tip:** `58872c9`

## Approval bar

**Verdict: CONDITIONAL** — merge OK; post-merge extract `up.py` managed-session module (see original finding #1).

**Update (2026-06-08):** Double `detect_proxy_runtime` in default command fixed (single call in `_ensure_proxy_running`).

---

## File size watch

| File | Lines | vs 1k rule |
|------|-------|------------|
| `up.py` | 681 | OK — but highest complexity concentration |
| `bootstrap.py` | 565 | OK — Fernet seed block is dense |
| `default_command.py` | 263 | OK |
| `health.py` | 234 | OK |
| `_common.py` | 143 | Good extraction |

No file crossed 1000 lines in this epic.

---

## Top structural findings (priority order)

### 1 — `up.py` orchestration sprawl (HIGH structural)

Three startup modes interleaved in one module:

- Foreground supervised `up` (sidecar + proxy)
- `start_supervised_proxy` (detached re-exec)
- Legacy `start_daemon`
- Service-managed reclaim (`_reclaim_managed_proxy_without_sidecar`, `_service_managed_session_owns_port`, `_managed_sidecar_healthy`)

**Code-judo move:** Extract `managed_session.py` (or `up/managed.py`) owning reclaim + sidecar-health + port-ownership invariants. Leaves `up.py` as CLI entry + foreground loop only.

Sonar S3776 on `_reclaim_managed_proxy_without_sidecar` reflects real complexity, not noise.

### 2 — Double `detect_proxy_runtime` in default command (MEDIUM)

`_proxy_is_running` and `_service_start_hint` each call `detect_proxy_runtime(home)` (`default_command.py:68, 76`). Single call could pass `ProxyRuntimeState` through Phase 2.

**Fix:** ~10 lines; reduces duplicate launchd/systemd probes per `worthless` invocation.

### 3 — Fernet seed policy block in bootstrap (MEDIUM)

`_seed_cache_from_advisory_source` (`bootstrap.py:282-346`) encodes service-managed, env, keyring/file compare, and TOCTOU fallback in one function.

**Code-judo move:** Small `FernetSeedPolicy` with ordered strategies (service-managed → env → keyring-wins → file). Same behavior, testable units, drops nested try/except readability cost.

### 4 — Test file sprawl (MEDIUM — maintainability)

Service epic spread across:

- `test_service_backends.py`
- `test_service_cli.py`
- `test_service_common.py`
- `test_service_templates.py`
- `test_service_up_managed.py`
- `test_proxy_state.py`
- `test_wor717_integration.py`

Overlap: foreign-unit tests + runtime detection + CLI wiring. Not wrong, but future edits require grep archaeology.

**Follow-up:** Consolidate into `tests/cli/service/` package with `test_foreign_unit.py`, `test_runtime.py`, `test_cli_wiring.py` — no rush for merge.

### 5 — `detect_proxy_runtime` ordering documents implicit priority (LOW)

PID → health → service is clear and tested (`test_proxy_state.py`). Health-before-service is a **product** choice with UX side effects (see security M1); not a code-quality smell by itself.

### 6 — Live-pack bash duplication (LOW)

`sync_fernet_for_launchd` embedded in lock-roundtrip script; `_live-pack-lib.sh` only header/footer helpers.

**Optional:** Move sync helper into `_live-pack-lib.sh` when a third script needs it.

---

## What reads well

- **`refuse_foreign_unit` + `unit_file_matches_home`** — single policy home in `_common.py`.
- **`ProxyRuntimeState` dataclass** — explicit source tagging aids tests.
- **`find_sidecar_socket_for_open`** — right layer (sidecar health module), IPC verify not just HELLO.
- **WOR-717 integration test** — proves `start_supervised_proxy` never calls `start_daemon`.
- **Backend symmetry** — launchd/systemd mirror mutator guards.

---

## Prior code-simplifier notes — verified

| Note | Still true? |
|------|-------------|
| Too many test files | Yes (#4 above) |
| Double `detect_proxy_runtime` | Yes (#2 above) |
| Architecture OK | Yes — boundaries mostly respected |

---

## Recommendation

| Action | When |
|--------|------|
| Merge stack | Now (CI green, thermo security CONDITIONAL) |
| Extract `up` managed-session module | Next bead off `main` |
| Collapse default-command double detect | Same ticket or drive-by |
| Test directory consolidation | Low priority chore |
| Fernet seed policy extract | When next touching bootstrap for WOR-435/uninstall |

---

## Approval summary

**CONDITIONAL** — merge the epic; schedule one structural cleanup pass on `up.py` + bootstrap within the next WOR-193 milestone, not as a merge gate.

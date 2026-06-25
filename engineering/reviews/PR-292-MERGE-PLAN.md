# PR #292 — merge plan (living doc)

**PR:** https://github.com/shacharm2/worthless/pull/292
**Branch:** `gsd/wor-193-wave3b-adversarial` → `main`
**Worktree:** `/Users/shachar/Projects/worthless/worthless-wor193-service`
**Updated:** 2026-06-25 (head `3beeaa1`) — **MERGE-READY**

This is the single checklist. Do not re-derive from chat.

---

## Gate matrix

| Gate | Status | Artifact / action |
|------|--------|-------------------|
| Pass-1 MUST-FIX (keystore S_ISREG, fernet chmod test, launchd plist test, PR Why, security doc trim) | **Done** | Replies on PR; code on branch |
| Pass-2 panel (default_command exit 2, single detect, keystore validate=True, stop(home) test) | **Done** | `engineering/reviews/thermo-nuclear/PR-292-pass2-verdict.md` → **GO** |
| Thermo-nuclear **security** | **PASS** | `engineering/reviews/thermo-nuclear/wor193-stack-security.md` |
| Thermo-nuclear **code quality** | **Approve** | `engineering/reviews/thermo-nuclear/wor193-stack-code-quality.md` |
| Claude / handoff review | **Done in-session** | `engineering/reviews/thermo-nuclear/PR-292-claude-handoff.md` |
| CodeRabbit | **pass** (status check) · **14/15 threads resolved** | 1 open: handoff note on `keystore.py` (yours) — resolve in UI post-merge optional |
| CI (`gh pr checks 292`) | **ALL GREEN** @ `3beeaa1` | `mergeStateStatus: CLEAN`, `mergeable: MERGEABLE`, exit 0 |
| Last blocker fix | **Done** | `3beeaa1` — `write_secure_fernet_key` in `test_up_with_sidecar` home fixture |

---

## CI snapshot (2026-06-25, all pass)

| Category | Jobs |
|----------|------|
| Tests | ubuntu py3.10, py3.13, windows smoke, quarantine, per-module coverage, SonarCloud |
| E2E | docker-e2e, install.sh matrix, host matrix, user flows (ubuntu + macos) |
| Security | CodeQL, Bandit, Semgrep (×2), Gitleaks, snyk, zizmor, actionlint, license |
| Other | CodeRabbit, license/cla, commit provenance, label, semgrep-cloud |

---

## What you should NOT have to ask again

1. **CodeRabbit** — review completed; code threads addressed. Optional: resolve the one handoff thread on `keystore.py`.
2. **Thermo-nuclear** — artifacts in `engineering/reviews/thermo-nuclear/`.
3. **CI** — green on `3beeaa1`; no pending/failed checks.
4. **Next action** — **you merge** (squash recommended).

---

## CI triage history (for archaeology)

| Job | Cause | Fix commit |
|-----|-------|------------|
| Test ubuntu py3.10/3.13 (fernet 0644) | `test_up_with_sidecar` home fixture | `3beeaa1` |
| Test ubuntu (stale mocks) | `_proxy_is_running` → `detect_proxy_runtime` | `90275ad` |
| docker-e2e fernet ownership | IPC-only stat gate | `90275ad` |
| Smoke windows py3.13 | Skip POSIX stat on Windows | `90275ad` |
| test_proxy_keyring loose fernet | `write_secure_fernet_key` | `54b77e5` |

---

## Post-merge follow-ups (do not block)

| Item | Tracking |
|------|----------|
| P2 orphan latch (`_reclaim_managed_proxy_without_sidecar`, no-pidfile + healthy port) | W3-ADV-3/9 |
| P3 `_managed_sidecar_healthy` HELLO degradation | backlog |
| dirty_env journeys (fixture exists; tests W3-ADV-10/16) | backlog |
| WOR-435 machine purge / `worthless uninstall` | backlog |
| macOS live-pack manual L7 | optional on dev machine |

---

## Merge sequence

1. ~~`gh pr checks 292` — all required green~~ **done**
2. **Squash merge #292 → `main`** ← you are here
3. Optional: macOS live pack from `engineering/testing/scripts/`
4. Close WOR-193 wave3b in Linear/beads after smoke on main

---

## Process note

**This file is the plan.** Update the **Updated** line after each push; do not rely on conversation memory.

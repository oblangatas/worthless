# PR #292 — Claude review handoff

**URL:** https://github.com/shacharm2/worthless/pull/292
**Branch:** `gsd/wor-193-wave3b-adversarial` → `main` (was 717-integration before #288–#290 merged)
**Stack (merge bottom → top):** #288 → #289 → #290 → **#292**
**Worktree:** `/Users/shachar/Projects/worthless/worthless-wor193-service`

## One-line truth

Wave 3b **foundation** for WOR-193: foreign-unit guards, managed-up/sidecar hardening (WOR-747/748/749), L3 pytest + **manual L7 live packs**. Does **not** close WOR-724 (2/17 W3-ADV done in verification doc).

## What this PR is NOT

- Full `worthless uninstall` / WOR-435 machine purge
- WOR-724 adversarial matrix complete
- WOR-725 chaos / Linux live / reboot
- CI-gated live packs (scripts are manual L7)

## What landed (review focus)

| Area | Files | Claim |
|------|-------|-------|
| Foreign unit guard | `service/_common.py`, `launchd.py`, `systemd.py` | `refuse_foreign_unit()` on all mutators |
| Runtime detection | `service/proxy_state.py` | Service state before health when unit installed |
| Default command | `default_command.py` | Exit **2** if service stopped/failed; no double detect |
| Managed up | `commands/up.py`, `bootstrap.py`, `keystore.py` | Reclaim orphan proxy, Fernet sync, SERVICE_MANAGED gate |
| Sidecar resolve | `sidecar/health.py` | `find_sidecar_socket_for_open` (IPC open, not HELLO-only) |
| L3 tests | `tests/cli/test_service_backends.py`, `test_service_up_managed.py`, … | Foreign mutators, managed session |
| Live packs | `engineering/testing/scripts/*-live-*.sh` | macOS lifecycle + lock roundtrip (manual) |
| Thermo audits | `engineering/reviews/thermo-nuclear/*.md` | Security PASS after M1–M3 fixes |

## Latest commit themes (tip `5e80262`)

1. Wave 3b core — foreign unit guard, managed-up, sidecar decrypt health, live packs
2. Review pass — bsa3 idempotency mocks, rh3b/88o5 tests, bootstrap zero_buf, legacy paths
3. Security beads — f7dd (IPC open in `_managed_sidecar_healthy`), l3qj (fernet stat gate), wfz7 (docstrings)
4. Thermo artifacts — `wor193-stack-security.md`, `wor193-stack-code-quality.md`

## Review prompts for Claude

```
Review PR #292 diff vs base main.

1. Security: refuse_foreign_unit coverage, bootstrap Fernet paths, reclaim kill guards, fernet.key stat gate, no key leak on spawn failure.
2. Correctness: detect_proxy_runtime ordering (service before health), default exit 2 stopped/failed, _managed_sidecar_healthy decrypt vs HELLO fallback.
3. Honesty: Title says WOR-724 — does it oversell? Cross-check engineering/testing/wor-193-wave-verification.md W3-ADV table.
4. Tests: L3 backed vs manual-only (live packs)? Any mock seams still stale?
5. Merge: Blockers before stack merge #288→#292?

Read engineering/reviews/thermo-nuclear/wor193-stack-security.md first.
Diff:
  git fetch origin main gsd/wor-193-wave3b-adversarial
  git diff origin/main...origin/gsd/wor-193-wave3b-adversarial
```

## CI / gates

- **Re-verify after each push** — `gh pr checks 292` (see `engineering/reviews/PR-292-MERGE-PLAN.md`)
- Sonar QG: pass (complexity/timeout style — non-blocking)
- CodeRabbit: 14/14 threads resolved (2026-06-08)
- #288–#290: verify CR threads on lower stack PRs

## Beads (review pass)

| Bead | Status |
|------|--------|
| worthless-bsa3, 1pt9, 59r9, rh3b, 88o5, f7dd, wfz7, l3qj | **Fixed in branch** |
| worthless-1j09 | **Open** — extract managed-session module (post-merge) |

## Manual proof (your Mac, PASS)

```bash
unset WORTHLESS_HOME
bash engineering/testing/scripts/service-lifecycle-live-macos.sh
bash engineering/testing/scripts/default-command-supervised-live-macos.sh
bash engineering/testing/scripts/service-lock-roundtrip-live-macos.sh
```

## Suggested merge sequence

1. Merge #288 → main chain (retarget if GitHub doesn't auto-update)
2. #289 → #290 → #292
3. Post-merge: WOR-724/WOR-725 on new branches off `main`

## Open follow-ups (not merge blockers)

- Extract `up.py` managed-session module (worthless-1j09 / code-quality thermo)
- WOR-724 remaining W3-ADV rows

# Good Morning — Release Orchestrator Spec Status

**Date prepared:** overnight 2026-05-31 → 2026-06-01
**For:** Shachar (you), waking up
**PR:** #252 / `chore/wor-598-postmortem-research`

---

## TL;DR

Overnight: 4 research agents researched the 4 CRITICAL findings (F-15..F-18) in depth. Each produced a morning-ready implementation ticket with verbatim spec edits, full code/YAML, TDD test rows, risks, and implementation order. **Nothing was applied to the spec yet — research only.**

**This morning your job is**: read the 4 tickets, approve (or adjust), say go, I execute the pre-written edits. Total time-to-merge after your go: ~30 minutes.

---

## Read order

| # | File | Read time | What it gives you |
|---|---|---|---|
| 1 | This file | 2 min | The morning briefing (you're here) |
| 2 | `fixup-6-research/F-15-research.md` | 5 min | R-21 canary tests wrong ruleset → fix is a lightweight unsigned `v0.0.0-canary-*` tag. ~20 LOC. |
| 3 | `fixup-6-research/F-16-research.md` | 8 min | Audit log JSONL schema (R-26) → 145-line JSON Schema + `--replay-day` doctor command. Biggest ticket. |
| 4 | `fixup-6-research/F-17-research.md` | 5 min | Offsite log shipping (R-27) to 3 channels (GH issue comment + private gist + git notes). Needs decision: pick AUDIT_TRACKER issue # (suggest #999). |
| 5 | `fixup-6-research/F-18-research.md` | 8 min | Pre-window beacon (R-29) + new `.github/workflows/audit-ruleset-watchdog.yml`. Biggest YAML. Needs decision: GitHub App creation (`release-orchestrator`). |
| 6 | `FOLLOWUPS.md` | 2 min | The 12 non-CRIT findings (HIGH/MED/LOW) tracked for implementation-time. |

**Total: ~30 min read.**

---

## Decisions needed before "go"

| # | Decision | Recommendation | Why |
|---|---|---|---|
| 1 | Pick AUDIT_TRACKER issue number (F-17, F-18) | `worthless#999` (or first available — `gh issue list -L 1000 --state all --json number`) | Hard-coded in code; one canonical issue forever |
| 2 | Create GitHub App `release-orchestrator` (F-18) | Yes — needed for the GHA watchdog workflow's ruleset PATCH | `GITHUB_TOKEN` doesn't carry `administration:write`; PAT explicitly NOT acceptable |
| 3 | F-17 token scope: extend R-9 (`repo,workflow,gist`) OR separate gist-only token | **Separate token** — cleaner | Minimum scope per call site; aligns with R-9 minimization principle |
| 4 | F-17 sync vs async shipping | **Synchronous fail-loud** | Async leaves attacker one full release cycle to also rewrite the offsite manifest |
| 5 | Apply all 4 fixes in ONE commit, or 4 separate commits | **4 separate** | Each is self-contained; easier to roll back one if needed; cleaner git log |

---

## What lands when you say go

| Path | Commits | Files modified | Files created | Files deleted |
|---|---|---|---|---|
| **B (close 4 CRITs only)** | 4 fixup commits | `SPEC.md`, `security-engineer.md` | `.github/workflows/audit-ruleset-watchdog.yml`, `scripts/release/audit-schema.json`, `adversarial-findings.md` flips F-15..F-18 ✅ | — |
| **B + CLEAN (recommended)** | 4 fixup commits + 1 cleanup commit | same | same | `.panel-*.md` × 4, `SECURITY-PANEL.md`, `adversarial-findings.md` (closed findings live in git log; open ones live in `FOLLOWUPS.md`) |

**Final tree on main after B + CLEAN merge:**

```
engineering/research/release-orchestrator-spec/
├── SPEC.md                      # the spec, F-1..F-18 closed
├── security-engineer.md         # R-1..R-29 (R-20, R-21, R-26, R-27, R-29 hardened)
├── deployment-engineer.md       # original phase shape narrative
└── FOLLOWUPS.md                 # 12 non-CRIT findings → bd-promotion source
```

Plus 2 new asset files outside the spec dir (referenced by SPEC.md):
- `.github/workflows/audit-ruleset-watchdog.yml`
- `scripts/release/audit-schema.json`

---

## What happened overnight (the trail in PR #252)

| Commit | What |
|---|---|
| `006169a` | Initial 5-file spec |
| `9e6367c` | R-10 upgrade — `gh attestation verify` works today |
| `b99d933` | Self-review fixes 1-5 |
| `e705a02` | `adversarial-findings.md` (14 findings, 14 ✅) |
| `56efb8e` | F-1 CRITICAL closed (Tool Trust §11, R-20, P11) |
| `c865282` | Straggler `10 gates → 11 gates` |
| `63e6732` | Cluster A+B fixup #4 (13 fixes) |
| `ae55837` | Straggler `10 preflights → 11 preflights` |
| `c9aa1ea` | 4-lens security panel (16 new findings F-15..F-30) |
| `cbd221a` | `FOLLOWUPS.md` (the 12 non-CRIT) |
| **(overnight)** | 4 research tickets in `fixup-6-research/` |

**Next commits when you say go**: fixup #6a/b/c/d (F-15/F-16/F-17/F-18) + cleanup.

---

## Quick gut-check before reading

**Diminishing returns test from yesterday: FAILED** (each of 4 lenses found different things). After closing F-15..F-18, the spec is design-complete by any reasonable open-source standard. The 12 remaining HIGH/MED/LOW findings are implementation-time work — they'll surface naturally when bash code exists.

**SOC 2 / SLSA L4 path is a separate epic** — don't pursue unless enterprise cert is this quarter.

---

## What to do when you wake up

1. ☕
2. `cat fixup-6-research/F-15-research.md` (5 min)
3. `cat fixup-6-research/F-16-research.md` (8 min)
4. `cat fixup-6-research/F-17-research.md` (5 min)
5. `cat fixup-6-research/F-18-research.md` (8 min)
6. Make the 5 decisions in the table above
7. Tell me "go with B+CLEAN" or "go with X adjustments"
8. ~30 min later: PR #252 is clean and ready to merge

Good morning. The hard thinking is done; only the typing remains.

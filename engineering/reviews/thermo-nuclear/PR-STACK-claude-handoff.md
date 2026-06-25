# WOR-193 stack — Claude review handoff (index)

**Merge order (bottom → top):** [#288](https://github.com/shacharm2/worthless/pull/288) → [#289](https://github.com/shacharm2/worthless/pull/289) → [#290](https://github.com/shacharm2/worthless/pull/290) → [#292](https://github.com/shacharm2/worthless/pull/292)

**Worktree (tip of stack):** `/Users/shachar/Projects/worthless/worthless-wor193-service` on `gsd/wor-193-wave3b-adversarial`

**Shared thermo audits (full stack diff):**
- [wor193-stack-security.md](wor193-stack-security.md)
- [wor193-stack-code-quality.md](wor193-stack-code-quality.md)
- [wor-193-wave-verification.md](../../testing/wor-193-wave-verification.md)

## Per-PR handoffs

| PR | Handoff | Base → Head | Tip (Jun 2026) | CI (Test + User flows) |
|----|---------|-------------|----------------|-------------------------|
| **#288** | [PR-288-claude-handoff.md](PR-288-claude-handoff.md) | `main` → `gsd/wor-193-wave1-service-skeleton` | `174d5ebd` | Green |
| **#289** | [PR-289-claude-handoff.md](PR-289-claude-handoff.md) | `#288` branch → `gsd/wor-193-service-lifecycle` | `4e424f39` | Green |
| **#290** | [PR-290-claude-handoff.md](PR-290-claude-handoff.md) | `#289` branch → `gsd/wor-193-wave3-717-integration` | `173f4ea1` | Green |
| **#292** | [PR-292-claude-handoff.md](PR-292-claude-handoff.md) | `#290` branch → `gsd/wor-193-wave3b-adversarial` | `5e80262` | Green |

## How to run in Claude

Review **one PR at a time** against its **immediate base**, not `main` (except #288).

```text
1. Open the handoff MD for the PR.
2. Paste the "Review prompts for Claude" block.
3. In repo: git fetch && git diff <base>...<head>   (command in each handoff)
4. Optional: paste wor193-stack-security.md for #292 only (or whole stack on #288).
5. Record blockers in beads / PR comment; merge bottom-up when all four pass.
```

## Stack truth (one paragraph)

Wave **1a** (#288) adds `worthless service` + platform units. Wave **2** (#289) routes bare `worthless` through sidecar-supervised `worthless up`. Wave **3** (#290) adds WOR-717 integration tests and deprecates naked `start_daemon`. Wave **3b** (#292) adds adversarial guards (foreign unit, managed-up/sidecar hardening, L3/L7 live packs) — **foundation only**, does **not** close WOR-724 (see verification doc).

## Post-merge (not in these PRs)

- **worthless-1j09** — extract managed-session logic from `up.py`
- WOR-724 remaining W3-ADV rows, WOR-725 chaos/live, WOR-435 full uninstall

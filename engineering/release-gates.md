# Release Gates (People First)

This file answers one question:
"Can a normal person install Worthless and use it safely today?"

Status values:
- `PASS`: requirement proven with current evidence
- `FAIL`: release blocker for that track
- `WAIVE`: explicit maintainer waiver with issue link, owner, and expiry

---

## Track A: Starter (regular people)

Definition: a solo dev can install, lock, run, recover, and trust the docs without internal knowledge.

### A1. Install works from public command (hard blocker)
- [ ] `curl -sSL https://worthless.sh | sh` works on clean macOS/Linux.
- [ ] `pipx install worthless` works on clean macOS/Linux.
- [ ] User gets a clear "next command" after install.

Evidence:
- install smoke workflows
- user-flow install traces

### A2. First-run magic moment works (hard blocker)
- [ ] Running `worthless` in a project with `.env` detects supported keys.
- [ ] It locks keys and starts proxy flow as documented.
- [ ] User-facing output is actionable and non-jargony.

Evidence:
- `tests/user_flows/`
- `CHANGELOG.md` release proof notes

### A3. App still works with no code changes (hard blocker)
- [ ] `wrap` path works end-to-end.
- [ ] `up` + `BASE_URL` path works end-to-end.
- [ ] No hidden requirement for internal setup knowledge.

Evidence:
- wrap/user-flow tests
- install/mcp docs consistency

### A4. Recovery works when things go wrong (hard blocker)
- [ ] `worthless doctor --fix` recovers known broken states.
- [ ] `worthless unlock` restores original keys when state is valid.
- [ ] Error messages explain recovery actions clearly.

Evidence:
- `docs/troubleshooting.md`
- recovery and stress tests under `tests/user_flows/`

### A5. Security messaging is honest (hard blocker)
- [ ] Public docs do not overclaim spend-cap behavior.
- [ ] Gate-before-reconstruct claim matches implementation/tests.
- [ ] Limitations are explicit where users will see them.

Evidence:
- `README.md`
- `docs/security.md`
- `SKILL.md`

### A6. Docs tell one consistent story (hard blocker)
- [ ] `README.md`, install docs, and `SKILL.md` do not contradict each other.
- [ ] No "planned" labels on already-shipped features.
- [ ] No shipped claims for features that are still manual/backlog.

Evidence:
- `README.md`
- `docs/install-*.md`
- `SKILL.md`
- `CHANGELOG.md`

---

## Track B: OpenClaw (separate from Starter)

Definition: OpenClaw users can install and run Worthless without manual/internal workaround steps.

### B1. Public install path exists (hard blocker)
- [ ] `docs/install-openclaw.md` is real, current, and complete.
- [ ] If claiming ClawHub one-command install, that path is live and tested.

### B2. Skill content is production-ready (hard blocker)
- [ ] OpenClaw skill is not placeholder/stub text.
- [ ] Lock/unlock OpenClaw integration is idempotent and tested.

### B3. OpenClaw journey proof exists (hard blocker)
- [ ] Fresh-machine OpenClaw journey has automated proof.
- [ ] Troubleshooting for OpenClaw failures is documented and tested.

---

## Snapshot: 2026-06-01

### Starter (Track A)

| Gate | Status | Why |
|---|---|---|
| A1 Install works from public command | `PASS` | Install proof exists in current install/user-flow evidence. |
| A2 First-run magic moment works | `PASS` | User-flow covers default command lock/start behavior. |
| A3 App still works with no code changes | `PASS` | Wrap/base-url journey is covered. |
| A4 Recovery works when things go wrong | `PASS` | Doctor/unlock/recovery journeys are covered. |
| A5 Security messaging is honest | `FAIL` | Spend-cap semantics are not consistently scoped across public surfaces. |
| A6 Docs tell one consistent story | `FAIL` | `docs/install-mcp.md` and OpenClaw docs conflict with `README.md`/`SKILL.md`/`CHANGELOG.md`. |

Starter decision: `FAIL` for GA, `Release Starter beta` after fixing A5 + A6.

### OpenClaw (Track B)

| Gate | Status | Why |
|---|---|---|
| B1 Public install path exists | `FAIL` | `docs/install-openclaw.md` absent; `website/install-openclaw.md` still says planned/not available. |
| B2 Skill content is production-ready | `FAIL` | Embedded OpenClaw skill file is still a phase placeholder. |
| B3 OpenClaw journey proof exists | `FAIL` | User-flow report still marks OpenClaw journey as a gap/backlog. |

OpenClaw decision: `FAIL` (hold general-release claims).

---

## Immediate fix list to flip Starter to PASS

1. Fix docs contradictions (`A6`):
- align `docs/install-mcp.md` with actual current capability
- align `docs/install-openclaw.md` label with actual status

2. Fix security wording drift (`A5`):
- unify spend-cap language in `README.md`, `docs/security.md`, and `SKILL.md`
- keep wording explicit: pre-check/best-effort where applicable

After these two are done, Starter can be announced as beta without overclaiming.

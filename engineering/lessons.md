# Lessons

Patterns banked after operator corrections. Read this at session start.

Format: one heading per lesson, then **the rule** (single sentence, imperative),
then a short paragraph on the originating mistake so future sessions
recognize the situation. Newest at the top.

---

## Never invent a ticket number for a branch name

**Rule:** Before putting a ticket ID in a branch name, call `get_issue` on it. If the work has no ticket, use a descriptive slug with no ID — never guess a number that "looks free".

Originated from a session correction on 2026-08-10 (WOR-852 CVE work). Closing dependabot alert #91 (nanoid) had no ticket, so I named the branch `fix/wor-874-nanoid-infinite-loop` — picking 874 because it sounded unused. It was not: WOR-874 is *"A dependency bump can merge without waiting for a check it never runs"*, Urgent, In Progress, with its own PR #491 and branch. Linear auto-links attachments from branch names, so my PR #494 landed on that ticket, putting two unrelated PRs on one Urgent item and misleading whoever picks it up.

Two things make this worse than a cosmetic slip:

1. **It is not cleanly reversible.** GitHub cannot repoint a PR's head branch, so fixing the name means closing the PR and opening a new one. The cheap fix is a comment explaining the mis-attachment — which leaves the wrong link in place forever.
2. **Ticket IDs are load-bearing here.** The repo's branch convention is `<type>/<ticket>-<slug>`, and tooling reads the ID. A wrong ID is not noise; it is a false cross-reference in the tracker.

The check costs one API call. `get_issue` on a free number returns not-found, which is the confirmation you want. A descriptive branch with no ticket (`fix/nanoid-infinite-loop-alert-91`) is always safe; a guessed number never is.

**Rule:** Capture every emergent discovery in beads. Export to Linear ONLY when team-visibility, scheduling, or non-engineer eyes actually need it — and even then, draft the proposed Linear ticket(s) inline in chat for operator confirmation before calling `save_issue`. Never mirror a bd issue to Linear by default.

Originated from a session correction on 2026-06-06. The operator asked for the bd issues `worthless-ftmg` and `worthless-2ygy` to "relate back to Linear". I interpreted this as create-new-tickets and immediately fired two `save_issue` calls (WOR-692 + WOR-693) without confirmation. The operator pushed back: *"wait we created linear tickets?"* and *"why do we need bead then if u went ahead and do linear?"* — three problems:

1. **Violated** `feedback_two_eyes_for_linear_edits` — non-trivial Linear edits require inline draft + operator OK before save.
2. **Conflated scopes.** Beads = local operator-level discoveries during execution. Linear = team-level milestone/scheduled work. These are different tools for different audiences. Mirroring one to the other adds tracking surface without value.
3. **Inflated the epic.** WOR-621's children should be the planned feature list (F1–F13). Side-quests don't belong as feature siblings; they muddy the milestone tracker.

Recovery: both Linear tickets canceled with explanatory comments. The work stays canonical in bd. WOR-649's G5 description references `worthless-2ygy` by name — that's the breadcrumb that surfaces it during post-PR-1 planning, no separate Linear slot needed until then.

When in doubt: bd. When team visibility actually matters: draft inline first.

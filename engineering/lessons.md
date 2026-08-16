# Lessons

Patterns banked after operator corrections. Read this at session start.

Format: one heading per lesson, then **the rule** (single sentence, imperative),
then a short paragraph on the originating mistake so future sessions
recognize the situation. Newest at the top.

---

## A reproduction is only evidence once you have watched it fail

**Rule:** Before claiming a repro confirms a diagnosis, make it produce the failure on the UNFIXED code first; a repro that only ever goes green cannot tell "fixed" from "never broken here".

Originated 2026-08-16, chasing WOR-864. Three fixture cases passed locally and in a container but failed on the runner. I diagnosed it wrong three times: a checkout quirk (guessed, never reproduced), inherited `commit.gpgsign` (reproduced the *same three exit codes* from an unrelated cause — the most dangerous one, because it looked like proof), and a non-root/`safe.directory` issue (the container ran as root, so it could never exhibit the bug). Each cost a CI round-trip. The real cause appeared in one shot the moment I built a repro that went RED first — a user with an empty passwd gecos field, which is what a runner has. The cause was my own `git` stub matching `verify-tag` as a substring, so it swallowed `git config user.name "verify-tag fixture"` and left every fixture repo with no identity. Same session, same shape: the "no global identity" and "`init.defaultBranch=main`" differences between my machine and CI were both invisible until something failed on purpose.

## A test that copies the code under test only proves the copy works

**Rule:** A regression test must EXECUTE the artifact it guards and assert that artifact's observable result; if you find yourself writing "verbatim from `<file>`", stop — and prove the test has teeth by deleting the defense and watching it go red.

Originated 2026-08-16 on PR #501. Cases written specifically to protect the WOR-864 fix re-implemented the guard inline and asserted git's behaviour. Deleting the entire fix from `verify-tag.sh` left the suite reporting `Pass: 10 Fail: 0`. Both post-verify security bindings were the same — replacing their `exit 1` with `:` stayed green. The only thing tying the script to its tests was a whole-file `grep`, which is satisfied by the marker appearing in a comment left behind by the deletion. Five independent reviewers found this simultaneously; I had already claimed the tests were "mutation-verified" on the strength of a single earlier mutation. The fix is three layers: cases that run the real script, comment-stripped markers, and a mutation gate that re-runs the suite with each defense disabled and requires red. The gate opens with a CONTROL (a comment-only edit must stay green) — which immediately caught the gate itself being broken, and without it every mutation would have reported success for the wrong reason.

## Never hand-roll a step that already has a script

**Rule:** Before typing a release, deploy, or signing command by hand, look for the repo's script or skill for it and use that — the flags you omit are exactly the ones that encode hard-won failures.

Originated 2026-08-16 shipping v0.3.12. I told the operator to run a bare `git tag -s`. Their local `gpg.format=ssh` made it an SSH-signed tag; CI verifies against a pinned OpenPGP key, so all four publishers failed a second time and the tag had to be deleted and redone. `scripts/tag-release.sh:102-104` already did it correctly — `git -c gpg.format=openpgp -c user.signingkey="$GPG_FINGERPRINT" tag -s`. Third instance in one session: I also skipped the `/release` skill entirely (operator caught it: *"wasn't there a skill?"*), and gave a three-step sequence that skipped my own step 5. The scripts exist because someone already paid for the mistake.

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

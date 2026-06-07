# Lessons

Patterns banked after operator corrections. Read this at session start.

Format: one heading per lesson, then **the rule** (single sentence, imperative),
then a short paragraph on the originating mistake so future sessions
recognize the situation. Newest at the top.

---

## Recursive-walk RED: enumerate every position a primitive can live

**Rule:** Before writing RED for a function that walks a structured input, enumerate every position a primitive can live in the input type. For JSON that's *value-at-any-depth*, *dict-KEY*, and *list-item*. Write a RED assertion for each position. Don't anchor on the one example the spec mentioned — the spec example is one position, not all of them.

Originated 2026-06-07 on F2 G5-B (`build_oc_rollback_entry_record` deep-redact). The continuation prompt's example was `headers.Authorization: "Bearer sk-..."` — a value. I wrote RED that pinned value-at-depth, list-item, and SecretRef-pointer paths, but missed dict-KEY. GREEN shipped with `{k: walk(v) for k,v in d.items()}` — walked values, ignored keys. A pathological config storing a key-shaped string AS a dict key would leak. Both code-reviewer (HIGH-1) and security-reviewer (MED-2) flagged it post-GREEN, turning what should have been one commit into three (RED + GREEN + panel polish). The panel doing its job is fine; the cycle cost was preventable.

Sharper RED takes 30 seconds: ask "where can a primitive live in this input type?" and write one assertion per position. The pattern applies to any recursive-walk feature: redact, transform, validate, serialize.

---

## Beads is the inbox; Linear is the scoreboard

**Rule:** Capture every emergent discovery in beads. Export to Linear ONLY when team-visibility, scheduling, or non-engineer eyes actually need it — and even then, draft the proposed Linear ticket(s) inline in chat for operator confirmation before calling `save_issue`. Never mirror a bd issue to Linear by default.

Originated from a session correction on 2026-06-06. The operator asked for the bd issues `worthless-ftmg` and `worthless-2ygy` to "relate back to Linear". I interpreted this as create-new-tickets and immediately fired two `save_issue` calls (WOR-692 + WOR-693) without confirmation. The operator pushed back: *"wait we reated linear tickets?"* and *"why do we need bead then if u went ahead and do linear?"* — three problems:

1. **Violated** `feedback_two_eyes_for_linear_edits` — non-trivial Linear edits require inline draft + operator OK before save.
2. **Conflated scopes.** Beads = local operator-level discoveries during execution. Linear = team-level milestone/scheduled work. These are different tools for different audiences. Mirroring one to the other adds tracking surface without value.
3. **Inflated the epic.** WOR-621's children should be the planned feature list (F1–F13). Side-quests don't belong as feature siblings; they muddy the milestone tracker.

Recovery: both Linear tickets canceled with explanatory comments. The work stays canonical in bd. WOR-649's G5 description references `worthless-2ygy` by name — that's the breadcrumb that surfaces it during post-PR-1 planning, no separate Linear slot needed until then.

When in doubt: bd. When team visibility actually matters: draft inline first.

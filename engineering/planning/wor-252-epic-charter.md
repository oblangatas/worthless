# WOR-252 epic charter

This file is the ledger for the `feat/wor-252-epic` integration branch.

## One-sentence outcome

> *"I can't accidentally destroy my `.env`, I can recover it if I do, and nothing I care about leaks in the meantime."*

## Scope

Three features. All three must ship before this epic merges to `main`:

| Ticket | Outcome | State |
|---|---|---|
| [WOR-275](https://linear.app/plumbusai/issue/WOR-275) | Writes can't destroy your data | **In progress** — code complete, awaiting review |
| [WOR-276](https://linear.app/plumbusai/issue/WOR-276) | Recovery works after a bad lock | **Todo** — plan at [engineering/planning/recovery-works-after-bad-lock.md](recovery-works-after-bad-lock.md) |
| [WOR-277](https://linear.app/plumbusai/issue/WOR-277) | No plaintext leaks anywhere | **Todo** — independent; may ship via a separate main-targeting PR |

## Merge rules

1. **Feature PRs target this branch, not `main`.** Rebasing is cheaper here than on main.
2. **Main → epic regularly.** Whenever `main` moves, merge `main` into this branch. Keeps the eventual epic → main merge small.
3. **Epic → main once.** When the one-sentence outcome is demonstrably true (plus Feature C shipped or explicitly deferred), this branch merges to `main` in one atomic commit.

## How we know we're done

The finish-line sentences from the feature plans must all be true in a fresh `$HOME` container:

- Feature A: *"I passed `worthless` a symlink to `.zshrc`. It refused instead of overwriting it."*
- Feature B: *"I corrupted my `.env`. I ran `worthless restore`. I got my file back. I didn't read any docs."*
- Feature C: *"I grepped every log, temp file, and core dump for the first 12 chars of my key. Nothing matched."*

Test counts are the evidence, not the definition. The sentences are the definition.

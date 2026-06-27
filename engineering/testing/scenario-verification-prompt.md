# Worthless CLI — Scenario Verification Prompt

> Read the source code, then verify each scenario below.
> For each: trace the code, state expected vs actual behavior, flag bugs, rate risk.

## Setup

Read these source files first:
- `src/worthless/cli/commands/lock.py`
- `src/worthless/cli/commands/unlock.py`
- `src/worthless/cli/commands/wrap.py`
- `src/worthless/cli/commands/up.py`
- `src/worthless/cli/commands/scan.py`
- `src/worthless/cli/commands/status.py`
- `src/worthless/storage/repository.py`
- `src/worthless/storage/schema.py`
- `src/worthless/cli/bootstrap.py`
- `src/worthless/cli/scanner.py`
- `src/worthless/cli/dotenv_rewriter.py`
- `src/worthless/cli/process.py`

Also read `.planning/docs/SCENARIO-MATRIX.md` for full context.

## Output Format

For EACH scenario:
```
### [CATEGORY] Scenario Name
TRACE: <step-by-step code path with function:line references>
EXPECTED: <what should happen>
ACTUAL: <what the code does>
BUGS: <defects found, or "None">
RISK: CRITICAL / HIGH / MEDIUM / LOW
TESTS: exist / missing / partial
```

---

## A. User Scenarios

1. First-time lock on .env with one openai key
2. Re-lock on already-locked .env (idempotency)
3. Same key value in two vars in same .env (API_KEY=X and API_KEY_DEV=X)
4. Same key in two .env files (project-a/.env and project-b/.env)
5. Lock → unlock roundtrip (exact content preservation)
6. enroll --key-stdin then lock (does lock protect the .env?)
7. unlock --alias when multiple enrollments exist (ambiguity handling)
8. unlock all keys enrolled from different .env files
9. wrap with only openai keys enrolled
10. wrap with google/xai keys enrolled (unsupported providers)

## B. Attacker Scenarios

11. Read ~/.worthless/ (same user local access) — full key reconstruction?
12. Read /proc/PID/environ of proxy — is fernet key visible?
13. Supply --alias="../fernet.key" to enroll
14. Supply --env=/etc/shadow to lock
15. Tamper with shard_a file (bit flip) — HMAC catches it?
16. Corrupt SQLite database — denial of service or key theft?

## C. System Scenarios

17. SIGKILL during lock after shard_a write but before DB write
18. SIGKILL during lock after DB write but before .env rewrite
19. Disk full during .env rewrite (shards already stored)
20. Two terminals run lock simultaneously
21. One terminal locks, another runs enroll (no lock file acquired by enroll)
22. Power loss during SQLite commit

## D. Integration Scenarios

23. git pull reverts .env after lock — does re-lock work?
24. CI: enroll via stdin + wrap + test + unlock
25. Docker restart mid-session (ephemeral volume)

---

## E. Known Bugs to Verify

These were identified by previous reviews. State whether STILL PRESENT or FIXED, with exact code path.

**KB-1: Duplicate key value left in plaintext**
Setup: .env has API_KEY=sk-xxx and API_KEY_DEV=sk-xxx (same value). Lock runs.
Suspected: Second var skipped by `shard_a_path.exists()` check — never rewritten with decoy.

**KB-2: Error compensation cascades destruction**
Setup: Lock processes multiple keys. One fails mid-way.
Suspected: `delete_enrolled(alias)` in except block CASCADE-deletes ALL enrollments for that alias.

**KB-3: enroll-then-lock leaves .env unprotected**
Setup: User runs enroll, then lock on same key.
Suspected: lock sees shard_a exists, skips, .env keeps real key.

**KB-4: Orphan shard_a blocks re-enrollment**
Setup: Previous lock crashed, left orphan shard_a file.
Suspected: O_EXCL fails, lock can never re-enroll this key.

---

## Final Request

After all scenarios: **list any additional scenarios not covered above that could cause data loss, security exposure, or user confusion.**

If you find new scenarios, **add them directly to `.planning/docs/SCENARIO-MATRIX.md`** under the appropriate section. Use the same format (Expected, Current behavior, Risk, Test status). This is a living document — every reviewer should expand it.

# Wave 3 — Rules Engine Implementation Plan

**Epic:** WOR-181
**Branch:** `gsd/v1.1-wave3`
**Estimate:** ~700 LOC (500 impl + 200 tests), 6-8 days

## Context

2 new rules for the gate-before-reconstruct pipeline. ModelAllowlistRule (WOR-159) was cut permanently — the proxy should be model-blind. Spend and time controls are sufficient. Plan reviewed by Security, Product, and Brutus agents.

## Execution Order

```
WOR-182 (done) → WOR-183 → (WOR-160 + WOR-161 parallel) → WOR-184 → close WOR-181
```

---

## Phase 0: Foundation Refactor — WOR-182

**Blocks all subsequent phases.**

### What
- Add `body: bytes` parameter to `Rule.evaluate()` protocol
- Proxy reads body once before rules engine, passes bytes to all rules
- Update SpendCapRule, RateLimitRule, RulesEngine signatures (accept `body`, ignore it)
- Update ~15 existing tests to pass `body=b""`
- Add spend_log 90-day retention cleanup in `migrate_db()`

### Why
Brutus found: ModelAllowlistRule would be the first rule to call `request.body()`. Starlette caches after first read, but if any middleware consumes the body stream first, the rule silently gets empty bytes and passes. Pre-reading the body in the proxy handler eliminates this invisible coupling.

### Files
- `src/worthless/proxy/rules.py` — Rule protocol + SpendCapRule + RateLimitRule signatures
- `src/worthless/proxy/app.py` — read body before rules engine, pass to evaluate()
- `src/worthless/storage/schema.py` — spend_log cleanup in migrate_db()
- `tests/test_rules.py` — update all existing tests
- `tests/test_proxy.py` — update test_rules_pass_then_reconstruct_called

### New Rule.evaluate() signature
```python
async def evaluate(self, alias: str, request: object, *, provider: str = "openai", body: bytes = b"") -> ErrorResponse | None
```

### Tests to update
All existing tests that call `rule.evaluate()` or `engine.evaluate()` — add `body=b""` kwarg.

---

## Phase 1: Schema Migration + Structured Error Factories — WOR-183

**Blocks all 3 rule implementations.**

### Schema changes
4 new nullable columns on `enrollment_config`:
```sql
ALTER TABLE enrollment_config ADD COLUMN token_budget_daily INTEGER;
ALTER TABLE enrollment_config ADD COLUMN token_budget_weekly INTEGER;
ALTER TABLE enrollment_config ADD COLUMN token_budget_monthly INTEGER;
ALTER TABLE enrollment_config ADD COLUMN time_window TEXT;
```

New index for TokenBudgetRule time-windowed queries:
```sql
CREATE INDEX IF NOT EXISTS idx_spend_log_alias_created ON spend_log (key_alias, created_at);
```

Migration uses existing `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` pattern from `migrate_db()`. NULL = feature disabled for all existing enrollments.

### Error factories
3 new factories in `errors.py` with structured messages:

1. `token_budget_error_response(period, used, limit, provider)` → 429
   - Message: "daily token budget exceeded: 85,000/100,000 — resets at midnight UTC"
3. `time_window_error_response(current_time, window, provider)` → 403
   - Message: "access denied: current time 22:15 UTC outside allowed window 09:00-17:00"

### Files
- `src/worthless/storage/schema.py` — SCHEMA DDL + migrate_db()
- `src/worthless/proxy/errors.py` — 3 new factories

### Tests (TDD)
- Migration adds columns to existing DB
- Migration is idempotent (run twice = no error)
- Fresh install has all columns
- Error factories return correct status codes + provider-formatted bodies

---

## Phase 2: TokenBudgetRule — WOR-160

**Priority: FIRST rule to implement** (Product review: cost explosion is #1 user fear)

### What
Enforce per-alias token budgets over rolling time windows (daily/weekly/monthly).

### Implementation
- New `@dataclass` class `TokenBudgetRule` in `rules.py` taking `db: aiosqlite.Connection`
- Query 3 budget columns from `enrollment_config`
- For each non-NULL budget: `SUM(tokens) FROM spend_log WHERE key_alias = ? AND created_at >= datetime('now', '-1 day')` (and '-7 days', '-30 days')
- Uses `BEGIN IMMEDIATE` like SpendCapRule (same TOCTOU caveat — documented, acceptable for PoC)
- Budget periods are UTC-anchored (no user-supplied timezone — Security review)
- Fail-closed on DB error → 429

### Files
- `src/worthless/proxy/rules.py` — TokenBudgetRule class
- `tests/test_rules.py` — 10 new tests

### Tests (TDD — write first)
1. All budgets NULL → pass
2. Under daily limit → pass
3. Daily budget exceeded → 429 with usage stats
4. Weekly budget exceeded → 429
5. Monthly budget exceeded → 429
6. Mixed: daily OK but monthly exceeded → 429
7. Spend records outside time window not counted
8. DB error → fail closed (429)
9. Concurrent check (two connections)
10. Anthropic error format

---

## Phase 3: TimeWindowRule — WOR-161

**Priority: LAST** (Product review: weak for solo dev persona, valuable for teams later)

### What
Restrict API access to configured time windows per alias.

### Implementation
- New `@dataclass` class `TimeWindowRule` in `rules.py` taking `db: aiosqlite.Connection`
- Query `time_window` JSON from `enrollment_config`
- Parse: `{"start":"09:00","end":"17:00","tz":"America/New_York","days":[1,2,3,4,5]}`
- Use `zoneinfo.ZoneInfo` (stdlib 3.9+) for timezone conversion
- Handle overnight windows (end < start spans midnight)
- Missing tz → UTC, missing days → all days
- **Validate tz at enrollment time** (Security review — defense in depth)
- Fail-closed on invalid tz or malformed JSON at request time → 403
- No `BEGIN IMMEDIATE` needed — pure read of config + clock check

### Files
- `src/worthless/proxy/rules.py` — TimeWindowRule class
- `tests/test_rules.py` — 8 new tests

### Tests (TDD — write first)
1. NULL time_window → pass
2. Within window → pass
3. Outside window (wrong hour) → 403 with current time + allowed window
4. Outside window (wrong day) → 403
5. Overnight window (end < start) → correct handling
6. Invalid timezone → fail closed (403)
7. Malformed JSON → fail closed (403)
8. Anthropic error format

---

## Phase 5: CLI Configuration — WOR-184

**After all rules exist.**

### What
Users need a way to configure rules at enrollment and update them post-enrollment without re-splitting the key.

### CLI additions
- `worthless lock` new flags:
  - `--model-allowlist gpt-4o-mini,gpt-4o` (comma-separated → stored as JSON array)
  - `--token-budget-daily 100000`
  - `--token-budget-weekly 500000`
  - `--token-budget-monthly 2000000`
  - `--time-window '{"start":"09:00","end":"17:00","tz":"UTC","days":[1,2,3,4,5]}'`

- `worthless rules update --alias <alias>` — patch server-side config without re-splitting key
- `worthless rules show --alias <alias>` — view current rule config for an alias
- Timezone validation at enrollment time: reject invalid tz strings against `zoneinfo.available_timezones()`

### Files
- `src/worthless/cli/commands/lock.py` — add flag handling
- `src/worthless/cli/commands/rules.py` — new file for rules update/show
- `src/worthless/cli/app.py` — register rules command group
- `tests/test_cli_rules.py` — new test file

---

## Phase 6: Wire + Integration — Close WOR-181

### What
Register all rules in app.py and verify end-to-end.

### Rule registration order (cheapest first)
```python
rules_engine = RulesEngine(
    rules=[
        TimeWindowRule(db=db),          # DB lookup + clock check
        SpendCapRule(db=db),            # DB aggregate
        TokenBudgetRule(db=db),         # 3x DB aggregates
        RateLimitRule(...),             # in-memory, side effects
    ]
)
```

### Final checklist before closing WOR-181
- [ ] All 6 subtasks done
- [ ] All tests pass (`uv run pytest`)
- [ ] Ruff clean (`uv run ruff check .`)
- [ ] Pre-commit hooks pass
- [ ] PR created and merged

---

## Review Findings (incorporated above)

### Security
- DENY on missing model field when allowlist configured ✅ Phase 3
- Case-insensitive model comparison ✅ Phase 3
- Validate timezone at enrollment ✅ Phase 5
- Body size already handled by existing BodySizeLimitMiddleware ✅

### Product
- Configuration path via CLI ✅ Phase 5
- Rules update without re-enrollment ✅ Phase 5
- Structured denial errors with state + remediation ✅ Phase 1
- Reprioritized: TokenBudget first ✅ Phase 2

### Brutus
- Body pre-read, pass bytes to rules ✅ Phase 0
- spend_log 90-day retention ✅ Phase 0
- Drop "mode-agnostic" label — these are V1/SQLite implementations ✅
- Realistic timeline: 8-10 days ✅

### Acknowledged (no action)
- TOCTOU on TokenBudget — same as SpendCap, documented
- JSON-in-TEXT columns — fine at 1-5 enrollments
- zoneinfo in Docker — works in bookworm

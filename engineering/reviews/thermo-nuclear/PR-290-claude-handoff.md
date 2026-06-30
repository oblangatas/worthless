# PR #290 — Claude review handoff

**URL:** https://github.com/shacharm2/worthless/pull/290
**Branch:** `gsd/wor-193-wave3-717-integration` → **`gsd/wor-193-service-lifecycle`** (#289)
**Stack position:** 3 of 4
**Tip:** `173f4ea1` (5 commits)
**Linear:** WOR-723 / WOR-717 integration follow-through

## One-line truth

**Proves** WOR-717 with integration tests (Popen contract, service-healthy skip) + user-flow journeys; marks **`start_daemon`** deprecated in CHANGELOG/docstring — not the full WOR-724 adversarial matrix (**#292**).

## What this PR is NOT

- `refuse_foreign_unit()` on all mutators (**#292**)
- Managed-up reclaim, Fernet SERVICE_MANAGED hardening, live packs (**#292**)
- Default exit **2** on stopped/failed service (**#292**)
- WOR-724 close (verification doc still has backlog rows)

## What landed (review focus)

| Area | Files | Claim |
|------|-------|-------|
| Integration | `tests/cli/test_wor717_integration.py` | Popen argv/env, service-healthy no-respawn |
| User flows | `tests/user_flows/test_native_cli_journeys.py` | Second `--yes` idempotency (mock seam — fixed in #292) |
| Service backends | `tests/cli/test_service_backends.py` | Extended coverage |
| Deprecation | `CHANGELOG.md`, `up.py` docstring | `start_daemon` legacy, v1.2 removal note |
| Verification | `engineering/testing/wor-193-wave-verification.md` | Wave status tracking |
| E2E trim | `tests/test_e2e_default_command.py` | Aligned with supervised path |

## Review prompts for Claude

```
Review PR #290 diff vs base gsd/wor-193-service-lifecycle.

1. WOR-717 AC: Do integration tests prove subprocess contract (argv[0], env, detach) not just mocks?
2. Service-managed skip: When launchd reports healthy + pidfile matches, is respawn prevented?
3. Idempotency test: Does test_wor717 / user_flow mock the right seam (detect_proxy_runtime vs _proxy_is_running)?
4. Deprecation: CHANGELOG + docstring sufficient? Any remaining start_daemon call sites in product path?
5. Honesty: Does this PR claim WOR-717 "done" — and is anything still delegated to #292?

Diff:
  git fetch origin gsd/wor-193-service-lifecycle gsd/wor-193-wave3-717-integration
  git diff origin/gsd/wor-193-service-lifecycle...origin/gsd/wor-193-wave3-717-integration

Focus paths:
  tests/cli/test_wor717_integration.py
  tests/user_flows/test_native_cli_journeys.py
  CHANGELOG.md
  src/worthless/cli/commands/up.py  (start_daemon docstring only)
```

## CI / gates

- **Green** on tip `173f4ea1` — Test ubuntu + User flows
- Verify: `gh pr checks 290`

## Suggested local tests

```bash
uv run pytest tests/cli/test_wor717_integration.py tests/user_flows/test_native_cli_journeys.py \
  tests/cli/test_service_backends.py -q
```

## Depends on / blocks

- **Requires:** #288 + #289 (review against #289 branch)
- **Blocks:** #292

## Note for stack reviewer

#292 **fixes** idempotency mock seams introduced/ exposed here (`detect_proxy_runtime` vs `_proxy_is_running`). If reviewing #290 in isolation, flag the seam; if reviewing after #292, confirm #292 resolves it.

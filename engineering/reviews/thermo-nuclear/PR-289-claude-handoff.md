# PR #289 — Claude review handoff

**URL:** https://github.com/shacharm2/worthless/pull/289
**Branch:** `gsd/wor-193-service-lifecycle` → **`gsd/wor-193-wave1-service-skeleton`** (#288)
**Stack position:** 2 of 4
**Tip:** `4e424f39` (3 commits)
**Linear:** WOR-717 (trust boundary — sidecar-supervised default start)

## One-line truth

Bare **`worthless`** after lock starts the proxy via **`start_supervised_proxy()`** (detached `worthless up` with sidecar), **not** sidecar-less `start_daemon()` — unit/mocked tests only; full subprocess ACs in **#290**.

## What this PR is NOT

- Integration tests for Popen argv/env/session (**#290**)
- Service-healthy “do not respawn” under launchd (**#290** / **#292**)
- Foreign-unit guards (**#292**)
- Deprecation CHANGELOG entry for `start_daemon` (**#290**)

## What landed (review focus)

| Area | Files | Claim |
|------|-------|-------|
| Supervised start | `commands/up.py` | `start_supervised_proxy()` — detached up, env wiring |
| Default path | `default_command.py` | `_ensure_proxy_running()` calls supervised start |
| Unit tests | `tests/test_cli_up.py`, `tests/test_cli_default.py` | Mocked supervised start wiring |
| Conftest | `tests/conftest.py` | Autouse mock updated for new path |
| User flow stub | `tests/user_flows/test_native_cli_journeys.py` | Minor alignment |

## Review prompts for Claude

```
Review PR #289 diff vs base gsd/wor-193-wave1-service-skeleton.

1. Trust boundary: Does every bare `worthless --yes` path that needs a proxy go through start_supervised_proxy (not start_daemon)?
2. Env hygiene: WORTHLESS_HOME, port, fernet transport — anything leak to child stderr or wrong cwd?
3. Idempotency: When proxy already running, does this PR skip spawn? (May be incomplete — flag gaps for #290.)
4. Failure modes: Supervised start failure — exit code, user message, key material in output?
5. Tests: Are mocks testing the real call graph or a stale seam (_proxy_is_running vs detect_proxy_runtime)?

Diff:
  git fetch origin gsd/wor-193-wave1-service-skeleton gsd/wor-193-service-lifecycle
  git diff origin/gsd/wor-193-wave1-service-skeleton...origin/gsd/wor-193-service-lifecycle

Focus paths:
  src/worthless/cli/commands/up.py  (start_supervised_proxy)
  src/worthless/cli/default_command.py
  tests/test_cli_up.py
  tests/test_cli_default.py
```

## CI / gates

- **Green** on tip `4e424f39` — Test ubuntu + User flows
- Verify: `gh pr checks 289`

## Suggested local tests

```bash
uv run pytest tests/test_cli_up.py tests/test_cli_default.py -k "supervised or Sidecar" -q
```

## Depends on / blocks

- **Requires:** #288 merged (or review against #288 branch)
- **Blocks:** #290, #292

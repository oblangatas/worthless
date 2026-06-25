# PR #288 — Claude review handoff

**URL:** https://github.com/shacharm2/worthless/pull/288
**Branch:** `gsd/wor-193-wave1-service-skeleton` → **`main`**
**Stack position:** 1 of 4 (merge first)
**Tip:** `174d5ebd` (8 commits)
**Linear:** WOR-193 / WOR-174 / WOR-175 (wave 1a skeleton)

## One-line truth

First-class **`worthless service`** CLI (launchd + systemd), unit templates, proxy-state detection, and default-command hints when a platform service exists but is stopped — **plumbing only**, not adversarial hardening (that lands in #292).

## What this PR is NOT

- Sidecar-supervised default start (WOR-717 → **#289**)
- WOR-717 integration / subprocess contract tests (**#290**)
- Foreign-unit refusal, managed-up reclaim, WOR-724 matrix (**#292**)
- Full WOR-435 uninstall / machine purge

## What landed (review focus)

| Area | Files | Claim |
|------|-------|-------|
| Service CLI | `src/worthless/cli/commands/service/*` | install/uninstall/status/start/stop/restart/logs |
| Unit templates | `templates.py`, `launchd.py`, `systemd.py` | Render plist/unit with `WORTHLESS_HOME`, port, log path |
| Proxy state | `service/proxy_state.py` | `detect_proxy_runtime`, service vs health |
| Service-managed up | `commands/up.py` (partial) | `WORTHLESS_SERVICE_MANAGED=1` idempotent path (early) |
| Default hints | `default_command.py` | Hint `worthless service start` when unit installed + stopped |
| Process helpers | `process.py` | `is_service_managed`, pid/health helpers |
| Docs | `docs/install/mac.md`, `linux.md`, agent schema | Install paths for service |
| Tests | `tests/cli/test_service*.py`, `test_proxy_state.py`, `test_cli_default.py` | Mocked backends + template tests |

## Review prompts for Claude

```
Review PR #288 diff vs main.

1. Architecture: Is the service module boundary clean (launchd vs systemd vs shared _common)? Any mutator missing from the public CLI surface?
2. Security (light): Do templates embed secrets? Is WORTHLESS_HOME injection safe in plist/unit lines?
3. Correctness: detect_proxy_runtime — when service STOPPED but /healthz answers, what happens? (Note: ordering may change in #292.)
4. UX: Default command hints — accurate strings, exit codes (exit 2 hardening is #292)?
5. Tests: Are backend tests mocked appropriately? What's untested that #290/#292 must cover?
6. Docs: Do install docs match actual unit paths and commands?

Diff:
  git fetch origin main gsd/wor-193-wave1-service-skeleton
  git diff origin/main...origin/gsd/wor-193-wave1-service-skeleton

Focus paths:
  src/worthless/cli/commands/service/
  src/worthless/cli/default_command.py
  src/worthless/cli/commands/up.py
  tests/cli/test_service_backends.py
  tests/cli/test_proxy_state.py
```

## CI / gates

- **Green** on tip `174d5ebd` — Test ubuntu py3.10/3.13 + User flows
- Verify: `gh pr checks 288`
- CodeRabbit: check for unresolved threads before merge

## Suggested local tests

```bash
uv run pytest tests/cli/test_service_backends.py tests/cli/test_service_common.py \
  tests/cli/test_proxy_state.py tests/test_cli_default.py -q
uv run ruff check src/worthless/cli/commands/service/
```

## Depends on / blocks

- **Blocks:** #289, #290, #292 (entire stack)
- **Merge:** Squash or merge to `main` first; retarget #289 if needed

# PR #292 — Pass-2 panel verdict

**Verdict: GO** (pass-1 MUST-FIX + pass-2 CI fixes landed at `cb53166`+; re-verify CI after openclaw/fernet-env fix).
Findings verified against the canonical `pr-292-head` git ref (not a working tree).

Repo: shacharm2/worthless · Head: `gsd/wor-193-wave3b-adversarial` → `main`.

---

## Why CI is red

### Cluster A — `tests/cli/test_service_cli.py::test_stop_invokes_backend` (unit, py3.10 + py3.13)
**STALE TEST — not a regression.** `refuse_foreign_unit` correctly changed `stop()` → `stop(home)`
(`commands/service/launchd.py:129`, `systemd.py:152`, called at `commands/service/__init__.py:169`).
The test asserts a zero-arg `stop.assert_called_once_with()`. Owned-unit stop is **not** broken.
→ Fix the test, do not revert the guard.

### Cluster B — 3 user-flow failures (macos-15 + ubuntu-24.04, py3.13): DROPPED #290 fixes
All in `src/worthless/cli/default_command.py`:
- **Exit code:** stopped/failed service hits `raise typer.Exit()` (lines 144/163/171/176) = **exit 0**;
  tests expect **2** (`test_default_with_{stopped,failed}_service_hints_without_supervised_start`).
- **Double-spawn:** `detect_proxy_runtime` is called **twice** — line 68 (`_proxy_is_running`) and
  line 76 (`_service_start_hint`). Second invocation re-spawns supervised → `supervised_calls == 2`,
  expected 1 (`test_default_second_invocation_skips_supervised_start`). Reproduced live by python-pro.

---

## Verified state (canonical ref)

| MUST-FIX | Status |
|---|---|
| 4 · `refuse_foreign_unit` on all mutators | PRESENT & complete (install/start/stop/uninstall, both backends) |
| 1 · keystore `_validate_fernet_file` S_ISREG | PRESENT but **bypassed on interactive read** — `keystore.py:324` passes `validate=_service_managed()` (False interactively); lines 208/301 correctly pass `validate=True` |

**Rebase-drop check:**
| # | Item | Status | Evidence |
|---|------|--------|----------|
| a | symlink `unit_file_matches_home` | PRESENT | `commands/service/_common.py` realpath match |
| b | `detect_proxy_runtime` service-before-health | **DROPPED** | `commands/service/proxy_state.py:43` probes health before service state — orphan pidfile + healthy port masks a FAILED/STOPPED unit |
| c | exit 2 on stopped service | **DROPPED** | `default_command.py:144/163/171/176` bare `typer.Exit()` |
| d | Dockerfile digest pin | PRESENT | `tests/install_fixtures/Dockerfile.service-lifecycle-live-linux` |

> Note: an earlier reviewer flagged "guard missing on mutators" — that was a **false positive** from
> reading a stale working tree. The guard is present on the canonical ref; disregard.

---

## Minimum worklist to green + safe

1. **`src/worthless/cli/default_command.py`** — call `detect_proxy_runtime(home)` **once** in
   `_ensure_proxy_running`; branch on the single `ProxyRuntimeState` (`.running` for early-return,
   `.service_state` for the hint); `raise typer.Exit(code=2)` on STOPPED/FAILED.
   → fixes all 3 Cluster B failures.
2. **`tests/cli/test_service_cli.py:153`** — `mock_backend.stop.assert_called_once_with(<home>)`
   (or loosen to `assert_called_once()`). → fixes Cluster A on py3.10 + py3.13.
3. **`src/worthless/cli/keystore.py:324`** — `validate=True` (unconditional gate; close the
   interactive-read hole). Security FIX-NOW.
4. *Recommended:* **`src/worthless/cli/commands/service/proxy_state.py`** — restore
   service-state-before-health ordering so an orphan pidfile doesn't mask a FAILED/STOPPED unit
   (the actual W3-ADV-3/9 orphan-latch fix).

## Defer (bead)
- `_managed_sidecar_healthy` HELLO fallback — narrow mid-enrollment false-negative only
  (`commands/up.py:89-121`). Not a blocker.

## Suggested PR-body "Why" line
> A failed or stopped service must halt the launch with a clear error (exit 2), not silently spawn a
> second proxy — the rebase dropped that guard and the double-detect; this restores both.

## Verify after fix
```bash
uv run pytest tests/cli/test_service_cli.py tests/user_flows/test_native_cli_journeys.py -o addopts= -q
```

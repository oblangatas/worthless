# PR #292 — Pass-2 review handoffs (run in parallel after push)

**When:** After Cursor lands pass-1 (rebase onto `main`, MUST-FIX 1–5) and `gh pr checks 292` is green or running.

**Base:** `main` (includes merged #290). **Head:** `gsd/wor-193-wave3b-adversarial`.

**Verify locally:**
```bash
uv run pytest tests/cli/test_service_backends.py tests/cli/test_start_supervised_proxy_integration.py tests/test_keystore.py tests/cli/test_service_up_managed.py -o addopts= -q
```

---

## Claude (security + thread closure)

```
Review PR #292 on shacharm2/worthless (branch gsd/wor-193-wave3b-adversarial → main).

Context: Wave 3b adversarial guards. #288–#290 already merged. Pass-1 fixed:
- keystore _validate_fernet_file S_ISREG guard
- test_keystore chmod 0o644 on loose-perms test
- launchd plist positive unit_file_matches_home test
- refuse_foreign_unit on all service mutators (launchd/systemd)
- wor193-stack-security.md thread count + L1/L2 fixes

Focus:
1. Confirm MUST-FIX items are complete; list any new blockers only.
2. P2/P3 follow-ups from prior review — fix vs defer with bead ID:
   - up.py orphan latch when read_pid→None + port healthy (W3-ADV-3/9)
   - keystore interactive read stat gate unconditional
   - _managed_sidecar_healthy HELLO fallback when enrollments exist
3. DO NOT re-litigate: unit_file_matches_home exact-match (#290), reclaim no-kill on PID mismatch, _proxy_is_running wrapper.

Output: merge verdict (GO/HOLD), bullet worklist if HOLD, suggested PR body "Why" line if still wrong.
```

---

## Codex (regression + diff scope)

```
PR #292 diff vs main — regression review only.

Stack: worthless WOR-193 wave3b. Prior merged: #290 supervised proxy hardening.

Check:
1. refuse_foreign_unit does not break owned-unit install/start/stop on macOS + Linux test matrix.
2. keystore WORTHLESS_SERVICE_MANAGED read order + _validate_fernet_file does not break enroll/lock roundtrip tests.
3. Rebase did not drop #290 fixes: symlink unit_file_matches_home, detect_proxy_runtime service-before-health, exit 2 on stopped service, Dockerfile digest.
4. Test renames: test_start_supervised_proxy_integration.py (not test_wor717_integration.py).

Output: cleared areas + likely regressions only. No style nits.
```

---

## Timing cheat sheet

| Phase | Who | Action |
|-------|-----|--------|
| Now | Cursor | pass-1 commit + push |
| T+0 | You | Paste Claude + Codex prompts above (parallel) |
| T+CI | Cursor | triage any new findings |
| T+green | You | "merge #292" |

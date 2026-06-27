# Implementation Plan: WOR-276 — Recovery works after a bad lock

## 1. Goal (user-outcome)

> *"I corrupted my `.env`. I ran `worthless restore`. I got my file back. I didn't read any docs."*

This ticket ships Feature B of epic WOR-252. Feature A (WOR-275, `safe_rewrite` gate) refuses destructive writes; this ticket puts a **net** under the refusal by backing up pre-write bytes out-of-repo and exposing a one-command recovery path. A+B must ship together — A alone is a UX regression for anyone whose `.env` was corrupted before the gate existed.

## 2. Preconditions

- WOR-275 (`safe_rewrite` gate + `_hook_before_replace` seam + `UnsafeReason` enum) merged into the epic branch `feat/wor-252-epic`.
- Local branch `feat/wor-276-recovery-works` cut from the current epic tip, which already has the `_hook_before_replace` seam at `src/worthless/cli/safe_rewrite.py:756` and the 13-member `UnsafeReason` enum at `src/worthless/cli/errors.py:32-52`.
- `main` merged into the epic branch before cutting WOR-276 (standard epic merge hygiene).
- `tests/safe_rewrite/` layout (15 files, see `conftest.py`) treated as the reference style.

## 3. Architecture — file map

### New files

| Path | Purpose |
|---|---|
| `src/worthless/cli/backup.py` | Pure backup module. Owns `write_backup(target, pre_bytes, *, repo_root) -> Path`, bucket-path computation (`_bucket_for_repo`), rotation (`_rotate_bucket`), first-run marker (`_emit_first_run_notice`), and the `_BACKUP_COUNTER` per-process monotonic int. No typer, no CLI. |
| `src/worthless/cli/commands/restore.py` | The `restore` Typer command group. Wraps `safe_restore()` (see §4) for the write path, owns `--list` / `--all-repos` / interactive picker / `--force` flags, stdin prompt handling. |
| `docs/RECOVERY.md` | One-page doc shipped in the wheel via `pyproject.toml` `[tool.hatch.build.targets.wheel.force-include]` (or package-data equivalent). First fenced block is literally `worthless restore`. |
| `tests/backup/__init__.py` + `tests/backup/conftest.py` | New test package for backup-level unit tests (mirrors `tests/safe_rewrite/conftest.py` style: `tmp_repo`, `fake_xdg`, `fake_time_ns` fixtures). |
| `tests/backup/test_backup_writes.py` | 14 tests on the backup write path. |
| `tests/backup/test_restore.py` | 9 tests on the restore command surface. |
| `tests/backup/test_first_run.py` | 6 tests on first-run output + RECOVERY.md shipping. |
| `tests/safe_rewrite/test_safe_restore.py` | 2 tests proving `safe_restore()` skips the delta gate but still enforces all others. |
| `tests/e2e/__init__.py` + `tests/e2e/test_restore_cli.py` | 3 end-to-end tests against the real CLI entrypoint (subprocess-style). |

### Edited files

| Path | Edit |
|---|---|
| `src/worthless/cli/safe_rewrite.py` | (a) Refactor the body of `safe_rewrite()` into `_safe_rewrite_core(target, new_content, *, skip_delta: bool, expected_baseline_sha256)`. `safe_rewrite()` keeps its signature and calls `_safe_rewrite_core(..., skip_delta=False)`. (b) Add new public `safe_restore(target, backup_bytes)` that calls `_safe_rewrite_core(..., skip_delta=True)`. (c) Wire `_hook_before_replace` default to `backup.write_backup` bound via a `set_backup_hook()` indirection (keeps existing hook tests happy). |
| `src/worthless/cli/errors.py` | Add `UnsafeReason.BACKUP = "backup"` as the 14th enum member. |
| `src/worthless/cli/__main__.py` | Register `restore` command group. |
| `tests/safe_rewrite/test_chaos.py` | Add 3 tests: orphan-allowlist for `*.bak.tmp-*`, `*.bak` after SIGKILL between backup-rename and target-rename, concurrent same-nanosecond collision avoidance. |
| `pyproject.toml` | Include `docs/RECOVERY.md` as package data so `importlib.resources.files("worthless").joinpath("RECOVERY.md")` resolves. |
| `README.md` | Link to `docs/RECOVERY.md` (acceptance-checklist item). |

### Bucket path contract (locked)

```text
$XDG_DATA_HOME/worthless/backups/<bucket>/<basename>.<ISO8601_ns>.<pid>.<counter>.bak
```

- `bucket = hashlib.sha256(str(repo_root.resolve()).encode("utf-8")).hexdigest()` — 64 hex chars.
- `$XDG_DATA_HOME` defaults to `~/.local/share` when unset/empty (per XDG spec).
- Bucket dir created with `os.mkdir(path, mode=0o700)`; if `FileExistsError`, `os.stat(path).st_mode & 0o777` must equal `0o700` or we raise `UnsafeReason.BACKUP`.
- Symlinks to the same repo resolve to the same bucket (intentional — same underlying repo). Worktrees and bind-mounts produce distinct buckets (their absolute resolved paths differ).
- POSIX-only. Windows is refused at the existing `_PLATFORM` gate in `safe_rewrite.py`.

## 4. Delta-gate decision — option (b)

**Problem:** `safe_rewrite()` refuses writes whose delta from current bytes exceeds the threshold (`UnsafeReason.DELTA`). A restore by definition replaces the whole file with historical bytes, so the delta gate would reject legitimate recovery.

**Rejected option (a):** "Restore bypasses `safe_rewrite` entirely." Loses the symlink / size / TOCTOU / containment / path-identity gates. Not acceptable — restore is exactly the moment we need those gates most.

**Chosen option (b):** Extract the body of `safe_rewrite()` into a private `_safe_rewrite_core(target, new_content, *, skip_delta: bool, expected_baseline_sha256)`. Gate dispatch in `_check_size_sniff_delta` becomes `if not skip_delta: _check_delta(...)`; size + sniff checks still run. Public surface:

```python
def safe_rewrite(target, new_content, *, expected_baseline_sha256=None):
    return _safe_rewrite_core(target, new_content, skip_delta=False,
                              expected_baseline_sha256=expected_baseline_sha256)

def safe_restore(target, backup_bytes):
    return _safe_rewrite_core(target, backup_bytes, skip_delta=True,
                              expected_baseline_sha256=None)
```

`skip_delta` is **not** exposed as a kwarg on `safe_rewrite()` — callers cannot opt out of the delta gate, only `safe_restore()` can. This is enforced by test `test_safe_rewrite_public_surface_has_no_skip_delta`.

Two tests prove the contract: `test_safe_restore_bypasses_delta_only` (writes 10 KiB over a 10-byte file — would be rejected by `safe_rewrite` with `UnsafeReason.DELTA` but succeeds via `safe_restore`); `test_safe_restore_still_enforces_symlink_size_toctou` (replaces target with a symlink, a 2 GiB file, and a mid-flight inode swap — each raises the corresponding `UnsafeReason`).

## 5. Test plan — 37 core tests + 7 bonus across 6 files

Core 37 are the acceptance surface. Bonus 7 (flagged B1–B7 in §5a) came out of the security / chaos / sre review pass and strengthen the existing RED without expanding scope.

### Core tests

### `tests/backup/test_backup_writes.py` — 14 tests

1. `test_backup_written_on_successful_rewrite` — content == pre-write bytes.
2. `test_backup_path_is_sha256_of_resolved_repo_root`.
3. `test_backup_filename_format_all_four_components` — regex `<basename>\.\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}\.\d+\.\d+\.bak`.
4. `test_backup_file_mode_is_0600`.
5. `test_bucket_dir_mode_is_0700`.
6. `test_backup_refuses_if_bucket_dir_has_weaker_mode` — `UnsafeReason.BACKUP`.
7. `test_backup_write_failure_aborts_rewrite` — patch `write_backup` to raise `OSError(ENOSPC)`; target untouched, gate raises `UnsafeReason.BACKUP`.
8. `test_backup_file_fsync_before_rename` — instrument via `_hook_after_backup_fsync`.
9. `test_backup_dir_fsync_before_return`.
10. `test_backup_atomic_via_tmp_rename` — no `.bak.tmp-*` left post-success.
11. `test_backup_rotation_keeps_last_50` — 55 sequential rewrites → exactly 50 `.bak` files, newest kept.
12. `test_backup_rotation_failure_does_not_abort_write` — unlink raises; write succeeds; warning logged.
13. `test_xdg_data_home_honoured_when_set` — `$XDG_DATA_HOME=/tmp/x` → `/tmp/x/worthless/backups/...`.
14. `test_xdg_data_home_empty_falls_back_to_local_share` — per XDG spec unset *and* empty both fall back.

### `tests/backup/test_restore.py` — 9 tests

15. `test_restore_list_empty_exits_zero` — fresh repo, no output, exit 0.
16. `test_restore_list_newest_first` — 3 backups, descending timestamp.
17. `test_restore_file_writes_via_safe_restore` — instrumented `safe_restore` is called with backup content.
18. `test_restore_prompts_when_target_diverged_since_backup` — stdin `n\n` → exit 1, target untouched; stdin `y\n` → restored; non-TTY stdin + no `--force` → exit 2.
19. `test_restore_force_bypasses_prompt_but_not_gate`.
20. `test_restore_all_repos_lists_every_bucket_grouped`.
21. `test_restore_interactive_picker_accepts_number_and_q` — `1\n` picks, `q\n` quits exit 0.
22. `test_restore_refuses_symlinked_backup_file` — symlinked `.bak` → `UnsafeReason.SYMLINK` propagates.
23. `test_restore_nonexistent_target_exits_nonzero`.

### `tests/backup/test_first_run.py` — 6 tests

24. `test_first_run_prints_backup_path_once` — second call silent.
25. `test_first_run_marker_file_created` — `.first-run-seen` exists in bucket.
26. `test_first_run_marker_mode_is_0600`.
27. `test_first_run_message_goes_to_stderr_not_stdout`.
28. `test_recovery_md_shipped_in_wheel` — `importlib.resources.files("worthless").joinpath("RECOVERY.md").is_file()`.
29. `test_recovery_md_first_fenced_block_is_the_command` — parses the markdown, asserts first ``` ``` ``` block contains `worthless restore`.

### `tests/safe_rewrite/test_chaos.py` additions — 3 tests

30. `test_sigkill_between_backup_write_and_rename_leaves_no_ghost_bak_tmp` — allowlist allows `.env.tmp-*`, `.env.staging-*`, `*.bak.tmp-*`.
31. `test_sigkill_between_backup_rename_and_target_rename_leaves_intact_bak` — backup survives, original target unchanged.
32. `test_concurrent_rewrites_do_not_collide_on_backup_filename` — (a) two processes, same `time_ns`, different `<pid>`; (b) same process, monkeypatched `time.time_ns` returning constant value, counter differs; `O_EXCL` trips `EEXIST` if both safeties fail.

### `tests/e2e/test_restore_cli.py` — 3 tests

33. `test_lock_then_corrupt_then_restore_round_trip` — real `worthless lock`, corrupt `.env`, `worthless restore <target>` with stdin `y\n`; byte-identical. `--force` variant asserts same outcome without prompt.
34. `test_restore_preserves_bom_crlf_and_export_lines` — round-trip exotic content byte-identical.
35. `test_restore_after_aborted_write_has_nothing_to_restore` — simulate `safe_rewrite` refusal mid-flight; no `.bak` created, `restore --list` empty.

### `tests/safe_rewrite/test_safe_restore.py` — 2 tests

36. `test_safe_restore_bypasses_delta_only` — 10 KiB over 10-byte target succeeds via `safe_restore`, would fail via `safe_rewrite`.
37. `test_safe_restore_still_enforces_symlink_size_toctou_containment` — parametrized over each gate.

### 5a. Bonus tests — 7 from batch-A review (security / chaos / sre)

Added strictly to strengthen the existing RED. None change the public surface; they close gaps in the attack / failure matrix the core 37 don't cover.

**Security (3, land in `tests/backup/test_backup_writes.py`):**

- B1. `test_refuses_if_bucket_dir_is_preexisting_symlink` — bucket path already a symlink to attacker-controlled dir → `UnsafeReason.BACKUP` before any write.
- B2. `test_bucket_dir_opened_with_o_nofollow_o_directory` — spy on `os.open` of the bucket-dir fd; assert flags include `O_NOFOLLOW | O_DIRECTORY`.
- B3. `test_ghost_bak_tmp_unlinked_on_write_failure` — simulate fsync failure mid-backup; `.bak.tmp-*` must be unlinked before `UnsafeReason.BACKUP` propagates (no orphan under `0o600` perms).

**Chaos (4, land in `tests/safe_rewrite/test_chaos.py`):**

- B4. `test_enospc_during_backup_tmp_write` — inject `OSError(ENOSPC)` on the tmp write; target untouched, no `.bak.tmp-*` left behind.
- B5. `test_enospc_during_rotation_unlink` — errno-pin: rotation unlink raises `ENOSPC`; write still succeeds, rotation logs warning (rotation is best-effort).
- B6. `test_rotation_self_heals_from_51_plus_files` — seed bucket with 60 pre-existing backups; next write prunes back to 50 without raising.
- B7. `test_rotation_sort_survives_clock_anomalies` — parametrized over forward jump, zero-delta, and negative-delta `time_ns` sequences; `(ts_ns, counter)` sort keeps newest 50 correctly under each.

## 6. Commit sequence — 9 atomic commits, TDD-enforced

Each commit: (a) red tests first, (b) implementation, (c) cumulative green count matches the table below. A commit that claims N green but the dashboard shows < N is backed out.

| # | Commit message | Red tests added | Green after | Cumulative |
|---|---|---|---|---|
| 1 | `test(wor-276): red suite for backup write seam + UnsafeReason.BACKUP` | 1-14, 30-32, B1–B7 (tests/backup/test_backup_writes.py + chaos additions + bonus) | 0 green — all red, seam asserted by import-only | **0 / 37** |
| 2 | `feat(wor-276): add UnsafeReason.BACKUP + backup.py with write_backup + bucket path` | — | 1-6, 13, 14 green (happy-path writes + bucket mode + XDG) | **8 / 37** |
| 3 | `feat(wor-276): atomic tmp-rename + fsync + 0o600 + failure-aborts-write for backup` | — | 7-10 green (durability + abort on ENOSPC) | **12 / 37** |
| 4 | `feat(wor-276): rotate backups to last 50 per target, best-effort on failure` | — | 11, 12 green | **14 / 37** |
| 5 | `feat(wor-276): chaos-resistant backup window + orphan allowlist` | — | 30-32 green (cumulative chaos) | **17 / 37** |
| 6 | `refactor(wor-276): extract _safe_rewrite_core(skip_delta) + safe_restore()` + `test(wor-276): red suite for safe_restore` | 36, 37 | 36, 37 green | **19 / 37** |
| 7 | `feat(wor-276): worthless restore --list + --all-repos` + red suite for restore cmd | 15-23 | 15, 16, 20 green (read-only paths) | **22 / 37** |
| 8 | `feat(wor-276): worthless restore <target> + --force + interactive picker` | — | 17, 18, 19, 21, 22, 23 green | **28 / 37** |
| 9 | `feat(wor-276): first-run notice + RECOVERY.md shipped in wheel` + `test(wor-276): red e2e suite` + impl | 24-29, 33-35 | 24-29, 33-35 green | **37 / 37 — DONE** |

Progress dashboard command (run at any commit):

```bash
uv run pytest tests/backup/ tests/e2e/test_restore_cli.py \
              tests/safe_rewrite/test_chaos.py \
              tests/safe_rewrite/test_safe_restore.py \
              -n 0 -p no:rerunfailures -o "addopts=" --timeout=90 -v
```

## 7. Live checklist — 11 items

- [ ] **C1** — Branch `feat/wor-276-recovery-works` cut from epic tip with `main` merged in.
- [ ] **C2** — Red tests for backup write seam landed (tests 1-14 + chaos 30-32), all failing for correct reason.
- [ ] **C3** — `backup.py` implements `write_backup`, bucket path, rotation; tests 1-14 green.
- [ ] **C4** — Red tests for `safe_restore` landed (36, 37); both failing with ImportError / AttributeError.
- [ ] **C5** — Refactor `safe_rewrite.py` into `_safe_rewrite_core(skip_delta)` + public `safe_restore()`; tests 36, 37 green; all existing `tests/safe_rewrite/*` still green.
- [ ] **C6** — `_hook_before_replace` default bound to `backup.write_backup` via `set_backup_hook()`; existing hook-seam tests unaffected.
- [ ] **C7** — `commands/restore.py` registered in `__main__.py`; `worthless restore --help` exits 0; tests 15-23 green.
- [ ] **C8** — Chaos additions (30-32) use the orphan allowlist pattern; SIGKILL between backup-rename and target-rename leaves exactly one `.bak` and nothing else.
- [ ] **C9** — E2E tests (33-35) invoke the real `worthless` entrypoint via subprocess, not unit mocks.
- [ ] **C10** — `docs/RECOVERY.md` shipped in wheel; first fenced block is literally `worthless restore`; linked from README.
- [ ] **C11** — Full dashboard green on macOS + Linux CI; `worthless restore` appears in `--help`; no backup dir inside any fixture repo after full test run.

## 8. Risks & follow-ups

| Risk | Mitigation |
|---|---|
| **Rotation race** — two processes rotating the same bucket concurrently may double-unlink. | `os.unlink` wrapped in `try/except FileNotFoundError: pass`; rotation is best-effort and never aborts the write. |
| **NFS / CIFS fsync lies** — `os.fsync` on network mounts may return success without durability. | Documented in RECOVERY.md ("backups are local-disk guarantees only"); out of scope to detect. Follow-up ticket if user data shows NFS usage. |
| **Clock skew under `ntpd` step / DST** — `time.time_ns()` is monotonic-ish but not guaranteed; two rewrites could produce out-of-order timestamps. | `<counter>` is a per-process monotonic int that breaks ties; rotation sorts by `(timestamp_ns, counter)` tuple, not filename lexicographic, to survive backward clock jumps. Test 32b exercises this. |
| **Bucket bind-mount collision** — two bind-mounts of the same repo at different paths produce different buckets; user sees split backup history. | Documented; `--all-repos` surfaces all buckets so discovery still works. Acceptable given bind-mounts are advanced usage. |
| **`--list` UX for large backup counts** — 50 × N targets × M repos can be noisy. | Default `--list` scopes to current repo; `--all-repos` is opt-in. Follow-up: `--target <basename>` filter if feedback demands. |
| **`safe_restore` exposes a bypass vector** — if attacker can call `safe_restore` directly with hostile bytes, they bypass the delta gate. | `safe_restore` is still gated by symlink / size / TOCTOU / containment / path-identity; delta is the *only* gate skipped, and delta was already a soft gate (threshold-based), not a security boundary. Reviewed in C5. |

## 9. Definition of done

Run on a fresh `$HOME` container:

```bash
worthless lock
echo "OOPS" > .env
worthless restore   # no flags, no docs
```

File byte-identical to pre-lock content → done. 37 green tests are the evidence; the sentence is the definition.

# WOR-252 Sub-PR 1 — `safe_rewrite` Invariants Engine (v2)

**Ticket:** [WOR-252](https://linear.app/plumbusai/issue/WOR-252) (Urgent)
**Scope:** Part A (invariants 1–8 + 10). Invariant 9 is CLI-layer, out of scope.
**Branch:** `shacharm/wor-252-sub-pr-1-safe-rewrite-invariants` → `main`
**Revision:** v2.2 — post-expert review (brutus, security-auditor, chaos-engineer, qa-expert) + delta correction.

**v2.2 delta correction (post-implementation):** Lower bound on the shrink ratio was removed for single-line files. Realistic `worthless lock` of a long API key (165+ char OpenAI `sk-proj-`) produces ratio ~0.22, which the v2 0.25 floor rejected. Since single-line truncation has near-zero attack value (basename + path identity + sniff already block substitution), only the blowup ceiling remains. Two refusal tests flipped to acceptance; one new realistic-scenario test added.

---

## Changes vs v1

Four independent reviews converged on three product-killer bugs in v1 of the plan. v2 fixes them.

1. **TOCTOU was still open.** `os.replace(tmp_path, target_path)` is path-based. v1's `O_NOFOLLOW` protects the read fd but not the rename. Attacker swaps `.env → ~/.zshrc` symlink between fstat and replace → we clobber `.zshrc`. **This is literally the bug the ticket exists to prevent.** v2 uses `renameat2(RENAME_NOREPLACE)` on Linux and dev/ino re-check via `os.fstatat` elsewhere.
2. **Backup location was wrong (sub-PR 3 concern, but frozen now).** `./.worthless/backups/` in-project syncs to iCloud / Dropbox / OneDrive / `git add -f` / `npm publish` / Docker `COPY` / CI cache. v2 moves backups to `$XDG_DATA_HOME/worthless/backups/<repo-sha256>/` (macOS: `~/Library/Application Support/worthless/backups/<repo-sha256>/`). RECOVERY.md documents the absolute path. Recovery-without-binary still works.
3. **No concurrency lock.** Two `lock` invocations in different tmux panes pass invariants independently and clobber each other's decoys silently. v2 adds `fcntl.flock(fd, LOCK_EX | LOCK_NB)` on the opened fd at function entry.

Also rolled in: literal `.env` basename equality (user mandate), full-file dotenv sniff (4 KiB was bypass-by-construction), delta bound widened to 0.25×–4× (first-run 200-char-key → 40-char-decoy is 5× shrink), `F_FULLFSYNC` on Darwin, sha256-on-refusal negative-space tests, deterministic mock-based TOCTOU tests (no thread races in CI), single public error code `UNSAFE_REWRITE_REFUSED` with granular reason in debug logs only.

---

## Files

### New
- `src/worthless/cli/safe_rewrite.py`
- `tests/safe_rewrite/test_basename.py`
- `tests/safe_rewrite/test_path_identity.py`
- `tests/safe_rewrite/test_special_files.py`
- `tests/safe_rewrite/test_containment.py`
- `tests/safe_rewrite/test_size.py`
- `tests/safe_rewrite/test_sniff.py`
- `tests/safe_rewrite/test_delta.py`
- `tests/safe_rewrite/test_atomic.py`
- `tests/safe_rewrite/test_flock.py`
- `tests/safe_rewrite/test_toctou.py`
- `tests/safe_rewrite/test_platform.py`
- `tests/safe_rewrite/test_sanitization.py`
- `tests/safe_rewrite/conftest.py` — shared fixtures

### Modified
- `src/worthless/cli/errors.py` — one public code `UNSAFE_REWRITE_REFUSED`; internal granular reasons logged at DEBUG.

---

## Frozen decisions

1. **Basename: literal `.env` only.** Equality check, not regex. Refuse `.env.local`, `.env.production`, `.env.example`, `.env.bak`, `.env.save`. Denylist (`.zshrc`, `.bashrc`, `.profile`, `.netrc`, `id_rsa`, `id_ed25519`, `credentials`, `config`, `authorized_keys`, `known_hosts`) retained as belt-and-suspenders.
2. **Case-sensitive on all OSes.** Refuse `.ENV` even on APFS.
3. **Non-existent target refused.** This is a *rewrite*.
4. **Windows refused at entry.**
5. **Backup location (Part B, frozen now):** `$XDG_DATA_HOME/worthless/backups/<repo-sha256>/<ISO8601>.env` with 1-ns suffix on collision. Never in project dir. No encryption. Mode 0600.
6. **Backup-directory unwritable → refuse the lock.** Never proceed backup-less. `ErrorCode.BACKUP_UNAVAILABLE`.
7. **Error ordering:** symlink check fires before basename check, so `.zshrc` symlinked to `.env` reports "symlink refused", not "not .env".
8. **Public error is `UNSAFE_REWRITE_REFUSED` only.** Granular cause at DEBUG level and in exception attribute — not user-facing.
9. **Tmp-file naming:** `.env.tmp-<secrets.token_hex(16)>` (128-bit entropy). Max 3 retries on `EEXIST`. No loop.
10. **Durability:** `F_FULLFSYNC` on Darwin (via `fcntl.fcntl`), plain `fsync` elsewhere. Dir fd fsynced. NFS/tmpfs caveat surfaced in user-facing lock output, not just docs.

---

## Invariant check order (revised)

1. Platform refuse (Windows, O(1)).
2. `os.lstat(user_arg)` — **symlink check first** so error message matches the actual problem.
3. Basename equality against `.env` + denylist.
4. Special-file guard (FIFO/device/socket) via lstat.
5. `os.open(target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)` — fails on symlink (defense in depth after step 2).
6. `fstat(fd)` → `st_size`, `st_mode`, `st_dev`, `st_ino`. Anchor for TOCTOU.
7. **`fcntl.flock(fd, LOCK_EX | LOCK_NB)`** — concurrent-lock defense.
8. Path identity: `realpath(user_arg) == realpath(target)`.
9. Repo containment + mount-ID check (`os.statvfs(fd).f_fsid` == repo fsid). Defeats bind-mount escapes. **Semantics**: "contained" means *descendant of `repo_root`* — monorepo / subpackage `.env` files (e.g. `repo/packages/api/.env`) are accepted. Defense-in-depth against nested-checkout attacks is provided by the basename allowlist + realpath resolution + fsid equality; an additional direct-child-only rule would add no bar against any concrete threat.
10. Size bound (≤1 MiB, ≤500 lines, read-up-to-1-MiB from fd).
11. Dotenv-parse full file (whole buffer, not 4 KiB sniff).
12. Delta shape — `len(new_content)` in `[0.25 × st_size, 4 × st_size]` or file was empty.
13. Atomic write:
    - Open `target.tmp-<token_hex(16)>` with `O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW`, mode 0600.
    - Write new_content. `fsync(tmp_fd)` (+ `F_FULLFSYNC` on Darwin).
    - `fsync(dir_fd)`.
    - **Re-stat target via `fstatat(dir_fd, ".env", AT_SYMLINK_NOFOLLOW)`** — assert `st_dev`/`st_ino` match step 6. Refuse if changed.
    - `renameat2(dir_fd, tmp_name, dir_fd, ".env", RENAME_NOREPLACE)` on Linux. `os.replace` + fstatat-recheck elsewhere.
    - `fsync(dir_fd)` final.
    - Release flock last.

Steps 2, 5, 13 are three layers of symlink defense. Steps 6 + 13-recheck pincer the TOCTOU window.

---

## Module structure

```text
safe_rewrite.py
├── class UnsafeRewriteRefused(WorthlessError)     # single public error
│   └── .reason: UnsafeReason enum (9 internal values)
├── _BASENAME = ".env"
├── _BASENAME_DENYLIST: frozenset[str]
├── _MAX_BYTES = 1 << 20
├── _MAX_LINES = 500
├── _DELTA_MIN = 0.25
├── _DELTA_MAX = 4.0
├── _TMP_RETRIES = 3
├── _SHELL_MARKERS: tuple[bytes, ...]
├── _fullfsync(fd)                                 # Darwin F_FULLFSYNC, POSIX fsync
├── _flock_exclusive_nonblocking(fd)
├── _check_platform()
├── _check_basename(path)                           # equality
├── _check_path_identity(user_arg, target)
├── _lstat_chain_no_symlinks(path)                  # for backup-dir (sub-PR 3 uses)
├── _check_special_file(path)
├── _open_nofollow_rdonly(path) -> fd
├── _check_containment(target, repo_root, allow_outside, fd)
├── _read_and_check_size(fd, st_size)
├── _check_dotenv_full(buf)                         # whole file, not 4 KiB
├── _check_delta(old_size, new_size)
├── _atomic_write(target, new_content, dir_fd, baseline_stat)
└── def safe_rewrite(target, new_content, *, original_user_arg, repo_root=None, allow_outside_repo=False, _hook_before_replace=None)
                                                    # hook: callback sub-PR 2 uses to insert shard-write
```

Single exposed exception. Callers see `UnsafeRewriteRefused` with an opaque message. Logs carry the reason code.

---

## Test plan — red-first order

Group 0 (`test_module_importable`) **deleted** — tautology; first real test imports the module.

**First test written:** `test_refuses_symlink_to_zshrc` — symlink `.env → ~/.zshrc`, call `safe_rewrite`, assert refusal AND `.zshrc` sha256 unchanged. This is the user's red line; it's the first test to go red.

### File-by-file breakdown

`test_basename.py` — 21 tests: `.zshrc`, `.bashrc`, `.profile`, `.netrc`, `id_rsa`, `id_ed25519`, `credentials`, `config`, `authorized_keys`, `known_hosts`, `.env.local` (refused), `.env.production` (refused), `.env.example` (refused), `.env.bak` (refused), `.ENV` (refused), `.env` (accepted), `notes.txt`, `..env`, `.env/`, `.env` + trailing U+0020 space, NUL-byte in path.

`test_path_identity.py` — 8 tests: symlink-to-zshrc (**first red test**), symlink-to-other-env, original-arg-mismatch, regular-file, `//` in path, `../.env`, trailing-slash, hardlink-to-denylisted-inode.

`test_special_files.py` — 5 tests: FIFO, `/dev/null`, `/proc/self/environ`, AF_UNIX socket, character-device path.

`test_containment.py` — 6 tests: outside-repo refused, override accepts, `repo_root=None` skips, realpath-escape, bind-mount-escape (`unshare --mount`), mount-ID mismatch.

`test_size.py` — 8 tests: 0 bytes (accept), 1 byte, 1 MiB exact, 1 MiB + 1 (refuse), 499 lines, 500 lines, 501 lines, 500-line no-trailing-newline boundary.

`test_sniff.py` — 9 tests: shebang, alias, export, function, source, if/case, heredoc, eval-chain, comments+blanks accept, quoted values accept, bypass-attempt-first-4KiB-clean-then-shellcode (v1-regression test, proves we scan full file).

`test_delta.py` — 7 tests: 10× blowup refused, 5× blowup (realistic first-run 200-char→40-char) accepted under 0.25×–4×, 0.1× shrink refused, exact bounds, empty-to-anything accept, boundary off-by-one.

`test_atomic.py` — 12 tests: happy path, mode 0600, same inode-dir, O_EXCL collision retry+fail-closed, tmp cleanup on failure, parent-dir EACCES, target-dir missing, target missing, ENOSPC on write (mocked), partial-write leaves target byte-identical, umask-0 doesn't leak mode, open flags include `O_NOFOLLOW | O_CLOEXEC` (mocked).

`test_flock.py` — 4 tests: two processes serialize, `LOCK_NB` fails fast on contention, lock released on exception, lock released on success.

`test_toctou.py` — 6 tests (all deterministic, mock-based, no threads): inode-change-before-replace refused, dev-change-before-replace refused, `fstatat` recheck invoked, `renameat2(RENAME_NOREPLACE)` called on Linux, `os.replace` path with fstatat-recheck on Darwin, crash-injection between fsync-dir and replace leaves target byte-identical.

`test_platform.py` — 2 tests: refuses Windows (monkeypatch `sys.platform`), fsync uses `F_FULLFSYNC` on Darwin (monkeypatch).

`test_sanitization.py` — 6 tests: single public error code, granular reason in `.reason` attribute, granular reason in DEBUG log, no absolute paths in `str(exc)`, no `os.environ` in traceback, sha256-preserved-on-refusal parametrized across all 9 reasons.

`test_chaos.py` — 14 failure-injection tests (all deterministic, subprocess + mock based):

1. SIGTERM between tmp-fsync and rename → target byte-identical, no ghost tmp in dir.
2. SIGKILL between tmp-fsync and rename → same invariant (subprocess harness).
3. SIGINT during write-loop → target byte-identical, tmp cleaned up on signal handler exit.
4. `EIO` injected on tmp write → raises `UnsafeRewriteRefused(reason=IO_ERROR)`, target byte-identical.
5. `ENOSPC` injected on `fsync(tmp_fd)` → raises, target byte-identical, tmp unlinked.
6. `EROFS` injected on rename (fs remounted read-only mid-op) → raises, target byte-identical.
7. `EMFILE` injected on `os.open` of target → raises cleanly, no side effects.
8. Target replaced with **directory** between open and rename → fstatat recheck refuses, no write.
9. Target inode deleted + recreated (inode reuse) between open and rename → fstatat recheck refuses.
10. Parent-dir fd invalidated (dir unlinked) mid-op → raises cleanly, no panic.
11. Target mode flipped to `0000` between stat and open → open fails, no write, original preserved.
12. Clock skew (future mtime on target) does **not** affect decision; sha256 is source of truth.
13. tmp-suffix collision 3× in a row (seeded RNG) → fails closed with `reason=TMP_COLLISION`, no write.
14. Concurrent `safe_rewrite` on same target in sibling process → second blocks on `flock`, first wins atomically; second sees updated state on acquire.

Tests 1–3 use a subprocess harness (`tests/safe_rewrite/_chaos_harness.py`) that spawns a child, waits for a marker file signaling "fsync done", then sends signal. Parent then asserts target sha256 and directory contents.

Tests 4–11 use `monkeypatch.setattr(os, "…")` raising the target errno at the exact syscall, per-test. No threading.

**v2.1 chaos hardening (post second-round red-team):**

15. `test_enospc_on_fsync_dir_fd` — ENOSPC on `fsync(dir_fd)` **after** rename; asserts target sha256 matches new_content (rename succeeded) but raises durability warning; tmp absent.
16. `test_emfile_on_dir_fd_open` — EMFILE when opening parent dir fd; raises, no write, no tmp.
17. `test_renameat2_enosys_falls_back_to_fstatat_recheck` — mock `renameat2` → ENOSYS; asserts `os.fstatat(AT_SYMLINK_NOFOLLOW)` called, dev/ino matched, then `os.replace` invoked. Closes silent-fallback hole.
18. `test_hook_raises_between_fsync_and_rename` — `_hook_before_replace` raises `RuntimeError`; asserts target byte-identical, tmp unlinked, exception propagates.
19. `test_flock_not_leaked_to_child_process` — `subprocess.Popen(close_fds=True)` after flock acquire; child cannot re-acquire on same path (blocked); asserts fd is `FD_CLOEXEC`.
20. `test_tmp_open_uses_O_NOFOLLOW` — mocked `os.open` records flags on tmp path creation; asserts `O_NOFOLLOW | O_CLOEXEC | O_EXCL | O_CREAT | O_WRONLY`.
21. `test_no_ghost_tmp_after_any_chaos_refusal` — **parametrized across tests 1–18**; after each failure mode, asserts `list(target.parent.glob(".env.tmp-*")) == []`. Single negative-space spine for tmp leaks.
22. `test_directory_swap_real_fs_sibling` — real FS (`tmp_path`): pre-swap target with a real directory via `_hook_before_replace` callback; asserts `renameat2(RENAME_NOREPLACE)` / `fstatat` recheck refuses. Complements mock-based test 8.
23. `test_inode_reuse_real_fs_sibling` — real FS: unlink + recreate target (new inode, same path) via hook; asserts fstatat recheck refuses. Complements mock-based test 9.

**Harness fixes (flake elimination):**
- Test 1 (SIGTERM): child does `os.kill(os.getpid(), signal.SIGSTOP)` after fsync marker; parent `os.waitpid(..., WUNTRACED)` until child stopped, then sends SIGTERM + SIGCONT. Deterministic.
- Test 2 (SIGKILL): same SIGSTOP handshake, then SIGKILL from parent after confirmed stopped. No race.
- Test 14 (concurrent flock): second process writes its pid to a barrier file before trying to acquire; first process waits for barrier before releasing. Deterministic ordering.
- Test 12 (clock skew): `pytest.skip` if `os.utime` with future timestamp is clamped on the host fs (check via setup probe).
- Tests 6 + 13: assertion added — tmp path absent after failure.

**Total: 110 tests.** Up from 87 (v2.0) → 101 (v2.0 + chaos) → 110 (v2.1 hardened). Chaos fixtures grow by 1: `barrier_file(tmp_path)` for two-process ordering.

### Shared fixtures (`conftest.py`)

- `make_env_file(tmp_path, content, mode=0o600)`
- `sha256_of(path)`
- `assert_byte_identical(path, expected_sha256)`
- `fake_windows(monkeypatch)`
- `fake_darwin(monkeypatch)`
- `in_fake_repo(tmp_path)` — creates `.git/` root, returns `repo_root`
- `chaos_signal_at(hook_name, signum)` — registers a `_hook_before_replace` callback that sends `signum` to `os.getpid()` when `hook_name` fires.
- `chaos_errno_at(syscall_name, errno_val)` — monkeypatches the named syscall to raise `OSError(errno_val)` on first call, passthrough after.
- `spawn_chaos_child(target, content, signal_at)` — subprocess harness for SIGKILL tests.

---

## TDD order (what goes red first)

1. `test_refuses_symlink_to_zshrc` — user's red line, catches 4 invariants at once.
2. `test_refusal_preserves_zshrc_sha256` — sha256 negative-space.
3. `test_refuses_dot_zshrc_basename` (no symlink).
4. `test_refuses_hardlink_to_denylisted_inode`.
5. `test_refuses_concurrent_lock` (flock).
6. `test_atomic_replace_leaves_target_byte_identical_on_crash`.
7. `test_sigkill_between_fsync_and_rename_leaves_target_byte_identical` (chaos red line).
8. `test_target_replaced_with_directory_mid_op_refused` (TOCTOU+chaos).
9. `test_refuses_10x_blowup` + `test_accepts_5x_shrink_first_run`.
10. … remainder in the order listed above.

After step 1 passes, everything else is refinement. Step 1 is the ticket's entire justification in one assertion.

---

## Non-goals for sub-PR 1

- **No** caller rewiring (`lock`, `unlock`, `revoke`, `dotenv_rewriter`, MCP) — sub-PR 2.
- **No** backup creation — sub-PR 3 (Part B).
- **No** `.gitignore` manipulation — sub-PR 3.
- **No** `worthless restore` command — sub-PR 4 (Part C).
- **No** RECOVERY.md — sub-PR 5 (Part D).
- **No** leak closures (excepthook, SARIF redaction, tempfile for scan) — sub-PR 6 (Part E).
- **No** Hypothesis property-based tests — sub-PR 4 (WOR-251 integration).

Sub-PR 1 exposes `_hook_before_replace` callback so sub-PR 2 can wire shard-write ordering without monkey-patching.

---

## Risks (v2)

| # | Risk | Mitigation |
|---|---|---|
| 1 | `renameat2` is Linux-only (kernel ≥3.15). | Fallback: `os.replace` + `fstatat` dev/ino recheck. Document on BSD. |
| 2 | `RENAME_NOREPLACE` requires filesystem support (ext4, btrfs, xfs, APFS partial). | Detect at runtime; fall back to fstatat-recheck. |
| 3 | `F_FULLFSYNC` costs ~100 ms on Darwin. | Acceptable for destructive ops; measured once per lock. |
| 4 | `fcntl.flock` semantics differ NFS. | `flock` is advisory; document; NFS is out of mainstream support. |
| 5 | Full-file dotenv parse on 1 MiB file: ~10 ms. Acceptable. | Budget. |
| 6 | Mount-ID check requires `os.statvfs` which can fail on overlayfs. | Treat failure as "cannot verify" → refuse unless `allow_outside_repo`. |
| 7 | Backup dir XDG + repo hash — different behavior inside vs outside git repo. | Frozen: if no git repo, backup under `<cwd-sha256>`. Document. |

---

## Success criteria (v2)

- [ ] 110 tests written RED before any line of `safe_rewrite.py` exists.
- [ ] `test_chaos.py` covers 23 failure-injection scenarios; all deterministic (no sleeps, no retries).
- [ ] `test_no_ghost_tmp_after_any_chaos_refusal` parametrized over all 18 injection points — single negative-space spine for tmp-leak invariant.
- [ ] Signal tests use SIGSTOP/SIGCONT handshake; no scheduler races.
- [ ] Linux-fallback path (`renameat2` ENOSYS) has explicit coverage; `fstatat` recheck asserted called on fallback.
- [ ] Real-FS sibling tests for directory-swap + inode-reuse (complement mock-based determinism).
- [ ] Chaos tests run in `<10s` total on CI (no flakes over 100 consecutive runs).
- [ ] First red test: `test_refuses_symlink_to_zshrc` + sha256-preservation pair.
- [ ] `UnsafeRewriteRefused` is the only public exception; public message is generic; `.reason` and DEBUG log carry granular reason.
- [ ] `renameat2` used on Linux; `os.replace` + `fstatat` recheck elsewhere.
- [ ] `F_FULLFSYNC` used on Darwin.
- [ ] `fcntl.flock(LOCK_EX | LOCK_NB)` gates every invocation.
- [ ] No production caller imports `safe_rewrite` yet (sub-PR 2 gate).
- [ ] Ruff, ruff-format, bandit, codespell, SR-01/SR-07 clean.
- [ ] `uv run pytest tests/safe_rewrite -v` runs under 15 s.

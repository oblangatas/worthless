# Scenario Matrix: "What Happens When?"

> Proactive edge-case coverage for the worthless CLI.
> Each scenario has: Expected behavior, Current behavior (if buggy), Risk level, Test status.

## State Model Reference

| Store | Location | Purpose |
|-------|----------|---------|
| shard_a files | `~/.worthless/shard_a/{alias}` | XOR shard A (filesystem, 0600) |
| SQLite DB | `~/.worthless/worthless.db` | shards table (shard_b_enc, commitment, nonce), enrollments table (alias->var_name->env_path) |
| Fernet key | `~/.worthless/fernet.key` | Encrypts shard_b at rest in SQLite |
| .env files | project dirs | Rewritten with decoys after lock |
| Lock file | `~/.worthless/.lock-in-progress` | Mutual exclusion for lock command (5min stale timeout) |
| PID file | `~/.worthless/proxy.pid` | Tracks daemon proxy (pid\nport format) |

## Consistency Invariants

These must always hold. Any scenario that breaks them is a bug:

- **INV-1**: For every shard_a file, a matching row exists in `shards` table (and vice versa)
- **INV-2**: For every enrollment row, the referenced key_alias exists in `shards`
- **INV-3**: A locked .env contains only decoy values (entropy < 4.5) for enrolled keys
- **INV-4**: `reconstruct_key(shard_a, shard_b, commitment, nonce)` always recovers the original key if INV-1 holds
- **INV-5**: Fernet key file exists whenever DB exists
- **INV-6**: At most one `.lock-in-progress` file exists at a time

---

## 1. User Scenarios

### 1.1 Enrollment & Locking

#### U-01: User enrolls a key for the first time via `lock`

- **Precondition**: .env has `OPENAI_API_KEY=sk-proj-abc123...` (high entropy, known prefix)
- **Expected**: Split key -> store shard_b in DB -> write shard_a file -> rewrite .env with decoy -> print success
- **State after**: shard_a file exists, shards row exists, enrollments row exists (with env_path), .env has decoy
- **Risk**: Low
- **Test status**: Tested (`test_cli_lock.py`)

#### U-02: User enrolls the same key twice (re-runs `lock` on same .env)

- **Precondition**: .env already locked (decoy in place)
- **Expected**: `scan_env_keys` returns empty (decoy entropy < threshold) -> "No unprotected API keys found" -> no-op
- **Depends on**: Decoy entropy staying below `ENTROPY_THRESHOLD` (4.5)
- **Risk**: Medium -- if decoy generation changes, idempotency breaks
- **Test status**: Tested (`test_cli_lock.py`)

#### U-03: User enrolls the same key from two different .env files

- **Precondition**: Key `sk-proj-X` in both `/a/.env` and `/b/.env`
- **Expected**: First lock succeeds. Second lock: `_make_alias` produces same alias (sha256-based) -> shard_a file already exists -> "Skipping (already enrolled)" warning. Enrollment row NOT created for second env_path.
- **Current behavior**: BUG -- second .env keeps the real key exposed. The skip logic checks shard_a file existence and skips entirely, never creating the enrollment row for the second path.
- **Risk**: HIGH -- real key remains in second .env file
- **Test status**: UNTESTED

#### U-04: User runs `lock` on .env with 5 keys

- **Precondition**: .env has 5 different provider keys (openai, anthropic, etc.)
- **Expected**: Each key processed sequentially. If any fails mid-way, compensating transaction cleans up that key only. Previously locked keys remain locked.
- **Risk**: Medium -- partial failure leaves some keys locked, some not
- **Test status**: Partially tested (single key paths tested)

#### U-05: User runs `lock` on an already-locked .env

- **Precondition**: All keys in .env are decoys
- **Expected**: `scan_env_keys` finds no high-entropy keys -> "No unprotected API keys found" -> exit 0
- **Risk**: Low
- **Test status**: Tested

#### U-06: User runs `enroll` (direct, no .env scanning)

- **Precondition**: No prior enrollment for this alias
- **Expected**: Write shard_a first, then DB. Enrollment row has `env_path=NULL`.
- **Current behavior**: NOTE -- `enroll` does NOT acquire the lock file (unlike `lock`). Two concurrent `enroll` calls can race.
- **Risk**: Medium
- **Test status**: Tested (`test_cli_lock.py`)

#### U-07: User runs `enroll` with an alias that already exists

- **Precondition**: shard_a file for alias already exists
- **Expected**: `O_CREAT|O_EXCL` on shard_a file raises `FileExistsError` -> unhandled exception
- **Current behavior**: BUG -- `_enroll_single` does not catch `FileExistsError`. Raw traceback shown to user.
- **Risk**: Medium (UX bug, not data loss)
- **Test status**: UNTESTED

### 1.2 Unlocking

#### U-08: User unlocks one key when multiple are enrolled

- **Precondition**: 3 keys enrolled, user runs `unlock --alias=openai-abc12345 --env=.env`
- **Expected**: Only that alias unlocked. .env rewritten with real key for that var. Other aliases untouched.
- **Risk**: Low
- **Test status**: Tested (`test_cli_unlock.py`)

#### U-09: User unlocks all keys (no --alias)

- **Precondition**: 3 keys enrolled, user runs `unlock --env=.env`
- **Expected**: Iterates all shard_a files, unlocks each. All .env vars restored.
- **Current behavior**: POTENTIAL BUG -- if keys were enrolled from different .env files, all get written to the single `--env` path specified. Keys from other env files silently written to wrong file.
- **Risk**: HIGH -- key written to wrong .env, or KeyError if var_name not in target .env
- **Test status**: Partially tested (single-env scenarios)

#### U-10: User unlocks a key enrolled from two .env files

- **Precondition**: Same key enrolled via lock from `/a/.env` and `/b/.env` (if U-03 bug is fixed)
- **Expected**: `unlock --env=/a/.env` restores key in `/a/.env`, deletes that enrollment row, but keeps shard + second enrollment. `unlock --env=/b/.env` restores and fully deletes.
- **Risk**: Medium
- **Test status**: UNTESTED

#### U-11: User unlocks when .env file is missing

- **Precondition**: .env was deleted or moved after lock
- **Expected**: Warning printed, key printed to stdout for recovery. Enrollment + shard cleaned up.
- **Risk**: Medium (key printed to terminal -- could be in scrollback)
- **Test status**: Tested

#### U-12: User unlocks when shard_a file is missing but DB has record

- **Precondition**: shard_a file manually deleted
- **Expected**: `WRTLS-102: Shard A not found for alias` error. Key is UNRECOVERABLE.
- **Risk**: CRITICAL -- data loss scenario
- **Test status**: Tested

#### U-13: User unlocks when DB has record but shard_b is corrupted

- **Precondition**: DB row exists but shard_b_enc is corrupt
- **Expected**: Fernet decryption fails -> `InvalidToken` exception -> unhandled crash
- **Current behavior**: LIKELY BUG -- `retrieve()` does not catch Fernet errors gracefully
- **Risk**: HIGH
- **Test status**: UNTESTED

### 1.3 Wrap & Up

#### U-14: User runs `wrap` with enrolled keys

- **Precondition**: At least one key enrolled
- **Expected**: Proxy spawns on random port -> health check passes -> child spawned with `{PROVIDER}_BASE_URL` injected -> child runs -> child exits -> proxy cleaned up -> exit with child's code
- **Risk**: Low
- **Test status**: Tested (`test_cli_wrap.py`)

#### U-15: User runs `wrap` with no enrolled keys

- **Precondition**: No shard_a files exist
- **Expected**: "No keys enrolled. Run 'worthless lock' first." -> exit 1
- **Risk**: Low
- **Test status**: Tested

#### U-16: User runs `up` then Ctrl+C

- **Precondition**: Proxy running in foreground
- **Expected**: SIGINT handler fires -> `proxy.terminate()` -> wait up to 5s -> `pid_file.unlink()` -> "Proxy stopped." -> `SystemExit(0)`
- **Risk**: Low
- **Test status**: Tested (`test_cli_up.py`)

#### U-17: User runs `up -d` then forgets about it

- **Precondition**: Proxy running as daemon
- **Expected**: Proxy runs indefinitely. PID file remains. Fernet key was passed via fd pipe (closed after read). Proxy holds reconstructed keys in memory for the lifetime of the process.
- **Risk**: Medium -- long-running process with keys in memory increases exposure window
- **Test status**: Partially tested (daemon start tested, long-running behavior not)

#### U-18: User runs `up` when proxy is already running

- **Precondition**: PID file exists, recorded PID is alive
- **Expected**: "Proxy already running (PID X on port Y). Stop it first." -> exit 1
- **Risk**: Low
- **Test status**: Tested

#### U-19: User runs `up` with stale PID file (process died)

- **Precondition**: PID file exists, recorded PID is dead
- **Expected**: "Reclaimed stale PID file" warning -> start proxy normally
- **Risk**: Low
- **Test status**: Tested

### 1.4 Scan

#### U-20: User runs `scan` on a locked .env

- **Precondition**: .env has decoy values (low entropy)
- **Expected**: No findings (decoys below entropy threshold) -> "No API keys found." -> exit 0
- **Current behavior**: NOTE -- scan always sets `is_protected=False`. The TODO in `scanner.py` notes hash-based enrollment lookup is not implemented. Decoy detection relies solely on entropy.
- **Risk**: Medium -- if a decoy accidentally has high entropy, it shows as "UNPROTECTED"
- **Test status**: Tested (`test_cli_scan.py`)

#### U-21: User runs `scan` on an unlocked .env

- **Precondition**: .env has real API keys
- **Expected**: Findings reported as UNPROTECTED -> "Run: worthless lock" suggestion -> exit 1
- **Risk**: Low
- **Test status**: Tested

#### U-22: User runs `scan --deep`

- **Precondition**: Keys might be in env vars, yaml, toml, json files
- **Expected**: Scans .env, .env.local, *.yml, *.yaml, *.toml, *.json, plus dumps `os.environ` to temp file and scans it.
- **Risk**: Medium -- temp file briefly contains all env vars on disk
- **Test status**: Partially tested

#### U-23: User runs `scan --pre-commit` with no explicit paths

- **Precondition**: Pre-commit hook passes no file arguments
- **Expected**: `scan_paths = []` (empty explicit list) -> `scan_files([])` -> no findings -> exit 0. Silent pass-through.
- **Current behavior**: This is arguably a bug -- pre-commit with no files does nothing useful but exits 0
- **Risk**: Low
- **Test status**: UNTESTED

### 1.5 Status

#### U-24: User runs `status` with no ~/.worthless/ dir

- **Precondition**: Never initialized
- **Expected**: `resolve_home()` returns None -> "No keys enrolled." + "Proxy: not running" -> exit 0
- **Risk**: Low
- **Test status**: Tested (`test_cli_status.py`)

#### U-25: User runs `status` with enrolled keys and running proxy

- **Precondition**: Keys enrolled, proxy on port 8787
- **Expected**: Lists aliases with providers, shows proxy healthy on port
- **Risk**: Low
- **Test status**: Tested

### 1.6 Destructive User Actions

#### U-26: User deletes `~/.worthless/` manually

- **Precondition**: Keys are enrolled, .env files have decoys
- **Expected**: ALL KEYS PERMANENTLY LOST. .env files still have decoys. No recovery path.
- **Risk**: CRITICAL -- this is the most dangerous user action
- **Test status**: UNTESTED (should test that next commands give clear error)

#### U-27: User deletes only `~/.worthless/shard_a/` directory

- **Precondition**: Keys enrolled
- **Expected**: DB still has shard_b. Unlock fails with "Shard A not found". Keys unrecoverable.
- **Risk**: CRITICAL
- **Test status**: UNTESTED

#### U-28: User deletes only `~/.worthless/worthless.db`

- **Precondition**: Keys enrolled, shard_a files exist
- **Expected**: `ensure_home` recreates empty DB on next command. shard_a files are orphaned. Unlock fails with "Shard B not found in DB".
- **Risk**: CRITICAL -- INV-1 broken, keys unrecoverable
- **Test status**: UNTESTED

#### U-29: User deletes `~/.worthless/fernet.key`

- **Precondition**: Keys enrolled in DB (encrypted with old Fernet key)
- **Expected**: `ensure_home` generates NEW Fernet key. Old shard_b records undecryptable. `InvalidToken` on any retrieve.
- **Risk**: CRITICAL -- silent data loss, keys unrecoverable
- **Test status**: UNTESTED

#### U-30: User runs `lock` from a different directory than original

- **Precondition**: Ran `lock --env=.env` from `/project-a/`, now in `/project-b/`
- **Expected**: Scans `/project-b/.env` (different file). If it has keys, enrolls them independently. No conflict.
- **Risk**: Low -- but user confusion if they think they're re-locking
- **Test status**: UNTESTED

#### U-31: User upgrades worthless (schema changes)

- **Precondition**: Old DB schema, new code with extra tables/columns
- **Expected**: `CREATE TABLE IF NOT EXISTS` in schema.py is additive-safe. New tables created, old tables untouched. No migration system exists.
- **Current behavior**: Works for additive changes. Column additions to existing tables would fail silently (old rows lack new columns).
- **Risk**: HIGH for non-additive schema changes
- **Test status**: UNTESTED

### 1.7 Cross-Command User Journeys

#### U-32: User has the same key value in two vars in one `.env`

- **Precondition**: `.env` has `OPENAI_API_KEY=sk-proj-X` and `OPENAI_API_KEY_DEV=sk-proj-X`
- **Expected**: Both vars get enrollment rows, both lines rewritten with decoys
- **Current behavior**: FIXED (commit 369c10e) -- shard_a exists path now creates enrollment + rewrites
- **Risk**: HIGH (was broken, now fixed)
- **Test status**: Tested (TestDuplicateKeyValueSameEnv)

#### U-33: User runs `enroll --key-stdin` and later `lock` on a `.env` containing the same key

- **Precondition**: Key was directly enrolled earlier with a user-chosen alias such as `ci-key`; later a project `.env` contains the same real key
- **Expected**: lock should detect existing shard_a, create enrollment for .env var, rewrite .env with decoy
- **Current behavior**: FIXED (commit 369c10e) -- shard_a exists path handles this
- **Risk**: HIGH (was broken, now fixed)
- **Test status**: Tested (TestEnrollThenLock)

#### U-34: User unlocks a directly enrolled key (env_path=NULL)

- **Precondition**: Key was enrolled via `enroll`, so the enrollment row has `env_path=NULL`
- **Expected**: Enrollment row + shard_a file + DB shard all cleaned up
- **Current behavior**: FIXED (commit eda84e6) -- delete_enrollment uses IS NULL, unlock uses enrollment.env_path
- **Risk**: HIGH (was broken, now fixed)
- **Test status**: Tested (TestEnrollUnlockNullEnvPath)

#### U-35: User runs `wrap` after direct `enroll` with a custom alias

- **Precondition**: Key was enrolled as `my-ci-key` or `apikey` instead of the lock-generated `provider-hash8` form
- **Expected**: wrap should still detect the provider and inject BASE_URL
- **Current behavior**: BEING FIXED -- wrap will query DB for provider instead of parsing alias name
- **Risk**: HIGH
- **Test status**: TODO

#### U-36: User runs `wrap` with only google/xai keys enrolled

- **Precondition**: Unsupported-provider keys were enrolled directly (for example `google-demo` or `xai-demo`)
- **Expected**: Clear warning that no providers can be proxied
- **Current behavior**: wrap shows "No keys enrolled" only if zero shards. If google/xai enrolled, it starts proxy but no BASE_URL injected. Provider gating in lock prevents this for lock flow, but direct enroll bypasses.
- **Risk**: MEDIUM
- **Test status**: Partial (provider gating in lock prevents this for lock flow, but direct enroll bypasses)

---

## 2. Attacker Scenarios

### 2.1 Local Access (Same User)

#### A-01: Attacker reads `~/.worthless/` (same user, local access)

- **Precondition**: Attacker has shell access as same user
- **Expected**: Can read fernet.key (0600) + DB (0600) + shard_a files (0600). Can reconstruct ALL keys.
- **Risk**: BY DESIGN -- worthless protects against accidental exposure (git push, log leak), NOT same-user local compromise. This is documented threat model.
- **Test status**: N/A (threat model boundary)

#### A-02: Attacker reads `/proc/PID/environ` of proxy process

- **Precondition**: Proxy running, attacker has same-UID access
- **Expected**: `WORTHLESS_FERNET_KEY` is NOT in environ (passed via fd pipe). `WORTHLESS_DB_PATH` and `WORTHLESS_SHARD_A_DIR` are visible but not secret.
- **Current behavior**: NOTE -- `WORTHLESS_ALLOW_INSECURE=true` IS in environ. Not a key leak but reveals proxy is in insecure mode.
- **Risk**: Low (Fernet key properly protected via fd)
- **Test status**: Tested (fd-passing logic in `test_process.py`)

#### A-03: Attacker reads `/proc/PID/environ` of wrap child process

- **Precondition**: `wrap` running, child process inherits env
- **Expected**: Child env has `OPENAI_BASE_URL=http://127.0.0.1:PORT` but NO API keys. Keys stay in proxy memory only.
- **Risk**: Low
- **Test status**: UNTESTED (verify child env does not leak keys)

### 2.2 Network Access

#### A-04: Attacker intercepts localhost traffic (127.0.0.1)

- **Precondition**: Proxy on 127.0.0.1, attacker on same host
- **Expected**: Traffic is plaintext HTTP on loopback. Attacker with tcpdump/wireshark on lo0 can see API keys in proxied requests.
- **Risk**: Medium -- requires root or CAP_NET_RAW on same host. Same-host attacker likely has easier paths (A-01).
- **Test status**: N/A (threat model boundary, but should be documented)

#### A-05: Attacker connects to proxy from remote host

- **Precondition**: Proxy bound to 127.0.0.1
- **Expected**: Connection refused -- uvicorn binds to `--host 127.0.0.1`, not `0.0.0.0`
- **Risk**: Low (correctly bound to loopback)
- **Test status**: Tested (bind address in spawn_proxy)

### 2.3 Tampering

#### A-06: Attacker modifies .env while `lock` is running

- **Precondition**: lock is between scan_env_keys and rewrite_env_key
- **Expected**: TOCTOU race. Lock reads key value, attacker changes it, lock writes decoy for the old key. Attacker's new key is overwritten with decoy. Old key is split and stored. Inconsistent state.
- **Risk**: Medium -- requires precise timing, local access
- **Test status**: UNTESTED

#### A-07: Attacker modifies shard_a files (bit flip)

- **Precondition**: Enrolled keys exist
- **Expected**: On unlock, `reconstruct_key` XORs corrupted shard_a with shard_b -> wrong key -> HMAC verification fails -> `ShardTamperedError` raised. Key NOT returned.
- **Risk**: Low -- HMAC commitment catches tampering
- **Test status**: Tested (`test_splitter.py`)

#### A-08: Attacker corrupts SQLite database

- **Precondition**: Replace or corrupt worthless.db
- **Expected**: Depends on corruption type. Missing rows -> "Shard B not found". Corrupt blob -> Fernet `InvalidToken`. Full replacement with attacker DB -> HMAC fails (wrong shard_b).
- **Risk**: Medium -- denial of service (keys unrecoverable) but not key theft
- **Test status**: Partially tested

#### A-09: Attacker sends crafted requests to proxy

- **Precondition**: Proxy running on localhost
- **Expected**: Proxy validates requests via rules engine. Unknown providers rejected. Malformed requests return 4xx.
- **Risk**: Medium -- depends on proxy hardening (separate from CLI scope)
- **Test status**: Tested (`test_proxy_hardening.py`)

#### A-10: Attacker supplies malicious `--alias` values

- **Precondition**: User runs `enroll --alias="../../etc/passwd"` or `--alias="$(rm -rf /)"`
- **Expected**: `_ALIAS_RE = re.compile(r"^[a-zA-Z0-9_-]+$")` rejects path traversal and shell injection. Error: "Invalid alias".
- **Current behavior**: Correctly validated in `_enroll_single`. BUT `_make_alias` in lock command generates aliases from `{provider}-{hash}` which always passes the pattern.
- **Risk**: Low (validated)
- **Test status**: Tested (`test_cli_security_hardening.py`)

#### A-11: Attacker supplies malicious `--env` paths

- **Precondition**: `lock --env=/etc/shadow` or `lock --env=../../sensitive`
- **Expected**: File read (scan_env_keys) would attempt to read the file. If readable, would scan for key patterns. If matches found, would REWRITE the file with decoys.
- **Current behavior**: NO PATH VALIDATION on --env. Any readable+writable file can be targeted.
- **Risk**: HIGH -- could corrupt arbitrary files if they contain key-like patterns
- **Test status**: UNTESTED

#### A-12: Attacker runs worthless commands as root

- **Precondition**: `sudo worthless lock`
- **Expected**: `~/.worthless/` resolves to `/root/.worthless/`. File permissions 0700/0600 still apply. No privilege escalation vector from worthless itself.
- **Risk**: Low -- but root's .env files might have system-wide keys
- **Test status**: UNTESTED

---

## 3. System / Crash Scenarios

### 3.1 Crash During Lock

#### S-01: Process crashes after DB write but before shard_a write

- **Precondition**: `_lock_keys` at line 110 (between `store_enrolled` and `os.open` for shard_a)
- **Expected**: Compensating transaction in except block deletes DB record. But if process is KILLED (SIGKILL), except block doesn't run.
- **Current behavior**: SIGKILL -> DB has shard record, no shard_a file. INV-1 broken. .env still has real key (not yet rewritten).
- **Risk**: HIGH
- **Test status**: UNTESTED

#### S-02: Process crashes after shard_a write but before .env rewrite

- **Precondition**: shard_a written, DB written, crash before `rewrite_env_key`
- **Expected**: Compensating transaction cleans up shard_a and DB. But SIGKILL -> both persist, .env still has real key. Next `lock` run: shard_a exists -> "already enrolled" skip -> .env never gets rewritten.
- **Current behavior**: BUG on SIGKILL -- .env retains real key permanently after this, and lock won't retry because shard_a exists.
- **Risk**: HIGH
- **Test status**: UNTESTED

#### S-03: Process crashes during .env rewrite (os.replace)

- **Precondition**: Temp file written, `os.replace` interrupted
- **Expected**: `os.replace` is atomic on POSIX (same filesystem). Either old .env or new .env exists, never partial. Temp file may be orphaned.
- **Risk**: Low on POSIX, Medium on Windows/cross-filesystem
- **Test status**: UNTESTED

### 3.2 Crash During Unlock

#### S-04: Process crashes after .env rewrite but before shard cleanup

- **Precondition**: Real key restored to .env, crash before `shard_a_path.unlink()` and `repo.delete_enrolled()`
- **Expected**: .env has real key. Shards still exist. Re-running unlock: real key re-read and re-written (idempotent). Then cleanup completes.
- **Risk**: Low -- unlock crash is more forgiving than lock crash
- **Test status**: UNTESTED

#### S-05: Process crashes after shard_a deletion but before DB cleanup

- **Precondition**: shard_a unlinked, crash before `repo.delete_enrolled()`
- **Expected**: DB has orphaned shard record. INV-1 broken. Not harmful (key already restored to .env). But `status` shows phantom enrolled key.
- **Risk**: Low (cosmetic, not data loss)
- **Test status**: UNTESTED

### 3.3 Resource Exhaustion

#### S-06: Disk full during lock (shard_a write)

- **Precondition**: Filesystem full
- **Expected**: `os.write(fd, bytes(sr.shard_a))` raises `OSError`. Compensating transaction fires: partial shard_a file removed, DB record deleted. .env unchanged.
- **Risk**: Medium -- partial write possible if disk fills mid-write
- **Test status**: UNTESTED

#### S-07: Disk full during .env rewrite

- **Precondition**: Filesystem full, temp file write fails
- **Expected**: `os.write(fd, ...)` in `rewrite_env_key` raises `OSError`. Temp file cleaned up in except block. Original .env preserved (not yet replaced). But shard_a and DB already written -> INV-1 holds but INV-3 broken (.env has real key, shards exist).
- **Risk**: HIGH -- next lock run skips (already enrolled), .env stuck with real key
- **Test status**: UNTESTED

#### S-08: SQLite locked by another process

- **Precondition**: Another tool has an exclusive lock on worthless.db
- **Expected**: `aiosqlite.connect` or `BEGIN IMMEDIATE` blocks, then times out -> `OperationalError: database is locked`
- **Current behavior**: Exception propagates up. In lock command: compensating transaction tries to delete from DB (which is also locked) -> double failure.
- **Risk**: Medium
- **Test status**: UNTESTED

#### S-09: Power loss during .env rewrite

- **Precondition**: Power cut between temp file write and os.replace
- **Expected**: Same as S-03. On POSIX with journaling filesystem: either old or new .env survives. Temp file may persist as `.env.tmp.XXXXX` in project dir.
- **Risk**: Low (POSIX atomicity) but temp files leak
- **Test status**: UNTESTED

### 3.4 Concurrency

#### S-10: Two terminals run `lock` simultaneously

- **Precondition**: Two shells, both run `worthless lock`
- **Expected**: First acquires `.lock-in-progress` via `O_CREAT|O_EXCL`. Second gets `WRTLS-105: Another worthless operation is in progress.`
- **Risk**: Low (correctly handled)
- **Test status**: Tested (`test_bootstrap.py`)

#### S-11: One terminal runs `lock`, another runs `enroll`

- **Precondition**: Concurrent lock and enroll
- **Expected**: `enroll` does NOT acquire the lock file. Both can write to DB and shard_a dir simultaneously. Race condition on same alias possible.
- **Current behavior**: BUG -- `enroll` bypasses the lock mechanism entirely
- **Risk**: HIGH (data corruption possible)
- **Test status**: UNTESTED

#### S-12: One terminal runs `lock`, another runs `unlock`

- **Precondition**: Concurrent lock and unlock
- **Expected**: `unlock` does NOT acquire the lock file. Can delete shards while lock is creating them.
- **Current behavior**: BUG -- `unlock` bypasses the lock mechanism
- **Risk**: HIGH (data corruption, key loss)
- **Test status**: UNTESTED

#### S-13: OS kills proxy via OOM

- **Precondition**: Proxy running under `wrap`, OOM killer fires
- **Expected**: Proxy dies. Watcher thread in wrap prints warning to stderr. Child continues without key protection. Child exit code returned.
- **Risk**: Medium -- child continues making API calls that fail (no proxy to inject keys)
- **Test status**: Partially tested (proxy crash during wrap)

---

## 4. Integration Scenarios

### 4.1 CI/CD

#### I-01: CI pipeline runs `lock` + `wrap` + `unlock`

- **Precondition**: CI runner, .env checked into repo (or mounted as secret)
- **Expected**: lock protects keys -> wrap runs tests with proxy -> unlock restores .env. Pipeline exits with wrap's child exit code.
- **Risk**: Medium -- CI might not run unlock on failure (no finally block in pipeline)
- **Test status**: UNTESTED (integration)

#### I-02: CI pipeline runs `enroll` + `wrap` (no .env)

- **Precondition**: Key provided via `--key-stdin`, no .env file
- **Expected**: enroll stores key directly -> wrap starts proxy -> child runs. No .env to restore on cleanup.
- **Risk**: Low
- **Test status**: UNTESTED

#### I-03: CI runner has no writable home directory

- **Precondition**: `$HOME` is read-only (some CI containers)
- **Expected**: `ensure_home` fails with permission error on `mkdir`. `WORTHLESS_HOME` env var can override.
- **Risk**: Medium (UX: unclear error message)
- **Test status**: UNTESTED

### 4.2 Container Scenarios

#### I-04: Docker container restarts mid-session

- **Precondition**: Keys enrolled, proxy running, container killed
- **Expected**: If `~/.worthless/` is on ephemeral volume: all state lost, keys unrecoverable. If on mounted volume: state persists, but proxy.pid is stale -> reclaimed on next `up`.
- **Risk**: CRITICAL if ephemeral, Low if volume-mounted
- **Test status**: UNTESTED

#### I-05: Docker bind-mount shares `~/.worthless/` across containers

- **Precondition**: Two containers mount same host directory as ~/.worthless/
- **Expected**: SQLite WAL mode should handle concurrent readers. Concurrent writers may fail with "database is locked". Lock file prevents concurrent lock commands across containers (if on shared filesystem with atomic O_EXCL).
- **Risk**: HIGH -- SQLite on NFS/overlayfs may not support WAL correctly
- **Test status**: UNTESTED

### 4.3 Git Interactions

#### I-06: `git pull` overwrites .env after lock

- **Precondition**: .env locked (has decoy), git pull brings a version with real key
- **Expected**: .env now has real key again. Shards still exist from previous lock. Running `lock` again: scan finds the key, `_make_alias` generates same alias, shard_a already exists -> "Skipping (already enrolled)". Key stays exposed.
- **Current behavior**: BUG -- same as S-02 aftermath. No mechanism to detect that .env was reverted.
- **Risk**: HIGH
- **Test status**: UNTESTED

#### I-07: Pre-commit hook runs `scan` during `lock`

- **Precondition**: User runs `lock`, which rewrites .env. If auto-commit triggers pre-commit hook with `scan`.
- **Expected**: Scan runs on partially-rewritten .env. Some keys decoy (below threshold), some still real. Scan reports the real ones as UNPROTECTED -> hook fails -> commit blocked.
- **Risk**: Low (correct behavior -- scan should block commit if keys exposed)
- **Test status**: UNTESTED

#### I-08: `.env` is in `.gitignore` but user runs `scan` on staged files

- **Precondition**: .env not in git index, scan invoked with explicit path
- **Expected**: Scan processes any explicitly-passed path regardless of gitignore.
- **Risk**: Low
- **Test status**: Tested

### 4.4 Cross-Command State Interactions

#### I-09: `status` called while `lock` is in progress

- **Precondition**: lock is mid-operation, status called from another terminal
- **Expected**: status reads DB (read-only) -- should work fine with WAL mode. May show partially-enrolled state.
- **Risk**: Low (read-only, eventual consistency acceptable)
- **Test status**: UNTESTED

#### I-10: `wrap` called immediately after `lock` (keys just enrolled)

- **Precondition**: Fresh lock, proxy not yet started
- **Expected**: wrap reads shard_a dir to find providers, spawns proxy, proxy reads DB + shard_a to reconstruct keys. Should work.
- **Risk**: Low
- **Test status**: Tested (implicitly via wrap tests)

#### I-11: `up -d` running, user runs `lock` to add more keys

- **Precondition**: Proxy daemon running, user enrolls new keys
- **Expected**: New keys in DB and shard_a, but running proxy has no hot-reload mechanism. Proxy only knows about keys loaded at startup. New keys not available until proxy restart.
- **Current behavior**: LIKELY BUG -- proxy reads keys per-request (depends on proxy implementation). Need to verify.
- **Risk**: Medium
- **Test status**: UNTESTED

#### I-12: Normal SDK traffic through `wrap`/`up` using only `BASE_URL` (no custom headers)

- **Precondition**: User runs `wrap` or points a client at `up`, and the client only knows the provider base URL override (`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`)
- **Expected**: SDK request hits proxy, proxy infers alias from path, request succeeds
- **Current behavior**: FIXED (commit eda84e6) -- `_infer_alias_from_path` added to proxy
- **Risk**: CRITICAL (was broken, now fixed)
- **Test status**: Tested (TestTransparentProxy)

---

## 5. Discovered Issues Summary

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| U-03 | HIGH | Same key from two .env files: second .env keeps real key | `lock.py:85-87` |
| U-07 | MEDIUM | `enroll` with existing alias: unhandled FileExistsError | `lock.py:172` |
| U-09 | HIGH | Unlock-all writes all keys to single --env regardless of enrollment source | `unlock.py:136-138` |
| U-13 | HIGH | Corrupt shard_b: unhandled Fernet InvalidToken | `repository.py:136` |
| U-32 | ~~HIGH~~ FIXED | ~~Same key in two vars in one `.env`: second var stays plaintext~~ Fixed in commit 369c10e | `lock.py:85-87`, `schema.py:40-47` |
| U-33 | ~~HIGH~~ FIXED | ~~Direct enroll then lock on same key: shard_a exists path skipped~~ Fixed in commit 369c10e | `lock.py:85-87` |
| U-34 | ~~HIGH~~ FIXED | ~~Direct-enroll unlock leaves NULL-path enrollment + shards behind~~ Fixed in commit eda84e6 | `unlock.py:54-100` |
| U-35 | HIGH | `wrap` infers provider from alias spelling, so custom direct-enroll aliases break wrap (being fixed) | `wrap.py:36-53` |
| A-11 | HIGH | No path validation on --env: can corrupt arbitrary files | `lock.py:190-206` |
| S-01 | HIGH | SIGKILL during lock: INV-1 broken, no recovery | `lock.py:90-131` |
| S-02 | HIGH | SIGKILL after shard write but before .env rewrite: .env stuck with real key | `lock.py:122` |
| S-07 | HIGH | Disk full during .env rewrite: shards written, .env unchanged, lock won't retry | `lock.py:122` |
| S-11 | HIGH | `enroll` bypasses lock mechanism: race condition | `lock.py:208-236` |
| S-12 | HIGH | `unlock` bypasses lock mechanism: concurrent data corruption | `unlock.py:113-144` |
| I-06 | HIGH | git pull reverts .env: lock won't re-protect (shard_a exists) | `lock.py:85-87` |
| I-12 | ~~CRITICAL~~ FIXED | ~~`wrap`/`up` set only BASE_URL, proxy requires `x-worthless-alias`~~ Fixed in commit eda84e6 (`_infer_alias_from_path`) | `wrap.py:175-185`, `proxy/app.py:223` |
| U-31 | HIGH | No schema migration system for upgrades | `schema.py` |

---

## 6. Test Coverage Matrix

| Scenario | Unit | Integration | E2E | Status |
|----------|------|-------------|-----|--------|
| U-01 First lock | x | | | DONE |
| U-02 Re-lock idempotent | x | | | DONE |
| U-03 Same key two envs | | | | TODO |
| U-04 Multi-key lock | | | | PARTIAL |
| U-06 Direct enroll | x | | | DONE |
| U-07 Duplicate enroll | | | | TODO |
| U-08 Unlock single | x | | | DONE |
| U-09 Unlock all multi-env | | | | TODO |
| U-12 Missing shard_a | x | | | DONE |
| U-13 Corrupt shard_b | | | | TODO |
| U-32 Same key in two vars | x | | | DONE |
| U-33 Direct enroll then lock | x | | | DONE |
| U-34 Direct-enroll unlock cleanup | x | | | DONE |
| U-35 Wrap after custom direct enroll alias | | | | TODO |
| U-36 Wrap with only unsupported providers enrolled | | | | PARTIAL |
| U-26 Delete ~/.worthless/ | | | | TODO |
| A-07 Tampered shard | x | | | DONE |
| A-10 Malicious alias | x | | | DONE |
| A-11 Malicious env path | | | | TODO |
| S-01 SIGKILL mid-lock | | | | TODO |
| S-10 Concurrent lock | x | | | DONE |
| S-11 Lock + enroll race | | | | TODO |
| I-01 CI pipeline | | | x | TODO |
| I-06 Git pull after lock | | | | TODO |
| I-12 SDK traffic through wrap/up | x | | x | DONE |

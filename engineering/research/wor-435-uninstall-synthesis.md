# WOR-435 expanded scope — synthesis of brutus + ux-researcher + architect-reviewer

> **STATUS — BLOCKED for implementation (2026-06-08).** Thermo-nuclear review on PR #286
> flagged the recovery manifest design (§5) as a High-severity SR-04/SR-05 conflict:
> it writes reconstructed `sk-*` API keys in plaintext to `~/worthless-recovery-<ts>.txt`,
> creating a durable secret bundle that survives via Time Machine, iCloud, Dropbox, and
> post-uninstall theft. **Do not implement §5 as written.** Resolve via one of three
> alternatives before WOR-435 code lands:
>
> 1. **Restore-in-place only** for Safe tier — manifest = paths + status only, no key export.
> 2. **Fernet-encrypted manifest** keyed to machine keyring (same trust boundary as shard-B).
> 3. **`worthless recover` (reinstall + unlock) BEFORE wipe** — keys never written to a file.
>
> Full review: `reviews/thermo-nuclear/pr-286.md` (H1, H2, M1, M3). Schema (§1), tiered
> uninstall flow (§4), grandfathering (§6.6), and cross-ticket impact remain valid.

## The bug, in one sentence

`worthless lock` rewrites user-owned `.env` files; current uninstall recipe wipes `~/.worthless` (deleting shard-B) without touching those `.env` files — projects are silently bricked, real keys unrecoverable.

## v1 ships (NOT deferred)

### 1. Schema — new `locked_files` table

```sql
CREATE TABLE locked_files (
  canonical_path  TEXT NOT NULL,        -- os.path.realpath(abspath(p)) at lock time
  machine_id      TEXT NOT NULL,        -- from keystore.py:_keyring_username
  enrollment_id   INTEGER NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
  original_sha256 BLOB NOT NULL,        -- pre-lock file digest
  locked_sha256   BLOB NOT NULL,        -- post-lock digest (drift detection)
  proxy_url       TEXT NOT NULL,        -- exact marker we wrote
  shard_a_digest  BLOB NOT NULL,        -- verify shard-A still intact
  locked_at       INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  PRIMARY KEY (canonical_path, machine_id)
);
CREATE INDEX idx_locked_files_machine ON locked_files(machine_id);
CREATE INDEX idx_locked_files_enrollment ON locked_files(enrollment_id);
```

### 2. Lock-time UX (sets the mental model)

```
Locking 1 file: ./.env

Your real OPENAI_API_KEY moves into Worthless. The .env will hold a proxy URL
instead — your app reads it the same way, but only works while Worthless is
running.

To go back: worthless unlock ./.env restores the original. Uninstalling
Worthless without unlocking first will leave this .env pointing at nothing.

Lock it? [Y/n]
```

### 3. `worthless list-locked` (read-only, dual-audience)

Lists tracked paths for current machine. Human-readable default, `--json` for agents/CI. ~30 LOC, huge trust signal.

### 4. `worthless uninstall` — classify each tracked path

For each row in `locked_files WHERE machine_id = current()`:

| Tier | Conditions | Action |
|---|---|---|
| **Safe** | file exists ∧ `locked_sha256` matches ∧ `proxy_url` present ∧ `shard_a_digest` matches | auto-restore in place |
| **Drifted** | file exists ∧ `proxy_url` present, but `locked_sha256` drifted | NO auto-restore; entry in recovery manifest; flagged "needs your review" |
| **Untrackable** | file missing OR `proxy_url` absent | skip; entry in recovery manifest as "could not locate" |

### 5. Recovery manifest — `worthless-recovery-<ts>.txt`

Written BEFORE any wipe, `chmod 600`, contains for each tracked path:

```
# Worthless recovery manifest — 2026-06-08T13:42:00Z
# Reconstructed real keys (shard-A XOR shard-B) for every .env locked on this machine.
# Keep this file safe; delete after you've restored what you need.

/Users/alice/projects/api-server/.env  OPENAI_API_KEY=<RECONSTRUCTED_KEY>  STATUS=auto-restored
/Users/alice/projects/billing/.env     OPENAI_API_KEY=<RECONSTRUCTED_KEY>  STATUS=drifted-review
/Users/alice/projects/old-proto/.env   OPENAI_API_KEY=<RECONSTRUCTED_KEY>  STATUS=path-missing
```

For shard-A-tampered cases where reconstruction fails: include the entry with `STATUS=unrecoverable; rotate at provider`.

### 6. Uninstall confirmation copy (matter-of-fact, no scare register)

```
Uninstalling Worthless. 3 projects are still locked:
  ./api-server/.env  -> will be restored
  ./billing/.env     -> edited since lock, needs your review
  ./old-proto/.env   -> project missing, will skip

A recovery file with all real keys will be written to:
  ~/worthless-recovery-2026-06-08T13:42:00Z.txt (chmod 600)

Restore what I can and continue? [Y/n]
```

### 7. Recovery message when user has already half-uninstalled

```
Your real keys are still safe — they were backed up before lock.
Run `worthless recover` to reinstall, restore from backup, and rewrite
affected .env files. If you skipped backups, the keys are gone;
rotate them at your provider.
```

## Failure modes that MUST be handled

1. **Missing path** (deleted project): skip + log to manifest. Never block.
2. **Renamed `$HOME`** (Time Machine): paths unresolvable → treat as missing. Offer `worthless unlock --manifest <file>` to re-point.
3. **Shard-A tampered/missing**: detect via stored digest. No restore. Manifest entry says "rotate at provider."
4. **iCloud-synced `~/.worthless` across machines**: PK includes `machine_id`; only this machine's rows considered.
5. **Containerized lock**: out of scope for v1; document that uninstall must run in same context.
6. **Pre-v1 enrollments (grandfathered)**: surface as "predate path tracking, won't be auto-restored." Do NOT scan filesystem looking for them — false positives are dangerous.

## Why not defer to v1.1

Brutus's verdict: *shipping uninstall without this IS the bug.* A half-uninstall that silently bricks projects is strictly worse than no uninstall command at all (current state, manual recipe). The recovery manifest is the floor of "uninstall that doesn't lose user data."

## Cross-ticket impact

- **WOR-435** (this ticket) — expand scope per above
- **WOR-694** (`curl worthless.sh/uninstall | sh`) — must call same code path. Update spec to reference this manifest behavior.
- **WOR-712** (sandbox script) — `cleanup.sh` should call `worthless uninstall` once it exists, instead of the raw `rm -rf` + keychain drain.

## Estimate

- Schema + lock-time capture: ~150 LOC
- `worthless list-locked` (human + json): ~50 LOC
- `worthless uninstall` (classify + manifest + restore): ~300 LOC
- Tests (unit + integration + e2e for each tier): ~400 LOC
- Total: ~900 LOC, ~3-4 days. Promotes WOR-435 from P1 to **launch-blocking P0** for v1.0.

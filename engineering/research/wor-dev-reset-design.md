# Design sketch: dev machine reset (future, not v1)

> **Status:** Design only. Not implemented. Full product uninstall is **WOR-435**;
> wave 3b live packs intentionally do **not** purge OS state.

## Problem

Engineers running L7 live packs (`service-lock-roundtrip-live-macos.sh`, lifecycle scripts)
accumulate:

- Stale enrollments and orphan aliases in `~/.worthless/proxy.db`
- Fernet drift between Keychain and `fernet.key` (WOR-464)
- Duplicate macOS Background Items notifications
- OpenClaw provider/skill churn from lock/unlock in temp dirs

Today the manual recipe lives in [wor-193-live-checklist.md](../testing/wor-193-live-checklist.md)
and [docs/install/mac.md](../../docs/install/mac.md). Pytest user-flow tests call
`delete_fernet_key(home_dir=...)` in conftest teardown; live packs do not.

## Non-goals

- Replace WOR-435 `worthless uninstall` (restore locked `.env`s, tiered manifest)
- Auto-pick Fernet drift side (WOR-464 guardrail)
- Run in CI or production default paths

## Option A — `worthless dev reset` (CLI)

Hidden or documented under `engineering/` only until promoted.

```text
worthless dev reset [--yes] [--purge-fernet] [--purge-db]
```

| Flag | Action |
|------|--------|
| (default) | `service uninstall --yes`, `worthless down`, remove stale pid/run dirs |
| `--purge-fernet` | Call existing `delete_fernet_key(home.base_dir)` |
| `--purge-db` | `rm -rf ~/.worthless` after confirmation — **requires zero locked real projects** or explicit `--i-locked-my-envs` |

Safety:

- Refuse `--purge-db` if `locked_files` table has rows outside temp paths (post WOR-435 schema)
- Until WOR-435: refuse if `worthless status` shows enrollments whose `env_path` exists and is not under `/tmp/`

Implementation reuse:

- `delete_fernet_key()` — [keystore.py](../../src/worthless/cli/keystore.py)
- `launchd.uninstall()` — [launchd.py](../../src/worthless/cli/commands/service/launchd.py)
- Same Keychain drain loop as mac.md §7

Estimate: ~150 LOC + tests.

## Option B — Live pack `--clean-home`

```bash
bash engineering/testing/scripts/service-lock-roundtrip-live-macos.sh --clean-home
```

Before mock-upstream:

1. Snapshot `WORTHLESS_HOME` to `$TMPDIR/worthless-home-backup-$$` (optional restore flag)
2. Or: `delete_fernet_key` + `rm -rf ~/.worthless` + touch `.bootstrapped` removal for truly empty home
3. Then run existing sync + lock flow on fresh Fernet key

Heavier; useful for reproducing first-install drift bugs. Default off.

Estimate: ~80 lines shell + doc.

## Recommendation

1. Ship **docs + checklist** (done in Phase A of OS-state plan).
2. Implement **Option B** only if live-pack flakes from accumulated state become frequent.
3. Implement **Option A** if multiple contributors need one command; otherwise manual recipe is enough until WOR-435.

## Related

- [wor-435-uninstall-synthesis.md](wor-435-uninstall-synthesis.md) — production uninstall
- [macos-background-items-verification.md](macos-background-items-verification.md) — LaunchAgent vs Settings UI

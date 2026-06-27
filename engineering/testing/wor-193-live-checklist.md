# WOR-193 — Live test checklist (L7)

> Manual proof on a real machine. **Not CI.** Record pass/fail per ticket before claiming “works live.”
>
> **Install from:** `main` (PR #292 merged `876d102`). Use editable install from your checkout: `uv sync && uv pip install -e .`
>
> **Verification lanes:** Adversarial + dirty pytest = **WOR-724** (`wor-193-wave-verification.md`). Chaos + repeat-run dirty = **WOR-725**. Live packs here = **L7**.

| Linear | Pack / proof |
|--------|----------------|
| WOR-720 | Lifecycle scripts (healthz only) |
| WOR-721 | `default-command-supervised-live-macos.sh` |
| WOR-747 | Unlock before temp dir delete in roundtrip script |
| WOR-748 | Fernet sync for launchd in roundtrip script |
| WOR-749 | `service-lock-roundtrip-live-macos.sh` PASS |

## Before you start

| Prerequisite | Check |
|--------------|-------|
| On `main` (or release tag) | `git checkout main && git pull` |
| Editable install | `uv sync && uv pip install -e .` |
| `worthless` on PATH | `which worthless` points at this checkout’s venv |
| Fernet key + enrollment | `~/.worthless/fernet.key` exists; at least one key locked or enrolled |
| Clean slate (recommended) | No existing worthless LaunchAgent / systemd unit for this home |
| Port free | `8787` (or your `WORTHLESS_PORT`) not held by another process |

**Optional isolation** — use a throwaway home so you don’t disturb daily config:

```bash
export WORTHLESS_HOME="$HOME/.worthless-live-test"
mkdir -p "$WORTHLESS_HOME"
# enroll/lock into this home first if empty, then continue below
```

**Teardown** (run after any pack or on failure):

```bash
worthless service uninstall --yes
worthless down 2>/dev/null || true
```

This removes the LaunchAgent plist and stops the foreground proxy. It does **not** purge Keychain, `~/.worthless/`, or locked project `.env` files — see [Dev machine reset](#dev-machine-reset) below.

**Script index** (`engineering/testing/scripts/`):

| Script | What it proves |
|--------|----------------|
| `service-lifecycle-live-macos.sh` | launchd install/stop/start/restart/uninstall + `/healthz` only |
| `service-lifecycle-live-linux.sh` | same on systemd (native Linux) |
| `run-service-lifecycle-linux-docker.sh` | lifecycle pack in Docker when no systemd host |
| `service-lock-roundtrip-live-macos.sh` | lock → **service install** → proxied request → mock upstream gets **real key** |
| `default-command-supervised-live-macos.sh` | bare `worthless --yes` supervised + idempotent |

Lifecycle packs do **not** exercise API keys. Use `service-lock-roundtrip-live-macos.sh` for that.

---

## Dev machine reset

Live packs and `worthless service uninstall` are **not** a full uninstall. They intentionally leave enrollments, shard-B, and the Fernet key intact ([L720-7](#pack-wor-720--wave-1a-service-skeleton-288): shard count unchanged after service uninstall).

### What live packs clean up

| Removed | Left on disk |
|---------|----------------|
| LaunchAgent plist + launchd job | `~/.worthless/` (DB, shards, `fernet.key`) |
| Foreground proxy / sidecar for the run | Keychain entry `worthless` / `fernet-key-*` (Fernet master key, **not** your `sk-*`) |
| Temp `/tmp/worthless-live-project-*` (unlock + delete) | Real locked projects elsewhere |

The lock roundtrip script also syncs Keychain → `fernet.key` for launchd; it does **not** call `delete_fernet_key`.

### When to reset

- After many live-pack iterations (stale enrollments, drift, duplicate Background Items notifications)
- Before handing the laptop to someone else
- When you want a Fernet clean slate (empty `~/.worthless`, new key on next lock)

### Dev teardown (after each live pack / mid-dev)

Stops launchd, proxy, and **stale sidecar `run/` dirs** — does **not** remove Fernet key or DB:

```bash
bash engineering/testing/scripts/dev-teardown-macos.sh   # macOS
bash engineering/testing/scripts/dev-teardown-linux.sh   # Linux systemd
```

The lock roundtrip script calls `dev-teardown-macos.sh` at startup automatically.

**WSL:** no launchd/systemd user session — use `worthless down` + `rm -rf ~/.worthless/run`. Full service live packs need native Linux or macOS; WSL is CLI/lock-only unless you run systemd user session.

### Fernet key cleaner (what exists today)

| Mechanism | Removes Fernet from Keychain + file? | When |
|-----------|--------------------------------------|------|
| `delete_fernet_key()` in code | Yes | Last enrollment `worthless revoke` only |
| `worthless service uninstall` | **No** | By design (L720-7) |
| `dev-teardown-*.sh` | **No** | Dev proxy/sidecar cleanup |
| Manual loop in mac.md §7 | Yes | Full machine purge |
| WOR-435 `worthless uninstall` (future) | Yes | After restore-in-place |

There is **no** automatic Fernet purge during live packs — that would brick existing locked projects.

### Full macOS reset (manual until [WOR-435](https://linear.app/plumbusai/issue/WOR-435))

**Unlock every locked `.env` first** — wiping `~/.worthless` without unlock bricks projects (shard-B gone, proxy URLs remain).

```bash
worthless down 2>/dev/null || true
worthless service uninstall --yes 2>/dev/null || true

# Per project: worthless unlock --env /path/to/.env

while security delete-generic-password -s worthless 2>/dev/null; do :; done
rm -rf ~/.worthless
```

Optional: **System Settings → General → Login Items & Extensions → Background Items** — disable `worthless` if it still appears after uninstall (plist may already be gone; UI can lag).

See [docs/install/mac.md §6–§7](../../docs/install/mac.md) for Background Items behavior and production uninstall notes.

---

## Pack WOR-720 — Wave 1a: Service skeleton (#288)

**Ticket:** [WOR-720](https://linear.app/plumbusai/issue/WOR-720)
**Proves:** launchd/systemd unit written, install → health verify → stop/start/restart → uninstall leaves keys intact.
**Does not prove:** key split, reconstruction, or upstream forwarding (see lock roundtrip pack below).
**Platform:** Run the macOS block on Darwin; Linux block on systemd user session.

**Runnable script (macOS):**

```bash
unset WORTHLESS_HOME
bash engineering/testing/scripts/service-lifecycle-live-macos.sh
```

### macOS (launchd) — inline steps

```bash
set -euo pipefail
PORT="${WORTHLESS_PORT:-8787}"
PLIST="$HOME/Library/LaunchAgents/dev.worthless.proxy.plist"

# --- L720-0: baseline ---
worthless --json service status | tee /tmp/wor720-status-0.json
test ! -f "$PLIST" || echo "WARN: plist already exists — uninstall first or use fresh user"

# --- L720-1: install ---
worthless service install --yes
test -f "$PLIST"
grep -q "WORTHLESS_SERVICE_MANAGED" "$PLIST"
grep -q "WORTHLESS_HOME" "$PLIST"
launchctl print "gui/$(id -u)/dev.worthless.proxy" >/dev/null

# --- L720-2: status running + healthy ---
worthless --json service status | tee /tmp/wor720-status-1.json
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-3: stop ---
worthless service stop
worthless --json service status | tee /tmp/wor720-status-2.json
# expect state stopped; healthz should fail or be unreachable
curl -sf "http://127.0.0.1:${PORT}/healthz" && echo "UNEXPECTED: still healthy after stop" && exit 1 || true

# --- L720-4: start ---
worthless service start
worthless --json service status | tee /tmp/wor720-status-3.json
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-5: restart ---
worthless service restart
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-6: logs (smoke) ---
worthless service logs | tail -5

# --- L720-7: uninstall, keys intact ---
SHARD_COUNT_BEFORE=$(find "${WORTHLESS_HOME:-$HOME/.worthless}"/shard_a -type f 2>/dev/null | wc -l | tr -d ' ')
worthless service uninstall --yes
test ! -f "$PLIST"
SHARD_COUNT_AFTER=$(find "${WORTHLESS_HOME:-$HOME/.worthless}"/shard_a -type f 2>/dev/null | wc -l | tr -d ' ')
test "$SHARD_COUNT_BEFORE" = "$SHARD_COUNT_AFTER"

echo "service lifecycle live pack (macOS): PASS"
```

| Step | What you’re proving | Pass? | Notes |
|------|---------------------|-------|-------|
| L720-0 | Clean or known starting state | ☐ | |
| L720-1 | Plist written, launchctl loaded | ☐ | |
| L720-2 | `status` + `/healthz` OK | ☐ | |
| L720-3 | Stop drops health | ☐ | |
| L720-4 | Start restores health | ☐ | |
| L720-5 | Restart restores health | ☐ | |
| L720-6 | Logs command works | ☐ | |
| L720-7 | Uninstall removes unit, shards unchanged | ☐ | |

**Expected `status --json` shapes (approximate):**

- After install/start: `"state": "running"`, `"healthy": true`
- After stop: `"state": "stopped"`, `"healthy": false`

### Linux (systemd user unit)

```bash
set -euo pipefail
PORT="${WORTHLESS_PORT:-8787}"
UNIT="$HOME/.config/systemd/user/worthless-proxy.service"

worthless service install --yes
test -f "$UNIT"
systemctl --user is-active worthless-proxy.service
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

worthless service stop
! systemctl --user is-active worthless-proxy.service

worthless service start
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

worthless service restart
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

worthless service uninstall --yes
test ! -f "$UNIT"

echo "service lifecycle live pack (Linux): PASS"
```

Or on macOS with Docker (no native systemd host):

```bash
bash engineering/testing/scripts/run-service-lifecycle-linux-docker.sh
```

Runnable script: `engineering/testing/scripts/service-lifecycle-live-linux.sh`

---

## Pack — Service lock roundtrip (keys through service-managed proxy)

**Linear:** [WOR-720](https://linear.app/plumbusai/issue/WOR-720) acceptance gap vs lifecycle-only proof
**Proves:** `worthless lock` → `worthless service install` → proxied chat request → mock upstream receives reconstructed **real** key (not shard-A).
**Requires:** Docker (mock-upstream on `:9999`), editable install, ports `8787` + `9999` free, `unset WORTHLESS_HOME` (uses `~/.worthless` + `providers.toml`).

```bash
cd /path/to/worthless
unset WORTHLESS_HOME
uv sync && uv pip install -e .
bash engineering/testing/scripts/service-lock-roundtrip-live-macos.sh
```

| Step | What you're proving | Pass? | Notes |
|------|---------------------|-------|-------|
| L-lock-1 | Provider registered + lock splits `.env` | ☐ | |
| L-lock-2 | Service install + healthz | ☐ | |
| L-lock-3 | Proxy forwards; upstream auth = real key | ☐ | |
| L-lock-4 | Service uninstall cleans plist | ☐ | |

---

## Pack WOR-721 — Supervised default + idempotent ``worthless --yes`` (#289 / WOR-717)

**Ticket:** [WOR-721](https://linear.app/plumbusai/issue/WOR-721)
**Proves:** bare ``worthless --yes`` uses sidecar-supervised ``worthless up`` (not legacy daemon); second invocation does not respawn.
**Platform:** macOS script below; Linux deferred (same supervised path, no systemd service).

```bash
unset WORTHLESS_HOME
bash engineering/testing/scripts/default-command-supervised-live-macos.sh
```

| Step | What you're proving | Pass? | Notes |
|------|---------------------|-------|-------|
| L721-1 | First ``--yes`` locks + starts one ``worthless up`` | ☐ | |
| L721-2 | Second ``--yes`` idempotent (same proc count, healthy) | ☐ | |
| L721-3 | No LaunchAgent/systemd unit installed | ☐ | |

---

## Next packs (not written yet)

| Ticket | Pack | Status |
|--------|------|--------|
| WOR-723 | Stopped service → hint, no duplicate proxy | pending |
| WOR-724 | Foreign unit mutators refuse | pending |
| WOR-725 | Reboot, linger, `sh.worthless.proxy` | pending |
| WOR-726 | Banner + `service doctor` | pending |
| WOR-727 | Full stack → merge `main` | pending |

When a pack passes, comment on the Linear ticket with date, OS, branch SHA, and link to this file section.

---

## Related

- [wor-193-wave-verification.md](wor-193-wave-verification.md) — L0–L6 automated ladder
- [scenario-matrix.md](scenario-matrix.md) — edge-case inventory
- [macos-background-items-verification.md](../research/macos-background-items-verification.md) — LaunchAgent vs Background Items UI (Phase C)
- [wor-dev-reset-design.md](../research/wor-dev-reset-design.md) — optional future `dev reset` / `--clean-home`
- [wor-435-uninstall-synthesis.md](../research/wor-435-uninstall-synthesis.md) — full OS purge (not wave 3b scope)

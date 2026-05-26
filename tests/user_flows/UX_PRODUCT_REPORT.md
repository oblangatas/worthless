# User-flow UX/Product report

Date: 2026-05-09
Scope: Linear `WOR-439`, first implementation branch `feature/wor-439-user-flow-suite`

## Executive summary

This report started with the first two user-flow lanes:

- `WOR-440`: native CLI operations.
- `WOR-445`: recovery, teammate handoff, rotation, and multi-project drift.

It does not yet protect install/reinstall/uninstall, Docker clean distro
journeys, OpenClaw, or agent/MCP setup. This branch now includes a first CI
lane for Linux/macOS user-flow proof plus uploaded terminal trace artifacts;
Windows native and WSL proof remain explicitly deferred.

The stress-test follow-on branches add native destructive-state journeys on top
of that baseline. The suite now contains 21 selected user-flow tests:

- 4 seed tests that already existed.
- 8 tests added by the first user-flow branch.
- 2 native stress tests added by `WOR-500`.
- 3 adversarial native/recovery tests added by `WOR-567`.
- 4 guarded macOS keychain-locality tests.

The product confidence gained is centered on "I have a project with `.env`;
Worthless can lock it, tell me what happened, recover it, and avoid corrupting
nearby projects." `WOR-441` extends that proof to "I am a new user starting
from installation": deterministic install traces exercise installer messaging,
reinstall/idempotency, failure diagnostics, and the current manual uninstall
guidance; GitHub install-smoke CI remains the checkout-local Ubuntu/macOS proof.
`WOR-442` starts the Docker proof lane: a host-native Worthless CLI locks a
project, the host proxy runs outside Docker, and an app container consumes the
locked `.env` through Docker's host bridge without receiving the raw key.

`WOR-544` adds the second pass over the suite: start from the top-level user
journey, then trace each step to automated proof, terminal proof,
checkout-local CI proof, or an explicit owner for the remaining gap. It does
not reopen the completed child tickets; it makes their coverage reviewable as
one product story.

## How to use this report

Use the tables below in two directions:

- Bottom up: start from a pytest and understand the UX promise it protects.
- Top down: manually replay a user journey, then use the mapped pytest as the
  first trace point when behavior does not match the expected UX.

Manual checks should use an isolated home:

```bash
export WORTHLESS_HOME="$(mktemp -d)/.worthless"
```

Do not use real provider keys for these local UX checks. Generate fake keys at
runtime:

```bash
python -c 'from tests.helpers import fake_openai_key, fake_anthropic_key; print("OPENAI_API_KEY="+fake_openai_key()); print("ANTHROPIC_API_KEY="+fake_anthropic_key())' > .env
```

Run the automated suite with:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/user_flows -m user_flow -q
```

For literal terminal proof, see [`TERMINAL_TRACES.md`](TERMINAL_TRACES.md).
It is generated from real `worthless` subprocess calls against isolated temp
projects with fake key material and redacted `.env` snapshots.

Refresh the traces with:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python tests/user_flows/render_traces.py \
  --output tests/user_flows/TERMINAL_TRACES.md
```

## WOR-544 top-down journey audit

This is the product map for manual review. Read it as the user would experience
Worthless: install first, then protect a project, prove protection, recover from
normal and abnormal states, and finally test app-specific integrations.

| Journey step | Current automated proof | Terminal trace proof | Checkout-local CI proof | Residual gap | Owning ticket |
| --- | --- | --- | --- | --- | --- |
| 1. Discover and install Worthless on a supported host | Installer static/logic tests plus install Docker matrix: `tests/test_install_static.py`, `tests/test_install_logic.py`, `tests/test_install_docker.py` | `TERMINAL_TRACES.md` starts with deterministic install/reinstall/manual-uninstall traces | `install-smoke.yml` runs checkout-local `sh ./install.sh` on macOS 15/14 and Ubuntu 24.04/22.04, plus Ubuntu proxy | **Partially covered:** `WOR-568` clarified public `curl https://worthless.sh \| sh` as release/manual proof; `WOR-597` adds second-pass install failure journeys like stale PATH binaries and older-version upgrades | `WOR-568`, `WOR-597`, `WOR-446` |
| 2. Verify the installed CLI exists and prints a version | Install smoke runs `uv run --no-project worthless --version`; static tests assert installer smoke-test behavior | Install lifecycle trace includes successful installer output | `install-smoke.yml` uploads `verify-version-*` artifacts | **Covered** for repo checkout installer; public `worthless.sh` version proof is required in the release/manual transcript | `WOR-441`, `WOR-568` |
| 3. Protect the first project `.env` with the default command | `test_native_cli_journeys.py::test_default_command_yes_detects_and_locks_project_env` | Covered indirectly by lock/status/scan/unlock trace; default command output is not rendered today | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Needs trace only:** add a rendered default-command trace when output review matters | `WOR-544` |
| 4. Protect one key with explicit `lock --env` | `test_native_cli_journeys.py::test_lock_status_scan_unlock_round_trip_restores_original_key` | `Lock, Status, Scan, Unlock` trace shows `.env` before/after and stderr | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** | `WOR-440` |
| 5. Verify protection with `status` and `scan` | `test_native_cli_journeys.py::test_scan_and_status_empty_states_are_plain_english` plus the round-trip test | `Lock, Status, Scan, Unlock` trace shows protected status and scan summary | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** for native local projects; multi-project status wording still has a stress gap | `WOR-440`, `WOR-500` |
| 6. Run an app through the proxy | `test_wrap_magic_moment.py::test_wrap_child_reaches_proxy_via_env_url` | No full app trace; terminal proof focuses on CLI and `.env` state | User-flow CI runs the wrap journey | **Needs trace only** if product review wants copy-pasted app-output proof | `WOR-440` |
| 7. Unlock and restore the original key | Round-trip test restores exact fake key | `Lock, Status, Scan, Unlock` trace shows restore and post-unlock empty status | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** | `WOR-440` |
| 8. Reinstall safely | Installer logic/static tests and deterministic trace tests cover idempotency paths | Install lifecycle trace includes pinned reinstall no-op | `install-smoke.yml` re-runs checkout-local installer on macOS and Ubuntu | **Covered** for installer idempotency; published-domain curl proof remains a release/manual transcript | `WOR-441`, `WOR-568` |
| 9. Uninstall / leave the machine clean | Trace documents current manual `uv tool uninstall worthless` limitation | Install lifecycle trace includes manual uninstall command output | No live cleanup proof beyond install smoke runner disposal | **Needs user-flow test / feature:** first-class `worthless uninstall` is still future work | `WOR-435` |
| 10. Teammate receives only a locked `.env` | `test_recovery_journeys.py::test_teammate_handoff_locked_env_without_db_fails_with_hint` | `Teammate Handoff Failure` trace shows safe failure and recovery wording | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** | `WOR-445` |
| 11. Rotate a key and re-lock | `test_recovery_journeys.py::test_rotation_relock_restores_new_raw_key` and `test_rotation_relock_accepts_different_shape_raw_key` | `Rotation Relock` trace shows old/new key transitions | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** | `WOR-445` |
| 12. Keep two projects isolated | `test_recovery_journeys.py::test_multi_project_unlock_keeps_other_project_protected` | `Multi-Project Isolation` trace shows project A unlock while project B remains protected | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Covered** for state behavior; path clarity remains a stress wording gap | `WOR-445`, `WOR-500` |
| 13. Survive destructive native state mishaps | `test_native_stress_journeys.py` covers refused rewrite and tampered locked value. `test_recovery_journeys.py` now covers deleted DB unlock wording, corrupt DB status fail-fast, and doctor multi-project repair safety. | `Native Stress` trace shows failure output and unchanged evidence | User-flow CI runs on Ubuntu 24.04 and macOS 15 | **Partially covered by `WOR-567`:** cleanup-failure partial-state and multi-project status path wording remain queued | `WOR-500`, `WOR-567` |
| 14. Install and use Worthless from WSL | Static installer logic allows WSL and docs describe the route | No WSL terminal trace | Windows job records deferral only; no real WSL environment is exercised | **Intentionally deferred:** needs real WSL runner or explicit manual release gate | `WOR-446` |
| 15. Native Windows behavior | Installer logic exits with the documented unsupported native-Windows path | No native Windows user trace | Windows smoke is not a real user-flow proof; user-flow workflow labels Windows deferred | **Intentionally deferred** until platform support decision | `WOR-446` |
| 16. Docker app journey | `tests/test_install_docker.py` covers clean distro install, container-local lock lifecycle, source CLI outside Docker + app-container `.env` bridge, skipped-bridge sample-app preflight, and unwritable `.env` refusal with no phantom enrollment | No rendered terminal trace for Docker app containers yet | `install-docker.yml` runs Docker-marked install matrix when installer, Docker, CLI, proxy, or mock-upstream paths change | **Covered for first `WOR-442` pass:** CI artifact/storytelling can still be improved if we want copy-paste Docker traces like native user flows | `WOR-442` |
| 17. OpenClaw user journey | Existing OpenClaw unit/integration tests cover apply/detect/doctor surfaces; `WOR-514`, PR #201 adds incident reproduction proof outside this branch | PR #201 contains manual quest docs and incident reproduction artifacts | OpenClaw fix CI depends on the active OpenClaw branch, not this report | **Needs live/manual proof and fixes:** cached token bypass, config corruption, gateway lifecycle | `WOR-443`, `WOR-514`, `WOR-515`, `WOR-516`, `WOR-517` |
| 18. Agent/MCP setup | In-process/lower-level coverage exists outside this user-flow suite | No child-process MCP terminal trace in this report | No dedicated MCP user-flow CI lane yet | **Needs user-flow test:** stdio initialize/list-tools/call-tool plus agent config examples | `WOR-444` |

### Ticket tree

| Status | Ticket | Product meaning |
| --- | --- | --- |
| Epic | `WOR-439` | User-flow / user-journey test suite umbrella |
| Done | `WOR-440` | Native CLI lock/status/scan/unlock and wrap flows |
| Done | `WOR-445` | Recovery, teammate handoff, rotation, multi-project flows |
| Done | `WOR-500` | Native destructive-state stress journeys |
| Done | `WOR-441` | Install, reinstall, manual uninstall proof |
| Done | `WOR-544` | Second-pass top-down audit and gap routing |
| Done | `WOR-567` | Adversarial native/recovery gaps: DB loss/corruption and surgical repair |
| Open | `WOR-514`, PR #201 | OpenClaw install incident reproduction proof, not the fix |
| Open | `WOR-515` | OpenClaw cached token bypass fix |
| Open | `WOR-516` | OpenClaw config corruption / restore safety fix |
| Open | `WOR-517` | Gateway lifecycle: restart, autostart, verification |
| Done | `WOR-442` | Docker clean distro / host-Worthless app-container journeys |
| Done | `WOR-568` | Public curl/manual evidence boundary and checkout-local CI proof honesty |
| In progress | `WOR-597` | Second-pass adversarial install failure journeys: stale PATH, older-version upgrades, partial install, PATH breakage, uninstall truth |
| Backlog | `WOR-443` | OpenClaw end-to-end user journey lane |
| Backlog | `WOR-444` | Agent/MCP user journey lane |
| Backlog | `WOR-446` | CI matrix governance, Windows, WSL, nightly/full sweep |

### Second-pass findings

- The native `.env` journey is strong: a reviewer can trace lock, status, scan,
  unlock, teammate failure, rotation, multi-project isolation, refused rewrite,
  and tamper handling from product promise to pytest and terminal output.
- Install proof is better than unit tests but not identical to the public user
  command. Per-PR CI runs `sh ./install.sh` from checkout; `WOR-568` made
  the public `curl https://worthless.sh | sh` path an explicit release/manual
  proof with copy-pasted terminal output until `WOR-446` adds a dedicated
  published-domain smoke. `WOR-597` covers the next adversarial install layer,
  starting with stale binaries that shadow the fresh uv-installed tool and
  older uv tool installs that must upgrade through the pinned path.
- Windows and WSL are not proven by the current suite. The Windows job is an
  explicit deferral marker, and WSL needs either a real WSL runner or a manual
  release gate.
- Docker now has product journey proof for "Worthless runs outside Docker and
  my app runs in Docker": the app container receives shard-A plus a
  Docker-routable proxy URL, while the mock upstream receives the reconstructed
  real key. The suite also catches the skipped `host.docker.internal` edit via
  a sample-app preflight and an unwritable `.env` refusal with no phantom
  enrollment. Remaining Docker polish is CI artifact/storytelling and real
  bind-mount UID/path variants.
- OpenClaw should stay open: `WOR-514`, PR #201 proves the incident, while
  `WOR-515`, `WOR-516`, and `WOR-517` own the actual fixes.

## UX promises now protected

| User journey | Product promise | Manual UX signs | Pytest trace |
| --- | --- | --- | --- |
| Existing keyring path, lock | Worthless should not repeatedly ask the native keyring for the same secret material. | On a native keyring machine, repeated lock should not cause repeated prompts. | `test_keychain_call_count.py::test_lock_calls_keyring_get_password_once_on_existing_key_path` |
| Existing keyring path, unlock | Unlock should use the cached keyring path efficiently. | Unlock should restore the original key without multiple keyring prompts. | `test_keychain_call_count.py::test_unlock_calls_keyring_get_password_once_on_existing_key_path` |
| Broken `.env` dogfood recovery | A user who breaks `.env` should see consistent status/doctor guidance and a recoverable path. | `unlock` fails clearly, `status`/`doctor` explain the issue, `doctor --fix` restores a clean state. | `test_doctor_dogfood.py::test_full_dogfood_lock_break_doctor_recover` |
| `wrap` magic moment | A wrapped child process should receive a usable provider base URL and reach the local proxy. | Child process sees provider base URL in its environment and can hit proxy health. | `test_wrap_magic_moment.py::test_wrap_child_reaches_proxy_via_env_url` |
| User-flow environment isolation | User-flow tests must not inherit real Worthless/provider state from the parent shell. | Manual failures should not depend on the developer's real shell env or `~/.worthless`. | `test_native_cli_journeys.py::test_scrubbed_env_deletes_ambient_worthless_overrides` |
| Default `worthless --yes` | A user can run the default command and get keys protected plus provider base URLs added. | Output names protected variables, raw keys disappear, `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` are written. | `test_native_cli_journeys.py::test_default_command_yes_detects_and_locks_project_env` |
| Lock/status/scan/unlock | The core native CLI round trip restores the exact original key. | `lock` protects, `status` says protected, `scan` finds no raw key, `unlock` restores the original value. | `test_native_cli_journeys.py::test_lock_status_scan_unlock_round_trip_restores_original_key` |
| Empty project status | A fresh project with no keys should produce plain-English empty states. | `scan` and `status` should not look like a crash or internal diagnostic. | `test_native_cli_journeys.py::test_scan_and_status_empty_states_are_plain_english` |
| Teammate handoff | A copied locked `.env` without local DB/keyring state should fail safely and explain recovery. | `unlock` fails without traceback and mentions no enrollment plus re-locking from the original machine. | `test_recovery_journeys.py::test_teammate_handoff_locked_env_without_db_fails_with_hint` |
| Local database loss | If a locked `.env` remains but local Worthless DB state is gone, the user should not get a misleading teammate-copy diagnosis. | `unlock --env` fails without traceback, names the missing `worthless.db`, and tells the user to restore state or replace with raw keys before locking again. | `test_recovery_journeys.py::test_unlock_after_local_database_loss_names_lost_worthless_state` |
| Corrupt local database | Status must not convert unreadable state into a clean empty install. | `status` exits non-zero, mentions the database problem, and does not print `No keys enrolled`. | `test_recovery_journeys.py::test_status_after_database_corruption_does_not_claim_empty_state` |
| Same-shape key rotation | A user can paste a replacement raw key into the same var and re-run `lock`. | Second `lock` protects the new value; `unlock` restores the new key, not the old one. | `test_recovery_journeys.py::test_rotation_relock_restores_new_raw_key` |
| Different-shape key rotation | Relock should also work when the replacement key has a different provider prefix shape. | Replacing `sk-proj-...` with `sk-...` should not produce `WRTLS-199` or a traceback. | `test_recovery_journeys.py::test_rotation_relock_accepts_different_shape_raw_key` |
| Multi-project isolation | Unlocking one project must not restore or corrupt another project under the same Worthless home. | Project A unlocks to raw key while project B remains protected until explicitly unlocked. | `test_recovery_journeys.py::test_multi_project_unlock_keeps_other_project_protected` |
| Multi-project doctor repair | Doctor repair should be surgical when one project is broken and a sibling project is still healthy. | `doctor --fix --yes` cleans the broken row only; the sibling `.env` remains locked and later unlocks to its original key. | `test_recovery_journeys.py::test_doctor_fix_repairs_broken_project_without_unlocking_sibling` |
| Refused rewrite after planned lock | If Worthless refuses to rewrite an unsafe `.env`, the user must not be left half-protected. | `lock` fails without traceback, original `.env` bytes remain, status has no protected phantom row, and explicit scan still finds the raw key. | `test_native_stress_journeys.py::test_lock_rewrite_refusal_leaves_env_and_status_recoverable` |
| Tampered locked `.env` | If a user edits a locked shard value, unlock should fail clearly without destroying evidence. | `unlock` fails without traceback, says the value was modified after lock / commitment mismatch, leaves `.env` unchanged, and status still shows protected state. | `test_native_stress_journeys.py::test_unlock_tampered_locked_env_fails_without_destroying_state` |
| Install lifecycle evidence | A new user should see a clear install result, safe reinstall behavior, actionable failure output, and honest uninstall guidance. | Deterministic terminal traces show PATH messaging, pinned reinstall no-op, pipx conflict guidance, uv failure diagnostics, and current `uv tool uninstall worthless` limitation. Checkout-local install-smoke CI uploads per-runner artifacts. | `test_render_traces.py::test_install_lifecycle_trace_documents_current_install_contract` + `test_install_static.py::test_install_smoke_uploads_terminal_artifacts` |
| Docker app on host Worthless | Worthless can run outside Docker, lock a project `.env`, run the proxy in host LAN mode, and let an app container call through the proxy without seeing the raw key. | `.env` contains shard-A plus `host.docker.internal`; the app container request succeeds; the mock upstream sees the reconstructed real key. | `test_install_docker.py::test_host_cli_locked_env_reaches_proxy_from_app_container` |
| Docker loopback mistake | If the user skips the Docker bridge edit and gives a container `127.0.0.1`, the sample app preflight should point at the real mistake. | The synthetic app container fails before the request and says it received a loopback base URL; this is not a Worthless-owned diagnostic for arbitrary apps. | `test_install_docker.py::test_app_container_fails_fast_when_locked_env_keeps_loopback_url` |
| Docker unwritable `.env` | If a host permission problem prevents rewriting `.env`, Worthless should fail without half-protecting the project. | `lock` refuses the unsafe rewrite, `.env` remains unchanged, and `status` says no keys are enrolled. Real bind-mount UID/path variants remain follow-up. | `test_install_docker.py::test_host_lock_unwritable_env_fails_without_phantom_enrollment` |

## Manual journey scripts

These are smoke scripts for human UX review. They intentionally mirror the
pytest journeys but leave room to judge wording, pacing, and clarity.

### Journey A: native lock/status/scan/unlock

1. Create a temporary project and fake `.env`.
2. Run `worthless lock --env .env`.
3. Run `worthless status`.
4. Run `worthless scan .`.
5. Run `worthless unlock --env .env`.

Expected UX:

- No traceback.
- Raw key is absent after lock.
- Status uses user-facing protected wording.
- Scan does not report the protected shard as a raw secret.
- Unlock restores the exact original key.

Trace first to:

- `test_native_cli_journeys.py::test_lock_status_scan_unlock_round_trip_restores_original_key`

### Journey B: default command

1. Create `.env` with fake OpenAI and Anthropic keys.
2. Run `worthless --yes`.
3. Inspect `.env`.

Expected UX:

- Output mentions both key vars.
- Both raw keys are replaced.
- Provider base URLs are added.
- Proxy startup/health messaging is understandable.

Trace first to:

- `test_native_cli_journeys.py::test_default_command_yes_detects_and_locks_project_env`

### Journey C: teammate handoff failure

1. Lock `.env` under one isolated `WORTHLESS_HOME`.
2. Copy only the locked `.env` into another project.
3. Switch to a fresh isolated `WORTHLESS_HOME`.
4. Run `worthless unlock --env .env`.

Expected UX:

- Command fails safely.
- No traceback.
- Output says no enrollment was found.
- Output tells the user to re-lock from the original machine.

Trace first to:

- `test_recovery_journeys.py::test_teammate_handoff_locked_env_without_db_fails_with_hint`

### Journey D: key rotation and relock

1. Lock an old fake key.
2. Replace the `.env` value with a new raw fake key in the same variable.
3. Run `worthless lock --env .env` again.
4. Run `worthless unlock --env .env`.

Expected UX:

- Second lock succeeds.
- The new raw key is protected.
- Unlock restores the new raw key.
- There is no internal error for prefix/length changes.

Trace first to:

- `test_recovery_journeys.py::test_rotation_relock_restores_new_raw_key`
- `test_recovery_journeys.py::test_rotation_relock_accepts_different_shape_raw_key`

### Journey E: multi-project safety

1. Create two projects under one isolated `WORTHLESS_HOME`.
2. Lock each project's `.env`.
3. Unlock project A.
4. Inspect project B.
5. Unlock project B.

Expected UX:

- Project A restores correctly.
- Project B remains protected after project A unlocks.
- Project B restores correctly only when explicitly unlocked.

Trace first to:

- `test_recovery_journeys.py::test_multi_project_unlock_keeps_other_project_protected`

### Journey F: unsafe rewrite refusal

1. Create `.env` with a fake raw key.
2. Create a hardlink to that same `.env`.
3. Run `worthless lock --env .env`.
4. Run `worthless status`.
5. Run `worthless scan .env`.

Expected UX:

- Lock fails without traceback.
- `.env` still contains the original raw key.
- Status does not claim the key is protected.
- Explicit scan reports the raw key as unprotected without exposing the full value.

Trace first to:

- `test_native_stress_journeys.py::test_lock_rewrite_refusal_leaves_env_and_status_recoverable`

### Journey G: tampered locked value

1. Lock a fake raw key.
2. Replace the locked `.env` value with another shape-valid fake key.
3. Run `worthless unlock --env .env`.
4. Run `worthless status`.

Expected UX:

- Unlock fails without traceback.
- Output says the locked value was modified after lock or has a commitment mismatch.
- `.env` keeps the tampered value for investigation/retry.
- Status still shows protected state; the DB row was not deleted.

Trace first to:

- `test_native_stress_journeys.py::test_unlock_tampered_locked_env_fails_without_destroying_state`

### Journey H: install/reinstall/manual uninstall

1. Run `sh ./install.sh` on a supported macOS/Linux shell.
2. Inspect whether the output says `worthless` is already on PATH, only works after PATH activation, or is shadowed by a stale PATH binary.
3. Re-run the installer with the same pinned version, then simulate an older uv-installed version and re-run again.
4. Simulate a pipx conflict or uv/network failure when reviewing failure wording.
5. For uninstall today, run `uv tool uninstall worthless` and then follow the platform docs for keychain/state cleanup.

Expected UX:

- Install exits 0 and prints a usable next command.
- Fresh shells without persistent `~/.local/bin` get a clear permanent PATH hint.
- If an older `worthless` is first on PATH, the installer names both the stale PATH version and the installed version instead of claiming clean success.
- Reinstall is safe and avoids unnecessary work when the pinned version is already installed; older uv tool installs upgrade through pinned `uv tool install --force`, not bare `uv tool upgrade`.
- Failure output keeps the underlying uv error above proxy/mirror hints.
- Uninstall guidance is honest: `uv tool uninstall worthless` removes the tool, but does not purge keychain or `~/.worthless` state until WOR-435 ships `worthless uninstall`; the trace includes a leftover local-state file.

Trace first to:

- `test_render_traces.py::test_install_lifecycle_trace_documents_current_install_contract`
- `test_install_static.py::test_install_smoke_uploads_terminal_artifacts`

### Journey I: Docker app on host Worthless

1. Install/run Worthless outside the app container.
2. Lock the project `.env` on the host.
3. Replace the locked `127.0.0.1:<port>` base URL with `host.docker.internal:<port>`.
4. Start the host proxy; on Linux without Docker Desktop, run it with `WORTHLESS_DEPLOY_MODE=lan`.
5. Run the app container with the locked `.env`.

Expected UX:

- The container never receives the raw provider key.
- The container sees a Docker-routable base URL, not `127.0.0.1`.
- A request from the app container reaches the host proxy.
- The upstream receives the reconstructed real key.
- If the user skips the bridge edit, the sample app preflight names the loopback mistake.
- If `.env` cannot be rewritten due to host permissions, the file remains unchanged and `status` does not show a phantom protected key.

Trace first to:

- `test_install_docker.py::test_host_cli_locked_env_reaches_proxy_from_app_container`
- `test_install_docker.py::test_app_container_fails_fast_when_locked_env_keeps_loopback_url`
- `test_install_docker.py::test_host_lock_unwritable_env_fails_without_phantom_enrollment`

## Current gaps

These are intentionally not covered by this first branch:

| Linear issue | Surface | Status |
| --- | --- | --- |
| `WOR-442` | Docker and clean distro matrix | In progress: first pass covered locally; awaiting PR/CI |
| `WOR-443` | OpenClaw install/config/protected request | Backlog |
| `WOR-444` | Agent and MCP driven setup | Backlog |
| `WOR-446` | CI user-flow lane | First pass in this branch: Ubuntu/macOS user flows and trace artifacts; Windows/WSL deferred |

Product-risk gaps still worth promoting into explicit journeys:

- Deleting part of `WORTHLESS_HOME` after lock.
- Corrupt shard DB or fernet material.
- Crash or disk-full during relock.
- Same key across two `.env` files.
- Unlock-all or multi-env state transitions.
- Agent-facing JSON/exit-code contracts.
- Non-TTY install and consent behavior beyond the deterministic installer traces.
- First-class `worthless uninstall` remains future WOR-435 scope.
- Real Docker bind-mount UID/path variants for apps that load `.env` from disk.

## Review rule

If manual UX testing finds a mismatch, record:

1. The journey name above.
2. The exact command and output.
3. The mapped pytest name.
4. Whether the mismatch is product wording, state behavior, platform behavior,
   or test harness drift.

That makes manual UX review traceable back to the automated suite without
turning the tests into vague end-to-end blobs.

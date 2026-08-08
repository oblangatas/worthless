# User journey stress-test matrix

Scope: follow-on branch after `WOR-439` / PR #177.

This document tracks failure modes that can ruin a user journey after the
happy-path user-flow suite already proves native lock, unlock, recovery,
rotation, and multi-project flows.

## Executive summary

The next stress lane should start with native `.env` and state durability. It
has the highest user impact, runs fast on local/macOS/Linux CI, and does not
depend on Docker, OpenClaw, or external networks.

Priority order:

1. Native destructive state transitions: refused rewrites, tampered locked
   `.env`, deleted DB, partial cleanup, and path ambiguity.
2. Proxy/default command stress: foreign listeners, port drift, and daemon
   health lies.
3. Platform/install stress: native keyring, GitHub runner matrix, WSL path
   behavior, Docker bind mounts, install/reinstall/uninstall.
4. Agent/OpenClaw/MCP stress: partial config rewrites, child process env
   contamination, stdio MCP handshake, upstream outage.

## Native state stress

| Priority | Failure mode | User symptom | Expected behavior | Existing coverage | Proposed user-flow proof |
| --- | --- | --- | --- | --- | --- |
| P0 | `.env` rewrite refused after DB writes | `lock` fails but later `status` claims the key is protected | Original `.env` bytes remain, DB is unwound, `scan` still reports an unprotected key, no traceback | Lower-level tests only | Hardlink `.env`, run `lock`, then assert unchanged `.env`, empty `status`, and raw-key `scan` |
| P0 | Locked shard-A value edited before unlock | `unlock` fails cryptically or corrupts state | Refuse restore, leave `.env` and DB unchanged, explain tamper/mismatch/re-lock/doctor | Xfail or lower-level coverage | Lock, replace locked value with shape-valid fake key, run `unlock --env` |
| P0 | DB deleted/corrupted after lock | `.env` is locked but machine state is gone | Fail loudly with recovery limitation and original-machine/re-lock guidance; `status` must not imply safety | `WOR-567` covers deleted DB `unlock` wording and corrupt DB `status` fail-fast | Add `scan` behavior if product decides scan should diagnose local DB loss |
| P1 | Unlock restores `.env`, DB cleanup fails | Plaintext returns but stale DB rows remain | No data loss; output says partial cleanup and doctor/retry path | Not user-flow covered | Monkeypatch cleanup failure in-process, assert restored plaintext plus actionable guidance |
| P1 | `doctor --fix` purges one broken project and damages another | Healthy sibling project becomes unrecoverable | Only orphan row is purged; healthy project remains protected and unlockable | `WOR-567` user-flow coverage | Lock two projects, delete one env line, run doctor fix, unlock healthy project |
| P1 | Multi-project `status` lacks path clarity | User cannot tell which project is protected or broken | Status distinguishes project/env path for each enrollment | Current user-flow only checks `PROTECTED` remains | Lock two projects and assert status shows both project names or env paths |
| P2 | Deep scan leaks ambient secrets or leaves temp files | CI logs expose secret suffixes or temp `.env` remains | Redacted output, temp cleanup on success/failure | Simple scan only | `scan --deep --show-suffix` with controlled fake env |

## Proxy and default command stress

| Priority | Failure mode | User symptom | Expected behavior | Existing coverage | Proposed user-flow proof |
| --- | --- | --- | --- | --- | --- |
| P0 | Default command trusts a foreign listener on the configured port | `worthless --yes` says proxy is healthy but traffic goes elsewhere | Detect/refuse foreign listener or provide actionable conflict output | `wrap` has collision tests; default command does not | Start dummy `/healthz` server on `WORTHLESS_PORT`, run `worthless --yes` |
| P0 | BASE_URL port drift after lock | User locks on port A, wraps/runs on port B, child app fails later | Early failure with re-lock/reconfigure hint | Same-port behavior only | Lock with port A, wrap with port B, assert preflight catches drift |
| P1 | Proxy subprocess inherits ambient provider secrets | Daemon process sees real parent shell keys | Proxy child env excludes provider keys/base URLs unless required | Fernet env scrub only | Patch `subprocess.Popen`, run `up --daemon`, inspect `env` |
| P2 | Upstream outage | App receives confusing proxy error or metering changes | Sanitized 502/504, no traceback, no spend row, proxy remains healthy | Lower-level ASGI tests | Local unused upstream port through wrapped child or SDK |

## Platform and install stress

| Priority | Failure mode | User symptom | Expected behavior | Existing coverage | Proposed proof |
| --- | --- | --- | --- | --- | --- |
| P0 | Native keyring unavailable or disabled | User sees Keychain/system-keystore promise that is false | File fallback wording is explicit; native keyring cases are guarded | First branch covers fallback wording | Add platform trace rows and keyring guarded user-flow proof |
| P0 | Windows/WSL path behavior | `.env` path resolves differently or filesystem checks refuse incorrectly | Clear support/defer signal; no false green | Windows user-flow job is deferred | Separate `WOR-446`/platform branch with Windows/WSL probes |
| P1 | Docker host/app URL mismatch | App container gets `127.0.0.1` and cannot reach the host proxy | Sample app preflight names the loopback mistake; happy path uses Docker's host bridge | `WOR-442` adds host CLI + app-container proof | `tests/test_install_docker.py::test_host_cli_locked_env_reaches_proxy_from_app_container` and `::test_app_container_fails_fast_when_locked_env_keeps_loopback_url` |
| P1 | Docker bind mount path/permission mismatch | Container locks wrong path or cannot write mounted `.env` | Host refused rewrite leaves `.env` unchanged and no phantom enrollment; real bind-mount UID/path cases remain follow-up | `WOR-442` adds unwritable-project proof | `tests/test_install_docker.py::test_host_lock_unwritable_env_fails_without_phantom_enrollment` |
| P1 | Install/reinstall/uninstall half-failure | New user cannot recover from partial install or trust the wrong proof bucket | Idempotent reinstall/uninstall with exact next step; checkout-local CI and public `worthless.sh` release proof are not conflated; stale PATH binaries are called out; older uv tool installs upgrade via pinned force-install | `WOR-441`/`WOR-442` cover checkout-local install and Docker first pass; `WOR-568` adds explicit public-curl evidence gate; `WOR-597` adds second-pass install failure journeys | `tests/test_install_static.py::test_install_smoke_name_matches_checkout_local_proof`, `::test_public_curl_manual_gate_requires_terminal_evidence`, `tests/test_install_logic.py::test_success_with_stale_worthless_on_path_warns_about_shadowing`, and `::test_older_uv_tool_install_upgrades_via_pinned_force_install` |

References used for platform assumptions:

- GitHub-hosted runners support Ubuntu, Windows, and macOS runner families, but
  macOS runs in GitHub's macOS cloud while Ubuntu/Windows run in Azure:
  https://docs.github.com/en/actions/reference/github-hosted-runners-reference
- Python `keyring` can be disabled with
  `PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring`, and headless Linux
  needs an explicit D-Bus/keyring session for Secret Service:
  https://keyring.readthedocs.io/en/latest/index.html
- Docker bind mounts have host write access by default and are tied to host
  filesystem semantics:
  https://docs.docker.com/engine/storage/bind-mounts/

## Agent/OpenClaw/MCP stress

| Priority | Failure mode | User symptom | Expected behavior | Existing coverage | Proposed proof |
| --- | --- | --- | --- | --- | --- |
| P1 | Bare default command hits OpenClaw partial failure | `.env` is locked but OpenClaw remains ungated | Exit 73, loud warning, status degraded, no fake success | Direct lock OpenClaw tests | Default command user-flow with malformed/symlinked OpenClaw config |
| P1 | OpenClaw config partial rewrite | Agent config is half-updated | Atomic config behavior and doctor/status guidance | OpenClaw tests, not first branch | `WOR-443` branch |
| P1 | MCP stdio drift | Agent cannot call `worthless_status` despite docs | MCP initialize/list-tools/call-tool works in child process | In-process MCP tests only | `WOR-444` branch |

# WOR-193 / WOR-717 — Wave verification stack

> **Source of truth** for service testing lanes. Synced to Linear: WOR-193, WOR-724, WOR-725, WOR-747–749, and the [ship plan doc](https://linear.app/plumbusai/document/wor-193-service-lifecycle-research-and-ship-plan-ee56bb0580d5).
>
> **Branch tip:** `main` @ `876d102` (PR #292 merged 2026-06-25)

## Four verification lanes

| Lane | Marker / layer | Wave | CI default? | Gate agent |
|------|----------------|------|-------------|------------|
| **Adversarial** | L3 `@pytest.mark.adversarial` | **WOR-724** | Yes (PR stack) | security-reviewer, regression-dog |
| **Dirty dev** | L3+ `@pytest.mark.dirty_env` | **WOR-724** pytest + **WOR-725** scripts | Opt-in (`-m dirty_env`) | karen |
| **Chaos** | L7 manual + chaos-engineer | **WOR-725** | No | chaos-engineer |
| **Contract** | L3 snapshots + Hypothesis | **WOR-724/725** | Yes (snapshots) | tdd-guide |

**Cross-refs:** [scenario-matrix.md §7](scenario-matrix.md) (S-SVC-*), [STRESS_TEST_MATRIX.md](../../tests/user_flows/STRESS_TEST_MATRIX.md) (proxy P0), [release-gates.md](../release-gates.md) Track A4 (doctor recovery).

---

## Ladder (always → sometimes)

| Layer | What | When | Agent / tool |
|-------|------|------|----------------|
| **L0** | Minimal repro + failing test name | Every fix | — |
| **L1** | Lane pytest (service, default, 717) | Every commit | `test-runner` |
| **L2** | `@pytest.mark.user_flow` journeys | Wave close | `test-runner` |
| **L3** | Adversarial + dirty_env + contract | WOR-724 close | security-reviewer, regression-dog |
| **L4** | Hypothesis / mutmut | crypto, keystore, parsers | `tdd-guide` |
| **L5** | Expert gate (one per close) | Before wave Done | Rotate: Jenny → karen → code-reviewer → security-reviewer |
| **L6** | CI matrix + `gh pr checks` | Ship truth | — |
| **L7** | Chaos + repeat-run live packs | WOR-725 | `chaos-engineer` |

**Rule:** Never skip L0→L1. WOR-724 is **not lean** on adversarial/dirty — coverage-first.

---

## Pipeline ↔ verification

| Wave | Linear | PR | Status | Close bar (tests) | Gate |
|------|--------|-----|--------|-------------------|------|
| **1a** | WOR-720 | #288 | Done | `test_service_*` templates | karen |
| **2** | WOR-721 | #289 | Done | WOR-717 integration + default | code-reviewer |
| **3** | WOR-723 | #290 | Done | W3-UF/SB added | regression-dog |
| **3b** | **WOR-724** | **#292** | **Done** (`876d102`) | W3-ADV/DIRTY/CONTRACT tables below | security-reviewer |
| **4+1b** | WOR-725 | #292 tail | backlog | W4-CHAOS/DIRTY + 1b AC + WOR-747–749 live | chaos-engineer |
| **5** | WOR-726 | #293 | backlog | banner, `service doctor` user_flow | ux-researcher |
| **6** | WOR-727 | #294 | backlog | full stack merge, release-gates Track A | Jenny |

**Live-pack tickets (children of WOR-725):** [WOR-747](https://linear.app/plumbusai/issue/WOR-747) unlock-in-trap · [WOR-748](https://linear.app/plumbusai/issue/WOR-748) fernet sync · [WOR-749](https://linear.app/plumbusai/issue/WOR-749) roundtrip PASS.

---

## WOR-724 close bar — adversarial (L3)

| ID | Test | File | Status |
|----|------|------|--------|
| W3-ADV-1 | Foreign unit on every service mutator | `test_service_backends.py` | **done** |
| W3-ADV-2 | Supervised spawn failure → no key leak | `test_native_stress_journeys.py` | **done** |
| W3-ADV-3 | `/healthz` OK, no pidfile → must spawn (6gkb) | `test_service_up_managed.py` | **pytest done**; P2 reclaim in `up.py` backlog |
| W3-ADV-4 | `/healthz` OK, pidfile matches → idempotent no-op | `test_service_up_managed.py` | partial |
| W3-ADV-5 | Fernet keyring vs stale file; SERVICE_MANAGED gate | `test_keystore.py` | done |
| W3-ADV-6 | Fernet drift → install/lock fails loud | `test_service_cli.py` / doctor | backlog |
| W3-ADV-7 | Stale `.lock-in-progress` / `.up.lock` recovery | `test_bootstrap.py` | backlog |
| W3-ADV-8 | Orphan enrollment (deleted env_path) → doctor purge | doctor tests | backlog |
| W3-ADV-9 | Port 8787 foreign listener → refuse/recover | `test_service_up_managed.py` | backlog |
| W3-ADV-10 | Trap without unlock → next run dirty (**WOR-747**) | new dirty_env journey | backlog |
| W3-ADV-11 | `WORTHLESS_HOME` mismatch vs plist | `test_service_backends.py` | backlog |
| W3-ADV-12 | SIGKILL mid supervised up → stale pidfile | stress journey | backlog |
| W3-ADV-13 | launchd env: file-only fernet path | keystore + service | partial |
| W3-ADV-14 | lock → service install → 401 class regression | integration | backlog |
| W3-ADV-15 | Dummy `/healthz` on port → default **and** service up (STRESS P0) | user_flow / service | backlog |
| W3-ADV-16 | Same as W3-ADV-10; blocks **WOR-749** | dirty_env | backlog |
| W3-ADV-17 | Fernet drift preflight before install | live script + pytest | partial |

---

## WOR-724 close bar — dirty dev (L3+)

Fixture: `tests/fixtures/dirty_home.py` (shipped #292; dirty_env journeys still backlog).

| ID | Seeds | Assert | Status |
|----|-------|--------|--------|
| W3-DIRTY-1 | Orphan enrollment → deleted temp `.env` | doctor purges; sibling untouched | backlog |
| W3-DIRTY-2 | Stale lock files | lock/up recover or clear error | backlog |
| W3-DIRTY-3 | DB row + missing shard_a (S-05) | honest status + doctor | backlog |
| W3-DIRTY-4 | Stale `proxy.pid`, no process | up coherent (not bare healthz) | backlog |
| W3-DIRTY-5 | Keyring shard + wrong `fernet.key` | managed vs interactive split | partial |

Run: `uv run pytest -m dirty_env` (marker registered; journeys mostly backlog).

---

## WOR-724 close bar — contract (L3)

| ID | Technique | Status |
|----|-----------|--------|
| W3-CONTRACT-1 | Syrupy: launchd plist + systemd unit required keys | backlog |
| W3-PROP-1 | Hypothesis: `ProxyRuntimeState` → single action | backlog |
| W3-E2E-1 | Real subprocess supervised `up` | backlog |
| W3-MUT-1 | mutmut on `keystore.py` after WOR-748 | backlog |

---

## WOR-725 close bar — chaos + L7

| ID | Proof | Status |
|----|-------|--------|
| W4-CHAOS-1 | Reboot + LaunchAgent auto-start (S2) | backlog |
| W4-CHAOS-2 | `kill -9` proxy/sidecar → launchd restart | backlog |
| W4-CHAOS-3 | systemd without linger → fail-closed | backlog |
| W4-DIRTY-6 | Run lifecycle live pack **twice** without teardown | backlog |
| W4-DIRTY-7 | Run lock roundtrip pack **twice** (needs WOR-747) | backlog |
| W4-CHAOS-8 | Container restart + mounted `~/.worthless` (I-04) | backlog |

Scripts: [wor-193-live-checklist.md](wor-193-live-checklist.md).

---

## Wave 3 — commands (copy/paste)

```bash
# L1 lane
uv run pytest tests/cli/test_service_backends.py tests/test_cli_default.py \
  tests/cli/test_wor717_integration.py tests/cli/test_service_up_managed.py \
  tests/test_keystore.py -o addopts= -q

# L3 adversarial
uv run pytest -m adversarial tests/cli tests/user_flows -o addopts= -q

# L3+ dirty (when marker exists)
uv run pytest -m dirty_env -o addopts= -q

# L2 user journeys
uv run pytest tests/user_flows/test_native_cli_journeys.py -m user_flow -o addopts= -q

# L6 CI (main)
gh run list --branch main --limit 3
```

---

## After each task

1. Update this file + Linear wave ticket + ship plan doc.
2. Run L1; on wave close run L3 + one L5 agent.

---

## Related

- [scenario-matrix.md](scenario-matrix.md) — §7 S-SVC-*
- [wor-193-live-checklist.md](wor-193-live-checklist.md) — L7 packs
- [scenario-verification-prompt.md](scenario-verification-prompt.md)
- [release-gates.md](../release-gates.md)

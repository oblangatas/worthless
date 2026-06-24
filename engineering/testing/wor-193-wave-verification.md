# WOR-193 / WOR-717 — Wave verification stack

> Living doc. Update after every wave close. Plan doc: [Linear WOR-193 plan](https://linear.app/plumbusai/document/wor-193-service-lifecycle-research-and-ship-plan-ee56bb0580d5).

## Ladder (always → sometimes)

| Layer | What | When | Agent / tool |
|-------|------|------|----------------|
| **L0** | Minimal repro + failing test name | Every fix | — |
| **L1** | Lane pytest (service, default, 717) | Every commit | `test-runner` |
| **L2** | `@pytest.mark.user_flow` journeys | Wave close | `test-runner` |
| **L3** | `@pytest.mark.adversarial` + stress | 3b, security touch | `regression-dog`, `security-reviewer` |
| **L4** | Hypothesis / mutmut | crypto, parsers only | `tdd-guide` |
| **L5** | Expert gate (one per close) | Before wave Done | Rotate: Jenny → karen → code-reviewer → security-reviewer |
| **L6** | CI matrix + `gh pr checks` | Ship truth | — |
| **L7** | Chaos / manual S2–S10 | Wave 4+ (1b) | `chaos-engineer` |

**Rule:** Never skip L0→L1. Climb only as high as blast radius.

---

## Pipeline ↔ verification

| Wave | Linear | PR | You are here | Tests to add / run | Gate agent |
|------|--------|-----|--------------|-------------------|------------|
| **1a** | WOR-720 | #288 | Done | `test_service_backends`, templates | karen |
| **2** | WOR-721 | #289 | Done | `test_cli_default`, `test_start_supervised_proxy_integration` | code-reviewer |
| **3** | WOR-723 | #290 | **active** | user_flow idempotent default; stopped-service hint; `test_supervised_proxy_adversarial` L3 | test-runner + regression-dog |
| **3b** | WOR-724 | #291 | next | lock no-op real; IPCError; socket proof; foreign unit **mutators** | security-reviewer, tdd-guide |
| **4+1b** | WOR-725 | #292 | backlog | S2 reboot, S5 keys-intact, `sh.worthless.proxy`, linger fail-closed | chaos-engineer |
| **5** | WOR-726 | #293 | backlog | banner, `service doctor` user_flow | ux-researcher |
| **6** | WOR-727 | #294 | backlog | full stack merge, release-gates Track A | Jenny |

---

## Wave 3 — commands (copy/paste)

```bash
# L1 lane
uv run pytest tests/cli/test_service_backends.py tests/test_cli_default.py \
  tests/cli/test_start_supervised_proxy_integration.py \
  tests/cli/test_supervised_proxy_adversarial.py -o addopts= -q

# L2 user journeys
uv run pytest tests/user_flows/test_native_cli_journeys.py -m user_flow -o addopts= -q

# L3 adversarial + stress (supervised proxy)
uv run pytest tests/cli/test_supervised_proxy_adversarial.py \
  tests/user_flows/test_native_stress_journeys.py -m "adversarial or user_flow" -o addopts= -q

# L6 CI
gh pr checks 290
```

---

## Wave 3 — test backlog (TDD)

| ID | Test | File | Status |
|----|------|------|--------|
| W3-UF-1 | Second `worthless --yes` skips `start_supervised_proxy` | `test_native_cli_journeys.py` | **added** |
| W3-UF-2 | Stopped service → hint `service start`, no spawn | `test_native_cli_journeys.py` | **added** |
| W3-SB-1 | `_session_user` never calls getlogin when USER set | `test_service_backends.py` | **added** |
| W3-SB-2 | `_session_user` pwd fallback when getlogin fails | `test_service_backends.py` | **added** |
| W3-ADV-1 | Foreign unit on install/uninstall (not just detect) | `test_service_backends.py` | Wave 3b |
| W3-ADV-2 | `start_supervised_proxy` failure → no key leak | `test_supervised_proxy_adversarial.py`, `test_native_stress_journeys.py` | **added** |
| W3-ADV-3 | Foreign `/healthz` listener skips spawn | `test_supervised_proxy_adversarial.py`, `test_native_stress_journeys.py` | **added** |
| W3-ADV-4 | Symlinked `WORTHLESS_HOME` unit ownership | `test_supervised_proxy_adversarial.py`, `test_service_backends.py` | **added** |
| W3-ADV-5 | Provider env inherited by supervised child (scrub gap) | `test_supervised_proxy_adversarial.py` | **added** (flip when #292 scrubs) |
| W3-ADV-6 | Concurrent `unit_file_matches_home` / idempotent ensure | `test_supervised_proxy_adversarial.py` | **added** |
| W3-E2E-1 | Real subprocess supervised `up` (optional) | `test_wrap_magic_moment.py` pattern | Wave 3b |

Cross-ref: [scenario-matrix.md](scenario-matrix.md) (U-*, S-*), plan S1–S10.

---

## After each task (agent report template)

1. Update Linear wave ticket + plan doc pipeline table.
2. Post:

```
| Wave | Status | You are here | Next |
| 3 | … | … | WOR-724 |
```

3. Run L1; if wave close, run L2 + one rotated L5 agent.

---

## Related

- [scenario-matrix.md](scenario-matrix.md) — edge-case inventory
- [scenario-verification-prompt.md](scenario-verification-prompt.md) — reviewer prompt
- [release-gates.md](../release-gates.md) — Track A ship criteria

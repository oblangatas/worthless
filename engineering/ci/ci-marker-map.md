# CI workflow ↔ pytest marker map

Which GitHub Actions workflow runs which pytest markers. **CodeQL** uses GitHub default setup (not a checked-in workflow) — active on PRs and weekly.

Cross-links: [pr-security-stack.md](pr-security-stack.md) (Layer 2 decoration), local `TESTING.md` (full lane matrix).

## Marker quick reference

| Marker | Meaning | Default local `pytest`? |
|--------|---------|------------------------|
| *(default)* | Unit/integration without excluded markers | Yes (`pyproject.toml` excludes live/docker/user_flow/real_ipc) |
| `real_ipc` | Real subprocess/sidecar IPC (serial, `-n0`) | No — excluded by default |
| `docker` | Needs Docker daemon | No |
| `openclaw` | OpenClaw container integration | No |
| `live` | Real LLM providers (costs $) | No |
| `user_flow` | Full CLI + keyring user journeys | No |
| `quarantine` | Flaky under investigation | No — separate non-blocking job |
| `contract` | Schema/protocol checks | Scheduled + manual only |
| `benchmark` | pytest-benchmark | Manual only |
| `adversarial` | Security/race/fuzz | Subset in default when not excluded |
| `e2e` | Full lifecycle smoke | Mixed (see workflows) |

## Workflow matrix

| Workflow | Trigger | Markers / filter | Blocking? |
|----------|---------|------------------|-------------|
| **tests.yml** → `test` | push, PR | `-m "not live and not docker and not user_flow and not real_ipc and not quarantine"` then serial `-m "real_ipc and not live and not docker and not quarantine"` | Yes |
| **tests.yml** → `quarantine` | push, PR | `-m quarantine` (`continue-on-error: true`) | No |
| **tests.yml** → `coverage-gate` | PR | Uses `coverage.xml` from py3.13 matrix job | Yes |
| **tests.yml** → `sonarcloud` | PR (human only; skips `dependabot[bot]`) | N/A (Sonar on `src/`) | Yes |
| **tests.yml** → `smoke-windows` | push, PR | Platform smoke subset | Yes |
| **sast.yml** | push, PR | bandit, semgrep, gitleaks, actionlint, zizmor, license | Yes |
| **docker-security.yml** | PR (`src/**`, `tests/**`, Dockerfiles) | `-m docker`, `-m openclaw`, `-m "openclaw and docker"` (load-bearing) | Yes |
| **install-docker.yml** | PR (install paths) | `-m docker` (install matrix) | Yes |
| **user-flows.yml** | PR (user_flow paths) | `-m user_flow` | Yes |
| **scheduled.yml** | cron + dispatch | mutmut crypto; `-m contract`; extended Hypothesis | Non-blocking contract |
| **pre-release.yml** | tag `v*` | Full mutmut; pip-audit; full coverage | Release gate |
| **benchmarks.yml** | dispatch | `-m benchmark --benchmark-only` | No |
| **flake-radar.yml** | schedule | `-m "not docker and not live and not user_flow and not quarantine"` | Informational |
| **CodeQL** (default setup) | PR, weekly | Python, JS/TS, Actions | Yes |

## Path filters (when workflows skip)

| Workflow | Runs when |
|----------|-----------|
| `docker-security.yml` | Changes under `src/`, `tests/`, Dockerfiles, compose |
| `user-flows.yml` | Changes under `tests/user_flows/**`, CLI paths (see workflow) |
| `install-docker.yml` | Install script / docker install paths |

## Sonar / Dependabot

- **Human PRs:** SonarCloud scan + PR decoration (`SONAR_TOKEN` available).
- **Dependabot PRs:** Sonar job skipped — bot runs cannot use repo secrets; tests + SAST still run. See [pr-security-stack.md](pr-security-stack.md).

## Related beads

- Epic: `worthless-vmmv` (Testing Fortification)
- Wave 5: `worthless-4a48` (this doc)

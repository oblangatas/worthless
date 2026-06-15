# PR security and quality stack

Additive layers on pull requests. **CodeRabbit stays** for LLM-style review (intent, design, readability). This doc covers deterministic tooling that posts checks or inline findings.

## On every PR (automated)

| Tool | Workflow / source | PR signal | Inline on diff? |
|------|-------------------|-----------|-----------------|
| **CodeQL** | GitHub default setup (Code security) | `CodeQL` check | Security tab + annotations when findings exist |
| **Semgrep** | `sast.yml` (CI SARIF) + Semgrep Code GitHub App | `semgrep-cloud-platform/scan` | App: yes; CI SARIF: Security tab only |
| **Bandit** | `sast.yml` | SARIF → Security tab | No |
| **Gitleaks** | `sast.yml`, pre-commit | SARIF / hook | No |
| **SonarCloud** | `tests.yml` → `sonarcloud` job | Scan + PR decoration (human PRs only; **skipped** on `dependabot[bot]` — no `SONAR_TOKEN` on bot runs) | Summary comment when bound to GitHub |
| **Snyk** | `snyk-security.yml` | Check | No |
| **Dependabot** | `.github/dependabot.yml` | Opens separate dependency PRs | N/A (uv weekly + actions patch/minor auto; action **majors** manual) |
| **Tests + coverage floors** | `tests.yml` | Matrix + `check-coverage-floors.py` | No |
| **CodeRabbit** | GitHub App | Review / summary | Yes (LLM) |

## Not duplicated on purpose

- **No checked-in CodeQL workflow** — default setup already analyzes Python, JS/TS, and Actions on PRs and weekly.
- **No changes to `.coderabbit.yaml`** — Layer 2 does not replace or disable CodeRabbit.

## One-time operator steps

| Step | Status | Action |
|------|--------|--------|
| CodeQL default setup | Done (configured 2026-04-24) | Repo → Settings → Code security → keep enabled |
| Semgrep GitHub App | Installed (`semgrep-code-shacharm2`) | Confirm inline comments on next security-touching PR |
| SonarCloud GitHub binding | Verify | SonarCloud project must be imported from GitHub (not manual-only) for PR decoration |
| Dependabot | After merge of `dependabot.yml` | First uv/actions PR within ~24h |
| Dependabot + Sonar | After #334 | Rebase open bot PRs (`@dependabot rebase`) so they pick up the skip; tests/SAST still run |

## Dependabot PRs vs SonarCloud

Dependabot PRs change lockfiles and workflow action pins — not `sonar.sources=src`. GitHub also withholds repository secrets (including `SONAR_TOKEN`) from Dependabot-triggered workflow runs unless explicitly configured, so SonarCloud cannot authenticate on bot PRs.

The `sonarcloud` job in `tests.yml` therefore skips when `github.actor == 'dependabot[bot]'`. Human-authored PRs are unchanged. Meaningful gates on dependency bumps remain: pytest matrix, Semgrep, CodeQL, Snyk, Bandit, coverage floors.

## Verify after changes

```bash
# CodeQL on a recent PR
gh pr checks <number> --repo shacharm2/worthless | grep -i codeql

# Default setup state
gh api repos/shacharm2/worthless/code-scanning/default-setup -q .state

# Sonar PR decoration: open a test PR and look for Sonar summary comment on the PR timeline
```

## Related

- **CI ↔ marker map:** [ci-marker-map.md](ci-marker-map.md) (Wave 5, `worthless-4a48`)
- Testing lanes and marker matrix: `TESTING.md` (local; gitignored — sync from engineering/ci when publishing)
- Layer 2 epic: beads `worthless-n3k7` and children

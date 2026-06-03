# `scripts/release.sh` — Design Spec (Deployment Engineering Lens)

> One command, one passphrase, one deterministic path from clean worktree to live PyPI + Worker + GitHub Release + Linear comment. Authored against bead **worthless-5xzo** (folds **worthless-avm7**).

---

# 1. Top-Level Shape

```text
./scripts/release.sh <version>           # happy path
./scripts/release.sh <version> --dry-run # read-only, no tag, no push
./scripts/release-recover.sh <version>   # called only when post-tag hint fires
```

Three subphases, strictly sequential, fail-closed between each:

```text
release.sh <version>
├── phase 1: preflight       (read-only, no secrets, ~30s)
│   └── 10 gates, each: check → pass | fail+remediation+exit
├── phase 2: tag-cut          (ONLY GPG step, passphrase prompted ONCE)
│   ├── tag -s with forced openpgp format
│   ├── local verify (git tag -v) before push
│   ├── CONFIRM-Y/N
│   └── push
└── phase 3: post-tag         (read-only watch + finalize, ~5min)
    ├── poll publish.yml + deploy-worker.yml
    ├── if verify-tag fails → print recover hint + exit
    ├── hard-gate: pip index versions | worker header | docker install
    ├── extract CHANGELOG section → gh release create
    ├── trigger release-sync-check.yml → report A1–A5
    ├── open CHANGELOG-date-stamp PR
    └── print Linear comment markdown
```

Call graph:

```text
release.sh
 ├── lib/preflight.sh        (10 gate functions)
 ├── lib/tag-cut.sh          (gpg-format-forced tag + verify + push)
 ├── lib/post-tag.sh         (poll, gate, finalize)
 └── lib/io.sh               (log, confirm, redact, exit_with_remediation)
release-recover.sh
 └── lib/ruleset.sh          (disable/enable + active-state guard)
```

---

# 2. Preflight Gates (Phase 1)

All 10 gates run unconditionally; first failure exits non-zero with **one** remediation line. No partial state.

| # | Gate | Check | Failure remediation (single line) |
|---|------|-------|------------------------------------|
| P1 | Clean worktree | `git status --porcelain` empty AND on `main` AND up-to-date with `origin/main` | `Stash or commit your changes, then re-run.` |
| P2 | Version arg sane | `<version>` matches `^[0-9]+\.[0-9]+\.[0-9]+$`, not already a tag | `Pick an unused semver; run scripts/bump-version.sh <version> first if needed.` |
| P3 | pyproject sync | `grep ^version pyproject.toml` == `<version>` | `Run scripts/bump-version.sh <version> and commit before release.sh.` |
| P4 | install.sh pin | `WORTHLESS_VERSION_PIN` in `install.sh` == `<version>` | `bump-version.sh missed install.sh — fix and recommit.` |
| P5 | CHANGELOG placeholder | `## <version> — TBD` heading exists | `Add a CHANGELOG.md section for <version> with TBD date marker.` |
| P6 | Smoke test green | `./scripts/smoke-test.sh` exits 0 (folds worthless-avm7) | `Smoke failed — fix lock/scan/unlock round-trip before releasing.` |
| P7 | GPG fingerprint match | `gpg --list-secret-keys --with-colons` includes repo Variable `MAINTAINER_GPG_FINGERPRINT` | `Your secret key fingerprint != MAINTAINER_GPG_FINGERPRINT repo Variable.` |
| P8 | `gh` auth | `gh auth status` returns 0 AND token scope includes BOTH `repo` AND `workflow` unconditionally (security-engineer R-9 — `workflow` is required even on the happy path because step 4.7 `gh workflow run` silently no-ops without it) | `Run gh auth refresh -s repo,workflow.` |
| P9 | Ruleset alive | `gh api /repos/:owner/:repo/rulesets/15719679 --jq .enforcement` == `active` | `v-tags-signed ruleset 15719679 not active — re-enable in repo settings.` |
| P10 | Workflows file fresh | `verify-tag.sh` exists, executable, hash recorded in `.release-meta` matches | `verify-tag.sh changed since last release — re-review and update .release-meta hash.` |

`--dry-run` runs P1–P10 then exits 0 with a "would cut tag v<version>" summary.

---

# 3. Tag-Cut (Phase 2)

The **only** step that needs the passphrase. Always force openpgp format to defeat the SSH-vs-GPG ambiguity from 0.3.7:

```bash
FPR="$(gh variable get MAINTAINER_GPG_FINGERPRINT)"
git -c gpg.format=openpgp \
    -c user.signingkey="$FPR" \
    tag -s "v${VERSION}" \
    -m "Release v${VERSION}"
```

Then **local** verification BEFORE any push:

```bash
git tag -v "v${VERSION}" 2>&1 | tee /tmp/tag-verify.out
grep -q "Good signature" /tmp/tag-verify.out || die "tag-cut: GPG signature missing"
grep -q "$FPR"            /tmp/tag-verify.out || die "tag-cut: signed by wrong key"
```

Then **mandatory** interactive confirmation (no `--yes` flag exists; non-TTY exits):

```text
About to push v0.3.8 (GPG-signed by D3AD…BEEF). Continue? [y/N]
```

Then `git push origin "v${VERSION}"`. On any local-verify failure, the local tag is **deleted** (`git tag -d`) before exit so re-runs start clean.

---

# 4. Post-Tag (Phase 3)

| Step | Tool | Gate behaviour |
|------|------|----------------|
| 4.1 | `gh run watch` for `publish.yml` + `deploy-worker.yml` (parallel) | If `verify-tag` step fails → print `Tag stuck — run scripts/release-recover.sh <version>` → exit 2 |
| 4.2 | `pip index versions worthless` (in clean venv) | Must list `<version>` within 10min poll, else exit |
| 4.3 | Worker probe via `ctx_execute` (sandbox HTTP) checking `X-Worthless-Script-Tag` header AND served `WORTHLESS_VERSION_PIN` == `<version>` | Mismatch → exit |
| 4.4 | Clean Docker install: `docker run --rm python:3.12-slim sh -c "pip install worthless==<version> && worthless --version"` | Non-zero → exit |
| 4.5 | Extract CHANGELOG section: `awk '/^## '"$VERSION"'/,/^## /' CHANGELOG.md \| sed '$d' > /tmp/notes.md` | Empty → exit |
| 4.6 | `gh release create v<version> --notes-file /tmp/notes.md --verify-tag` | — |
| 4.7 | `gh workflow run release-sync-check.yml`, then watch | Report each of A1–A5 individually with PASS/FAIL line |
| 4.8 | Open date-stamp PR | Auto-branch `chore/changelog-stamp-<version>`, single-file edit (`TBD` → today), `gh pr create` |
| 4.9 | Emit Linear comment markdown to stdout | Maintainer copy-pastes into the release ticket — no MCP coupling in release.sh |

---

# 5. `scripts/release-recover.sh <version>`

Strict 6-step recovery (R1–R6), each step idempotent:

```bash
R1  gh api -X PATCH /repos/:owner/:repo/rulesets/15719679 -f enforcement=disabled
R2  git push --delete origin "v${VERSION}"  ;  git tag -d "v${VERSION}" 2>/dev/null || true
R3  require_local_tag_gpg_signed "${VERSION}"      # blocks until maintainer re-runs tag-cut
R4  git push origin "v${VERSION}"
R5  gh api -X PATCH /repos/:owner/:repo/rulesets/15719679 -f enforcement=active
R6  GUARD: re-query ruleset; exit non-zero if not `active`   # never exit with ruleset off
```

Trap on EXIT re-asserts R5+R6 — if the script dies between R1 and R5, the trap re-enables the ruleset. **Never** leave production exposed.

---

# 6. Error Handling Philosophy

- `set -euo pipefail` + `IFS=$'\n\t'` at top of every script.
- `trap on_err ERR` prints the failing line + remediation, exits.
- `trap on_exit EXIT` enforces invariants (ruleset active, no orphan local tags older than this run).
- Every `die` call takes exactly **one** next-action sentence. No multi-paragraph errors.
- Phases never "soft-continue." A failed gate = process exit. Re-run is the recovery model.
- All secrets-bearing output (`gpg`, `gh api`) piped through a redactor (`lib/io.sh::redact`) before logging.

---

# 7. Out-of-Scope (Explicit Non-Goals)

- Does **not** bump version (`scripts/bump-version.sh` is separate, runs in the prep PR).
- Does **not** write or edit CHANGELOG body — only stamps the date in phase 4.8.
- Does **not** post to Linear, Slack, X, or any social. Emits markdown for maintainer to paste.
- Does **not** edit CI workflows, rulesets (except disable/re-enable in recover), or repo settings.
- Does **not** sign anything other than the version tag.

---

# 8. Test Strategy

| Layer | Tool | Asserts |
|-------|------|---------|
| Static | `shellcheck -x scripts/release.sh scripts/release-recover.sh lib/*.sh` | zero warnings, `-x` follows sources |
| Dry-run | `./scripts/release.sh 9.9.9 --dry-run` in CI on every PR touching `scripts/` | All 10 preflight gates execute, none mutate, exit 0 |
| Mock harness | `tests/release/test_phases.bats` with `PATH`-shimmed `gh`/`git`/`pip`/`docker` | Phase ordering enforced; phase 2 never runs if any P-gate failed; phase 3 never runs if push failed |
| Recovery | `tests/release/test_recover.bats` with mocked `gh api` | Ruleset re-enabled even when R3 aborts; EXIT trap fires; no orphan local tags |
| Negative-path | Inject SSH-format git config | tag-cut still produces openpgp signature (regression for 0.3.7 root cause) |
| Negative-path | Mock `verify-tag` failure | Phase 3 prints recover hint with exact command, exits 2 |

CI job `release-script-ci.yml` runs static + dry-run + bats on every PR touching `scripts/release*.sh` or `lib/*.sh`. Real releases require the bats suite green on `main`.

---

**End of spec.** Implementation PR should be split: (1) `lib/io.sh` + preflight, (2) tag-cut + recover, (3) post-tag + finalize, (4) bats harness. Each PR independently mergeable; full orchestrator behind a feature flag (`WORTHLESS_RELEASE_SH=1`) until 0.3.8 cuts cleanly with it end-to-end.

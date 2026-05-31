# Release Orchestrator — Joint Spec

> Synthesis of deployment-engineer (phase shape, gates, error handling) + security-engineer (18 hard rules, threat model). Beads: **worthless-5xzo** (folds **worthless-avm7**). Phase 3 #2 of WOR-598 close-out.

**Reads:** [`deployment-engineer.md`](./deployment-engineer.md) · [`security-engineer.md`](./security-engineer.md)

---

## 0. Why this exists

worthless 0.3.7 cut took ~2 hours across two terminals and surfaced four pain points:

1. SSH-vs-GPG ambiguity (maintainer's `git config gpg.format ssh` silently signed the tag SSH → both workflows fail-closed-rejected → recovery dance).
2. `v-tags-signed` ruleset (id `15719679`) blocked the recovery dance until temporarily disabled.
3. Post-lock scan UX confusion (`scripts/smoke-test.sh` hung invisibly on lock's `Scan now?` prompt — worthless-mouc).
4. "Did anything deploy?" uncertainty between tag push and live PyPI / Worker / docs.

The orchestrator is a thin, auditable shim that turns `~30 commands + judgement calls` into `one command + one GPG passphrase + 5 confirms`. The trust root stays in `verify-tag.sh` + the maintainer's GPG fingerprint + the ruleset — this script just makes the maintainer's path through them harder to footgun.

---

## 1. Top-level shape (deployment-engineer §1)

```
./scripts/release.sh <version>           # happy path
./scripts/release.sh <version> --dry-run # read-only preflight only
./scripts/release-recover.sh <version>   # called when post-tag hint fires
./scripts/release-doctor.sh              # standalone ruleset/state check (R-4)
```

Three subphases, strictly sequential, fail-closed between each:

| Phase | What | Secrets touched | Max wall time |
|---|---|---|---|
| 1. Preflight | 10 gates (worktree, version sync, smoke, GPG fingerprint, gh auth, ruleset alive) | none | ~30s |
| 2. Tag-cut | `git tag -s` (forced openpgp) + local `git tag -v` parse + CONFIRM Y/N + push | GPG (gpg-agent only) | ~5s after passphrase |
| 3. Post-tag | Poll publish + deploy; PyPI/worker/docker hard-gates; GH Release; sync-check; date-stamp PR; Linear comment | none | ~5min |

Plus the `--verify-self` SHA check (R-14) and `release-self-check.sh` grep-based prohibitions check (R-11) run before phase 1 starts.

---

## 2. The 10 preflight gates (deployment-engineer §2)

Unconditional, first-fail-exits, one-line remediation each. Full table in `deployment-engineer.md` §2; highlights:

- **P3/P4** — pyproject.toml version + install.sh pin both match `<version>` (defeats the file↔pin↔tag drift class WOR-601 also targets)
- **P6** — `scripts/smoke-test.sh` exits 0 (folds worthless-avm7; assumes worthless-mouc fixed first so the wrapper doesn't hang invisibly)
- **P7** — local GPG secret key fingerprint matches the repo Variable `MAINTAINER_GPG_FINGERPRINT` exactly (no short-ID collisions — R-2)
- **P9** — `v-tags-signed` ruleset (id `15719679`) is `active` (catches "we forgot to re-enable" before any push)

`--dry-run` runs all 10 then exits 0 with a "would cut tag v<version>" summary. Wired in CI on every PR touching `scripts/`.

---

## 3. Tag-cut (deployment-engineer §3 + R-1, R-2, R-7, R-8, R-19)

The **only** GPG step. Passphrase prompted once via gpg-agent, never via `--passphrase*`.

**Expected-SHA capture happens in preflight gate P1.5 (new):** `EXPECTED_SHA=$(git rev-parse origin/main)` written to `.release-state/<version>/expected-sha`. The signed tag must point at exactly this commit — defends against `main` advancing between preflight + tag-cut (R-19).

```bash
EXPECTED_SHA=$(cat .release-state/${VERSION}/expected-sha)

git -c gpg.format=openpgp \
    -c user.signingkey="$MAINTAINER_GPG_FINGERPRINT" \
    -c tag.gpgSign=true \
    tag -s "v${VERSION}" "$EXPECTED_SHA" -m "$TAG_MSG"

# R-19: Verify the tag points at EXACTLY the SHA captured in preflight.
ACTUAL_SHA=$(git rev-parse "v${VERSION}^{commit}")
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || die "tag points at $ACTUAL_SHA, expected $EXPECTED_SHA (main advanced mid-release? wrong commit signed)"

git tag -v "v${VERSION}" 2>&1 | tee /tmp/tag-verify.out
grep -q "Good signature"                                    /tmp/tag-verify.out || die "GPG signature missing"
grep -q "$MAINTAINER_GPG_FINGERPRINT"                       /tmp/tag-verify.out || die "signed by wrong key (short-ID match not accepted)"
! grep -qE "Signature made.*(ssh-|x509)"                    /tmp/tag-verify.out || die "non-GPG signature format detected"
```

Then CONFIRM Y/N (non-TTY exits). Then push. On any local-verify failure: delete the local tag, exit non-zero, operator inspects.

`set +x` enforced at script top + re-asserted in this block (R-8).

---

## 4. Post-tag (deployment-engineer §4)

| Step | Hard gate |
|---|---|
| 4.1 | `gh run watch publish.yml deploy-worker.yml` — if `verify-tag` job fails → print exact `scripts/release-recover.sh <v>` command + exit 2 |
| 4.2 | `pip index versions worthless` polled with max-attempts + exponential backoff (R-17) until `<version>` appears. Then `pip download --no-deps --dest .release-state/<v>/ worthless==<version>` to fetch the wheel; capture its SHA256 to `.release-state/<v>/wheel.sha256`. The **pinned file** is the artifact for all subsequent verification steps. |
| 4.2b | **`gh attestation verify .release-state/<v>/worthless-<v>-*.whl --owner shacharm2 --repo worthless`** against the EXACT pinned wheel from 4.2 (NOT a fresh fetch — defeats TOCTOU). Sigstore bundle MUST chain to GHA OIDC issuer + worthless repo + `v<version>` tag ref. Failure → exit non-zero (R-10). |
| 4.3 | Worker `X-Worthless-Script-Tag` header + served `install.sh` `WORTHLESS_VERSION_PIN` both match `<version>` |
| 4.4 | Docker install proof using the **already-verified wheel from 4.2** (NOT a fresh `pip install` — that downloads a different wheel and bypasses the attestation chain): `docker run --rm -v "$PWD/.release-state/<v>:/wheels:ro" python:3.12-slim sh -c "pip install /wheels/worthless-*.whl && worthless --version"` succeeds with `<v>` |
| 4.5 | `awk` extract CHANGELOG section → non-empty |
| 4.6 | `gh release create v<v> --notes-file ... --verify-tag` |
| 4.7 | `gh workflow run release-sync-check.yml` → individual A1-A5 PASS/FAIL report |
| 4.8 | Auto-open `chore/changelog-stamp-<v>` PR with the date replacement (the Phase 3 #1 pattern, now automatic) |
| 4.9 | Emit Linear comment markdown to stdout — maintainer pastes (R-NEW: no MCP coupling in release.sh, keeps the script auditable and offline-capable) |

**R-10:** Step 4.2b calls `gh attestation verify` — cryptographic proof the wheel was built by our CI from the signed tag (works today). End-user `pip install` does NOT yet verify attestations at install time (PEP 740 enforcement in pip/uv is in progress) — user-facing wording is "verified at release-cut by maintainer; client-side enforcement when pip/uv ship it."

---

## 5. release-recover.sh (deployment-engineer §5 + R-3, R-4, R-5, R-15)

Strict 6-step dance, each idempotent, with a watchdog and trap stack:

```
R1  Snapshot current ruleset JSON (R-5) to /tmp
R2  Disable v-tags-signed (PATCH enforcement=disabled) — REQUIRES --allow-ruleset-disable flag (R-3)
    Start 120-second watchdog: ( sleep 120; re-enable from snapshot; kill -TERM $$ ) & WATCHDOG_PID=$!
    Install trap: trap re_enable_from_snapshot EXIT INT TERM HUP
R3  git push --delete origin "v${VERSION}"  ;  git tag -d "v${VERSION}" 2>/dev/null
R4  require_local_tag_gpg_signed "${VERSION}"  — BLOCKS until operator re-runs tag-cut
R5  git push origin "v${VERSION}"
R6  Re-enable v-tags-signed (PUT the R1 snapshot back, not a hard-coded body)
    Kill watchdog. GUARD: re-query enforcement; exit 1 if not `active`
```

Audit log `.release-audit/YYYY-MM-DD.log` written for every disable/enable/sign/push (R-15).

`release-doctor.sh` runs unconditionally at end of `release.sh` AND at end of `release-recover.sh` AND is callable standalone — its sole job is asserting `v-tags-signed` is `active`. Exit-1 on inactive = alarm bell (R-4, mitigates `kill -9` bypassing the trap).

---

## 6. The 18 hard rules (security-engineer §1-9, full table in `security-engineer.md`)

Compressed cross-reference:

| Lens | Rules |
|---|---|
| **Tag integrity** | R-1 forced `gpg.format=openpgp` + explicit `user.signingkey`; R-2 fingerprint + format verified before push; R-19 expected-SHA assertion (captured in P1.5 preflight, checked in tag-cut) |
| **Ruleset window** | R-3 opt-in flag + 120s watchdog + 4-signal trap; R-4 doctor standalone; R-5 snapshot-restore not hard-coded body; R-15 audit log |
| **Idempotency / replay** | R-6 every phase classified; markers in `.release-state/<v>/` |
| **Secret hygiene** | R-7 gpg-agent only; R-8 no rc-sourcing, no env export, no `bash -x`; R-13 stderr redactor; R-16 tag-message regex lint |
| **Token scope** | R-9 exactly `repo` (or `repo, workflow`), reject broader, reject CI `GITHUB_TOKEN` |
| **Live trust** | R-10 `gh attestation verify` mandatory in step 4.2b (works today, chains Sigstore bundle to GHA OIDC + repo + tag ref); R-17 bounded polling |
| **Negative space** | R-11 grep-based self-check (no force-push, hard-reset, workflow edits, `curl\|sh`, ...); R-12 no writes to trust-root paths; R-18 no `git config --global`, no `gpg --import` |
| **Supply chain** | R-14 SHA256 self-pin in `SECURITY_RULES.md` SR-09; `--accept-script-change` requires both flag + env var |

R-1 + R-3 are the rules I'd most fight a reviewer over — they encode the 0.3.7 incident as immutable safety properties.

---

## 7. Out of scope (combined non-goals)

- No version bumping (`scripts/bump-version.sh` stays separate, runs in prep PR)
- No CHANGELOG body authoring — only the date stamp in 4.8
- No social posting to Linear/Slack/X — emits paste-ready markdown only (auditability)
- No CI workflow edits, ruleset edits beyond disable/re-enable in recover, repo settings edits
- No signing anything other than the version tag
- No `gpg --import` (R-18) — keyring is operator-managed
- No deletion of `v*` tags from `origin` (only via documented recovery)

---

## 8. Test strategy (deployment-engineer §8)

| Layer | Tool | Asserts |
|---|---|---|
| Static | `shellcheck -x` | zero warnings, follows sourced libs |
| Self-check | `release-self-check.sh` | grep prohibitions all absent (R-11) |
| SHA pin | `--verify-self` | SHA256 matches SR-09 pin (R-14) |
| Dry-run | `release.sh 9.9.9 --dry-run` on every `scripts/` PR | All 10 preflights run, none mutate, exit 0 |
| Mock harness | `bats` with `PATH`-shimmed `gh`/`git`/`pip`/`docker` | Phase ordering enforced; phase 2 never runs if any P-gate failed |
| Recovery | `bats` with mocked `gh api` ruleset endpoint | Ruleset re-enabled on R3 abort; EXIT trap fires; no orphan local tags |
| Regression | inject `git config gpg.format ssh`; assert tag-cut still produces openpgp signature | 0.3.7 root cause becomes a regression test |
| Negative | mock `verify-tag` failure | Phase 3 prints exact recover hint + exit 2 |

CI job `release-script-ci.yml` runs the above on every PR touching `scripts/release*.sh` or `lib/*.sh`. Real releases require this suite green on `main`.

---

## 9. Implementation plan (suggested PR sequence)

| PR | Adds | Reviewable by |
|---|---|---|
| 1 | `lib/io.sh` + `release-self-check.sh` + preflight gates P1-P10 + `--dry-run` + bats harness scaffold | deployment-engineer + security-engineer |
| 2 | tag-cut + `release-recover.sh` + `release-doctor.sh` + ruleset snapshot/restore + watchdog + trap stack | security-engineer (primary) |
| 3 | post-tag steps 4.1-4.9 + worker probe + docker proof + CHANGELOG awk + GH Release + sync-check report + date-stamp PR auto-open | deployment-engineer (primary) |
| 4 | Linear comment markdown emit + SR-09 SHA pin in `SECURITY_RULES.md` + CI workflow `release-script-ci.yml` | both |

Each PR independently mergeable; full orchestrator gated behind `WORTHLESS_RELEASE_SH=1` env flag until 0.3.8 cuts cleanly with it end-to-end. The 0.3.8 cut becomes the dogfood test.

---

## 10. Approval gate

This is **design-only**. Implementation requires the maintainer's explicit go on this SPEC + the two raw agent files. Open questions for the maintainer:

1. **The `Linear comment markdown to stdout`** (4.9) vs MCP coupling — is paste-acceptable, or should we wire `mcp__linear__save_comment`? Recommended: paste, keeps script offline-capable + auditable.
2. **The `--allow-ruleset-disable` flag** (R-3) — opt-in or default-on? Recommended: opt-in. Forces deliberate keystrokes for the dangerous path.
3. **PEP 740 attestation** (R-10) — RESOLVED 2026-05-30 fixup: `release.sh` calls `gh attestation verify` directly in step 4.2b (works today). User-facing release notes say "verified at release-cut; client-side enforcement when pip/uv ship PEP 740 support."
4. **PR-1's scope** — is 10 preflight gates + scaffold the right first slice, or split smaller (e.g., 5 gates + scaffold first)? Recommended: full 10, since each gate is small and they share lib helpers.

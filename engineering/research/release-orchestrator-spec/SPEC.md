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
| 1. Preflight | 11 gates (worktree, version sync, smoke, GPG fingerprint, gh auth, ruleset alive, Tool Trust SHA pins per F-1/§11) | none | ~30s |
| 2. Tag-cut | `git tag -s` (forced openpgp) + local `git tag -v` parse + CONFIRM Y/N + push | GPG (gpg-agent only) | ~5s after passphrase |
| 3. Post-tag | Poll publish + deploy; PyPI/worker/docker hard-gates; GH Release; sync-check; date-stamp PR; Linear comment | none | ~5min |

Plus the `--verify-self` SHA check (R-14) and `release-self-check.sh` grep-based prohibitions check (R-11) run before phase 1 starts.

---

## 2. The 11 preflight gates (deployment-engineer §2 + P11 from F-1)

Unconditional, first-fail-exits, one-line remediation each. Full table in `deployment-engineer.md` §2; highlights:

- **P1** — clean worktree on `main` ff'd from origin; **also assert `.gitignore` contains both `.release-state/` and `.release-audit/` literal lines** (F-11 / R-6 — defends against `git add -A` leaking audit artifacts containing `gh api` responses or wheel hashes)
- **P3/P4** — pyproject.toml version + install.sh pin both match `<version>` (defeats the file↔pin↔tag drift class WOR-601 also targets)
- **P6** — `scripts/smoke-test.sh` exits 0 (folds worthless-avm7; assumes worthless-mouc fixed first so the wrapper doesn't hang invisibly)
- **P7** — local GPG secret key fingerprint matches the repo Variable `MAINTAINER_GPG_FINGERPRINT` exactly (no short-ID collisions — R-2)
- **P8** — `gh auth status` shows BOTH `repo` AND `workflow` scopes (F-9 / R-9 — `gh workflow run` in step 4.7 silently no-ops with `repo`-only token)
- **P9** — `v-tags-signed` ruleset (id `15719679`) is `active` via API **AND second-channel canary push rejected** (F-3 / R-21 — defends against MITM forging `enforcement: active`)
- **P11 (F-1 closure)** — Tool Trust: SHA256 hash of every external binary (`gh`, `gpg`, `docker`, `pip`, `awk`, `jq`, `sha256sum`, `python3`, `curl`) matches the pins in `SECURITY_RULES.md` SR-10. **Runs before P7/P9** so no GPG or `gh api` call ever executes against an unverified binary. See §11 Tool Trust for the full list + refresh policy (R-20).

`--dry-run` runs all 11 then exits 0 with a "would cut tag v<version>" summary. Wired in CI on every PR touching `scripts/`.

---

## 3. Tag-cut (deployment-engineer §3 + R-1, R-2, R-7, R-8, R-19)

The **only** GPG step. Passphrase prompted once via gpg-agent, never via `--passphrase*`.

**Expected-SHA capture happens in preflight gate P1.5 (new):** `EXPECTED_SHA=$(git rev-parse origin/main)` written to `.release-state/<version>/expected-sha`. The signed tag must point at exactly this commit — defends against `main` advancing between preflight + tag-cut (R-19).

```bash
EXPECTED_SHA=$(cat .release-state/${VERSION}/expected-sha)

# R-7 (F-2): pin gpg-agent socket, refuse env redirect
[ -z "${GPG_AGENT_INFO:-}" ] || die "GPG_AGENT_INFO set — refusing (deprecated socket-redirect vector)"
AGENT_SOCK=$(gpgconf --list-dirs agent-socket)
case "$AGENT_SOCK" in "$HOME/.gnupg/"*) ;; *) die "gpg-agent socket outside ~/.gnupg/: $AGENT_SOCK" ;; esac

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
| 4.4 | Docker install proof using the **already-verified wheel from 4.2** + **in-container attestation re-verify** (F-10 defense-in-depth against TOCTOU on `.release-state/<v>/`): first `docker run --rm -v "$PWD/.release-state/<v>:/wheels:ro" -e GH_TOKEN ghcr.io/cli/cli:latest sh -c "gh attestation verify /wheels/worthless-*.whl --owner shacharm2 --repo worthless"` MUST pass; THEN `docker run --rm -v "$PWD/.release-state/<v>:/wheels:ro" python:3.12-slim sh -c "pip install /wheels/worthless-*.whl && worthless --version"` succeeds with `<v>`. Mutated wheel fails the in-container verify, install never runs. |
| 4.5 | `awk` extract CHANGELOG section → non-empty |
| 4.5a | **Date-stamp in-memory copy** of notes (F-8): substitute `## [Unreleased]` (and any `<v>` placeholder header) → `## [<v>] — $(date -u +%Y-%m-%d)` BEFORE 4.6. Write to `.release-state/<v>/notes.md`. Assert `grep -E '^## \[<v>\] — [0-9]{4}-[0-9]{2}-[0-9]{2}'` succeeds. |
| 4.6 | `gh release create v<v> --notes-file .release-state/<v>/notes.md --verify-tag` (reads the dated copy from 4.5a, NOT the raw extract — defends against published Release body saying `TBD` forever) |
| 4.7 | `gh workflow run release-sync-check.yml` → individual A1-A5 PASS/FAIL report |
| 4.8 | Auto-open `chore/changelog-stamp-<v>` PR with the date replacement (the Phase 3 #1 pattern, now automatic) |
| 4.9 | Emit Linear comment markdown to stdout — maintainer pastes (no MCP coupling, keeps script auditable + offline-capable). Emitter MUST (F-13, R-16): (a) re-assert R-16 regex on tag body; (b) HTML-escape `< > &` in every free-form field (tag body, CHANGELOG excerpt); (c) refuse to emit and fail-closed if R-16 regex fails. Defense-in-depth: even if a malformed tag slipped past tag-cut preflight, the emitter stops markdown/HTML injection at the paste boundary. |

**R-10:** Step 4.2b calls `gh attestation verify` — cryptographic proof the wheel was built by our CI from the signed tag (works today). End-user `pip install` does NOT yet verify attestations at install time (PEP 740 enforcement in pip/uv is in progress) — user-facing wording is "verified at release-cut by maintainer; client-side enforcement when pip/uv ship it."

---

## 5. release-recover.sh (deployment-engineer §5 + R-3, R-4, R-5, R-15, R-21..R-25)

Strict 6-step dance with watchdog + heartbeat + full trap stack:

```bash
R1  Snapshot current ruleset JSON (R-5) to /tmp
R1.5 R-29 (F-18): OFFSITE beacon BEFORE the disable — survives kill -9 -<pgid>
    SNAPSHOT_SHA=$(sha256sum "$SNAPSHOT_JSON"|awk '{print $1}')
    GIST_URL=$(gh gist create --private --filename ruleset-snapshot.json "$SNAPSHOT_JSON"|tail -n1)
    DEADLINE_EPOCH=$(( $(date +%s) + 120 ))
    gh api -X POST "/repos/$REPO/issues/$AUDIT_TRACKER/comments" -f body="RULESET-DISABLED v${VERSION} START $(date -u +%FT%TZ) PID $$ EXPECT-RESTORE-BY <+120s> SNAPSHOT-SHA256: $SNAPSHOT_SHA SNAPSHOT-GIST: $GIST_URL"
    gh workflow run audit-ruleset-watchdog.yml -f version="$VERSION" -f deadline_epoch="$DEADLINE_EPOCH" -f snapshot_gist_url="$GIST_URL" -f snapshot_sha256="$SNAPSHOT_SHA" -f audit_issue_number="$AUDIT_TRACKER"
    # BLOCK ≤30s for WATCHDOG-ARMED comment; fail-closed if absent (never disable without offsite failsafe)
    for i in $(seq 1 30); do gh api ".../comments?..." --jq '...WATCHDOG-ARMED...' | grep -qx '[1-9]*' && { ARMED=1; break; }; sleep 1; done
    [ "${ARMED:-0}" = 1 ] || die "R-29: GHA watchdog did not arm within 30s"
R2  Disable v-tags-signed (PATCH enforcement=disabled)
    # R-25 (F-12): require BOTH the CLI flag AND env var; refuse if invoked under shell completion
    [ "$ALLOW_RULESET_DISABLE" = "1" ] && [ "$WORTHLESS_ALLOW_RULESET_DISABLE" = "1" ] || die "R-25 violation"
    case "$(ps -o comm= -p $PPID)" in *_complete*|*-completion*|compdef*) die "R-25: completion-injected flag detected" ;; esac

    # R-23 (F-6): full signal coverage; ignore SIGPIPE so closed-terminal still runs cleanup
    trap '' PIPE
    trap re_enable_from_snapshot EXIT INT TERM HUP PIPE QUIT USR1 USR2

    # R-22 (F-5): wall-clock deadline, suspend-safe (NOT a single sleep 120)
    DEADLINE=$(( $(date +%s) + 120 ))
    ( while [ "$(date +%s)" -lt "$DEADLINE" ]; do sleep 5; done; \
      re_enable_from_snapshot; kill -TERM $$ ) & WATCHDOG_PID=$!

    # R-3 (F-4): heartbeat the watchdog; SIGKILL on it = disarmed failsafe = abort
    ( while kill -0 "$WATCHDOG_PID" 2>/dev/null; do sleep 5; done; \
      kill -TERM $$ ) & WATCHDOG_HEARTBEAT_PID=$!

R3  git push --delete origin "v${VERSION}"  ;  git tag -d "v${VERSION}" 2>/dev/null
R4  require_local_tag_gpg_signed "${VERSION}"  — BLOCKS until operator re-runs tag-cut
R5  git push origin "v${VERSION}"
R6  Re-enable v-tags-signed (PUT the R1 snapshot back, not a hard-coded body)
    Kill watchdog + heartbeat.

    # R-24 (F-7): edge cache may serve stale; require 3 consecutive no-cache reads
    for i in 1 2 3; do
      gh api -H "Cache-Control: no-cache" "/repos/$REPO/rulesets/15719679" \
        | jq -re '.enforcement=="active"' >/dev/null || die "R6 poll $i: ruleset not active"
      sleep 2
    done

    # R-21 (F-3, F-15): canary MUST target refs/tags/v* and rejection MUST name
    # v-tags-signed. A canary on refs/canary/* would be bounced by an UNRELATED
    # ruleset → false-green. Cleaned up via RETURN-trap regardless of outcome.
    CANARY_TAG="v0.0.0-canary-$$-$(date +%s)"
    git tag "$CANARY_TAG" HEAD
    cleanup_canary() { git tag -d "$CANARY_TAG" 2>/dev/null||true; git push origin --delete "refs/tags/$CANARY_TAG" 2>/dev/null||true; }
    trap 'cleanup_canary' RETURN
    CANARY_OUT=$(git push origin "refs/tags/$CANARY_TAG" 2>&1); CANARY_RC=$?
    [ $CANARY_RC -eq 0 ] && { cleanup_canary; die "R-21: canary tag pushed SUCCESSFULLY — v-tags-signed is OFF"; }
    printf '%s\n' "$CANARY_OUT" | grep -Eq 'rejected.*(v-tags-signed|Required signatures)' \
      || { cleanup_canary; die "R-21: canary rejected but NOT by v-tags-signed — treat as DISABLED"; }
    cleanup_canary
```

After R6 success, post `RULESET-RESTORED v${VERSION} END <iso> DOCTOR-VERIFIED: true` to the audit issue (R-29) — the GHA watchdog sees this and exits clean instead of re-enabling.

**Audit log (R-15, R-26, R-27 / F-14, F-16, F-17).** `.release-audit/YYYY-MM-DD.log` is **JSONL** (schema: `scripts/release/audit-schema.json`, built in impl PR). Every line witnesses the resolved tool path+SHA256 *at that call*, gpg-agent socket, gh token scopes, watchdog liveness, RUID/tty/umask, `script_git_sha`, and R-13-redacted env keys — so a post-breach investigator can prove which binary/agent actually ran (F-16). Append-only (`chflags uappnd`/`chattr +a`, single `printf` under `flock`), GPG-signed `.log.asc` at exit. Then **shipped offsite to 3 independent channels** (audit-issue comment + private gist + `git notes`), because a compromised laptop can clear the append-only flag and re-sign with the cached subkey — local-only audit is no audit (F-17, R-27).

`release-doctor.sh` runs unconditionally at end of `release.sh` AND `release-recover.sh` AND is callable standalone — asserts `v-tags-signed` is `active` (R-21 canary verified, R-24 cache-bypass verified), `--verify-audit-log` re-verifies every `.asc` + R-26 schema, `--replay-day` checks cross-line invariants, `--verify-audit-shipped` re-fetches the 3 offsite copies. Exit-1 on any failure = alarm bell (R-4).

---

## 6. The 28 hard rules (security-engineer §1-9, full table in `security-engineer.md`)

Compressed cross-reference:

| Lens | Rules |
|---|---|
| **Tag integrity** | R-1 forced `gpg.format=openpgp` + explicit `user.signingkey`; R-2 fingerprint + format verified before push; R-19 expected-SHA assertion (captured in P1.5 preflight, checked in tag-cut) |
| **Tool Trust** | R-20 SHA256-pin every external binary (`gh`, `gpg`, `docker`, `pip`, `awk`, `jq`, `sha256sum`, `python3`, `curl`) in `SECURITY_RULES.md` SR-10; preflight P11 enforces before any GPG/`gh` call. See §11. |
| **Ruleset window** | R-3 opt-in flag + 120s wall-clock watchdog + 8-signal trap stack; R-4 doctor standalone; R-5 snapshot-restore not hard-coded body; R-21 canary pushes an UNSIGNED `v0.0.0-canary` tag matching `refs/tags/v*` + parses rejection for `v-tags-signed` by name (F-15); R-22 wall-clock deadline (suspend-safe); R-23 PIPE/QUIT/USR1/USR2 trap; R-24 R6 3x no-cache verification; R-25 alias/completion injection defense; R-29 OFFSITE pre-window beacon + GHA deadman-switch surviving `kill -9 -<pgid>` (F-18) |
| **Forensics / audit** | R-15 append-only JSONL + GPG-signed `.asc`; R-26 witnessed-field schema (`scripts/release/audit-schema.json`) + `--replay-day` cross-line invariants (F-16); R-27 3-channel offsite shipping (issue comment + private gist + `git notes`) so a compromised laptop can't erase the trail (F-17) |
| **Idempotency / replay** | R-6 every phase classified; markers in `.release-state/<v>/`; both state dirs in `.gitignore` (F-11) |
| **Secret hygiene** | R-7 gpg-agent socket pinned + `GPG_AGENT_INFO` refused (F-2); R-8 no rc-sourcing, no env export, no `bash -x`; R-13 stderr redactor; R-16 tag-message regex lint + markdown/HTML escape (F-13) |
| **Token scope** | R-9 BOTH `repo` AND `workflow` unconditionally (F-9), reject broader, reject CI `GITHUB_TOKEN`, never `--show-token` |
| **Live trust** | R-10 `gh attestation verify` mandatory against the pinned wheel in step 4.2b (works today, chains Sigstore bundle to GHA OIDC + repo + tag ref); R-17 bounded polling |
| **Negative space** | R-11 grep-based self-check (no force-push, hard-reset, workflow edits, `curl\|sh`, ...); R-12 no writes to trust-root paths; R-18 no `git config --global`, no `gpg --import` |
| **Supply chain** | R-14 SHA256 self-pin in `SECURITY_RULES.md` SR-09; `--accept-script-change` requires both flag + env var |

R-1 + R-3 are the rules I'd most fight a reviewer over — they encode the 0.3.7 incident as immutable safety properties. **R-28 is reserved** for the tag-provenance trailer (F-23, deferred to FOLLOWUPS.md).

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
| Dry-run | `release.sh 9.9.9 --dry-run` on every `scripts/` PR | All 11 preflights run, none mutate, exit 0 |
| Mock harness | `bats` with `PATH`-shimmed `gh`/`git`/`pip`/`docker` | Phase ordering enforced; phase 2 never runs if any P-gate failed |
| Recovery | `bats` with mocked `gh api` ruleset endpoint | Ruleset re-enabled on R3 abort; EXIT trap fires; no orphan local tags |
| Regression | inject `git config gpg.format ssh`; assert tag-cut still produces openpgp signature | 0.3.7 root cause becomes a regression test |
| Negative | mock `verify-tag` failure | Phase 3 prints exact recover hint + exit 2 |
| Negative (F-1) | inject fake `gh` binary on `$PATH` that exits 0 from any `gh attestation verify` call | Preflight P11 MUST abort with `tool binary SHA drift: gh (got <hash>, expected <hash>)` BEFORE any `gh attestation verify` call executes. Regression test for compromised-toolchain class. |
| Negative (F-2) | set `GPG_AGENT_INFO=/tmp/evil.sock` pointing at a no-prompt forging agent | Tag-cut MUST refuse before `git tag -s` — assert `GPG_AGENT_INFO` unset, socket resolves under `$HOME/.gnupg/`, `gpg --version` SHA matches R-20 pin |
| Negative (F-3 / F-15) | MITM `gh api /rulesets` returns `enforcement: active` while upstream disabled — 3 sub-cases: (a) `v-tags-signed` OFF + no other tag-ruleset → canary tag push succeeds; (b) `v-tags-signed` OFF + `branch-protection` rejects with non-matching name; (c) `v-tags-signed` ON → rejected naming it | P9 + R-4 doctor MUST: (a) die `canary tag pushed SUCCESSFULLY — v-tags-signed is OFF`; (b) die `rejected but NOT by v-tags-signed`; (c) pass. All 3 leave zero `v0.0.0-canary-*` tags locally + on remote |
| Negative (F-4) | after R2 starts watchdog, `kill -9 $WATCHDOG_PID` from second shell, let R4 proceed | Parent MUST detect dead watchdog within 5s via `kill -0` heartbeat poll, abort recovery, re-enable ruleset from snapshot, exit non-zero |
| Negative (F-5) | mid-recovery `SIGSTOP` watchdog for 200s then `SIGCONT` (simulates laptop suspend) | Wall-clock deadline MUST detect `date +%s` exceeded `START+120`, re-enable from snapshot, exit non-zero — `sleep 120` resumption MUST NOT extend window |
| Negative (F-6) | after R2 disables ruleset, send `SIGPIPE` (close terminal mid-pipe) or `SIGQUIT` (Ctrl-\) to parent | Trap MUST fire, re-enable ruleset from snapshot. Test runs once per signal in `{PIPE, QUIT, USR1, USR2}` |
| Negative (F-7) | mock `gh api /rulesets/15719679` returns cached `disabled` then `active` 4 seconds later | R6 MUST poll 3× with `-H 'Cache-Control: no-cache'` 2s apart; ALL three must be `active` before declaring success |
| Negative (F-8) | CHANGELOG header is undated (`## [Unreleased]`) at tag time | release.sh MUST date-stamp notes in-memory BEFORE step 4.6; assertion: `grep -E '^## \[<v>\] — [0-9]{4}-[0-9]{2}-[0-9]{2}'` succeeds and the published GH Release body contains the date, not `TBD` |
| Negative (F-9) | GH_TOKEN has `repo` only (no `workflow`) | release.sh MUST fail in P8 BEFORE step 4.2 with explicit "missing workflow scope" error; never reach 4.7 with under-scoped token |
| Negative (F-10) | wheel in `.release-state/<v>/` mutated between step 4.2 and 4.4 (TOCTOU) | step 4.4 MUST re-run `gh attestation verify` INSIDE the container BEFORE `pip install`; mutated wheel fails verify, install never runs |
| Negative (F-11) | repo `.gitignore` is missing `.release-state/` or `.release-audit/` | preflight P1 MUST fail-closed BEFORE step 4.1; never allow audit markers (which may contain token-scoped `gh api` responses) to be stageable |
| Negative (F-12) | define `alias release.sh='release.sh --allow-ruleset-disable'` in zshrc OR have zsh completion auto-insert flag | Script MUST refuse: env var `WORTHLESS_ALLOW_RULESET_DISABLE=1` not also set ⇒ exit; PPID matching completion subprocess ⇒ exit `completion-injected flag detected` |
| Negative (F-13) | tag annotation contains `[click me](https://evil.example)` or raw `<script>` | step 4.9 emitter MUST HTML-escape tag body before Linear paste AND R-16 regex MUST reject the tag at creation time; both layers fail-closed |
| Negative (F-14) | after recovery writes a line to `.release-audit/<date>.log`, run `sed -i '' '1d'` to rewrite history | OS append-only flag (`chflags uappnd` mac / `chattr +a` Linux) MUST cause `sed` to fail with EPERM; `release-doctor.sh --verify-audit-log` MUST detect GPG-signature mismatch on the day's log |
| Negative (F-16) | hand-craft a `.release-audit/<date>.log` line omitting a required R-26 field (e.g. `tool_witness`), re-sign with valid GPG; AND a second `sign` line whose `gpg` SHA256 differs from the P11 baseline | `--verify-audit-log` MUST refuse `schema-violation: missing required property`; `--replay-day` MUST refuse `tool-swap-detected: gpg sha256 changed mid-window-marker`; both exit 1 |
| Negative (F-17) | block egress to `api.github.com` after `.asc` sealed but before R-27 ships; AND post-ship, locally rewrite the log + re-sign with cached subkey | ship MUST exit-3 `R-27 channel (a) failed`, no `ship-manifest.json`; `--reship-audit` with net restored succeeds; `--verify-audit-shipped` MUST exit-1 `sha256 drift channel (a): local=<X> remote=<Y>` |
| Negative (F-18) | after `WATCHDOG-ARMED` posts + ruleset disabled, `kill -9 -<pgid>` the whole process group (bypasses local trap + watchdog + heartbeat in one syscall); IR has only `gh` read access | GHA `audit-ruleset-watchdog.yml` MUST detect deadline passed without `RULESET-RESTORED`, PUT the snapshot, confirm `active` via 3× no-cache reads, post `RULESET-REENABLED-BY-WATCHDOG` + `WATCHDOG-FINAL-STATE`; cold IR reconstructs tag + window + snapshot from `gh issue view` alone |

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

1. **The `Linear comment markdown to stdout`** (4.9) — RESOLVED fixup #4: paste, with R-16 / F-13 HTML-escape + markdown-injection rejection in the emitter. Keeps script offline-capable + auditable + defends against tag-message injection.
2. **The `--allow-ruleset-disable` flag** (R-3) — RESOLVED fixup #4: opt-in CLI flag + `WORTHLESS_ALLOW_RULESET_DISABLE=1` env var BOTH required (R-25 / F-12). PPID-completion-detection also refuses to run if invoked from shell completion subprocess.
3. **PEP 740 attestation** (R-10) — RESOLVED 2026-05-30 fixup: `release.sh` calls `gh attestation verify` directly in step 4.2b (works today). User-facing release notes say "verified at release-cut; client-side enforcement when pip/uv ship PEP 740 support."
4. **PR-1's scope** — is 11 preflight gates + scaffold the right first slice, or split smaller (e.g., 5 gates + scaffold first)? Recommended: full 11, since each gate is small and they share lib helpers.

---

## 11. Tool Trust (F-1 closure — fixup #3)

The orchestrator is only as trustworthy as the binaries it shells out to. R-1, R-2, R-10 all assume `gh`/`gpg`/`docker`/`pip` faithfully execute the cryptography we ask of them. A compromised binary on `$PATH` (malicious brew tap, hijacked package, attacker write to `~/.local/bin`, `PATH` injection via `~/.zshrc`) returns "verified" without doing anything — every downstream check becomes theatre.

**Defense:** preflight gate **P11 (Tool Trust)** runs before any cryptographic call, hashes the resolved binary path for each external tool, compares to pins in `SECURITY_RULES.md` SR-10 (new section). First drift → exit non-zero with the failing binary + got/expected hashes. See R-20.

### The pinned binaries

| Binary | Used for | Pin location |
|---|---|---|
| `gh` | `attestation verify`, `api`, `release create`, `workflow run`, `pr create`, `auth status/token` | SR-10 |
| `gpg` | tag signing (R-1), tag verification (R-2), audit log signing (R-15, F-14) | SR-10 |
| `docker` | step 4.4 install proof | SR-10 |
| `pip` | step 4.2 `pip download --no-deps` (wheel pinning for R-10) | SR-10 |
| `awk` | step 4.5 CHANGELOG section extract | SR-10 |
| `jq` | parsing `gh api` JSON responses | SR-10 |
| `sha256sum` | the self-check that computes all the above pins (chicken-and-egg note below) | SR-10 |
| `python3` | helper computations | SR-10 |
| `curl` | `worthless.sh` worker probe (4.3) | SR-10 |

### Pin refresh policy

- **Refresh = explicit PR.** A `brew upgrade gh` that bumps the binary triggers P11 to refuse on the maintainer's next release; the fix is a manual PR updating SR-10 with new pins, reviewer signoff confirms the new binary's provenance (e.g., checksums from upstream release page).
- **No auto-bump.** A flag like `--accept-binary-drift` mirrors `--accept-script-change` (R-14): requires both the CLI flag AND `WORTHLESS_ACCEPT_BINARY_DRIFT=1` env var. Defeats accidental flag paste.
- **First-commit chicken-and-egg.** Same pattern as R-14: PR-1 of the implementation series lands the binaries' pins in SR-10 alongside the P11 code. Reviewers manually verify pins match the binaries on the PR-1 author's machine before merge.
- **`sha256sum` is the recursive trust anchor.** P11 can't verify `sha256sum` with itself. The first-pass uses BOTH `shasum -a 256` (macOS built-in) and `sha256sum` (Linux/brew) and asserts identical output as a self-check.

### Out of scope for P11

- TOCTOU between P11 and the actual binary invocation (a privileged attacker swapping the binary mid-script is out of our threat model — would require a different defense like `mlock` or `O_TMPFILE`-based invocation).
- Library/syscall trust (linker, kernel, shell built-ins like `command -v`). Mitigation by `O_TMPFILE` or chroot is overkill for a maintainer-laptop release script.

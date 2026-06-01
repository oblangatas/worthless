# F-18 Implementation Ticket — R-29 Pre-Window Beacon + GHA Watchdog

> "120 seconds with no one watching from offsite is the same as 120 minutes." A compromised laptop mid-recovery freezes the failsafe; the world cannot tell the ruleset was even disabled, let alone for which tag. The fix moves the deadman switch off the laptop entirely — into a GHA workflow whose only job is to slam the ruleset closed if the local script doesn't say it already did.

## 1. Problem

**ELI5.** The release script briefly turns off the lock on the `v*` tag rules so the maintainer can re-push a fixed tag after a botched recovery. It promises to turn the lock back on within 120 seconds, using a babysitter process. If someone unplugs the maintainer's laptop (or `kill -9`s the whole process tree) during those 120 seconds, the babysitter dies too — and the lock stays open. Worse, no one else on Earth knows the lock is open, or for which tag, or for how long.

**Technical.** R-3's watchdog and heartbeat are both children of the same shell. `kill -9 -<pgid>` reaps the entire group atomically — neither trap nor heartbeat fires. The ruleset stays `disabled` until a human notices and visits the GitHub UI. IR cold-arriving has no way to learn: (a) the ruleset is currently disabled, (b) which tag was being recovered, (c) the operator's snapshot of the ruleset, (d) when the window started/expected to end. F-18 is the only F-class finding where prevention controls are *all bypassable by killing the laptop*.

## 2. Current text being amended

**R-3 (security-engineer.md):** existing single-row entry (R-22/R-23/R-25 cross-refs already in place).

**SPEC §5 R2 block:** the existing 17-line block (R-25 flag check, trap, deadline-watchdog, heartbeat).

These remain. R-29 *adds* a third leg (offsite beacon + GHA watchdog) without removing local controls.

## 3. Proposed R-29 + new workflow

### R-29 (new row in security-engineer.md, after R-25)

> **R-29 (Offsite Recovery Beacon).** BEFORE the R2 PATCH that disables `v-tags-signed`, `release-recover.sh` MUST (a) post a comment to designated audit issue `worthless#<AUDIT_TRACKER>` of exact form `RULESET-DISABLED v<version> START <iso8601> PID <pid> EXPECT-RESTORE-BY <iso8601+120s>\nSNAPSHOT-SHA256: <hex>\nSNAPSHOT-GIST: <gist-url>` (snapshot from R1 uploaded as private gist; both URL and SHA256 captured BEFORE PATCH so compromised laptop cannot redact); (b) dispatch GHA workflow `audit-ruleset-watchdog.yml` via `gh workflow run` with inputs `{version, deadline_epoch, snapshot_gist_url, snapshot_sha256, audit_issue_number}`; (c) BLOCK until workflow's first heartbeat comment `WATCHDOG-ARMED run=<run-id>` appears on the issue (max 30s, fail-closed if missing). After R6 success, script MUST post `RULESET-RESTORED v<version> END <iso8601> DOCTOR-VERIFIED: true` — workflow polls for this comment and exits clean when seen. Workflow re-enables ruleset from snapshot if `deadline_epoch` passes without `RULESET-RESTORED` comment. | F-18 (laptop SIGKILL mid-window with no offsite recovery).

### `.github/workflows/audit-ruleset-watchdog.yml` (NEW — full content, ready to paste)

```yaml
name: audit-ruleset-watchdog

# R-29 (F-18): offsite failsafe for release-recover.sh 120s ruleset-disabled window.
# Triggered by release-recover.sh via `gh workflow run audit-ruleset-watchdog.yml`.
# Polls audit issue for RULESET-RESTORED comment; PUTs snapshot back if deadline passes.

on:
  workflow_dispatch:
    inputs:
      version:           { description: "Release version", required: true, type: string }
      deadline_epoch:    { description: "Unix epoch deadline", required: true, type: string }
      snapshot_gist_url: { description: "Private gist URL with pre-disable ruleset JSON", required: true, type: string }
      snapshot_sha256:   { description: "SHA256 of snapshot JSON", required: true, type: string }
      audit_issue_number:{ description: "Issue number of audit tracker", required: true, type: string }

permissions:
  contents: read
  issues: write
  id-token: write
  actions: read

concurrency:
  group: ruleset-watchdog-${{ inputs.version }}
  cancel-in-progress: true

jobs:
  watchdog:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      RULESET_ID: "15719679"
      REPO: "shacharm2/worthless"
      AUDIT_ISSUE: ${{ inputs.audit_issue_number }}
      DEADLINE: ${{ inputs.deadline_epoch }}
      VERSION: ${{ inputs.version }}
      SNAPSHOT_URL: ${{ inputs.snapshot_gist_url }}
      SNAPSHOT_SHA: ${{ inputs.snapshot_sha256 }}
    steps:
      - name: Mint repo-scoped GitHub App token via OIDC
        id: app-token
        uses: actions/create-github-app-token@v1
        with:
          app-id:        ${{ vars.RELEASE_ORCHESTRATOR_APP_ID }}
          private-key:   ${{ secrets.RELEASE_ORCHESTRATOR_APP_KEY }}
          owner:         shacharm2
          repositories:  worthless

      - name: Heartbeat — WATCHDOG-ARMED (unblocks local script)
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          set -euo pipefail
          NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          gh api -X POST "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments" \
            -f body="WATCHDOG-ARMED v${VERSION} run=${{ github.run_id }} at ${NOW} deadline=${DEADLINE}"

      - name: Fetch + verify snapshot
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          set -euo pipefail
          mkdir -p /tmp/wd
          gh api "${SNAPSHOT_URL}" --jq '.files | to_entries[0].value.content' > /tmp/wd/snapshot.json
          ACTUAL="$(sha256sum /tmp/wd/snapshot.json | awk '{print $1}')"
          [ "${ACTUAL}" = "${SNAPSHOT_SHA}" ] || { echo "::error::snapshot SHA mismatch"; exit 1; }
          jq -re '.enforcement == "active"' /tmp/wd/snapshot.json >/dev/null

      - name: Poll for RULESET-RESTORED until deadline
        id: poll
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          set -euo pipefail
          OUTCOME="timeout"
          while :; do
            NOW="$(date +%s)"
            if [ "${NOW}" -ge "${DEADLINE}" ]; then break; fi
            FOUND="$(gh api -H 'Cache-Control: no-cache' \
              "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments?per_page=100&sort=created&direction=desc" \
              --jq "[.[] | select(.body | startswith(\"RULESET-RESTORED v${VERSION}\"))] | length")"
            if [ "${FOUND:-0}" -gt 0 ]; then OUTCOME="clean"; break; fi
            sleep 5
          done
          echo "outcome=${OUTCOME}" >> "$GITHUB_OUTPUT"

      - name: Re-enable ruleset from snapshot (deadline missed)
        if: steps.poll.outputs.outcome == 'timeout'
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          set -euo pipefail
          gh api -X PUT "/repos/${REPO}/rulesets/${RULESET_ID}" --input /tmp/wd/snapshot.json >/dev/null
          ok=0
          for i in 1 2 3; do
            sleep 2
            STATE="$(gh api -H 'Cache-Control: no-cache' "/repos/${REPO}/rulesets/${RULESET_ID}" --jq .enforcement)"
            [ "${STATE}" = "active" ] && ok=$((ok+1))
          done
          [ "${ok}" -eq 3 ] || { gh api -X POST "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments" -f body="WATCHDOG-FAILED v${VERSION} run=${{ github.run_id }} — MANUAL INTERVENTION"; exit 1; }
          NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          gh api -X POST "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments" \
            -f body="RULESET-REENABLED-BY-WATCHDOG v${VERSION} run=${{ github.run_id }} at ${NOW}"

      - name: Post clean exit
        if: steps.poll.outputs.outcome == 'clean'
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          gh api -X POST "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments" \
            -f body="WATCHDOG-EXIT-CLEAN v${VERSION} run=${{ github.run_id }} at ${NOW}"

      - name: Always — final state assertion
        if: always()
        env: { GH_TOKEN: "${{ steps.app-token.outputs.token }}" }
        run: |
          STATE="$(gh api -H 'Cache-Control: no-cache' "/repos/${REPO}/rulesets/${RULESET_ID}" --jq .enforcement || echo unknown)"
          NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          gh api -X POST "/repos/${REPO}/issues/${AUDIT_ISSUE}/comments" \
            -f body="WATCHDOG-FINAL-STATE v${VERSION} run=${{ github.run_id }} at ${NOW} ruleset=${STATE}" || true
          [ "${STATE}" = "active" ] || exit 1
```

### Local script additions (`release-recover.sh` R2 pre-PATCH):

```bash
# R-29: offsite beacon BEFORE we touch the ruleset
SNAPSHOT_JSON=".release-state/${VERSION}/ruleset-snapshot.json"
SNAPSHOT_SHA=$(sha256sum "$SNAPSHOT_JSON" | awk '{print $1}')
GIST_URL=$(gh gist create --private --filename ruleset-snapshot.json "$SNAPSHOT_JSON" 2>/dev/null | tail -n1)
DEADLINE_EPOCH=$(( $(date +%s) + 120 ))
START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
END_ISO=$(date -u -r "$DEADLINE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

gh api -X POST "/repos/$REPO/issues/$AUDIT_TRACKER/comments" -f body="$(cat <<EOF
RULESET-DISABLED v${VERSION} START ${START_ISO} PID $$ EXPECT-RESTORE-BY ${END_ISO}
SNAPSHOT-SHA256: ${SNAPSHOT_SHA}
SNAPSHOT-GIST: ${GIST_URL}
EOF
)" >/dev/null

gh workflow run audit-ruleset-watchdog.yml \
  -f version="$VERSION" \
  -f deadline_epoch="$DEADLINE_EPOCH" \
  -f snapshot_gist_url="$GIST_URL" \
  -f snapshot_sha256="$SNAPSHOT_SHA" \
  -f audit_issue_number="$AUDIT_TRACKER"

# Block (max 30s) until WATCHDOG-ARMED comment appears
for i in $(seq 1 30); do
  if gh api "/repos/$REPO/issues/$AUDIT_TRACKER/comments?per_page=20&sort=created&direction=desc" \
       --jq "[.[] | select(.body | startswith(\"WATCHDOG-ARMED v${VERSION}\"))] | length" \
       | grep -qx "[1-9]*"; then
    WATCHDOG_ARMED=1; break
  fi
  sleep 1
done
[ "${WATCHDOG_ARMED:-0}" = 1 ] || die "R-29: GHA watchdog did not arm within 30s"

# ... THEN PATCH disable ... (existing R-3 local watchdog stays)
```

Post-R6:
```bash
gh api -X POST "/repos/$REPO/issues/$AUDIT_TRACKER/comments" \
  -f body="RULESET-RESTORED v${VERSION} END $(date -u +%Y-%m-%dT%H:%M:%SZ) DOCTOR-VERIFIED: true" >/dev/null
```

## 4. Audit-issue lifecycle — decision

**Recommendation: ONE permanent issue per repo, never closed.** Title: `[AUDIT] Release Orchestrator — Ruleset Window Log (do not close)`, pinned, locked to maintainer + App writer. Per-release threading via `v<version>` prefix; `gh api .../comments --jq '.[] | select(.body | contains("v0.3.8"))'` reconstructs any release cold.

Rationale: per-release issues are decoy-vulnerable; single canonical ID hard-coded in workflow defeats spoofing. Never auto-close — historical evidence chain is the point. GitHub Discussions API too shaky.

## 5. TDD §8 row

```
| Negative (F-18) | After release-recover.sh posts WATCHDOG-ARMED confirmation and disables ruleset, send `kill -9 -<pgid>` to entire process group from sibling shell (bypasses local trap + watchdog + heartbeat in single syscall). IR has only `gh` read access from clean machine. | (a) GHA workflow detects deadline epoch passed without RULESET-RESTORED within 120s ±10s grace; (b) workflow PUTs verified snapshot, 3× no-cache reads return `enforcement: active`; (c) posts RULESET-REENABLED-BY-WATCHDOG AND WATCHDOG-FINAL-STATE ruleset=active; (d) cold IR running `gh issue view <AUDIT_TRACKER> --comments` reconstructs: tag, start ISO, end ISO, snapshot SHA, snapshot gist URL, watchdog run ID — without laptop access. |
```

## 6. Risks / open questions

1. **R6 / GHA double-PUT race.** Local R6 succeeds T+115, posts RULESET-RESTORED T+116. GHA polled T+115 (nothing), enters re-enable T+120, PUTs T+121. Both PUTs identical → harmless duplicate. Mitigation: re-check for RULESET-RESTORED with no-cache immediately before PUT. Document race as "harmless duplicate, false positive in audit thread acceptable." Alternative: `If-Match: <etag>` on PUT.
2. **GHA queue backlog widens the window.** Workflow dispatch → first step start can take 30s-10min. Local script blocks on WATCHDOG-ARMED for 30s max then dies fail-closed — but during 30s wait, local 120s deadline hasn't started either (haven't PATCHed yet). If workflow doesn't arm in 30s, never disable ruleset.
3. **Recursive trust on workflow itself.** Attacker with write access can edit `audit-ruleset-watchdog.yml` to no-op. Mitigation: include in `v-tags-signed` ruleset's branch protection (codeowners required-review). Better: SEPARATE ruleset `workflows-audit-protected` covering `.github/workflows/audit-*.yml`. Document as R-31 future work.
4. **OIDC scope for ruleset PATCH.** `GITHUB_TOKEN` doesn't carry repository administration. Workflow MUST use GitHub App with `administration:write`. PAT explicitly NOT acceptable.
5. **AUDIT_TRACKER issue number — bootstrap.** Hard-code into `lib/io.sh` constants alongside `RULESET_ID=15719679`. Reviewer-visible, not configurable.
6. **Snapshot gist as private — visibility model.** App token can read; SHA256 in issue comment makes tampering detectable. Gist contains ruleset definition (not secret).
7. **`gh workflow run` blocks on auth.** R-20/P11 (tool trust SHA pin) covers; R-29 inherits.

## 7. Estimated lines changed

| File | LOC |
|---|---|
| `SPEC.md` (§5 R2 block + §6 table + §8 row + §10 question) | ~55 |
| `security-engineer.md` (R-29 row, R-3 cross-ref) | ~12 |
| `.github/workflows/audit-ruleset-watchdog.yml` (NEW) | ~115 |
| `scripts/release-recover.sh` (R-29 pre-PATCH + arm-block + RESTORED) | ~35 |
| `lib/io.sh` (constants: `AUDIT_TRACKER`, helper `post_audit_comment`) | ~15 |
| `tests/bats/test_recover_f18.bats` (kill -9 -pgid scenario) | ~60 |
| **Total** | **~292 LOC** (~115 workflow YAML) |

## 8. Implementation order

**Workflow YAML first.** Reasons:
1. Local script blocks fail-closed on WATCHDOG-ARMED — writing local R-29 changes before workflow exists makes `release-recover.sh` un-runnable.
2. Workflow has own integration surface (App creation, App permissions, install on repo, `vars.RELEASE_ORCHESTRATOR_APP_ID`, `secrets.RELEASE_ORCHESTRATOR_APP_KEY`) — infrastructure setup blocks the merge.
3. Spec text for R-29 references workflow filename + input schema. Locking those down by writing YAML first means spec documents reality.

**Proposed PR sequence (extends SPEC §9):**
- **PR-2a (NEW):** add `audit-ruleset-watchdog.yml`, create `release-orchestrator` GitHub App, install on repo, smoke-test via manual dispatch against throwaway test ruleset. **Merges before PR-2.**
- **PR-2 (amended):** tag-cut + recover + doctor + ruleset snapshot/restore + watchdog + trap stack **+ R-29 local-side beacon + arm-block + RESTORED post**. SPEC.md amendments land here.
- **PR-2b (NEW, test):** F-18 bats regression — requires dedicated test ruleset + test audit issue; runs nightly, not per-PR (flips real ruleset).

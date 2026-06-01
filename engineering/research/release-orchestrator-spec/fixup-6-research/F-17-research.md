# F-17 Implementation Ticket — Ship audit log offsite to 3 independent channels (R-27)

## 1. Problem

**ELI5.** We keep a tamper-evident logbook (`.release-audit/YYYY-MM-DD.log` + `.asc`) of every release action. The pages are glued shut (`chflags uappnd`) and counter-signed. But the logbook lives in one drawer — the maintainer's laptop. If the laptop is owned, the attacker unsticks the pages (`chflags nouappnd` runs unprivileged on macOS as the file owner), edits the entries, and re-signs with the GPG subkey that gpg-agent has already cached. The signed git tag survives on GitHub; the audit trail of *how* the tag was cut does not.

**Technical.** R-15 is local-integrity-only. Under a compromised-host threat model the same principal who writes the log can (a) clear the append-only flag, (b) rewrite the JSONL, (c) re-sign with the cached subkey. Forensics reconstruction post-incident requires an offsite copy that the attacker cannot retroactively rewrite. R-27 ships every freshly-sealed `.asc` to three independent GitHub surfaces (issue comments, private gists, git notes on the signed tag) so any one survivor anchors the timeline.

## 2. Current text being amended

**SPEC.md §5:** `Append-only audit log .release-audit/YYYY-MM-DD.log written for every disable/enable/sign/push, sealed with GPG-detached signature .log.asc at script exit (R-15, F-14).`

**security-engineer.md R-15 row** (referenced by SPEC §6 cross-ref).

## 3. Proposed R-27 (new rule)

### Insert after R-26 in `security-engineer.md`:

> **R-27 — Offsite audit shipping (3 independent channels).** After R-15 produces `.release-audit/YYYY-MM-DD.log.asc`, AND after `release-doctor.sh --verify-audit-log` confirms the signature chains to `$MAINTAINER_GPG_FINGERPRINT`, ship the freshly-sealed `.asc` (and JSONL) to three independent GitHub surfaces. Shipping runs at end of BOTH `release.sh` AND `release-recover.sh` (every invocation, not only successful releases — failed runs are most forensically valuable). Each channel is mandatory; script is **synchronous fail-loud** — any channel's terminal failure aborts with exit-3 and prints recovery hint `release-doctor.sh --reship-audit YYYY-MM-DD`.

**Channel (a) — GitHub issue comment** (`.asc` only, ref env `$AUDIT_TRACKER_ISSUE`):
```bash
gh api -X POST "/repos/shacharm2/worthless/issues/${AUDIT_TRACKER_ISSUE}/comments" \
  -f body="$(printf '```\n%s\n```\n\nsha256: %s\ntag: %s' \
    "$(cat .release-audit/${DATE}.log.asc)" \
    "$(sha256sum .release-audit/${DATE}.log.asc | awk '{print $1}')" \
    "${TAG}")"
```
Expected: HTTP 201, JSON with `.html_url`. Retry: 3× exponential (2s, 8s, 32s) on 5xx/network. Fail-hard on 401/403/404/422.

**Channel (b) — Private gist (JSONL body)** — primary if R-13 redactor classifies any line private:
```bash
gh gist create --private \
  --desc "worthless release audit ${DATE} tag=${TAG}" \
  --filename "${DATE}.log.jsonl" \
  .release-audit/${DATE}.log
GIST_ID=$(gh gist list --limit 1 --json id,description \
  --jq ".[] | select(.description | contains(\"${DATE} tag=${TAG}\")) | .id")
gh gist edit "${GIST_ID}" --add ".release-audit/${DATE}.log.asc"
```
Expected: stdout = gist URL. Retry: 3× exponential.

**Channel (c) — Git notes on signed tag** (cryptographically bound):
```bash
git notes --ref=refs/notes/audit add -F .release-audit/${DATE}.log.asc "${TAG}"
git push origin refs/notes/audit
```
Retry: `git fetch origin refs/notes/audit:refs/notes/audit-remote && git notes --ref=refs/notes/audit merge -s cat_sort_uniq refs/notes/audit-remote`, re-push. Fail-hard after 2 attempts.

**Local manifest** `.release-audit/${DATE}.ship-manifest.json` (also `chflags uappnd`):
```json
{"date":"2026-06-01","tag":"v0.4.0","channels":{
  "issue_comment_url":"https://github.com/shacharm2/worthless/issues/999#issuecomment-...",
  "gist_url":"https://gist.github.com/...",
  "git_notes_ref":"refs/notes/audit @ <commit-sha>"
},"shipped_at":"2026-06-01T08:00:00Z","sha256_asc":"..."}
```

`release-doctor.sh --verify-audit-shipped YYYY-MM-DD` re-fetches all three URLs, recomputes `sha256` of the `.asc`, asserts byte-equality with the local manifest. Mismatch ⇒ exit-1.

## 4. Decisions needed before implementation

1. **Audit tracker issue number.** Create `worthless#999` titled "Release audit log archive — DO NOT CLOSE" with locked conversation, label `audit-log-archive`. Pin `AUDIT_TRACKER_ISSUE=999` in `lib/release-env.sh`. Confirm number with maintainer (`gh issue list -L 1000 --state all --json number`).
2. **Privacy / R-13 redactor cross-check.** Pre-impl: enumerate every field R-15 JSONL writer emits. Confirm none can carry `gh api` response body, `GH_TOKEN` echo, `gpg --status-fd` key material. If R-13 redactor passes JSONL clean, channel (a) can carry JSONL too (defense-in-depth); if not, channel (a) ships only `.asc`, JSONL is gist-only.
3. **Sync vs async.** **Decision: synchronous fail-loud.** Audit corruption survives until next release if async; shipping 3 small payloads is sub-2s steady state; threat model treats laptop compromise as imminent.

## 5. TDD §8 rows

```
| Negative (F-17) | block network egress to api.github.com after .asc sealed but before R-27 ships | release.sh MUST exit-3 with "R-27 channel (a) failed after 3 retries"; .release-audit/${DATE}.ship-manifest.json MUST NOT exist; subsequent `release-doctor.sh --reship-audit ${DATE}` with network restored MUST succeed and produce manifest with 3 URLs |
| Negative (F-17b) | after successful ship, locally rewrite `.release-audit/${DATE}.log` and re-sign (simulating laptop compromise + cached subkey) | `release-doctor.sh --verify-audit-shipped ${DATE}` MUST exit-1 with "sha256 drift channel (a): local=<X> remote=<Y>"; all 3 channels independently flagged |
```

## 6. Risks / open questions

1. **Issue-comment size limit.** GitHub caps comment bodies at 65,536 chars. `.asc` is ~900 bytes; safe. JSONL could grow on long recovery — cap at 60KB or fall back to gist-only with comment pointer.
2. **`refs/notes/audit` push race** between maintainers (theoretical for single-signer, real once R-31 co-signer lands). Mitigation: documented `cat_sort_uniq` merge in retry path.
3. **Token scope creep.** Channel (b) `gh gist create` needs `gist` scope; R-9 pins `repo`/`repo+workflow`. Decision: extend R-9 to allow `repo,workflow,gist` OR separate token bound only to `gist`. Latter is cleaner — preflight P8 validates both.
4. **Tracker issue spoofing.** If attacker edits `lib/release-env.sh` `AUDIT_TRACKER_ISSUE`, they redirect to attacker-controlled issue. Mitigation: also bake into `SECURITY_RULES.md` SR-11; grep-check via R-11 self-check.
5. **Replay defense.** Nothing stops re-posting yesterday's `.asc` today. Mitigation: include `tag` + ISO date in comment body and gist description; `--verify-audit-shipped` asserts date-match.
6. **Public issue exposure of release cadence.** Issue (a) leaks tag timestamps to the world. Acceptable: tags are already public via GitHub Releases feed. Document explicitly.

## 7. Estimated lines changed

| File | Add | Mod |
|---|---|---|
| `SPEC.md` §5 paragraph | +6 | 1 |
| `SPEC.md` §6 rules-table row | +1 | 1 |
| `SPEC.md` §8 test rows | +2 | 0 |
| `security-engineer.md` R-27 row | +14 | 0 |
| `SECURITY_RULES.md` SR-11 (tracker pin) | +4 | 0 |
| Bash impl `lib/release-audit-ship.sh` (next ticket) | +95 | 0 |
| `lib/release-env.sh` constants | +3 | 0 |
| **Spec-only total (this ticket):** | **+27** | **2** |

## 8. Implementation order

1. Decide audit-tracker issue # (`gh issue list` check + create #999 with locked-conv).
2. R-13 redactor cross-check on R-15 JSONL fields — privacy decision (channel-a content scope).
3. Token scope decision (R-9 amendment OR dual-token).
4. Edit `security-engineer.md` — add R-27 row immediately after R-26.
5. Edit `SPEC.md` §5 — append R-27 paragraph after the R-15 paragraph.
6. Edit `SPEC.md` §6 — append to **Ruleset window** lens row.
7. Edit `SPEC.md` §8 — append two F-17 negative test rows.
8. Edit `SECURITY_RULES.md` — add SR-11 `AUDIT_TRACKER_ISSUE=999` pin.
9. Flip F-17 ✅ in SECURITY-PANEL.md.
10. File follow-on bead for `lib/release-audit-ship.sh` implementation + bats coverage.

---

**Morning-me copy-paste checklist:**
```
gh issue list -R shacharm2/worthless -L 1000 --state all --json number,title --jq 'map(select(.number==999))'
gh issue create -R shacharm2/worthless --title "Release audit log archive — DO NOT CLOSE" --label audit-log-archive --body "Append-only archive of release.sh / release-recover.sh GPG-signed audit logs (R-27). Do not close; do not edit comments."
gh issue lock -R shacharm2/worthless <issue-number>
```

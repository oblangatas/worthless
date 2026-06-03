# release.sh Spec — Open Follow-ups

> **Source:** 4-lens security panel (brutus + pentester + IR + auditor), 2026-06-01.
> **Status:** these are spec gaps to address during the 4-PR implementation series. NOT release-blockers.
> **Promotion path:** when `bd` is back online → one umbrella bead `worthless-release-sh-spec-followups` (P1) containing this table; individual findings tick off as implementation PRs close them.

## The 12 open findings

### HIGH (6) — close during implementation; each PR closes the relevant ones

| ID | Source | Headline | Where it lands | Estimated effort |
|---|---|---|---|---|
| F-19 | brutus | R-10 attestation chains to ref name, not GPG signature on tag | Implementation PR-3 (post-tag verify) — add `gh attestation verify --predicate-type ... \| jq '.subject.digest.sha1 == $EXPECTED_SHA'` assertion | 1 hr |
| F-20 | brutus | §11 Tool Trust ignores `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` | Implementation PR-1 (preflight) — unset env vars at top of `release.sh`; assert remain unset before each crypto call; refuse `$HOME`-rooted binaries | 2 hr |
| F-21 | pentester | Watchdog re-arm race (parent never observes heartbeat death between fork and R3) | Implementation PR-2 (recover.sh) — third reaper outside process group, OR `systemd-run --user` / `launchd` LaunchAgent | 3 hr (research the OS-supervisor route) |
| F-22 | pentester | jq + grep-of-MITM-stderr bypass of R-24 | Implementation PR-2 (recover.sh) — SPKI-pin BOTH `api.github.com` AND `github.com` in SR-10; canary over SSH (not HTTPS) | 2 hr |
| F-23 | IR | Tag message lacks structured provenance trailer | Implementation PR-2 (tag-cut) — append `--- Provenance ---` trailer with `Release-SHA / Wheel-SHA256 / Builder-Run-URL / Audit-Manifest` | 30 min |
| F-24 | IR | Linear paste is prose; no structured IR sidecar | Implementation PR-3 (post-tag step 4.9) — emit `.release-state/<v>/ir-sidecar.json` alongside the markdown; append to `.release-audit/INDEX.jsonl` | 1 hr |

### MEDIUM (5) — close during implementation OR defer to a polish PR

| ID | Source | Headline | Where it lands | Estimated effort |
|---|---|---|---|---|
| F-25 | brutus | "Offline-capable" claim misleading | Implementation PR-3 — strike from §10 item 1; replace with accurate framing | 5 min |
| F-26 | pentester | pip index ordering + multi-wheel docker mount | Implementation PR-3 (step 4.2 + 4.4) — `pip download --isolated --no-config --index-url https://pypi.org/simple/`; docker mount single file + in-container `sha256sum` re-verify | 1 hr |
| F-27 | pentester | CHANGELOG content can inject sed/awk/markdown at 4.5a | Implementation PR-3 (step 4.5a) — implement via `python3 -c` with strict bytes replace, no shell interpolation; add `notes.md` lint for backticks / `$(` / HTML tags | 1 hr |
| F-28 | auditor | n=1 signer / no segregation of duties (SOC 2 CC8.1 blocker) | NEW EPIC (not release.sh implementation) — defer until enterprise/SOC2 push | DEFER |
| F-29 | auditor | No SBOM / CVE scan gate before tag-push | Implementation PR-1 (preflight) — add P12: `pip-audit` + `syft` SBOM, fail on HIGH/CRITICAL CVE, attach SBOM to GH Release in step 4.6 | 2 hr |

### LOW (1)

| ID | Source | Headline | Where it lands | Estimated effort |
|---|---|---|---|---|
| F-30 | auditor | Tool Trust pin refresh lacks upstream-signed-checksum citation | Implementation PR-4 (CI + supply chain) — R-32: pin updates must cite upstream signed checksum URL in PR body | 30 min |

## Cross-cutting context

- **SLSA Build L3 achieved** — gap to L4 requires (a) two-party `main` review (CODEOWNERS), (b) reproducible builds (`SOURCE_DATE_EPOCH` in `publish.yml`), (c) parameterless builds. Track as separate epic `worthless-slsa-l4` if pursued.
- **SOC 2 CC8.1 blocker (F-28)** is the only finding that genuinely needs a new design epic (co-signer attestation, second maintainer GPG key). Everything else is implementation-time tightening.

## How to read this file in 6 months

If you're an implementer of the release.sh series and this file exists, the 4 CRITs (F-15..F-18) are closed in the spec at merge time. Your job is to close the HIGH+MED+LOW above as you implement each phase. Each entry tells you which PR slice owns it. Tick off in this file (or in the corresponding bead if `bd` is back) as you close.

If you're a security reviewer asked "did the WOR-598 spec address all 4-lens findings before merge" — yes for the 4 CRITs (see SPEC.md + security-engineer.md commits in PR #252 history). The HIGH/MED/LOW were intentionally deferred to implementation-time per the maintainer's decision (recorded in PR #252 commit `c9aa1ea` discussion).

# Incident Runbook — docs.wless.io + wless.io 403

**Bead:** worthless-6uoe | **Severity:** P0 | **Detected:** 2026-05-30 ~14:30 UTC | **Commander:** sole admin (Shachar)
**Author:** incident-responder agent, 2026-05-30 (returned inline due to sandbox-Write block; persisted by parent session)

## §1 Blast Radius

- `https://docs.wless.io` and `https://wless.io` — 403 globally.
- **Install banner** (`worthless` CLI): final line "Docs: https://docs.wless.io" — every new user hits 403 within seconds of install.
- **SKILL.md** shipped with the package references `docs.wless.io` — every Claude Code / Cursor / OpenClaw agent that resolves the skill 403s.
- **GitHub README** links to `wless.io` for install instructions.
- **Social / search / referral traffic** → 403 first-touch. SEO damage accumulates if Google caches the 403.

**Who is impacted:** 100% of *new* users from any channel. Existing CLI users operating against the proxy are **unaffected at runtime**. Docs/marketing only.

**Severity rationale:** no data loss, no security exposure, no key material at risk. 100% of acquisition funnel is dead. Brand-trust hit grows with every minute.

**Workaround:** GitHub repo README still resolves; install command + quickstart live there.

## §2 Containment Options (ranked by ETA)

| # | Option | ETA | Risk | Completeness | Verdict |
|---|--------|-----|------|--------------|---------|
| 1 | GitHub README banner + pinned issue | <5 min | none | sets expectations only | **DO FIRST (parallel with #2)** |
| 2 | CF Pages dashboard → Rollback to last green deployment | <10 min | low (deploys are immutable, atomic) | full if cause is bad deploy | **PRIMARY containment** |
| 3 | Disable CF Access policy if one is enabled | <5 min | low | full for Branch B only | conditional |
| 4 | Repoint DNS to static 503 maintenance page | <30 min | medium (TTL + cert) | partial | fallback if #2 fails |
| 5 | Serve stopgap landing via `worthless.sh` Worker on alt hostname | <60 min | medium | partial, breaks deep links | last resort |
| 6 | Full redeploy from last-good commit via GH Actions | <2 hr | medium | full | only if rollback unavailable |

**Order of operations:** #1 immediately (60 s of typing). Then #2. If #2 fails, branch into §3.

## §3 Decision Tree — Recovery Steps by Cause

### Branch A — Build failed → Pages serving 403 on a broken deploy
**Signal:** recent deploy shows "Failed" in CF Pages, or last "Success" predates 14:30 UTC.
1. CF dashboard → Workers & Pages → select project (handle `docs` and `wless` separately).
2. Deployments → find last green deploy (Success, age predates 14:30 UTC).
3. Click "..." → **Rollback to this deployment**. Confirm.
4. Wait 30–60 s for edge propagation.
5. **Verify:** `curl -sI https://docs.wless.io | head -1` → `HTTP/2 200`. Repeat for `wless.io`.
6. Fix the broken build in a follow-up PR. Do not redeploy until verified locally.

### Branch B — Cloudflare Access policy enabled / misconfigured
**Signal:** 403 body contains a CF Access challenge HTML or `cf-access-*` headers.
1. CF dashboard → Zero Trust → Access → Applications.
2. Find the application matching `docs.wless.io` / `*.wless.io`.
3. **Delete the app** (if added by mistake) or **edit the policy** → Bypass / Allow everyone for public paths.
4. Save. <30 s propagation.
5. **Verify:** `curl -sI https://docs.wless.io | head -1` → `HTTP/2 200`. Headers MUST NOT contain `cf-access-*`.
6. Audit who/when via CF audit log.

### Branch C — DNS / cert / SSL handshake change
**Signal:** DNS record changed, SSL/TLS mode flipped, or Universal SSL cert expired/revoked.
1. CF dashboard → DNS → confirm `docs` and root `wless.io` point to correct project.
2. If DNS changed: restore prior record.
3. SSL/TLS → Overview → confirm mode (Pages needs Full or Full Strict).
4. Edge Certificates → confirm Universal SSL Active. Re-trigger issuance if expired/pending.
5. **Verify:** `openssl s_client -connect docs.wless.io:443 -servername docs.wless.io </dev/null 2>&1 | grep -E "subject=|Verify return"` → valid chain.
6. `curl -sI https://docs.wless.io | head -1` → `HTTP/2 200`.

## §4 Communication

Minimal, honest, no cause speculation. Channels in order:
1. **GitHub repo README** — top-of-file banner (one commit, revert when resolved).
2. **Pinned GitHub issue** "Docs site temporarily unavailable — 2026-05-30".
3. **X / social** — only if outage exceeds 1 hour. No cause speculation.
4. **Status page** — does not exist yet (§5).

**Holding statement:**
> The docs.wless.io and wless.io sites are returning 403 errors as of 2026-05-30 ~14:30 UTC. We are investigating and will restore service shortly. The CLI, proxy, and your existing keys are unaffected — this is a documentation-site issue only. Install instructions live at github.com/shacharm2/worthless in the meantime.

## §5 Post-Incident Hardening (top 3)

1. **External uptime monitoring on both hostnames**, separate from the release pipeline. UptimeRobot / Better Stack, 1-min interval, alerts to email + Slack.
2. **One-click rollback in the deploy workflow.** `workflow_dispatch` accepting `commit_sha`, redeploys exact SHA via CF API.
3. **Public status page** (CF Workers + static JSON, or Better Stack / Instatus). Components: Docs, Marketing, Proxy, Reconstruction.

---

**Containment recommendation (one line):** Post the GitHub README banner + pinned issue immediately (60 s), then rollback to the last green Cloudflare Pages deployment (Branch A in §3) — highest-probability cause, cheapest reversible action.

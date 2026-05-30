# Docs/Website Deploy Topology — devops-engineer findings

**Bead:** worthless-6uoe | **Detected:** 2026-05-30 ~14:30 UTC
**Author:** devops-engineer agent, 2026-05-30 (returned inline due to sandbox-Write block; persisted by parent session)

## §1 Deploy topology

| Hostname | Source | System | Trigger | Target |
|---|---|---|---|---|
| `wless.io` apex | `website/**` (static HTML, CNAME=`wless.io`) | `.github/workflows/deploy-website.yml` | `push` to `main` with `website/**` paths; also `workflow_dispatch` | GitHub Pages via `actions/upload-pages-artifact` + `actions/deploy-pages@v4` |
| `docs.wless.io` | `docs/**`, `astro.config.mjs`, `wrangler.jsonc`, `package.json`, `src/content.config.ts` | **Cloudflare Workers Builds** (external — no GH Actions workflow) | CF auto-build on push to `main`; root `wrangler.jsonc` → `name: worthless-docs`, static assets from `./dist/` | CF Worker `worthless-docs` with custom domain `docs.wless.io` |
| `worthless.sh` GREEN | `workers/worthless-sh/**` | `.github/workflows/deploy-worker.yml` | Signed `v*` tag push | CF Worker `worthless-sh-production` |

Authoritative comment: `deploy-worker.yml` lines 211–215 explicitly state root `wrangler.jsonc` is the docs.wless.io Astro site auto-deployed by **Cloudflare Workers Builds** (PR #113). `docs-spike.yml` is PR-only build verification, no deploy step.

The `origin/website` branch (last commit 2026-05-01) and `origin/website-dev` (2026-05-28) are NOT used as deploy sources — Pages reads from the artifact uploaded by the workflow.

## §2 Last 10 deploy runs

**deploy-website.yml** — all 10 most recent runs SUCCESS. Last push/main deploys:
- 2026-05-20 13:15 UTC, success — #204 ticker impact lines
- 2026-05-19 06:49 UTC, success — WOR-503
- 2026-05-18 17:12 UTC, success — #200 CSP fix

`wless.io` has not been redeployed in 10 days.

**docs-spike.yml** — last 10 SUCCESS (most recent 2026-05-29 07:50 UTC on PR #230 = 9bad4bd). PR-only, does not deploy.

**Cloudflare Workers Builds** — no repo-side visibility. Must check CF dashboard for the build triggered by 9bad4bd (~2026-05-29 20:42 UTC).

Outage day CI: one `Scorecard security analysis` failure on main at 15:31 UTC (post-outage, OSSF cron, not a deploy job).

## §3 Recent commits / PRs that could have affected docs/website

Touching `docs/`, `wrangler.jsonc`, `astro.config.mjs`, `package.json`, `src/content.config.ts`:
- `9bad4bd` 2026-05-29 23:42 (+03:00) — #230 sidecar security docs (content-only, no config churn)
- `684b9be` 2026-05-24 — #212 Docker journeys
- `19d5767` 2026-05-15 — devalue 5.7.1→5.8.1

Touching `website/`:
- `17cfa43` 2026-05-20 — #204 ticker impact lines (last website change, 10 days ago)

## §4 Verdict

**Likely cause: NOT a build/deploy regression in this repo.**

- wless.io hasn't been redeployed in 10 days with all green runs.
- docs.wless.io's last change (9bad4bd, content-only, passing CI) merged ~18h before the outage.
- Two distinct delivery systems (GitHub Pages + Cloudflare Workers Builds) failing simultaneously, while the third CF Worker `worthless.sh` on the separate `worthless.sh` zone is GREEN, points at a **Cloudflare `wless.io` zone-level issue**:
  - WAF rule applied at zone level
  - Plan / billing suspension
  - Custom-domain unbind
  - DNS record removal

**Action:** investigate CF dashboard zone `wless.io` first (zone health, WAF/firewall, billing status), then `worthless-docs` Workers Builds deployments, then GitHub Pages custom-domain status for `shacharm2/worthless`. Do NOT touch repo deploys until zone-level state is confirmed clean.

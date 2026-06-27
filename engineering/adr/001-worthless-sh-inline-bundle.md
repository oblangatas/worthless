# Architecture Decision: Inline (A) vs Fetch-from-GitHub (B)

Source: architect-reviewer agent pass + threat-model followup, 2026-04-24.

## Decision: **Option A (inline/bundle) + verifiable response headers + signed-tag deploy gate**

80/20 call for A, upgraded to 95/5 after threat model surfaced tag-mutation attacks that weaken B.

## Why A

**Option A (inline):** install.sh is bundled into the Worker bundle at build time via a Wrangler Text rule. Worker ships with it baked in. Deploy = new Worker bundle.

**Option B (fetch):** Worker fetches install.sh from `raw.githubusercontent.com/.../v0.3.0/install.sh` per request.

| Dimension | A | B |
|---|---|---|
| Single-credential compromise (GitHub push only) | Safe until redeploy | **Poisons immediately** — `git tag -f v0.3.0 <evil commit>` works because tags are mutable |
| Resilience to GitHub outage | No impact | 502 until cache warms |
| First-byte speed | ~50ms faster | slower on cold cache |
| Deploy cadence cost | One `wrangler deploy` per install.sh change (~monthly) | One env var bump + deploy |
| Auditability for paranoid user | Via verifiable headers (see below) | Diff vs GitHub |

A wins on security (two-credential compromise required: GitHub + Cloudflare) and resilience. Loses ~50ms on first byte; acceptable.

## Required additions beyond "just bundle"

Per threat model findings F-12, F-34, F-35 — **A alone is not enough** if attacker can force-push a tag AND trigger a deploy. Must pair with:

1. **Signed git tags + protected tag patterns** on main repo. `git tag -s v*`. GitHub ruleset blocks unsigned tag pushes.
2. **Deploy-time tag signature verification** in the GitHub Action — before `wrangler deploy`, verify the tag ref is signed and matches expected maintainer keys. Abort deploy if not.
3. **Actions environment with required reviewers** for `worthless-sh-production` deploy. Short-lived scoped Cloudflare token, not account-scoped. (Same env name as referenced in `deploy-worker.yml`; `-prod` was the original placeholder text in the ADR draft.)
4. **Worker response headers** for post-deploy verification by auditors:
   ```text
   X-Worthless-Script-Sha256: <hex>
   X-Worthless-Script-Tag: v0.3.0
   X-Worthless-Script-Commit: <full sha>
   X-Worthless-Build-Provenance: https://github.com/shacharm2/worthless/actions/runs/XXX
   ```
5. **Sigstore-signed artifact** (`install.sh.sig` + cert) published as GitHub Release asset. `cosign verify-blob` works against the published identity.

## Concrete changes in `workers/worthless-sh/`

- Add to `wrangler.toml`: `[[rules]] type = "Text" globs = ["**/*.sh"]` so `import INSTALL_SH from "../../install.sh"` returns the script as a string at build time.
- Remove `GITHUB_RAW_URL` env var (fetch path gone). Keep `REDIRECT_URL`.
- `src/index.ts` serves `INSTALL_SH` with `content-type: text/plain; charset=utf-8`, cache headers, verifiability headers.
- CI check: `sha256(install.sh)` matches the sha256 the Worker bundles + the sha256 announced in the `X-Worthless-Script-Sha256` header.

## Failure modes for A

- **Deploy drift** (Worker bundled outdated install.sh). Mitigation: CI assertion on every deploy that `sha256(repo-install.sh) == sha256(bundled-install.sh)`.
- **Cloudflare compromise.** Mitigation: two-credential requirement (GitHub + Cloudflare) + Actions env protection.
- **Someone bypasses the Action and runs `wrangler deploy` locally.** Mitigation: disable direct deploy access; Action is the only path.

## Operational cost

- **A:** one Wrangler deploy per install.sh release (~monthly). Fully automated via tag-push Action.
- Maintenance tax: `sha256` drift check in CI (one line).
- **B:** GitHub raw availability monitoring + cache-poisoning awareness + env var bump on every tag + synthetic check hitting `raw.githubusercontent.com`. Recurring cognitive load.

A wins here too.

## Tag force-push is a real attack

The naive "B pinned to v0.3.0 is immutable" argument is WRONG. Git tags are mutable by anyone with push access. An attacker compromising GitHub can `git tag -f v0.3.0 <evil commit>` and serve poison within the Cloudflare cache TTL.

Option A defeats this **at request time** (bundled content is static). It does NOT defeat a deploy-time attack — attacker with GitHub push could force-tag, then their tag-push triggers the deploy Action, which runs `wrangler deploy` with the evil content.

Required defense: **protected tag patterns** (GitHub ruleset forbids force-push on `v*` tags) + **signed tag verification at deploy time** (Action checks signature before wrangler runs).

Without both, A is just as vulnerable as B to tag attacks.

## Summary

Option A + signed tags + protected tag ruleset + Actions env protection + verifiable response headers + Sigstore artifact signing = the composite defense. Drop any one and the story weakens.

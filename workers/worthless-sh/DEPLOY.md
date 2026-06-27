# Deploy Runbook — `worthless.sh` Cloudflare Worker

Operator runbook for the install-script Worker. Covers one-time setup
(including signed-tag GPG anchors), per-release procedure, token
rotation, rollback, and known residual risks. Source of truth for
"what do I do when the deploy is on fire" lives here.

---

## Architecture (one paragraph)

A single Cloudflare Worker at `worthless.sh` serves `install.sh` to
curl-family clients and 302-redirects browsers to `wless.io`. The script
is bundled into the Worker bytes at build time (Option A inline-bundle
per `engineering/adr/001-worthless-sh-inline-bundle.md`) — no runtime
fetch from GitHub. The Worker emits `X-Worthless-Script-Sha256` so
auditors can compute `curl worthless.sh | sha256sum` and confirm match.

Deploy pipeline: a `v*` tag push fires `.github/workflows/deploy-worker.yml`,
which runs vitest, computes the install.sh sha256, verifies the tag
signature, then `wrangler deploy --env production` with `SCRIPT_TAG` /
`SCRIPT_COMMIT` injected at deploy time.

---

## One-time setup

### 1. Cloudflare account

| Setting | Value | Why |
|---|---|---|
| Domain | `worthless.sh` (apex) on Cloudflare DNS | Required for the route binding. |
| SSL/TLS mode | **Full (strict)** | Anything weaker accepts MITM-substituted certs. |
| HSTS | `max-age=63072000; includeSubDomains; preload` | Matches the Worker-emitted header. Submit to hstspreload.org after first prod deploy. |
| Bot Fight Mode | **OFF** | A challenge page served to a curl client and piped to `sh` is RCE-class. |
| Always Use HTTPS | ON | Defence-in-depth. |
| Min TLS Version | 1.2 | RFC 8996 deprecates 1.0/1.1. |
| Cache Level | Bypass for `worthless.sh/*` | The Worker emits its own cache headers; CDN-level caching could collide with `Vary: User-Agent`. |

### 2. Cloudflare API token

Create a **scoped** token (NOT the global account token):

- **Permissions:** `Account → Workers Scripts → Edit`
- **Account resources:** Include → your account only
- **Zone resources:** Include → `worthless.sh` only
- **Client IP filter:** GitHub Actions IP ranges (optional, hardening)
- **TTL:** 90 days, calendared rotation

Future hardening: when Cloudflare ships OIDC for GHA, swap to
short-lived issued tokens — see "Known residual risks" §6.

### 3. GitHub repository setup

#### Actions environments (Settings → Environments)

Create two environments:

| Name | Required reviewers | Wait timer | Deployment branches |
|---|---|---|---|
| `worthless-sh-preview` | 0 (solo dev) | 0 min | `main`, `feature/wor-300-*` |
| `worthless-sh-production` | 0 (per WOR-330; solo until v2.x) | 0 min | tags matching `v*` only |

Each environment scopes secrets:

| Secret | Set in env | Value |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | both | scoped token from §2 |
| `CLOUDFLARE_ACCOUNT_ID` | both | from Cloudflare dashboard |
| `CLOUDFLARE_ACCOUNT_SUBDOMAIN` | preview only | your `*.workers.dev` subdomain |

#### Branch / tag rulesets

Settings → Rules → Rulesets:

1. **Tag protection (`v*`):**
   - Require signed tags
   - Block force pushes
   - Block deletion
   - Bypass list: empty (no admin override)

2. **Branch protection (`main`):**
   - Require signed commits
   - Require PR before merge
   - Require status checks: `Tests`, `Install Docker (bare-Ubuntu integration)`,
     and (post-Phase 6) `Worker vitest` (WOR-339)

Configure via UI; IaC for rulesets is deferred (post-WOR-323).

### 4. Set up signed tags

The deploy workflow's GPG-verify step is fail-closed and requires two
repository **Variables** (not Secrets — public keys are public):

- `MAINTAINER_GPG_PUBKEY` — ASCII-armored public key.
- `MAINTAINER_GPG_FINGERPRINT` — 40-char hex fingerprint of the same key.

The fingerprint pin **raises the bar** against a Variable-swap attack —
swapping the pubkey alone (without a matching fingerprint update) fails
the verify step. It does NOT defeat a full Variable-swap by an attacker
with `gh` write who atomically updates BOTH Variables; the audit-trail
entries in GitHub's Settings → Security log are the operator-side
detective control for that case. The verify step also rejects multi-key
ASCII armor (decoy attack) before checking the fingerprint.

#### One-time setup

```bash
# (a) Generate an ed25519 key, or repurpose an existing one.
gpg --full-generate-key                       # choose ECC → ed25519
gpg --list-secret-keys --keyid-format=long    # capture the long KEYID

# (b) Export the ASCII-armored public key.
gpg --armor --export <KEYID> > /tmp/maintainer.pub

# (c) Capture the fingerprint (no spaces, uppercase hex).
gpg --batch --with-colons --fingerprint <KEYID> \
  | awk -F: '/^fpr:/ {print $10; exit}'

# (d) Configure local git to sign tags + commits.
git config --global user.signingkey <KEYID>
git config --global tag.gpgSign true
git config --global commit.gpgsign true

# (e) Upload the same pubkey to your GitHub user profile so signed
# commits show "Verified" in the UI:
# https://github.com/settings/keys → New GPG key → paste /tmp/maintainer.pub
```

Then in the repo's Settings → Secrets and variables → Actions →
**Variables** tab:

| Variable | Value |
|---|---|
| `MAINTAINER_GPG_PUBKEY` | the contents of `/tmp/maintainer.pub` |
| `MAINTAINER_GPG_FINGERPRINT` | the 40-char hex fingerprint from step (c) |

#### Verifying the setup

Push a test signed tag against a sandbox branch:

```bash
git tag -s v0.0.0-verify-test -m "test"
git push origin v0.0.0-verify-test
gh run watch
# Verify step should print: "Tag v0.0.0-verify-test verified against pinned fingerprint <FPR>."
git push --delete origin v0.0.0-verify-test
git tag -d v0.0.0-verify-test
```

Negative test: push an unsigned tag from the same sandbox branch — verify
step must exit non-zero with `::error title=Unsigned or untrusted tag::…`.

#### Rotation cadence

Rotate the GPG key on compromise, on maintainer departure, or
proactively every 12–24 months. **Both** Variables MUST update atomically
— the fingerprint is what gates the new pubkey. Tags signed during the
rotation window must be re-signed against the new key before push.

---

## Per-release deploy

Standard release procedure once setup is complete:

```bash
# 1. From the feature branch, ensure tests are green and PR is merged.
gh pr checks <PR>
gh pr merge <PR> --squash

# 2. Pull latest main locally.
git checkout main && git pull

# 3. Tag with a signed tag (gpg key configured in git config).
git tag -s v0.3.1 -m "Release v0.3.1 — <one-line summary>"

# 4. Push the tag. This fires .github/workflows/deploy-worker.yml.
git push origin v0.3.1

# 5. Watch the deploy workflow.
gh run watch
```

The workflow's smoke-test step verifies `curl worthless.sh | sha256sum`
matches `X-Worthless-Script-Sha256` matches the build-time hash. If the
smoke test fails, the deploy is recorded as failed but the route may
already be live — proceed to rollback.

### Pre-deploy: dry-run via workflow_dispatch (preview)

Before tagging a release for production, exercise the full pipeline against
the preview environment:

```bash
gh workflow run deploy-worker.yml -f target=preview
gh run watch
```

Then dogfood the preview URL:

```bash
PREVIEW_URL="https://worthless-sh-preview.<account>.workers.dev"
curl -sSL "${PREVIEW_URL}/" | head -10                        # → install.sh
curl -sSL "${PREVIEW_URL}/?explain=1" | head -10              # → walkthrough
curl -sSI "${PREVIEW_URL}/" | grep -i x-worthless             # → verifiability headers
curl -sSI -A "Mozilla/5.0" "${PREVIEW_URL}/" | grep -i location  # → 302 to wless.io
```

If preview is good, push the production tag.

---

## Token rotation runbook

Cloudflare API tokens age into compromise risk. Server-side TTL is the
primary control; the runbook is the backup.

### When

- **Every 90 days**, enforced by the Cloudflare token's server-side
  expiry (set on creation). When the token expires, the next deploy
  fails fast — that is the rotation reminder. Don't rely on a calendar.
- Immediately on suspected compromise (lost laptop, leaked log line,
  ex-maintainer access).
- On maintainer departure.

### How — preview token

The preview token can be account-wide; preview deploys cannot reach
production routes.

1. Cloudflare dashboard → My Profile → API Tokens → "Create Token".
2. Template: "Edit Cloudflare Workers".
3. Permissions: `Account → Workers Scripts → Edit`. Add `Zone →
   Workers Routes → Edit` if needed.
4. Account resources: Include → your account only.
5. Zone resources: All zones.
6. **TTL: 90 days.** Calendared expiry forces rotation.
7. Settings → Environments → `worthless-sh-preview` → paste new token
   into `CLOUDFLARE_API_TOKEN`.
8. Trigger `gh workflow run deploy-worker.yml -f target=preview` to
   confirm new token works.
9. Delete the old token in Cloudflare → API Tokens.

### How — production token

The production token must be **Worker-only + zone-only** so a token leak
cannot pivot to other Cloudflare resources.

1. Cloudflare dashboard → My Profile → API Tokens → "Create Token".
2. Custom token (not the template — the template is too broad).
3. Permissions: `Account → Workers Scripts → Edit` ONLY (no DNS, no
   Account Settings, no Page Rules).
4. Account resources: Include → your account only.
5. **Zone resources: Include → `worthless.sh` only** (not "All zones").
6. **TTL: 90 days.**
7. Settings → Environments → `worthless-sh-production` → paste new
   token into `CLOUDFLARE_API_TOKEN`.
8. Cannot test via dispatch (production is tag-only); push a no-op
   patch tag to verify (or wait for the next legitimate release).
9. Delete the old token in Cloudflare → API Tokens.

### Audit

- Cloudflare → Audit Logs: shows token issuance and use.
- GitHub → Settings → Security log: shows env-secret changes.
- Both should be reviewed monthly.

---

## Rollback

Three layers, fastest first:

### 1. Cloudflare dashboard — kill the route (~30 seconds)

The "stop the bleeding" path. Removes the route binding immediately;
`curl worthless.sh` starts returning DNS-only Cloudflare default (404).

```
Cloudflare Dashboard → Workers & Pages → worthless-sh →
  Triggers → delete the worthless.sh/* route
```

Users who try to install during the outage see a clear failure rather
than a malicious script. Restore the route once the bad deploy is
identified.

### 2. Re-deploy a known-good tag (~2 minutes)

Production deploys are tag-only — there is no `workflow_dispatch` path
into production (the dispatch trigger only offers `preview`). Rollback
is by re-tagging a known-good commit and pushing the new signed tag:

```bash
git checkout v0.3.0      # the last-good tag (or its commit sha)
git tag -s v0.3.2-rollback-of-v0.3.1 -m "Roll back v0.3.1 — see <incident>"
git push origin v0.3.2-rollback-of-v0.3.1
```

Convention: rollback tags are clearly named so the audit trail shows
intent. The deploy workflow's GPG-verify step gates the rollback tag
the same way it gates a forward release — sign with the maintainer
key whose fingerprint matches `MAINTAINER_GPG_FINGERPRINT`.

### 3. Domain compromise (~5 minutes, last resort)

If the Cloudflare account itself is compromised, delete the DNS records
at the registrar:

```
Registrar (e.g., Porkbun) → worthless.sh → DNS →
  Delete the `worthless.sh` A/AAAA/CNAME record
```

`curl worthless.sh` then NXDOMAIN-fails, which is the safest possible
outcome. Restore once the account is recovered. Full IR runbook lives
at WOR-331.

---

## Verification (post-deploy auditor checklist)

```bash
# 1. Body sha256 matches the release.
curl -sSL https://worthless.sh/ | sha256sum
# → compare to the published value in the GitHub release notes

# 2. X-Worthless-Script-Sha256 header matches the body.
curl -sSI https://worthless.sh/ | grep -i x-worthless-script-sha256

# 3. Tag and commit headers point at the right ref.
curl -sSI https://worthless.sh/ | grep -i 'x-worthless-script-tag\|x-worthless-script-commit'

# 4. Browser fail-safe still works.
curl -sSI -A "Mozilla/5.0" https://worthless.sh/ | head -3
# → expect HTTP/2 302; location: https://wless.io

# 5. Walkthrough still works.
curl -sSL https://worthless.sh/?explain=1 | head -10

# 6. Security headers still attached.
curl -sSI https://worthless.sh/ | grep -i 'strict-transport\|nosniff\|referrer-policy'

# 7. /.well-known/security.txt still served (RFC 9116).
curl -sSL https://worthless.sh/.well-known/security.txt | head -10
```

---

## Known residual risks (post-WOR-323)

WOR-323 closed the original three soft-fails (GPG verify is now fatal
with fingerprint pinning; production deploy is tag-only with no
workflow_dispatch path; preview/production tokens are scoped). The
following residual risks are NOT covered by WOR-323 and should be
acknowledged before each release:

1. **Software signing key on a maintainer laptop.** The GPG key that
   signs `v*` tags lives on disk, unprotected by hardware. Compromise of
   the maintainer machine = compromise of the release pipeline.
   *Mitigation path:* hardware-backed keys (YubiKey + GPG smartcard) on
   the maintainer's primary device. Tracked as a follow-up; not gating
   v1.1.

2. **No origin attestation (TOFU on `X-Worthless-Script-Sha256`).** The
   Worker emits a sha256 header that matches the body, but the *same
   origin* serves both. An attacker who controls the response controls
   both the body and the header. The integrity check in the README
   catches **post-download local-file tampering** and **CDN cache
   poisoning** (the realistic threats), NOT a compromised origin —
   transit MITM is already prevented by TLS + HSTS, and same-origin
   attestation is impossible by construction. *Mitigation path:*
   cosign-signed release manifests (WOR-303), trust anchored in the
   GitHub Actions OIDC
   identity, separate from the Cloudflare deploy path.

3. **No SLSA / Sigstore provenance.** Same root as #2 — until WOR-303
   lands there is no third-party-verifiable record of *which CI run
   produced these bytes*. Auditors today must trust git history + the
   deploy log alignment.

4. **CDN cache propagation window.** After a successful deploy, there
   is a sub-minute window where Cloudflare's edge nodes may serve the
   *previous* bundle while origin serves the new one. The post-deploy
   smoke test retries 3× with linear backoff (10s, 20s; 30s total) and
   uses a per-run cache-buster query; this catches typical edge-
   propagation lag but cannot defend against a sustained cache poisoning
   attack. Re-run the workflow's smoke step on suspected cache mismatch.

5. **Pubkey rotation atomicity.** `MAINTAINER_GPG_PUBKEY` and
   `MAINTAINER_GPG_FINGERPRINT` must be updated *atomically* (GitHub's
   Variables API does not transactionally bind them). A push that lands
   between updating one Variable but not the other would fail the verify step
   with "Fingerprint mismatch" — recoverable, but operators should
   pause tag pushes during rotation.

6. **Cloudflare token at rest in GitHub.** The token is stored in
   GitHub Actions Secrets, encrypted at rest and not exfiltrable from
   the Actions runner UI. A repo compromise (admin write) would still
   surface it through a malicious workflow change. *Mitigation path:*
   Cloudflare OIDC for GHA — waiting on Cloudflare to ship it.

7. **No alerting on `MAINTAINER_GPG_*` Variable changes.** The GitHub
   audit log records every Variable change, but no notification fires
   on update. An attacker with `gh` write who atomically swaps both
   Variables leaves a trail but no real-time signal. *Mitigation path:*
   wire the audit log into a notification channel before scaling
   beyond ~10 deploys/year (brutus round-3 follow-up).

For solo dev, **production environment required-reviewers stays at 0**
(per WOR-330) — but the `worthless-sh-production` env's deployment-branch
rule restricts it to `v*` tags only, so a malicious workflow_dispatch
cannot cut a production deploy without a signed tag.

---

## Known gotchas

- **Wrangler picks the wrong `[env.*]` block.** If you forget
  `--env preview`, Wrangler deploys against the bare config, which has
  no route binding but is named `worthless-sh` — colliding with the
  production worker's name. Always pass `--env`.

- **`compatibility_date` drift.** Bumping the date in `wrangler.toml`
  can change runtime semantics (e.g., header normalisation, stream
  behaviour). Bump in a dedicated commit + PR with the full vitest
  suite re-run.

- **Cloudflare cache outliving the Worker.** Cache-Control values from
  the Worker are honoured but the CDN may cache the redirect for the
  TTL anyway. Purge via dashboard if the redirect target ever changes.

- **`workers.dev` subdomain leaks the account name.** Preview URL is
  `https://worthless-sh-preview.<account>.workers.dev`. Acceptable for
  internal dogfood; do not link to it publicly.

---

## Contacts

* **On-call:** see `.github/SECURITY.md`
* **Incident response:** WOR-331
* **Threat model:** `security-audit/threat-model-worthless-sh.md`

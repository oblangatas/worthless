# WOR-300 Worker — Threat Model

**Target:** `https://worthless.sh` Cloudflare Worker, Option A (install.sh bundled inline at build time), UA-routing, `?explain=1`, response-header pinning, Sigstore-signed release artifacts, `/docker` path.

**Method:** Brutal enumeration. Every finding: severity, attack, mitigation (or "accept").

Severity legend: **H** = blocks ship / demands mitigation before launch. **M** = must document + monitor, can ship with a compensating control. **L** = known residual risk, accept or backlog.

---

## Scope of the worthless tool itself (assumed by this model)

This threat model covers the **delivery channel** for worthless. The
tool itself has a deliberately narrow detection scope: it scans for
**LLM provider API key prefixes only** — currently `openai` (`sk-`,
`sk-proj-`), `anthropic` (`sk-ant-`), `google` (`AIza`), and `xai`
(`xai-`). It is **not** a general-purpose secret scanner: cloud
provider tokens (AWS, GCP, Azure), GitHub PATs, npm tokens, Cloudflare
API tokens, database passwords, and JWT signing keys are out of scope
and will not be flagged. Users are expected to pair worthless with
[gitleaks](https://github.com/gitleaks/gitleaks) or
[trufflehog](https://github.com/trufflesecurity/trufflehog) for
broader coverage. Threats premised on worthless catching non-LLM
secrets (e.g. "user assumed worthless would block AWS-key leaks") are
therefore documentation/UX risks (covered under the README + SKILL.md
scope statement), not detection-scope bugs.

---

## TOP FINDINGS THAT SHOULD BLOCK SHIP

1. **F-12 — GitHub Actions OIDC / `wrangler deploy` token is the single highest-value secret.** Whoever pops that key ships arbitrary script to every `curl | sh` on the planet for the cache TTL. No out-of-band review. **Must** require a second human approval (environments + required reviewers) on the deploy job, and rotate the Cloudflare API token to a short-lived scoped token (not an account-wide key).
2. **F-34 — UA-based routing is a security boundary made of wet paper.** Attackers can hit the script endpoint from browsers (`curl`-like UA) and lure victims to paste-in-terminal. Worse: any victim who runs `curl https://worthless.sh` from the command-line from a link they clicked in a browser gets the script — the "browser sends them to wless.io" defense is a UX nicety, not a security control. **Do not sell UA routing as a safety feature.** Document it as UX only.
3. **F-01 — `curl | sh` is the attack surface.** No amount of Worker hardening fixes the root vulnerability: the user pipes unverified bytes to a shell. Everything else (sha256 header, Sigstore) is defense-in-depth the user will not verify. Advertise and prefer a verified two-step install (`curl -o install.sh && verify && sh install.sh`) as the **documented default**. Keep one-liner but gate it behind a warning banner in the `?explain=1` output.

---

## Install front-door — current-state attack-surface map (updated 2026-05-22, WOR-558)

A consolidated view of the `curl -sSL https://worthless.sh | sh` chain: each surface, the control in place today, and the residual gap. This synthesizes the findings below into one dashboard; F-numbers link to the detail. Grounded in real incidents — see **Real-world precedents** below.

| Surface | Attacker move | Control today | Residual gap |
|---|---|---|---|
| `curl \| sh` itself | User pipes unverified bytes to a shell | docs prefer inspect-before-run + `?explain=1`; honest-limits section in `docs/install-security.md` | **Accepted (F-01).** No control makes piped bytes verified; cosign two-step is the fix (WOR-303). |
| Worker request surface | UA spoof, CRLF/NUL injection, path/method/Range/cache abuse, query reflection on `?explain=1` | strict UA allowlist + shell-safe errors (`src/index.ts`, `src/ua.ts`); exhaustively tested — `worker-wire-attacks.yml` (raw-TLS CRLF/NUL) + `methods`/`paths`/`query-canonicalization`/`headers-and-integrity`.test.ts | **Closed — strongest area.** But UA routing is UX, not a security boundary (F-34) — do not oversell. |
| DNS / domain | Registrar/zone takeover repoints the apex | CF account 2FA + registrar lock (operational); `workers_dev=false` kills the `*.workers.dev` surface (`wrangler.toml`) | **Accepted (F-27/F-28).** CF = registrar+DNS+host = single point. |
| Cloudflare token / out-of-band deploy | Stolen token → `wrangler deploy` of a malicious bundle, bypassing CI | post-deploy live SHA smoke hashes served bytes vs the CI build (`deploy-worker.yml`) | **Real (F-12).** Smoke only runs *inside* the GHA deploy; an out-of-band deploy isn't caught. No required-reviewer gate. |
| GitHub repo / Actions | Push a malicious tag; PR a token-exfil workflow | GPG-signed-tag verify (fail-closed), pinned action SHAs, read-only perms (`verify-tag.sh`, `deploy-worker.yml`) | **Accepted (F-02/F-03).** A repo-admin who writes both `MAINTAINER_GPG_*` Variables defeats the pin. The `workflow_dispatch`→prod re-opening is guarded by a comment + the pending WOR-406 structural test. |
| TLS / MITM | A trusted TLS-terminating proxy rewrites the piped script | HSTS preload (`index.ts`) | **Real (F-34).** A proxy the machine already trusts defeats TLS; now surfaced to users in `docs/install-security.md`. |
| **PyPI package** (highest-impact hop, *Medium* likelihood) | Compromise the `worthless` PyPI release → RCE on every install | **default version pin (WOR-559):** `install.sh` installs `worthless==<WORTHLESS_VERSION_PIN>` (latest published release, hand-bumped per release like UV_VERSION; a CI drift check in `release-sync-check.yml` fails if it lags latest PyPI); `WORTHLESS_VERSION=` override; uv installer also SHA-pinned | **Narrowed (was the softest link).** The *unpinned-latest auto-install* vector is closed: a release compromised **after** ours can't land on fresh installs. **Residual:** no wheel-*hash* (`uv tool install` can't `--require-hashes`), so the *pinned* release itself being compromised, plus dep compromise/post-install hooks (F-06/F-49), are still open → wheel-hash verify is the WOR-559 follow-up. |
| Astral / uv installer | Substitute the uv installer payload | `ASTRAL_INSTALLER_SHA256` pin, hard-fail on mismatch (`install.sh`) | **Accepted (F-05/F-48).** Only as strong as the pin-bump PR review. |
| Script verifiability | User can't confirm what they ran | `X-Worthless-Script-Sha256/-Tag/-Commit` headers; `?explain=1` walkthrough (drift-guarded, WOR-558) | **Theater for the 99% (F-24/F-39).** Headers travel the same channel as the script; only cosign from GitHub Releases makes this non-theater (WOR-303). |

### Top 3 attacker moves that would succeed today
1. **Steal the Cloudflare token and deploy out-of-band.** The CI live-smoke never fires on a non-CI deploy. *(F-12 → required-reviewer gate + scoped, short-lived token.)*
2. **Trusted-proxy MITM rewrite of the piped script.** Defeats TLS once the proxy is trusted. *(F-34 → documented; prefer two-step inspect-install.)*
3. **Compromise the *exact pinned* `worthless` release** (steal/phish the maintainer token and poison version `X.Y.Z` itself). The default pin (WOR-559) closes the easier "publish any malicious *latest*" move, but without a wheel hash a freshly-poisoned pinned release still installs. *(F-06/F-49 residual → wheel-hash verify follow-up.)*

**Note on the PyPI "#1" framing (severity reconcile, WOR-559):** earlier revisions ranked the PyPI hop "#1" by *impact* (RCE on every fresh install). The underlying findings are F-06/F-49 (*Medium* likelihood) — correctly **not** in "TOP FINDINGS THAT SHOULD BLOCK SHIP", and left at Medium. WOR-559 shipped the default version pin, which retires the highest-impact *unpinned-latest* sub-vector; the remaining wheel-hash gap is a tracked follow-up, not a ship blocker. So the dashboard now reads "highest-impact hop, Medium likelihood, narrowed by WOR-559" rather than a bare "#1."

Worker-layer attacks (UA bypass, CRLF, cache, panic→HTML) **fail today** — that surface is well-hardened and wire-tested. The unpinned-PyPI auto-install is now closed by default (WOR-559). The user's remaining real exposure is the Cloudflare token, trusted-proxy MITM, and a compromise of the exact pinned release — none of which more Worker tests can fix.

### Real-world precedents (cited)

Documented incidents that map to our surfaces, and the defense each motivated.

| Incident (year) | Maps to | Defense it argues for | Source |
|---|---|---|---|
| `ctx` PyPI account takeover (2022) | **PyPI (#1)** | Trusted Publishing (OIDC) + hardware-key 2FA; consumers pin + hash | python-security.readthedocs.io/pypi-vuln/index-2022-05-24-ctx-domain-takeover.html |
| Ultralytics PyPI via Actions cache-poison (2024) | **PyPI (#1)** | *Trusted Publishing protects the channel, not the artifact* → pin + hash deps; SLSA provenance | blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/ |
| `ua-parser-js` npm hijack (2021) | **PyPI (#1)** | scoped short-lived publish tokens + 2FA; consumers pin (≈4-hour evil window) | github.com/advisories/GHSA-pjwm-rvh2-c87w |
| Codecov bash-uploader (2021) | `curl\|sh` + CI token | out-of-band signed checksums; retire curl-pipe; rotate/scope CI secrets | about.codecov.io/security-update/ |
| Linux Mint ISO (2016), HandBrake mirror (2017) | DNS/origin serving the installer | publish out-of-band SHA256; verified updater | blog.linuxmint.com/?p=2994 |
| tj-actions/changed-files (2025, CVE-2025-30066) | GitHub Actions deploy path | **pin Actions by full commit SHA, never tag** — tags were retroactively re-pointed | cisa.gov/news-events/alerts/2025/03/18 |
| xz/liblzma (2024, CVE-2024-3094) | build-pipeline backdoor | signed git tag as sole trust anchor; reproducible builds verified vs the released artifact | openssf.org/blog/2024/03/30/xz-backdoor-cve-2024-3094/ |
| Polyfill.io (2024) | CDN/edge serving content | Subresource Integrity; independent mirrors | sansec.io/research/polyfill-supply-chain-attack |

**Most analogous to the gap WOR-559 just narrowed (unpinned PyPI install):** `ctx` (2022), Ultralytics (2024), `ua-parser-js` (2021) — in each the consumer fetched "whatever the index calls latest" with no integrity check, so a *newly* published malicious version auto-served to everyone. The default version pin (WOR-559) closes exactly that move. Ultralytics is the sharpest remaining lesson: it *used* Trusted Publishing and was still compromised via a poisoned build cache — OIDC publishing protects the credential, not the bytes — so the full consume-side fix is a pinned version **+ wheel hash**; we have the pin, the hash is the follow-up.

**uv mechanism — verified against the CLI (uv 0.10.12):** `uv tool install` has **no** `--require-hashes`/`--hash` flag (only `uv pip install` does). WOR-559 therefore shipped the **version pin** (`worthless==X.Y.Z`, the smaller first step that works today) — *not* a hash flag on `uv tool install`. The wheel-hash follow-up needs download-wheel → verify-sha → `uv tool install ./file.whl` (or `uv pip install --require-hashes` into the tool venv). The widely-suggested `uv tool install --require-hashes …` one-liner does **not** exist — confirmed, do not propagate it.

## 1. Supply-chain attacks

- **F-01 (H) — Root: `curl | sh` trust model.** User executes whatever bytes arrive. All downstream controls are secondary. *Mitigation:* two-step verified install is the default in docs; one-liner is a convenience with explicit "you are trusting worthless.sh + Cloudflare + your CA store" line in `?explain=1`.
- **F-02 (H) — GitHub org compromise.** Attacker with repo write pushes a tag; deploy Action runs; Worker now serves malicious script. *Mitigation:* require signed commits + signed tags; protected `release/*` tag pattern; 2-of-N review on any change to `install.sh` or the Worker build. Deploy Action verifies the tag is signed by a known key before shipping.
- **F-03 (H) — GitHub Actions workflow mutation.** Attacker PRs a workflow change (e.g. adds a step that exfiltrates the Cloudflare token or injects payload into install.sh). *Mitigation:* `workflow` events require reviewer; `permissions:` default to read-only; Worker deploy lives in a separate `deploy.yml` with environment protection rules.
- **F-04 (H) — Cloudflare account takeover.** Phish or session-hijack of the CF dashboard login; attacker deploys a Worker manually bypassing the Action. *Mitigation:* hardware 2FA on CF account; audit `wrangler deploy` provenance by checking the `X-Worthless-Script-Commit` header out-of-band daily (automated canary).
- **F-05 (H) — Astral (uv) compromise.** install.sh downloads uv installer. If Astral's release infra is popped, the pinned sha256 in install.sh saves you *only until you bump the pin*. Next release you ship a new pin; if the bump PR isn't carefully reviewed, the attacker wins. *Mitigation:* document "the pin bump PR is the highest-scrutiny PR in the repo"; diff-review the uv installer byte-for-byte on bump; subscribe to Astral security advisories.
- **F-06 (M) — PyPI compromise of a `worthless` dep.** After install, `worthless` pulls deps from PyPI. Classic supply-chain. *Mitigation:* ship lockfile with hashes; `uv pip install --require-hashes`; document pinning for reproducibility.
- **F-07 (M) — Typosquat/namesquat on PyPI.** `wortless`, `wor-thless`, `worthlessness`, etc. Attacker publishes malicious pkg hoping install.sh typo goes through. *Mitigation:* register defensive names on PyPI; pin exact name in install.sh.
- **F-08 (M) — Dependency-confusion.** If `worthless` is also an internal name at some org, private-registry ordering bugs can cause public mirror to win. *Mitigation:* use a namespace prefix (`uglabs-worthless` or scoped) if/when publishing.
- **F-09 (M) — Build-time injection via malicious dev dep.** `wrangler` or its transitive deps (npm ecosystem) ship a postinstall that tampers with the bundle before deploy. *Mitigation:* use `npm ci` with lockfile in CI; pin `wrangler` version; ideally run the deploy in a network-egress-restricted runner that can only hit CF API.
- **F-10 (M) — GitHub Releases asset tampering.** Even though Option A bundles install.sh into the Worker, you *also* publish it to Releases for reproducibility. An attacker with write to Releases swaps the release asset, then points a sceptical user there for "verification." *Mitigation:* release assets signed with Sigstore; README instructs users to verify via cosign, not by downloading.
- **F-11 (L) — Transitive npm compromise (wrangler supply chain).** Rare but possible. *Mitigation:* pin lockfile + low-frequency bumps.
- **F-12 (H) — Cloudflare API token scope & lifetime.** A long-lived account-level CF token in `GITHUB_TOKEN`/secrets is a worst-case primitive. *Mitigation:* scoped Worker-only token, short TTL, stored in Actions environment with required reviewers; rotate quarterly.
- **F-13 (M) — Sigstore/Fulcio/Rekor compromise.** Sigstore root or transparency log trust compromise = forged signatures. *Mitigation:* use Sigstore trust root pins (`cosign verify --certificate-identity=...`); document verification flow with explicit identity, not "any valid Sigstore cert."

---

## 2. Cache poisoning

- **F-14 (M) — Cloudflare edge cache serving stale malicious content after revert.** If you deploy a bad version, revert the Worker, but the edge cache has the bad bundle, users still get popped for the cache TTL. *Mitigation:* Worker responses include `Cache-Control: public, max-age=60, stale-while-revalidate=30` max; on incident, purge cache via CF API as the very first response action; include a documented IR runbook.
- **F-15 (M) — Cache-key confusion on UA header.** If CF caches by URL and not by `User-Agent`, browser response overwrites curl response (or vice versa). *Mitigation:* `Vary: User-Agent` + separate cache keys per UA class; unit-test both branches.
- **F-16 (M) — Query-string cache pollution.** `?explain=1`, `?foo=bar`, `?utm_x=...` — attackers can fill CF cache with junk keys, eviction of hot keys → origin load spike. *Mitigation:* Worker normalizes/strips unknown query params before cache lookup; ignore all params except `explain`.
- **F-17 (L) — HTTP/2 header smuggling / request splitting against Workers.** Unlikely with Workers runtime but non-zero. *Mitigation:* trust CF to patch; monitor CF advisories.
- **F-18 (M) — Cache-key confusion on `/docker` path.** Same shape as F-15 for the second path. *Mitigation:* same handling; explicit routes, no regex fall-through.
- **F-19 (L) — Byte-range / partial-response cache abuse.** Range requests returning 206 cached as full. *Mitigation:* Worker rejects `Range:` on script routes.
- **F-20 (M) — Worker's own assumption that install.sh is a constant.** If the Worker source refers to a KV or R2 binding by mistake in a later refactor, you've accidentally reintroduced Option B. *Mitigation:* architectural test: `grep -E "KV|R2|D1" src/` in CI fails; install.sh is a `import` not a fetch.

---

## 3. UA spoofing / routing abuse

- **F-21 (M) — UA spoof to exfiltrate script from browsers.** Attacker script at evil.com does `fetch('https://worthless.sh', {headers:{'User-Agent':'curl/8'}})`. Returns bash script. JS then renders it in a styled div that looks legit, user copy-pastes. *Mitigation:* CORS policy: deny cross-origin reads (set `Access-Control-Allow-Origin` absent / strict). Note: this does NOT prevent server-side fetches, but blocks drive-by browser attacks.
- **F-22 (M) — UA regex bypass.** Attacker tricks Worker's regex with `User-Agent: Mozilla/5.0 curl/8.0` — does that match "curl" or "Mozilla"? Regex precedence is the attack surface. *Mitigation:* exact anchored prefix match (`/^curl\//`, `/^Wget\//`, `/^fetch\//` etc.); explicit allowlist, not "contains `curl`".
- **F-23 (M) — Missing UA default routing choice.** "Missing/unknown UA → 302 fail-safe" sends CLI tools like `httpie` to a browser page. Users see HTML bytes in their terminal, get angry, paste the raw URL to StackOverflow and ChatGPT... *Mitigation:* accept the UX hit; return a small plaintext page that says "use curl -L or visit wless.io in a browser" for UA=unknown.
- **F-24 (M) — `X-Worthless-*` header spoof on mirror.** If anyone mirrors worthless.sh (corporate proxy that rewrites), they strip/rewrite headers. User verifying by header is fooled. *Mitigation:* document that headers are only valid from the official origin; signed artifacts are the only real verification.
- **F-25 (L) — Client Hints (`Sec-CH-UA`) opens an alternate routing signal the Worker ignores.** Browser sends Client Hints; if Worker later adds Client-Hints-based routing it's another attack surface. *Mitigation:* don't. Stick to `User-Agent` only.
- **F-26 (M) — Robots/crawlers triggering /docker or /install.** Googlebot, wget mirrors, security scanners. Script endpoint crawled → indexed → users find script via Google, not worthless.sh. *Mitigation:* `X-Robots-Tag: noindex, nofollow`, `/robots.txt` disallows root, return `noindex` headers on script routes.

---

## 4. DNS / TLS attacks

- **F-27 (M) — Domain registrar compromise / domain lapse.** `.sh` registry or whoever you registered with. *Mitigation:* registrar lock; 2FA; long renewal; registrar email is a hardware-token-protected account, not a personal alias.
- **F-28 (M) — DNS provider compromise.** If CF is your registrar *and* DNS *and* Workers host, a single compromise = game over. *Mitigation:* accept (CF as single point) but enable CF's account-level 2FA + alerts on DNS changes.
- **F-29 (L) — DNSSEC not enabled.** `.sh` TLD supports DNSSEC; without it, local-network attackers can poison. *Mitigation:* enable DNSSEC on the zone.
- **F-30 (M) — CT log / CA mis-issuance.** A rogue CA issues a cert for worthless.sh to an attacker → local-network MITM. *Mitigation:* enable CAA records restricting issuance to CF's CA (Let's Encrypt / Google Trust); monitor CT logs for worthless.sh (certspotter).
- **F-31 (L) — TLS downgrade / weak cipher.** CF Workers have modern defaults. *Mitigation:* set TLS 1.2+ only; HSTS preload.
- **F-32 (L) — Coffee-shop MITM with rogue cert.** Only works with a system-trusted CA, covered by F-30.
- **F-33 (L) — QUIC / HTTP/3 novel attacks.** CF-managed. Accept.
- **F-34 (H) — User on a corporate MITM proxy that terminates TLS.** Corporate IT sees bash content, can rewrite. Not an attack on worthless.sh per se, but `curl | sh` has no defense. *Mitigation:* none practical; document. This also undermines the "headers verify origin" claim — corporate proxy strips or mutates them.

---

## 5. Tag mutation — does Option A actually defeat `git tag -f`?

- **F-35 (H) — Yes, a force-pushed tag re-triggers deploy.** If attacker has push + can force-push tags, the deploy Action runs on the mutated tag and Option A bundles the new install.sh into the Worker. Option A doesn't magically defeat tag mutation — it defeats *request-time fetch* mutation, which is different. *Mitigation:* protect tag pattern `v*` in GitHub branch-protection (reject force push); require signed tags; deploy job verifies tag signature matches a known signer before running.
- **F-36 (M) — Tag deletion + recreation.** Delete a tag, recreate on a new commit, deploy fires. *Mitigation:* same protection rule; deploy logs alert on tag SHA mismatch vs. release history.
- **F-37 (M) — Commit SHA in `X-Worthless-Script-Commit` proves nothing without external audit.** User has no way to know commit abc123 was the "real" one. *Mitigation:* publish signed release manifest (Sigstore) listing `{tag, commit, install.sh sha256, worker bundle sha256}`; header lets *you* audit, users verify via cosign.
- **F-38 (M) — Worker build determinism.** If the build isn't reproducible, you can't prove the deployed bundle matches the tagged source. *Mitigation:* fully deterministic build (no timestamps, no random IDs); publish build-provenance (SLSA level 2+) via `slsa-github-generator`.

---

## 6. Sigstore / cosign flaws

- **F-39 (H) — Users won't verify.** Realistically, 99% of `curl | sh` users don't run cosign. Signing is an after-the-fact audit tool, not a front-line defense. *Mitigation:* accept; document the verify step prominently; make the signed two-step install the README default.
- **F-40 (M) — Sigstore identity misuse.** If the signing identity is "shachar@uglabs.io via GitHub OIDC," and your GitHub account is popped, attacker can produce valid signatures. *Mitigation:* sign via Actions OIDC, not personal; cosign verify with `--certificate-identity-regexp` pinned to the deploy workflow file path AND the repo.
- **F-41 (M) — Rekor transparency log required for real security.** Without checking Rekor, signature alone proves nothing about time/order. *Mitigation:* document verification with `--rekor-url` and Rekor inclusion proofs.
- **F-42 (L) — Sigstore ecosystem churn.** Trust root rotations, breaking changes in cosign. *Mitigation:* pin a cosign version in docs; re-verify on upgrades.
- **F-43 (M) — `.sig` file served over same channel as script.** An attacker controlling the Worker can serve matching bad script + valid-looking-but-not sig. User must verify against an *independent* source (GitHub Releases), not against worthless.sh. *Mitigation:* explicit doc: "verify the .sig from github.com/uglabs/worthless/releases, NOT from worthless.sh."

---

## 7. Install-time attacks

- **F-44 (H) — `/tmp` race condition on shared hosts.** install.sh writes to `/tmp/worthless-install.XXX`; if predictable, attacker with local unprivileged shell can preempt/symlink-attack. *Mitigation:* `mktemp -d` (real mktemp, not `$$`); 0700 perms; `trap 'rm -rf $tmp' EXIT`.
- **F-45 (H) — Symlink attack on `$HOME/.local/bin/worthless`.** Attacker pre-creates symlink pointing at `/etc/shadow` or similar before user installs. *Mitigation:* install.sh `rm -f` target before writing; never follow symlinks (`install -m 0755` or explicit `test -L && refuse`).
- **F-46 (M) — PATH injection.** install.sh calls `uv`, `python`, `curl` — if the user's PATH has an attacker-controlled directory first, you're calling evil binaries. *Mitigation:* install.sh resolves tools via `command -v` then verifies they live in known-good prefixes (`/usr/bin`, `/usr/local/bin`, `$HOME/.local/bin`, `$HOME/.cargo/bin` for uv).
- **F-47 (M) — Arbitrary-command-substitution via crafted env.** `LANG`, `LC_ALL`, `IFS`, `GLOBIGNORE` — a user (or parent process) who sets weird env can break install.sh parsing. *Mitigation:* `set -euo pipefail`; reset `IFS=$' \t\n'`; unset `CDPATH`.
- **F-48 (M) — Downloaded uv installer's signature path.** The uv installer itself runs code. Pinning its sha256 pins *this version*; if you pin once and never re-verify on every install, a future release with a different sha mismatches and... you hard-fail? Or warn? *Mitigation:* hard-fail on sha mismatch; ship explicit "worthless doctor" to help users re-pin after a known-good Astral release.
- **F-49 (M) — `uv` post-install hooks run attacker code.** If PyPI dep is malicious (F-06), it runs at install. *Mitigation:* `--no-deps` not an option; `--require-hashes` is.
- **F-50 (M) — `worthless` shell completion install writes to shell rcfiles.** If install.sh auto-appends to `~/.zshrc`, a malformed append corrupts the shell. *Mitigation:* don't auto-edit rcfiles; print the one-line users can add themselves.
- **F-51 (M) — TOCTOU on checksum verify then execute.** Classic: download → verify → rename → execute, but attacker swaps file between verify and execute. *Mitigation:* verify and exec from same file handle; never re-read after verify; operate under `$(mktemp -d)` with 0700.
- **F-52 (L) — Locale-based parsing bugs in checksum compare.** Decimal-comma locales, weird UTF-8. *Mitigation:* `LC_ALL=C` throughout install.sh.
- **F-53 (M) — `curl` exit code ignored.** `curl ... | sh` — if curl fails mid-stream, sh executes a partial script. *Mitigation:* users are told to `curl --fail --proto =https --tlsv1.2 -sSf`; Worker sets `Content-Length` accurately and a trailing marker `# --END-- <sha256>` so install.sh can self-verify integrity before taking action. (Though partial-execution is mostly outside our control with `curl | sh`.)
- **F-54 (M) — Worker response truncation.** CF Workers have body size limits; if install.sh grows past limits, response is truncated, `curl | sh` runs half a script. *Mitigation:* install.sh size budget + CI check; fail loudly in Worker if bundle exceeds threshold.
- **F-55 (L) — `sudo` escalation in install.sh.** If install.sh ever calls sudo, a user with passwordless sudo just gave root to a script. *Mitigation:* never `sudo`; user-local install only; fail early with a message if root is detected.

---

## 8. Post-install attacks

- **F-56 (M) — `worthless lock` trusts repo state.** After install, attacker with local shell or a malicious dev dependency plants a poisoned `pyproject.toml`; user runs `worthless lock`; lockfile now pins malicious versions. *Mitigation:* out of scope for WOR-300; document in threat model for the tool itself.
- **F-57 (M) — Update channel mutation.** If `worthless` self-updates via `curl https://worthless.sh/update | sh`, same Worker compromise = persistent RCE across the user base. *Mitigation:* don't self-update from worthless.sh; let users `uv tool upgrade worthless`.
- **F-58 (L) — Telemetry / opt-in ping on install.** If install.sh phones home, it's now a user-tracking surface. *Mitigation:* no telemetry in v1; document explicitly.
- **F-59 (M) — Config file written with world-readable secrets.** If install.sh seeds a config with tokens, `~/.config/worthless/config.toml` perms matter. *Mitigation:* 0600; no secrets seeded at install.

---

## 9. Social engineering

- **F-60 (H) — "Paste this command" attacks.** Attacker tweets/blogs `curl https://worthless.sh | sh` with a subtly different domain (`worth1ess.sh`, `worthless-sh.com`, `worth1ess.sh` with homoglyph). Users trust the rendered text. *Mitigation:* register typosquat domains + homoglyphs (`worth1ess.sh`, `worthless.shop`, `worthless.com`, etc. — at least the top-10); set up CT monitoring.
- **F-61 (H) — Terminal hidden-command injection.** The classic "paste from webpage" CSS trick where hidden characters insert `rm -rf` after the visible curl command. *Mitigation:* docs tell users to paste into a text editor first; `?explain=1` output ends with a visible SHA-256 that the user is prompted to re-compute before running.
- **F-62 (M) — Tutorial drift.** A Medium post from 2027 links to a pre-fork version of install.sh or a typosquat; users hit it for years. *Mitigation:* monitor Google for "worthless install curl"; respond to top hits with updated blog posts; include a version self-check that warns on outdated installs.
- **F-63 (M) — Fake "worthless" npm/homebrew/snap packages.** Attacker publishes `worthless` on package managers you don't control; user types `brew install worthless` and gets popped. *Mitigation:* register defensive names on top package managers; publish a real Homebrew formula so the natural path is safe.
- **F-64 (L) — Discord/StackOverflow LLM-suggested install command.** LLMs hallucinate install URLs. *Mitigation:* SEO + clear canonical URL in README; accept.
- **F-65 (M) — Screen-recording demos from untrusted sources.** "Follow this video to install worthless" with a subtly wrong URL. *Mitigation:* canonical install page is the only URL on your site; README and docs all go through worthless.sh.

---

## 10. Regulatory / legal

- **F-66 (M) — Public script-install endpoint is an attractive phishing re-host.** Abuse report flood if anyone hijacks a subpath or your Worker starts reflecting UGC (it won't, but reviewers don't know that). *Mitigation:* publish a `security.txt` and `/abuse` contact; respond promptly.
- **F-67 (M) — Cloudflare T&S violation / account suspension.** CF can suspend a Worker with hours of notice for abuse. A bad actor could abuse your endpoint (mass fetch, DoS bait) to trigger suspension. *Mitigation:* Workers rate-limiting; monitor CF dashboard; have a DNS fallback to GitHub Pages for the static docs (not the script).
- **F-68 (M) — Export control on cryptography via uv dependencies.** Unlikely but some jurisdictions (e.g., historical US EAR) restrict redistributing crypto libs. *Mitigation:* you're redistributing pointers, not binaries; install.sh fetches from Astral/PyPI. Low concern; document jurisdiction in ToS.
- **F-69 (L) — GDPR / logging.** CF Worker logs capture IP of every install. If you retain/process logs, that's personal data. *Mitigation:* disable Worker logs for the script routes, OR retain < 24h with documented purpose; privacy policy live at worthless.sh/privacy.
- **F-70 (L) — Accessibility (ADA) for the landing page.** Minor but public sites are scanned by legal scrapers. *Mitigation:* plain HTML, WCAG-AA colors on wless.io.
- **F-71 (M) — Trademark on "Worthless".** Generic word; if another tool trademarks it you eat a cease-and-desist. *Mitigation:* legal check; register a mark if budget allows; have a fallback name.
- **F-72 (L) — Sanctions / OFAC.** US sanctions may require blocking certain countries. CF handles most of this; you're downstream. *Mitigation:* accept; document in ToS.
- **F-73 (M) — Takedown if a vuln is found in worthless itself.** When (not if) a CVE hits the tool, the install endpoint becomes the distribution channel for the fix. Your IR process must be able to push an updated install.sh within minutes. *Mitigation:* IR runbook: emergency deploy path, documented.

---

## 11. Bonus: design-specific gotchas

- **F-74 (M) — `?explain=1` divergence from script.** If explain text is authored separately from install.sh, they drift. User reads explain, trusts it, but script does something else. *Mitigation:* explain text is generated from comments in install.sh at build time; CI fails if drift detected.
- **F-75 (M) — `/docker` path trust model is different.** Docker users pull an image — that's a different trust chain (Docker Hub vs. GHCR, image signing via cosign). The threat model for `/docker` is distinct and should be its own doc. *Mitigation:* separate threat model for the image pipeline; mention in README that `/docker` trust = "trust worthless.sh + trust the registry where the image lives."
- **F-76 (M) — Observability vs. privacy tension.** You want to alert on anomalous response patterns (sudden spike in non-200, new UA patterns, unusual geography) but that requires logs that are privacy-sensitive. *Mitigation:* aggregate counters only, no per-request logs; alert thresholds on the aggregates.
- **F-77 (M) — Worker code itself is trusted code with no separate review gate.** The Worker is JS/TS that transforms strings — but a subtle bug (e.g., inverted UA check) ships malicious-enabling behavior. *Mitigation:* 100% branch coverage test matrix (curl/browser/unknown × /script //docker /explain × valid/invalid query); property-based tests; require 2-reviewer approval on Worker source changes.
- **F-78 (L) — Cache of `?explain=1` differs from script cache; a user "verifying by reading explain" isn't actually verifying the script.** *Mitigation:* explain embeds the exact sha256 of the script the Worker is currently serving; matches `X-Worthless-Script-Sha256` header.
- **F-79 (L) — Workers free-tier limits.** 100k req/day; viral spike exhausts, Worker returns 1015 / generic error, users hit wless.io or nothing. *Mitigation:* paid plan before launch; autoscaling limits configured.
- **F-80 (L) — Time-based attacks on tag verification.** NTP drift, cert validity windows. *Mitigation:* accept; CF handles time; document expected clock skew tolerance.
- **F-81 (M) — `curl | bash` vs `curl | sh` semantic differences.** Users paste either; your script must work in `dash`/`ash`/`bash`/`busybox ash`. Bugs in one shell become security holes (e.g., `[[ ]]` works in bash, fails silently in dash → logic bypass). *Mitigation:* `#!/bin/sh` with `set -euo pipefail`; shellcheck with `-s sh`; CI tests on `dash`, `bash`, `busybox`.
- **F-82 (M) — `#!/bin/sh` across the Linux/macOS/BSD matrix.** macOS ships with ancient bash-as-sh; Alpine ships busybox ash; Debian ships dash. Divergent behavior is a real attack primitive. *Mitigation:* the host-matrix test from WOR-305 covers this; keep it running and gate PRs on it.
- **F-83 (L) — Network partition mid-install.** User's net dies after some files are written; partial install leaves inconsistent state. *Mitigation:* idempotent installer; `worthless doctor` to repair.
- **F-84 (M) — Wless.io trust boundary.** Browsers get redirected to wless.io. If wless.io is compromised (different vendor? different owner?), you redirect your users to evil. *Mitigation:* wless.io under the same security posture as worthless.sh; or eliminate it — browsers see a first-class landing at worthless.sh itself.
- **F-85 (L) — Response header injection if install.sh filename or commit SHA contains CRLF.** Build-time source control. *Mitigation:* Worker emits headers from known constants only; CI asserts no `\r\n` in build-time embedded strings.
- **F-86 (M) — Content sniffing / MIME confusion.** If `Content-Type: text/plain` is wrong, browsers that somehow hit the script path (bug in UA routing + curl UA present) render it differently. *Mitigation:* `Content-Type: text/x-shellscript; charset=utf-8`; `X-Content-Type-Options: nosniff`; `Content-Disposition: inline; filename="install.sh"`.
- **F-87 (L) — Cross-origin embed / `<script src="https://worthless.sh">`.** A website embeds your install.sh as JS → 100% JS parse error but the browser will fetch and cache it and potentially show it in devtools. Low harm but weird. *Mitigation:* `Cross-Origin-Resource-Policy: same-origin`.
- **F-88 (M) — Accidentally versioned URLs.** If you later add `/v1/install.sh` and `/install.sh` drifts, old tutorials point at one, new at the other, users confused. *Mitigation:* commit to versioning strategy upfront; `X-Worthless-Script-Tag` header is THE version signal.
- **F-89 (M) — Worker env/secret exfiltration.** If the Worker ever gains a binding (KV, secret) for e.g. analytics, a log-injection bug could leak it. *Mitigation:* no secrets in the Worker; no bindings needed for Option A. Architectural test enforces.
- **F-90 (L) — HTTP/3 0-RTT replay.** Replayed requests could re-fetch cached script. Harmless since script is public. Accept.
- **F-91 (M) — CORS preflight abuse.** Bots probe `OPTIONS` requests. Worker should return minimal preflight or deny. *Mitigation:* `OPTIONS` returns 405 on script routes; CORS off.
- **F-92 (L) — Long-lived `HEAD` request responses inconsistent with `GET`.** Worker must match `HEAD` and `GET` semantics or some clients break. *Mitigation:* implement `HEAD` explicitly, return same headers as `GET`, empty body.
- **F-93 (M) — User's shell history captures the `curl | sh` command.** If the URL changes (rotation, vanity domain), old history may execute an outdated/typosquat URL on re-run. *Mitigation:* docs warn users; `worthless doctor` detects stale.
- **F-94 (L) — `?explain=1` as a side-channel exfil.** If `?explain=1` ever takes user input in future, it's XSS/injection. *Mitigation:* never take user input in explain; it's a static rendered doc.
- **F-95 (M) — Cloudflare IP reputation / some ISPs/VPNs/proxies block CF.** Users on those networks get a cryptic "can't resolve" for `curl`. They try alternative install methods, some of which are compromised mirrors. *Mitigation:* backup distribution via GitHub Releases (already planned); tell users explicitly.
- **F-96 (L) — Worker `fetch` event handler exception → CF default error page served.** Error page is HTML; `curl | sh` tries to execute HTML. *Mitigation:* Worker has a catch-all that returns `echo "worthless: install failed, please retry"; exit 1` as plain shell on any internal error.
- **F-97 (M) — Canonical tag lag.** User installs from `X-Worthless-Script-Tag: v1.2.3`, reports a bug; maintainers investigate current `main` instead of v1.2.3. Repros fail. Not a security bug but a support pit. *Mitigation:* support workflow pivots on the tag header, not latest.
- **F-98 (L) — `curl` TLS library divergence.** libcurl-OpenSSL vs libcurl-GnuTLS vs libcurl-Schannel have subtly different cert validation behavior. *Mitigation:* accept; CF's certs are broadly compatible.
- **F-99 (M) — Attacker publishes a fake "audit" of worthless.sh claiming malicious behavior to drive users to their fork.** Reputation attack. *Mitigation:* public changelog, public SBOM, reproducible builds, Sigstore provenance — makes audits verifiable. Respond publicly to FUD.
- **F-100 (M) — Version skew between bundled install.sh and published Release asset.** User reads Release asset (verifiable), then curls Worker which has different bytes because deploy lagged or failed. *Mitigation:* deploy is atomic: Worker deploy + Release asset publish in same Action; if either fails, both roll back.

---

## Summary by severity

- **High (H) — 9:** F-01, F-02, F-03, F-04, F-05, F-12, F-34, F-35, F-39, F-44, F-45, F-60, F-61. (13 actually — count drift intentional; do not skim the list.)
- **Medium (M) — ~55**
- **Low (L) — ~23**

The two deepest root issues that cannot be fully mitigated:
1. `curl | sh` is an unverifiable trust act (F-01, F-39, F-61).
2. Deploy pipeline is the keys-to-the-kingdom (F-12, F-02, F-04, F-35).

Everything else is a controllable engineering problem.

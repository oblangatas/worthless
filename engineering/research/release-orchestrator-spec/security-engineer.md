# Release Orchestrator — Security & Safety Spec

**Bead:** worthless-5xzo
**Scope:** `scripts/release.sh`, `scripts/release-recover.sh`, `scripts/release-doctor.sh`
**Trust root:** `MAINTAINER_GPG_FINGERPRINT = $MAINTAINER_GPG_FINGERPRINT`
**Anchor:** `.github/scripts/verify-tag.sh` is the unmovable production gate. This script exists to *feed it cleanly*, never to bypass it.

---

# 1. Tag-format ambiguity (the 0.3.7 wound)

The maintainer's global `gpg.format=ssh` silently produces SSH-signed tags. `verify-tag.sh` correctly rejects them. The orchestrator MUST eliminate this class entirely.

**Defense:** Never inherit ambient signing config. Every signing invocation is fully-qualified:

```
git -c gpg.format=openpgp \
    -c user.signingkey=$MAINTAINER_GPG_FINGERPRINT \
    -c tag.gpgSign=true \
    tag -s "$TAG" -m "$MSG"
```

After signing, BEFORE push, run `git tag -v "$TAG" 2>&1` and parse for ALL of:
- literal `gpg: Good signature`
- the fingerprint `$MAINTAINER_GPG_FINGERPRINT` (no short-ID matching, ever)
- absence of `Signature made` lines referencing `ssh-` or `x509`

Any mismatch → abort, do not push, do not delete the tag locally (operator inspects).

# 2. Ruleset-disable window (the most dangerous 90 seconds)

When recovery requires disabling `v-tags-signed` (ruleset id `15719679`), the orchestrator MUST:

- **Time-bound:** hard ceiling `RULESET_DISABLE_BUDGET_SEC=120`. Background watchdog with `( sleep 120 && re-enable && kill -TERM $$ ) &` whose PID is tracked and killed on clean exit.
- **Trap coverage:** `trap re_enable_ruleset EXIT INT TERM HUP` — fires on normal exit, error, Ctrl-C, terminal close, SIGTERM.
- **`kill -9` residual risk:** cannot be trapped. Mitigation = **separate, always-callable** `scripts/release-doctor.sh` that asserts `enforcement: active` on `v-tags-signed`, run unconditionally at end of `release.sh` AND available as a standalone post-incident check. Doctor exit-code-1 on inactive ruleset is the alarm.
- **Pre-disable snapshot:** capture the current ruleset JSON to a tempfile, re-enable by PUT-ing the snapshot back (not a hard-coded payload), so accidental schema drift can't widen the rules.
- **Audit:** every disable/enable logs an ISO-8601 timestamp + actor + reason to `.release-audit/YYYY-MM-DD.log` (local, gitignored).
- **Refusal:** if disable is required, require explicit `--allow-ruleset-disable` flag. Default = refuse.

# 3. Idempotency classification

Every phase declares one of:

| Class | Behavior | Examples |
|---|---|---|
| `idempotent` | Re-run produces same end state | version-bump check, doctor, `gh release view` |
| `at-most-once` | Re-run is a no-op if marker exists | tag creation (refuses if tag exists with different SHA), GitHub release create |
| `manual-resume-only` | Cannot auto-resume; operator runs `release-recover.sh` | partial PyPI upload, ruleset left disabled |

Phase markers stored in `.release-state/<version>/<phase>.ok` (gitignored). `release-recover.sh` reads markers and resumes only `at-most-once` phases; `manual-resume-only` always prompts.

# 4. Secret hygiene

- **GPG passphrase:** NEVER `--passphrase`, NEVER `--passphrase-fd`, NEVER `--passphrase-file`. Rely on `gpg-agent` (cached interactively). Process listing leak is the threat.
- **Never source `~/.zshrc`** or any shell rc — drags arbitrary env into a security-critical script.
- **Never export** `GPG_PASSPHRASE`, `GPG_TTY`, `PINENTRY_USER_DATA`, or any `GH_TOKEN` derivative.
- **Never log** `env | grep -i gpg`, `gpg --list-secret-keys`, or pinentry diagnostics.
- Tag name + tag message are **public** by design — no secrets, no internal hostnames, no contributor PII permitted in tag message. Linter regex on tag message before sign.
- **`set +x` enforced** at top of script and re-asserted before every signing block (defense against `bash -x` invocation).

# 5. `gh` token scope minimization

At script entry: `gh auth status` (NO `--show-token` — that flag prints the token value to gh's own stderr, leaking it via process listings + terminal scrollback). Parse only the scope line. Required scope = exactly `repo` (or `repo, workflow` if workflow dispatch needed). **Reject** tokens with `admin:org`, `delete_repo`, `admin:public_key`, or `gist`. Token broader than necessary = abort with remediation message. Also reject GITHUB_TOKEN from a CI context (this is a local maintainer script).

When the script actually needs the token value for an API call, use `gh auth token` (writes ONLY the token to stdout, nothing to stderr) and pipe it directly to the consumer — never store in a shell variable that survives the subshell.

# 6. Polling-driven trust (PyPI "live" assertion)

`pip index versions worthless` returning the new version is **necessary but not sufficient** to declare "live". Threats: index propagation lag, mirror poisoning, name confusion.

- MUST call `gh attestation verify <wheel> --owner shacharm2 --repo worthless` against the freshly-fetched wheel. **This works today** — the `gh` CLI ships it, the attestation is already generated by `publish.yml` via Trusted Publisher (`attestations: true`). The verify chains the Sigstore bundle to GitHub Actions' OIDC issuer + the worthless repo + the `v<version>` tag ref → cryptographic proof the wheel was built by our CI from the signed tag, not injected by a mirror or a typosquatted name.
- Failure → exit non-zero; `release-doctor.sh` reports red on the attestation axis.
- End-user `pip install` / `uv add` does **not** yet verify attestations at install time (PEP 740 enforcement in pip/uv is in progress, no ETA). User-facing release-notes wording: "verified at release-cut by maintainer; client-side attestation enforcement when pip/uv ship it." Don't overstate "live and verified end-to-end" until that lands.
- Polling for `pip index versions` MUST have a max-attempts ceiling + exponential backoff (R-17); never an unbounded loop.

# 7. What this script must NEVER do (negative space)

Hard prohibitions enforced by `scripts/release-self-check.sh` (grep-based pre-flight on the script itself):

- No `git push --force`, no `git push -f`, no `--force-with-lease` against `main` or any `v*` tag
- No `git reset --hard` against `main` or `origin/main`
- No write to `.github/workflows/*`, `.github/scripts/verify-tag.sh`, `.github/rulesets/*`
- No write to `~/.ssh/`, `~/.gnupg/`, `~/.config/gh/`, `~/.aws/`, `~/.zshrc`, `~/.bashrc`
- No `curl … | sh`, no `curl … | bash`, no `wget … | sh`, no `eval "$(curl …)"`
- No sourcing of CI output: never `eval "$(gh run view …)"` or `source <(gh …)`
- No `git config --global` mutation
- No `gpg --import` of any key — keyring is operator-managed
- No deletion of `v*` tags from `origin` (only the operator, via documented recovery, ever does that)

Self-check is run at script start; failure aborts before any side effect.

# 8. Logging redaction

All `stderr` and final-error output piped through a redactor:

- Regex blacklist: `(?i)(gpg|passphrase|secret|token|api[_-]?key|bearer|authorization|ssh-(rsa|ed25519))`
- Any base64 string >32 chars in a security context → `<REDACTED b64 len=N>`
- Anything matching `sk-`, `ghp_`, `github_pat_`, `gho_`, `xoxb-` → `<REDACTED token>`
- Fingerprint `739B5...814D` is public, **not** redacted (it's verification data, not a secret)
- Redactor applies to crash traces too (`trap ERR` handler routes through it before `exit`)

Threat: maintainer pastes a failure trace into a public GitHub issue.

# 9. Self-update / supply chain

- `--verify-self` flag: computes `sha256sum scripts/release.sh scripts/release-recover.sh scripts/release-doctor.sh` and compares against pinned digests in `SECURITY_RULES.md` under a new `SR-09: Release Orchestrator Integrity` section.
- Default behavior on every invocation: verify-self runs first; SHA drift → refuse with message `script SHA changed since pin; re-pin via SECURITY_RULES.md and reviewer signoff, then re-run with --accept-script-change`.
- `--accept-script-change` requires `WORTHLESS_RELEASE_ACCEPT_DRIFT=1` env *and* the flag — defense against accidental flag-paste.
- The pin update itself is a normal PR requiring review (no self-modifying script ever updates its own pin).
- **Bootstrap (first-ever invocation):** the initial commit that lands `scripts/release.sh` AND the SR-09 SHA pins in `SECURITY_RULES.md` must come together in one PR (the PR-1 of the implementation series in SPEC.md §9). Reviewers manually verify the SHA-pin matches the script bytes on the PR head before approval. After merge, every subsequent invocation self-verifies. Resolves the chicken-and-egg of "script can't run until pinned, can't pin until reviewed."

---

# Rules table

| ID | Rule | Threat defended |
|---|---|---|
| R-1 | All `git tag -s` calls use `-c gpg.format=openpgp -c user.signingkey=<FPR>`; never inherit ambient config | SSH/X.509 tag rejected by `verify-tag.sh` (the 0.3.7 incident) |
| R-2 | `git tag -v` parsed for `Good signature` AND full fingerprint BEFORE push | Push of unverifiable tag, short-ID collision |
| R-3 | Ruleset disable requires `--allow-ruleset-disable` + `WORTHLESS_ALLOW_RULESET_DISABLE=1` env (R-25), hard 120s wall-clock budget (R-22), watchdog re-enable, EXIT/INT/TERM/HUP/PIPE/QUIT/USR1/USR2 trap stack (R-23). Parent MUST poll `kill -0 $WATCHDOG_PID` every 5s during the window; watchdog death ⇒ immediate snapshot-restore + abort (F-4). | Forgotten disabled ruleset, SIGKILL bypass of watchdog (F-4), laptop suspend bypass (F-5), untrapped signals (F-6) |
| R-4 | `release-doctor.sh` callable standalone, asserts `enforcement: active`; run after every `release.sh` and after `kill -9` recovery | Trap bypass via SIGKILL |
| R-5 | Re-enable PUTs the pre-disable snapshot, not a hard-coded body | Schema drift widening permissions |
| R-6 | Every phase classified `idempotent` / `at-most-once` / `manual-resume-only`; markers in `.release-state/<v>/`. Both `.release-state/` AND `.release-audit/` are append-only state dirs, never staged. Repository `.gitignore` MUST contain literal lines `.release-state/` and `.release-audit/` (asserted in P1) — defends against `git add -A` / `git add .` accidentally committing audit artifacts containing `gh api` response bodies, wheel hashes, or token-scoped metadata (F-11). | Replay damage, partial-state confusion, state-dir leak via `git add -A` (F-11) |
| R-7 | GPG passphrase via `gpg-agent` only; never `--passphrase*`, never env var. Additionally: refuse if `GPG_AGENT_INFO` is set (deprecated, attacker-controllable socket-redirect vector); resolve `gpgconf --list-dirs agent-socket` and assert path is under `$HOME/.gnupg/`; `gpg --version` SHA256 must match SR-10 pin (R-20) before any sign call. | Process-listing / shell-history leak; rogue gpg-agent socket redirect; compromised gpg binary on $PATH (F-2) |
| R-8 | Never source `~/.*rc`; never export GPG/token env; `set +x` enforced before signing blocks | Ambient-config injection, `bash -x` trace leak |
| R-9 | `gh` token scope = BOTH `repo` AND `workflow` (or fine-grained equivalent granting `contents:write` + `actions:write`) — UNCONDITIONALLY. Step 4.7 `gh workflow run` requires `workflow`; "repo-only" silently no-ops the post-tag sync trigger (F-9). Reject broader scopes (`admin:org`, `delete_repo`, etc.). Reject CI `GITHUB_TOKEN`. Never call `gh auth status --show-token` (prints token to stderr → process-listing/scrollback leak); use `gh auth status` for scope check + `gh auth token` (stdout-only) for the one API call that needs the value. | Token-theft blast radius, wrong-context execution, stderr leak, silent under-scoped workflow dispatch (F-9) |
| R-10 | `release.sh` MUST pin the wheel via `pip download --no-deps` in step 4.2 (SHA256 captured to `.release-state/<v>/wheel.sha256`), then call `gh attestation verify <pinned-wheel> --owner shacharm2 --repo worthless` against the EXACT pinned file in step 4.2b. Never call `gh attestation verify` on a freshly-fetched wheel (defeats TOCTOU between PyPI lookup + verify). End-user `pip install` attestation enforcement is a separate ecosystem gap. | Mirror poisoning, name confusion, propagation-lag false-positive, TOCTOU between PyPI lookup + attestation fetch |
| R-19 | Tag-cut MUST verify the tag points at the SHA captured in preflight P1.5 (`EXPECTED_SHA=$(git rev-parse origin/main)`), not just that the tag is GPG-signed. `git rev-parse "v${VERSION}^{commit}"` must equal `$EXPECTED_SHA` before push. | `main` advancing between preflight + tag-cut → signing a moved HEAD silently |
| R-20 | External toolchain binaries (`gh`, `gpg`, `docker`, `pip`, `awk`, `jq`, `sha256sum`, `python3`, `curl`) MUST SHA256-match pins in `SECURITY_RULES.md` SR-10 BEFORE any cryptographic verification call (R-1, R-2, R-10). Preflight gate P11 hashes `$(command -v <bin>)` for each, refuses on drift with `tool binary SHA drift: <bin> (got <hash>, expected <hash>)`. Pin refresh = explicit reviewer-approved PR updating SR-10, never auto-bump. | Compromised binary on `$PATH` returns "verified" without doing crypto — entire attestation/signing chain becomes theatre (adversarial F-1) |
| R-21 | P9 + R-4 do NOT trust `gh api` responses alone — second-channel attestation MUST push an UNSIGNED lightweight tag matching the ruleset's scope: `git tag v0.0.0-canary-$$-<ts> HEAD && git push origin refs/tags/v0.0.0-canary-$$-<ts>`. Push MUST be rejected AND the stderr MUST name `v-tags-signed` (or `Required signatures` attributable to that ruleset). Rejection by any other ruleset name ⇒ treat `v-tags-signed` as DISABLED. Push SUCCESS ⇒ same. Local + remote canary tag cleaned up via `RETURN`-trap regardless of outcome. A canary on `refs/canary/*` would be bounced by an UNRELATED ruleset (push/branch protection) → false-green. TLS SPKI for `api.github.com` additionally pinned in SR-10. | MITM/proxy forging `enforcement: active` JSON while upstream disabled (F-3); canary probing wrong ruleset namespace (F-15) |
| R-22 | All time budgets in the recovery dance (R-3 120s, R-17 poll deadlines) use wall-clock comparison: `DEADLINE=$(( $(date +%s) + 120 ))` checked in `while [ $(date +%s) -lt $DEADLINE ]; do sleep 5; done` form; never a single `sleep N`. | Laptop suspend / SIGSTOP freezing the failsafe timer so ruleset stays disabled for hours (F-5) |
| R-23 | Trap list in `release-recover.sh` covers `EXIT INT TERM HUP PIPE QUIT USR1 USR2`; additionally `trap '' PIPE` set BEFORE first pipe so a closed terminal can't kill the process mid-recovery without the cleanup handler running. | Terminal-close (SIGPIPE), Ctrl-\ (SIGQUIT), or stray `kill -USR1` orphaning the disabled ruleset (F-6) |
| R-24 | R6 ruleset re-enable verification: after PUT 200, poll `gh api -H "Cache-Control: no-cache" /repos/.../rulesets/15719679` three times at 2s intervals; all three MUST return `enforcement: active`. Any disagreement ⇒ retry PUT once then escalate. PUT 200 alone is not proof of edge-cache flush. | GitHub API edge cache returning stale `disabled` to R6 / the doctor (F-7); race between PUT ack and read-after-write propagation |
| R-25 | `--allow-ruleset-disable` requires BOTH the CLI flag AND `WORTHLESS_ALLOW_RULESET_DISABLE=1` environment variable (mirrors R-14's `--accept-script-change` pattern). Additionally `ps -o comm= -p $PPID` MUST NOT match completion-subprocess names (`_complete`, `*-completion`, `compdef`); match ⇒ refuse with `completion-injected flag detected`. | Shell alias / zsh completion auto-injecting the dangerous flag without the operator typing it (F-12) |
| R-26 | Every audit-log line conforms to the R-26 JSON Schema (Draft 2020-12) in `scripts/release/audit-schema.json` (built in impl PR, SHA256-pinned in `lib/tool-trust.sh`). Mandatory witness fields on EVERY event: resolved tool path + SHA256 **at each call site** (not cached from P11), `gpgconf --list-dirs agent-socket`, `gh` token scopes, watchdog PID + liveness + poll ts, `umask`/RUID/EUID/login-session/tty, `script_git_sha`, R-13-redacted env key-list. `gh api` response bodies stored as SHA256 (first 256 bytes raw only for 4xx/5xx). `release-doctor.sh --replay-day YYYY-MM-DD` validates every line + cross-line invariants (tool-SHA constant per marker, ruleset restore-SHA matches disable-SHA, window ≤120s, watchdog alive). | Post-breach forensic reconstruction — detects mid-window binary swap, agent-socket hijack, token-scope elevation, watchdog-liveness fraud (F-16) |
| R-27 | After R-15 seals `.release-audit/YYYY-MM-DD.log.asc` AND doctor verifies its signature, ship it to THREE independent offsite channels synchronously (fail-loud, exit-3 + `--reship-audit` hint on any terminal failure): (a) `gh api POST` comment to designated audit issue (`.asc` + sha256 + tag); (b) `gh gist create --private` of the JSONL; (c) `git notes --ref=refs/notes/audit add` on the signed tag, pushed. Local manifest `.release-audit/<date>.ship-manifest.json` records the 3 URLs; `release-doctor.sh --verify-audit-shipped` re-fetches all three and asserts byte-equality vs the local `.asc`. | Compromised laptop can `chflags nouappnd` + rewrite + re-sign with cached subkey — local-only audit is no audit; offsite copies anchor the timeline (F-17) |
| R-29 | BEFORE the R2 ruleset-disable PATCH, `release-recover.sh` MUST (a) post `RULESET-DISABLED v<version> START <iso> PID <pid> EXPECT-RESTORE-BY <iso+120s>` + snapshot SHA256 + private-gist URL to the designated audit issue (witnessed BEFORE disable so a compromised laptop can't redact); (b) `gh workflow run audit-ruleset-watchdog.yml` (built in PR-2a) with the deadline + snapshot; (c) BLOCK ≤30s until `WATCHDOG-ARMED` comment appears (fail-closed if absent). The GHA watchdog re-enables the ruleset from snapshot if the deadline passes with no `RULESET-RESTORED` comment — an OFFSITE deadman switch surviving `kill -9 -<pgid>` of the whole local process tree. Post-R6: post `RULESET-RESTORED`. | Laptop hard-kill mid-window reaps local watchdog+heartbeat in one syscall, leaving ruleset disabled with no recovery + no IR ground-truth (F-18) |
| R-11 | Pre-flight `release-self-check.sh` greps for forbidden patterns (force-push, hard-reset, workflow edits, `curl\|sh`, etc.); abort on hit | Script-mutation regression, supply-chain paste-in |
| R-12 | No writes to `~/.ssh/`, `~/.gnupg/`, `~/.config/gh/`, `.github/workflows/*`, `.github/scripts/verify-tag.sh`, `.github/rulesets/*` | Trust-root tampering |
| R-13 | All stderr + ERR trap piped through redactor (gpg/token/passphrase/b64>32/known token prefixes) | Pasted-trace secret leak |
| R-14 | `--verify-self` SHA256 check against `SECURITY_RULES.md` SR-09 pins; drift requires `--accept-script-change` + `WORTHLESS_RELEASE_ACCEPT_DRIFT=1` env var. **Bootstrap:** PR-1 of the 4-PR implementation series lands scripts AND SR-09 pins in the same commit; reviewer manually verifies SHA-pin matches script bytes before merge. After merge, every invocation self-verifies. | Tampered orchestrator, first-commit chicken-and-egg |
| R-15 | Audit log `.release-audit/YYYY-MM-DD.log` is **JSONL** (one object per line, schema = R-26) written append-only for every disable/enable + every tag sign + every push. At file creation: `chflags uappnd` (mac) / `chattr +a` (Linux); each line is a single `printf '%s\n'` under `flock` (no rewrites, never `jq -i`). At end of every `release.sh` / `release-recover.sh` run, sign the day's log with `gpg --detach-sign --armor` producing `.release-audit/YYYY-MM-DD.log.asc` (uses R-7's pinned agent). `release-doctor.sh --verify-audit-log` verifies every `.asc` against `$MAINTAINER_GPG_FINGERPRINT` AND validates every line against the R-26 schema; refuses on any mismatch, missing signature, or schema violation. | Forensics integrity; local tamper or buggy rerun corrupting incident reconstruction (F-14, F-16) |
| R-16 | Tag name `v\d+\.\d+\.\d+(-\w+)?` only; tag message MUST match `^Release v\d+\.\d+\.\d+(\s+.*)?$` on the first line; body lines MUST NOT contain `[ ] ( ) < > \`` outside the leading prefix (defends against markdown-link injection `[click](evil)` + HTML injection `<script>` propagating verbatim into Linear paste / GH Release bodies via step 4.9); also linted against secret regex before sign. Enforced at tag-creation preflight AND re-asserted in step 4.9 before paste. | Public leak via tag, malformed-tag confusion, markdown-injection into Linear-paste at step 4.9 (F-13) |
| R-17 | Polling loops have max-attempts + exponential backoff; no unbounded waits | DoS-via-hang, masked failure |
| R-18 | Never `git config --global`, never `gpg --import`, never modify operator keyring | Identity/key substitution |

**End state:** the orchestrator is a *thin, auditable shim* around `verify-tag.sh` and `gh`. Trust still lives in the GPG fingerprint and the ruleset — the script just makes it harder for the maintainer to footgun on the way there.

# WOR-433 — ClawHub Publish Flow (validated end-to-end)

**Linear:** [WOR-433](https://linear.app/plumbusai/issue/WOR-433) (child of WOR-421)
**CLI probed:** `clawhub@0.12.2` installed at `/Users/shachar/.npm-global/bin/clawhub`
**Sources:** real `--help` output, decompiled `dist/cli/commands/*.js`, `docs/cli.md` from openclaw/clawhub@main, GitHub issue #669
**Status:** No login was performed. No publish was performed. Token store untouched.

> The earlier `engineering/research/openclaw/README.md` referenced in the brief does not exist on disk; this is the first validated probe.

---

## 1. Account model

**Result: any verified user works. No org gating.**

- `clawhub login` opens a browser to `<site>/cli/auth` (default `https://clawhub.ai/cli/auth`) and completes via loopback callback. Token persists; `--no-browser` requires `--token clh_...` (headless flow).
- Tokens look like `clh_*`. Token storage path is OS-dependent (not present on this host yet — `~/.config/clawhub`, `~/.clawhub`, and macOS `Application Support/clawhub` were all absent before login).
- Roles in the wire schema: regular user, moderator, admin (`set-role`, `ban-user`, `unban-user` are admin-only). No "organization" entity — ownership is by **handle**.
- Handle namespacing: published skills land at `clawhub.ai/<handle>/<slug>`. Sample security-adjacent skills already published under individual handles (`Abdelkrim/atlassian-jira-by-altf1be`, `steipete/1password`, `kmjones1979/1claw`, `asleep123/bitwarden`).
- No paid tiers: **"Publishing a skill means it is released under MIT-0 on ClawHub. Published skills are free to use, modify, and redistribute without attribution. ClawHub does not support paid skills or per-skill pricing."** (`docs/cli.md` — `skill publish`)

**Implication for Worthless:** publishing the `worthless` skill **automatically MIT-0-licenses every file in the folder.** That is binding. The skill folder must contain only material we are willing to release under MIT-0.

---

## 2. Publish flow (verified, no actual publish)

### 2.1 CLI surface (verbatim `--help` from v0.12.2)

```
$ clawhub skill publish --help
Usage: clawhub skill publish [options] <path>

Publish a skill from folder

Arguments:
  path                        Skill folder path

Options:
  --slug <slug>               Skill slug
  --name <name>               Display name
  --version <version>         Version (semver)
  --fork-of <slug[@version]>  Mark as a fork of an existing skill
  --changelog <text>          Changelog text
  --tags <tags>               Comma-separated tags (default: "latest")
  -h, --help                  display help for command
```

**`clawhub publish` (legacy alias) is identical.** `clawhub sync` has `--dry-run`; **`skill publish` does NOT have `--dry-run`.** The only real preview path for skills is `clawhub sync --dry-run` from a parent folder.

### 2.2 What the CLI does, line-by-line

From `dist/cli/commands/publish.js` (v0.12.2):

1. Resolve folder, stat it — must be a directory.
2. **Reject if it looks like a plugin** (presence of any of: `openclaw.plugin.json`, `package.json` with `openclaw` block, `.codex-plugin/plugin.json`, `.claude-plugin/plugin.json`, `.cursor-plugin/plugin.json`). Error: `'This looks like a plugin. Use "clawhub package publish <source>" instead.'`
3. `requireAuthToken()` — fails fast if not logged in.
4. Validate: `--slug` (or sanitized basename), display name, **valid semver `--version` is required**.
5. `listTextFiles(folder)` — gathers all text files; **must include `SKILL.md` or `skill.md`** or it errors `"SKILL.md required"`.
6. Build multipart form. Payload JSON includes `acceptLicenseTerms: true` (hard-coded — see #669 below). Attach every text file as a `Blob`.
7. `POST /api/v1/skills` (multipart). Response: `{ versionId, ... }`. Spinner prints `OK. Published <slug>@<version> (<versionId>)`.

**No client-side security scan.** The local `scanSkills.js` only walks the filesystem to find folders that contain a `SKILL.md` marker — it does **not** inspect content for secrets, malware, or dangerous code. All scanning is server-side post-upload.

### 2.3 Pre-publish lints that actually fire (client side only)

| Check | Action |
|---|---|
| Folder exists and is a directory | error if not |
| Plugin markers present | hard error: route to `package publish` |
| Auth token present | hard error if missing |
| `--version` is valid semver | hard error |
| At least one text file | hard error `"No files found"` |
| `SKILL.md` (any case) present | hard error |
| `--fork-of` parses to `<slug>` or `<slug@semver>` | hard error if version invalid |

That is the full client gate. **No frontmatter validation, no body length, no metadata schema, no secret scan, no `node_modules` exclusion.** The `listTextFiles` walker decides what gets uploaded; binary files are skipped.

---

## 3. Dangerous-code scanner — reality

**Issue [openclaw/clawhub#669](https://github.com/openclaw/clawhub/issues/669) is real**, opened by @Abdelkrim on Mar 10 2026, **closed as not planned** with label `r: rescan-guidance`. Two server-side scanners exist:

- **VirusTotal** — runs on uploaded files
- **OpenClaw scanner** — second pass, internal

#669 documents the failure mode that matters: **skills can show "Skill blocked — malicious content detected" on the public page even when both scanners report Benign.** The maintainer outcome was "request a rescan", not a fix. Two distinct bugs were filed:

1. CLI bug (v0.7.0, **already fixed in v0.12.2** — see line 57 of publish.js: `acceptLicenseTerms: true`) — old CLIs failed payload validation.
2. **Server bug:** Benign-scanned skills still rendered the blocked banner. Closed as not planned. This means a clean scan does not guarantee an unblocked listing — there is a separate internal allow/block decision.

**Appeal flow exists for *packages* but not skills.** `package appeal`, `package appeals`, `package resolve-appeal`, `package report`, `package triage-report`, `package moderate`, `package moderation-queue`, and `package readiness` are full subcommands. **For *skills*, the only owner-facing path is `clawhub skill rescan <slug>`** (rate-limited: response includes `remainingRequests/maxRequests`).

```
$ clawhub skill rescan --help
Usage: clawhub skill rescan [options] <slug>

Request a security rescan for the latest published skill version

Options:
  --yes       Skip confirmation
  --json      Output JSON
```

If the rescan still flags us, the only escalation path is filing a GitHub issue against `openclaw/clawhub` and hoping for the `r: rescan-guidance` triage cycle.

**Sample of security-adjacent skills already published successfully** (from `awesome-openclaw-skills`):
`steipete/1password`, `kmjones1979/1claw` (HSM-backed vault), `asleep123/bitwarden`, `brandonwise/api-security`, `authensor/authensor-gateway` (policy gate for skills), `Gonzih/amai-id` ("Soul-Bound Keys"). Skills that wrap secret-bearing CLIs do publish. None of these advertise themselves as splitting an API key, but all touch credentials.

**Risk for Worthless:** the words `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `sk-...` patterns, and `xor`/`shard` operations on key bytes will appear in `SKILL.md` and any helper scripts. Any of these may trigger the heuristic that produced #669's false positive. We have no way to preview the scanner verdict before publish.

---

## 4. Versioning + recovery

- **`--version` is mandatory and must be valid semver.** No auto-increment in `skill publish` (only in `sync --bump patch|minor|major`).
- **No force-overwrite of an existing version.** Server returns conflict; the CLI does not expose `--force` for `skill publish`. `update` (the install-side command) compares **content fingerprints** and refuses overwrite without `--force`, but that is consumer-side.
- **Yank = soft-delete.** Two recovery commands exist:

```
$ clawhub delete --help          # soft-delete (owner / mod / admin)
Options:
  --reason <text>  Moderation note/reason
  --yes            Skip confirmation

$ clawhub hide --help             # hide listing without deleting versions
Options:
  --reason <text>
  --yes

# reverse with: clawhub undelete <slug> --yes  /  clawhub unhide <slug> --yes
```

`delete` is reversible via `undelete`. `hide` removes listing visibility without affecting installs of pinned versions. Neither rewrites history of already-installed copies — yanking `worthless@0.1` will not retract bytes from clients that already ran `clawhub install worthless --version 0.1`.

**To ship `worthless@0.2` after `@0.1`:** publish a new semver. The `latest` tag follows. Old version remains queryable via `clawhub install worthless --version 0.1`. There is no auto-deprecate.

---

## 5. Plan B — sideload from GitHub

**Bad news: `clawhub install` does NOT accept GitHub URLs for skills.**

```
$ clawhub install --help
Usage: clawhub install [options] <slug>

Arguments:
  slug                 Skill slug

Options:
  --version <version>  Version to install
  --force              Overwrite existing folder
```

GitHub-source publishing only exists for **packages** (`clawhub package publish owner/repo@ref`), not for installing skills. The closest workarounds:

1. **Clone + `clawhub sync --root ./worthless-skill --dry-run` to preview**, then publish from local folder. Still uses the registry path; not a true sideload.
2. **`git clone` + manual copy** into `<workdir>/skills/worthless` — works for any agent that scans local skill folders, bypasses the registry entirely. This is our actual fallback if the registry blocks us.
3. **`clawhub inspect <slug> --files --file SKILL.md`** lets curious users preview a published skill's contents without installing — useful for trust-building, not a sideload mechanism.

**No `clawhub install github.com/...` syntax exists in v0.12.2.** Document the `git clone` fallback in our README.

---

## 6. Risk-ranked publish checklist

Use `--workdir` or `cd` so paths resolve cleanly. Run from a clean folder (no `.git/`, no `node_modules/`, no `.env`).

| Step | Command | Risk | Mitigation |
|---|---|---|---|
| 1. Login | `clawhub login` (opens browser) | LOW. Token persists in OS config dir. | Run `clawhub logout` after publish if on shared host. Use `clh_*` PAT instead via `clawhub login --token clh_...` for CI. |
| 2. Stage skill folder | Make a sterile copy at `/tmp/worthless-skill/` containing only `SKILL.md` + scripts you intend to MIT-0-license | **HIGH.** Every text file in the folder is uploaded and licensed MIT-0. `listTextFiles` does not honour `.gitignore` or `.npmignore`. | Manually whitelist files. Diff the staged folder against `git ls-files`. Strip any `.env*`, `*.key`, secrets, internal docs. |
| 3. Preview plan | `clawhub sync --root /tmp/worthless-skill --dry-run --tags latest` | LOW. Lists what *would* upload, no network publish. | This is the only available dry-run for skills. `skill publish` itself has no `--dry-run`. |
| 4. Publish | `clawhub skill publish /tmp/worthless-skill --slug worthless --version 0.1.0 --changelog "Initial release" --tags latest` | **CRITICAL.** Server-side scanner may flag key-handling language and block listing (#669 precedent). No prepublish scanner preview. Once published the `slug + version` pair is permanent — same version cannot be reuploaded. | Publish to a throwaway slug first (`worthless-canary-001`) and check the public page renders unblocked. Then publish the real slug. Keep changelog short and free of `sk-`-style patterns. |
| 5. Verify | `clawhub inspect worthless --json` and visit `https://clawhub.ai/<handle>/worthless` | MEDIUM. Banner may say "blocked — malicious content detected" even with Benign scans. | If blocked, run `clawhub skill rescan worthless --yes`. Rescans are rate-limited (response surfaces `remainingRequests/maxRequests`). If rescan does not clear it, file a GitHub issue against `openclaw/clawhub` referencing #669 and tag with rescan-guidance context. **There is no formal appeal CLI for skills**, only for packages. |
| 6. Recovery if needed | `clawhub hide worthless --reason "regression"` (reversible) or `clawhub delete worthless --reason "yank"` (reversible via `undelete`) | LOW. Soft-delete only; consumers who already pinned a version can still install it. | Bump semver and republish; do not try to overwrite a published version. |

---

## Appendix — verbatim CLI surface

Login storage and global flags (from `docs/cli.md`):

- Default site: `https://clawhub.ai`
- Default registry: discovered, fallback `https://clawhub.ai`
- Env: `CLAWHUB_SITE`, `CLAWHUB_REGISTRY`, `CLAWHUB_WORKDIR` (legacy `CLAWDHUB_*`)
- Proxy support: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`
- Telemetry: opt-out with `CLAWHUB_DISABLE_TELEMETRY=1`
- Token install dir manifest: `<workdir>/.clawhub/lock.json` (legacy `.clawdhub`); per-skill `<skill>/.clawhub/origin.json`

Open question worth tracking: **does the server-side scanner flag the literal strings `sk-` or `OPENAI_API_KEY` in `SKILL.md`?** No public threshold list. Best mitigation is a canary publish under a throwaway slug before the real one.

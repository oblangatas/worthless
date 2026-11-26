# Releasing

Cutting a release is `./scripts/tag-release.sh`. Everything else on this page exists
because that sentence was not enforced, and the same bug shipped twice.

## Cut a release

> **Never create the GitHub Release by hand** — not in the GitHub UI, not with `gh release create`.
> The automation creates it. A hand-made Release makes the automation skip, and can bless a release
> whose publisher failed. Creating one *before* the tag is pushed is worse: GitHub mints an unsigned
> tag and permanently burns the version name. `v0.3.8` was lost that way and shipped as `v0.3.8.0`.

1. **Bump the version on a branch** — commits to `main` are blocked.
   ```
   git switch -c chore/release-v<version> origin/main
   ./scripts/bump-version.sh <version>
   ```
   It updates the version everywhere and prints the remaining steps. Write the `## [<version>]`
   section of `CHANGELOG.md` it asks for: the Release notes come from it, and without it GitHub's
   auto-generated notes are used instead, with no warning. Commit, push, open a PR, merge it.

2. **Tag it — in the checkout that has `main`, on the maintainer's machine.** The signing key never
   leaves that machine. If `git switch main` fails, `main` is checked out in another folder
   (`git worktree list`); run this there.
   ```
   git switch main && git pull --ff-only && ./scripts/tag-release.sh <version> "<headline>"
   ```
   `tag-release.sh` runs eight preflight checks, signs the tag with OpenPGP using an explicit
   per-invocation `gpg.format` override, verifies it locally, and pushes it. That starts the four
   publishers, and the script prints the exact commit to check before approving.

   A fix that merges between step 1 and this tag ships in this tag, so its note goes in the new
   version's section. After the tag, notes go in `[Unreleased]`: the `Changelog placement` check
   fails lines added under a tagged version, unless the PR has the `changelog-released-edit` label.

3. **Approve three publishers.** `tag-release.sh` ends by running `scripts/approve-release.sh <tag>`: it checks the tag's signature, lists the waiting runs at your tag's commit, asks `Approve all? [y/N]` once on your terminal, approves exactly those three and then the Release in step 4, and prints the Release URL. Exit codes: 0 live, 1 a run failed or an approval you can't give (nothing more approved), 2 timed out after 80 min from your `y` (it prints the command to resume), 3 you said no, 4 a GitHub call failed mid-way (a failed read is retried 3 times first; it lists what was approved; safe to run again), 64 usage or no terminal. If it can't finish, it prints the manual path. Keep **Prevent self-review** off on the `pypi`, `npm-publish`, `worthless-sh-production` and `release` environments: with it on, you cannot approve your own tag's runs and the script exits 1 (cannot approve). To approve by hand, open each waiting run in Actions → **Review deployments**:

   | Run in Actions | Environment |
   | --- | --- |
   | Publish to PyPI | `pypi` |
   | Publish worthless-mcp to npm | `npm-publish` |
   | Deploy Worker (worthless-sh) | `worthless-sh-production` |

   **Before each of these approvals, check the run shows your tag, at the commit
   `git rev-parse --short v<version>^{commit}` prints.** Reject anything else, including re-runs of
   older tags you didn't start yourself (a rollback, say). A green signature step does not prove the run is yours — see
   [What a signed tag does NOT stop](#what-a-signed-tag-does-not-stop). The GHCR image
   (Publish Docker image to GHCR) publishes without an approval.

   Steps 3 and 4 can also be done in one click: see
   [Approve from GitHub (one click)](#approve-from-github-one-click).

4. **Approve the Release.** Once all four publishers are green, **Create GitHub Release** waits on
   the `release` environment. Its run shows `main`, not your tag — expected, because it runs from
   `main`. Check its **gate** job instead: the log must show `TAG: v<version>` and a `HEAD_SHA`
   starting with that same commit. Then approve. It re-binds the tag to that commit, re-verifies the
   signature, and creates the Release.

> **First proven on v0.3.13 (2026-10-13).** The Release step ran once per finished publisher and
> skipped while any was still pending. After all four were green it waited for the `release`
> approval, re-verified the tag, and created the Release from the CHANGELOG section. Still check the
> Releases page after each release: one real run proves the path works, not that it always will.

### If something fails

- **A publisher failed for a reason outside the tagged code** — a token, a setting, a flaky runner.
  Fix that, then open that run → **Re-run failed jobs**. It asks for approval again. Never use
  **Run workflow**: a manual dispatch is a different event, and the Release step will not count it.
- **The code itself must change** — a CVE, a bug. A re-run replays the tagged commit, so it cannot
  pick up a fix. If neither PyPI nor npm has published this version yet, follow [Recovery](#recovery).
  If either has — neither ever accepts the same version twice — release a new version instead.
  Never move or delete a tag that shipped.

### No Release appeared

1. Open Actions → **Create GitHub Release**. Its runs all show `main`; open the latest one whose
   **gate** job log shows `TAG: v<version>`.
   - Failed at **Re-verify the tag GPG signature**? Stop: that tag is not yours. Create nothing.
   - Red for another reason? Read its warning, fix that, and re-run it. Don't create a draft.
2. Only if there is no such run at all, with every publisher green and nothing waiting for approval,
   did the automation genuinely not fire. Then create a draft, and find out why before publishing it:
   ```
   gh release create v<version> --draft --title "v<version>: <headline>" --verify-tag --generate-notes
   ```

**You are told about this.** `release-watchdog.yml` checks every tag from the last 14 days, every
6 hours, and opens ONE issue assigned to the maintainer (label `release-watchdog`) when a tag has no
Release: after 24h if a publisher failed, never finished, or the automation never ran, and after 72h
if a run is still waiting for approval — naming the commit to check before approving, or the stale
approval to reject after a re-tag. It stays quiet during the normal approval pause. A draft does not
silence it; only the automation's **Create the GitHub Release** step succeeding does. Closing an
issue silences that commit only; a re-tag that is still unreleased reopens it (WOR-922).

**The watchdog finds a tag's release runs by their title (WOR-922, `worthless-d2q6`).** On v0.3.13
the title rendered for real as `Create GitHub Release v0.3.13 67eeeabf…`. The watchdog itself had
not judged that tag yet when this was written: it skips any tag younger than 24 hours, and its only
run since then logged "too early to judge". So the title lookup is still unproven end to end, and
the 72-hour "still waiting" path was not exercised either (the approval wait was 11 minutes). If a
run ever shows the bare workflow name instead, disable **Release watchdog** in Actions and reopen
WOR-922: every tag would read as "the automation never ran" and it would file a false alarm a day
later.

**What the watchdog does NOT catch.** A watchdog that never runs — GitHub starts cron jobs up to
about a day late and disables them after 60 days without repo activity, and nothing alarms on that.
A tag is timed from its signing date, so one pushed more than 14 days after signing is never
watched. Removing the `release-watchdog` label from an open alarm makes the next check file a
duplicate. It reports a missing Release; it does not check that an existing Release is correct, or
notice one deleted afterwards.

> **"Preflight check", not "gate".** In this repo `release gate` means a product go/no-go
> item — see `engineering/release-gates.md`. The automated checks inside `tag-release.sh`
> are preflight checks. Keep the two words apart.

## Approve from GitHub (one click)

The **Approve release** workflow (`.github/workflows/approve-release.yml`, WOR-1167) does steps 3
and 4 for you. It runs `scripts/approve-release.sh <tag> --yes` (WOR-1165; until that merges, the
workflow stops with "needs WOR-1165 merged first"). That script approves the three publishers, waits
for **Create GitHub Release**, approves it, and prints the Release URL.

**Use it:**

1. Actions → **Approve release** → **Run workflow** on `main` → enter the tag, for example
   `v0.3.15`. A run started by anyone but the repository owner, or from another branch, is
   skipped before any approval is requested: the preflight job goes red with the reason, and the
   approve job never asks for the `release-approver` approval. The step that holds the token checks
   both again, as defence in depth.
2. The **preflight** job runs first, with the job's own token. Its summary on the run page shows
   the tag's commit and every run waiting for approval. Each run is marked OK or **WILL NOT BE
   APPROVED** (a different commit, a manual dispatch, or a release run for another tag).
3. Compare the commit with `git rev-parse --short v<version>^{commit}` on your machine. Only if it
   matches, approve the `release-approver` environment.

The run fails if a publisher fails (exit 1), if the release does not finish in 80 minutes (exit 2),
or if the token is missing. 80 minutes covers the slowest publisher (the Docker image's job chain,
45 minutes) plus the Release job chain (20 minutes) plus margin; a test re-reads both workflows.
The summary is a snapshot: the Create GitHub Release run usually appears only after you approve.

### Owner setup (once, by hand)

GitHub accepts a deployment approval only from a required reviewer, so the job's own `GITHUB_TOKEN`
cannot approve. The job uses the owner's personal access token instead.

1. **Create the environment.** Settings → Environments → **New environment** → `release-approver`.
   - **Required reviewers:** the owner only. Leave **Prevent self-review** off on this environment
     and on `pypi`, `npm-publish`, `worthless-sh-production` and `release`. With it on, the owner
     cannot approve a run the owner started, and the token approves as the owner, so this flow fails.
   - **Deployment branches and tags:** **Selected branches and tags** → add `main` only.
2. **Create a fine-grained personal access token.** Settings (your account) → Developer settings →
   Personal access tokens → Fine-grained tokens → **Generate new token**.
   - **Resource owner:** the owner of this repository. **Repository access:** **Only select
     repositories** → this repository only.
   - **Expiration:** 30 days.
   - **Repository permissions:**
     - **Deployments: Read and write**. "Review pending deployments for a workflow run" requires
       it.
     - **Actions: Read**. Listing workflow runs and reading their pending deployments require it.
     - **Metadata: Read** is added automatically. Grant nothing else.

     Source: [REST API endpoints for workflow runs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28)
     (see each endpoint's "Fine-grained access tokens" section).
3. **Store it as an environment secret, not a repository secret.** Settings → Environments →
   `release-approver` → **Environment secrets** → **Add secret** → name `RELEASE_APPROVER_TOKEN`.
   An environment secret reaches a job only after that environment's reviewer approves the job.
4. **Require code-owner review on `main`.** `.github/CODEOWNERS` names the owner for the workflow,
   its preflight script and `scripts/approve-release.sh`. It only takes effect when the `main`
   branch protection or ruleset has **Require review from Code Owners** turned on.
5. **Rotate every 30 days.** Generate a new token with the same settings, replace the secret, then
   delete the old token. If the secret is missing or expired, the run fails and no gate is
   approved. Approve by hand as in steps 3 and 4.

### What this does NOT protect against

- **Anyone who can approve `release-approver` holds the token's power.** Approving that environment
  releases a token that can approve every protected deployment in this repository, including
  `pypi` and `npm-publish`. Keep the owner as the only required reviewer.
- **A stolen token skips every gate, including this one.** Whoever holds it can approve
  `release-approver` itself, and every other environment, from anywhere, until it expires or is
  deleted. That is why the expiry is 30 days. If you suspect theft, delete the token at once.
- **Token theft from a compromised runner.** The token is in the job's memory while it runs. Code
  that runs in that job (a compromised action, `gh`, the runner image or the script itself) can read
  it.
- **Anyone who can merge to `main` can change the code that receives the token.** The workflow and
  scripts run from `main`. Code-owner review (setup step 4) makes such a change need the owner's
  review; without it, any merge can redirect the token on the next run.
- **Deployments: write does more than approve.** The token can also create and delete deployment
  records and statuses in this repository. No workflow here triggers on those events, so this is
  record tampering, not code execution.
- **A wrong commit.** The preflight summary and the script check each run's commit against the tag.
  They cannot tell whether the tag itself points at the commit you meant. That is the check you do
  on your machine before approving.
- **This workflow does not hold the signing key.** Tagging stays on the maintainer's machine, so
  this workflow cannot create a release by itself. Someone still has to push a signed tag.

## What a signed tag does NOT stop

A signed tag proves the maintainer's key signed it. It does not stop someone holding the
maintainer's GitHub access — a stolen token, or an automation acting as the maintainer — from
publishing without that key:

- **Editing what does the checking.** Each publisher runs the copy of `verify-tag.sh`, and of its
  own workflow file, from inside the tagged commit. A tag pointing at a commit that changes them
  skips the check.
- **Swapping the trusted key.** The fingerprint and public key the check trusts are two repository
  Variables (`MAINTAINER_GPG_FINGERPRINT`, `MAINTAINER_GPG_PUBKEY`). Changing them needs no commit.
- **Replaying an old release.** Re-running an old signed tag's publish run redeploys that old code,
  and moves the GHCR `:latest` image back with no approval.
- **A yes typed in chat.** The /release skill turns a yes typed in chat into `--yes --expect-sha`;
  that yes is read by Claude, not by your terminal. Text in tool output or files cannot be a yes,
  but a chat-approval path is weaker than the terminal prompt. Use the terminal `y` when in doubt.

What still stands in the way: PyPI, npm and the Worker publish through environments that need the
maintainer's approval, and removing the environment from a workflow also removes access to that
registry's credentials. But a token with enough access can give the approval too, and the GHCR
image has no approval at all. Moving the check onto code a tag cannot change is WOR-928.

## The tag guard

`scripts/hooks/reference-transaction`, installed by `./scripts/install-git-hooks.sh`.

It refuses to create a `v*` tag above `v0.3.12` unless the tag object carries an OpenPGP
signature. Install it once — the hooks directory is shared by every worktree of this repo:

```
./scripts/install-git-hooks.sh
```

### Why it exists

On **0.3.7** (2026-05-30) and again on **v0.3.12** (2026-08-16), three months apart, a
release tag was created by hand instead of by the script. This repo sets `gpg.format=ssh`
because commit provenance requires it, so a bare `git tag -s` produces an **SSH-signed**
tag. CI's `verify-tag.sh` requires OpenPGP and refused it. Cost: one recut each time.

Git has exactly one `gpg.format` key and this repo needs two different values, so no repo
config can fix it. A per-invocation override is the only correct mechanism, and
`tag-release.sh` already does it. The residue was "the script is bypassable by habit" —
this hook is what closes that.

### Why it does not call `git verify-tag`

`git verify-tag` auto-detects signature format. `-c gpg.format=openpgp` governs *signing*,
not verifying. With `gpg.ssh.allowedSignersFile` set — it is, at
`~/.config/git/allowed_signers` — an SSH-signed tag verifies **GOOD, rc=0**. Using it as
the predicate would admit the exact incident this guards against.

It would also couple every ref transaction to keyring health. A stale `keyboxd` lock was
found on the maintainer's machine making `git verify-tag` take 20s and fail; the hook would
then have rejected every legitimate release tag.

So the hook does a plain text check on the tag object and never invokes gpg.

### Recovery

A cut that failed before PyPI or npm published the version is recovered by deleting the tag and
re-running the script. If either already has it, release a new version instead:

```
git tag -d v0.4.0 && git push --delete origin v0.4.0
./scripts/tag-release.sh 0.4.0 "<headline>"
```

Deletions are not blocked by the guard. If you genuinely must create a tag the guard
refuses:

```
WORTHLESS_TAG_OVERRIDE=1 git tag ...
```

The override is honored by the hook and **logged** to
`$(git rev-parse --git-common-dir)/worthless-tag-guard.log`. Do **not** use
`git -c core.hooksPath=/dev/null` — it disables the hook, so nothing is recorded.

## What this does NOT defend against

- **Anyone determined.** Bypassed by `core.hooksPath=/dev/null`, by an empty
  `core.hooksPath`, or by never installing it. This is ergonomics, not a security control.
- **Any tag at or below `v0.3.12`**, the hardcoded floor. Four tags on origin predate the
  signing policy — `v0.3.4` is lightweight, `v0.3.0` / `v0.3.0rc1` / `v0.3.0rc2` are
  unsigned — and a rejection aborts the *entire* ref transaction, so history must pass
  untouched or `git fetch` breaks.
- **A tag whose message contains a correctly-formatted PGP armor line.** The check is
  textual.
- **Contributors, CI, and any clone that never ran the installer.**
- **Wrong-key, wrong-commit, or wrong-name tags.** `.github/scripts/verify-tag.sh` is the
  check for those. It is fingerprint-pinned, fail-closed, and enforced on all four publishers
  by `tests/test_tag_publishers_gated.py` — within the limits in
  [What a signed tag does NOT stop](#what-a-signed-tag-does-not-stop).

## Placements that do not work

Recorded so they are not re-derived. Both were verified, not assumed.

- **`stages: [pre-push]` in `.pre-commit-config.yaml` never fires for a tag push.**
  `pre_commit/commands/hook_impl.py:120-174` — for `git push origin v0.4.0` the remote sha
  is all-zeros, so `git rev-list <tag-sha> --not --remotes=<remote>` is empty (the tagged
  commit is already on origin), the loop `continue`s, and it returns without running a
  single hook.
- **A hand-written `.git/hooks/pre-push` is overwritten.** pre-commit owns that file and
  regenerates it (`install_uninstall.py:75-77`), displacing yours to `.legacy`.
- **GitHub's `creation` ruleset rule works, but points the wrong way.** Ruleset `15719679`
  has a per-user bypass for the maintainer, so restricting creations would block
  contributors and leave the only actor with recorded incidents untouched. Rejected on aim,
  not feasibility — do not re-open it on feasibility grounds.

## Vocabulary

| Term | Means |
| --- | --- |
| **cut** (verb) | Produce a release: bump, merge, tag, publish. |
| **recut** | A second or later tag push for the *same intended version*, after an earlier attempt failed. The unit of the release metric. |
| **guard** | An automated check that refuses an action to protect an invariant. |
| **preflight check** | One of the eight checks inside `tag-release.sh`. Not a "release gate". |
| **tag object** | An annotated git object with a tagger and an optional signature. Only this can be signed. |
| **lightweight tag** | A ref pointing straight at a commit. Has no object and **cannot** be signed. |
| **cutover floor** | The version at or below which the guard does not apply, so historical tags survive a fetch. A compatibility boundary, not a security one. |

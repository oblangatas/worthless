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

3. **Approve three publishers.** In Actions, open each waiting run → **Review deployments**:

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

4. **Approve the Release.** Once all four publishers are green, **Create GitHub Release** waits on
   the `release` environment. Its run shows `main`, not your tag — expected, because it runs from
   `main`. Check its **gate** job instead: the log must show `TAG: v<version>` and a `HEAD_SHA`
   starting with that same commit. Then approve. It re-binds the tag to that commit, re-verifies the
   signature, and creates the Release.

> **Not yet proven on a real release.** The three publisher approvals and the automatic Release were
> set up in September 2026. A test run showed the Release step starts, checks the publishers, waits
> for approval and re-verifies the tag — then skipped creating the Release, because that one already
> existed. After your next release, confirm the Release page actually appeared.

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
   did the automation genuinely not fire — and nothing alerts you to that yet. Then create a draft,
   and find out why before publishing it:
   ```
   gh release create v<version> --draft --title "v<version>: <headline>" --verify-tag --generate-notes
   ```

> **"Preflight check", not "gate".** In this repo `release gate` means a product go/no-go
> item — see `engineering/release-gates.md`. The automated checks inside `tag-release.sh`
> are preflight checks. Keep the two words apart.

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

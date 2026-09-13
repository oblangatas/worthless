# Releasing

Cutting a release is `./scripts/tag-release.sh`. Everything else on this page exists
because that sentence was not enforced, and the same bug shipped twice.

## Cut a release

```
./scripts/bump-version.sh <version>      # bump, commit, PR
#   ... merge the PR to main ...
./scripts/tag-release.sh <version> "<headline>"
```

`tag-release.sh` runs eight preflight checks, signs the tag with OpenPGP using an explicit
per-invocation `gpg.format` override, verifies it locally, pushes it, and then prints the
`gh release create` command to run **after** CI is green.

**Never run `gh release create` before the tag is pushed.** It creates the git tag itself,
unsigned, and permanently tombstones the name on GitHub — the name cannot be reused even
after deleting both the release and the tag. `v0.3.8` was burned this way and shipped as
`v0.3.8.0`.

> **"Preflight check", not "gate".** In this repo `release gate` means a product go/no-go
> item — see `engineering/release-gates.md`. The automated checks inside `tag-release.sh`
> are preflight checks. Keep the two words apart.

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

A failed cut is recovered by deleting the tag and re-running the script:

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
- **Wrong-key, wrong-commit, or wrong-name tags.** Only `.github/scripts/verify-tag.sh`
  decides what actually ships. It is fingerprint-pinned, fail-closed, and enforced on all
  four publishers by `tests/test_tag_publishers_gated.py`.

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

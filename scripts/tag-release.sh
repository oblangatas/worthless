#!/bin/sh
# tag-release.sh — GPG-sign and push a release tag; release-notes.yml then
# auto-creates the GitHub Release once all publishers pass.
#
# NEVER create a GitHub Release before pushing the signed tag.  gh release create
# also creates the git tag (unsigned), which (a) fails the GPG gate in publish.yml
# and (b) tombstones the tag name in GitHub permanently — even after deleting both
# the release and the tag, the name cannot be recreated.  This script enforces the
# correct order:
#
#   1. GPG-sign the tag (openpgp, explicit fingerprint)
#   2. Verify the signature locally
#   3. Push the tag  →  the four publishers fire automatically
#   4. release-notes.yml auto-creates the GitHub Release once all publishers pass
#
# Usage:
#   ./scripts/tag-release.sh 0.3.9 "agents and exits"
#
# Prerequisites:
#   - You are on main, up-to-date with origin/main
#   - pyproject.toml already bumped to <version> and committed
#   - GPG key 739B528ACF5AC12FE63E447592F719843935814D is available
#     (gpg --list-secret-keys)

set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

GPG_FINGERPRINT="739B528ACF5AC12FE63E447592F719843935814D"

# --- 1. Validate args --------------------------------------------------------

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <version> [headline]"
    echo "Example: $0 0.3.9 \"agents and exits\""
    exit 1
fi

version="$1"
headline="${2:-}"

if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([._-]?(a|b|rc|alpha|beta|dev|post)[0-9]+)?$'; then
    echo "ERROR: '$version' doesn't look like a semver/PEP-440 version."
    exit 1
fi

tag="v${version}"

# --- 0. Is the local tag guard installed? ------------------------------------
# Warn, never block: this check is redundant with the guard itself and with CI's
# verify-tag.sh, and a blocking check here would invent a new way to not ship.
# It exists because an uninstalled guard is otherwise silent -- and the release
# script is the one thing guaranteed to run at the moment it matters.
_hooks_dir=$(git config --get core.hooksPath || true)
[ -n "$_hooks_dir" ] || _hooks_dir="$(git rev-parse --git-common-dir)/hooks"
if [ ! -x "$_hooks_dir/reference-transaction" ]; then
    echo "WARNING: the tag guard is not installed ($_hooks_dir/reference-transaction)."
    echo "  A bare 'git tag' will not be refused on this machine. See RELEASING.md."
    echo "  Install it with: ./scripts/install-git-hooks.sh"
    echo
fi

# --- 2. Preflight checks -----------------------------------------------------

# Must be on main
current_branch=$(git branch --show-current)
if [ "$current_branch" != "main" ]; then
    echo "ERROR: must be on main (currently on '$current_branch')."
    echo "  git checkout main && git pull --rebase"
    exit 1
fi

# pyproject.toml must match the requested version
pyproject_version=$(awk -F'"' '/^version =/ { print $2; exit }' pyproject.toml)
if [ "$pyproject_version" != "$version" ]; then
    echo "ERROR: pyproject.toml says '$pyproject_version' but you asked to tag '$version'."
    echo "  Run ./scripts/bump-version.sh $version first."
    exit 1
fi

# Docs Docker image pins must match the release. bump-version.sh keeps these
# in sync; this is the fail-closed gate in case it was skipped — a release must
# not ship docs that tell users to pull a stale `worthless-proxy:` image
# (worthless-zij5 / WOR-743).
if ! python3 scripts/check_docs_versions.py "$version"; then
    echo "ERROR: docs/ image pins above don't all match '$version' — tag NOT created."
    echo "  Run ./scripts/bump-version.sh $version (then commit), or fix the listed files."
    exit 1
fi

# Must not already exist locally
if git rev-parse "$tag" >/dev/null 2>&1; then
    echo "ERROR: tag '$tag' already exists locally."
    echo "  If you need to re-tag: git tag -d $tag"
    exit 1
fi

# GPG key must be available
if ! gpg --list-secret-keys "$GPG_FINGERPRINT" >/dev/null 2>&1; then
    echo "ERROR: GPG key $GPG_FINGERPRINT not found in keyring."
    echo "  Import it with: gpg --import <keyfile>"
    exit 1
fi

# PyPI Trusted Publisher must be confirmed for the CURRENT owner.
# publish.yml uploads via OIDC with no token, and PyPI does not follow a GitHub
# account rename — so a rename silently breaks publishing, and the only place
# that surfaces is the release itself (worthless-c478). This is an attestation
# that someone looked, not a proof that the binding works; see the script.
if ! ./scripts/verify-pypi-publisher.sh --check; then
    echo "  Tag NOT created."
    exit 1
fi

echo "Pre-flight OK: on main, pyproject=$version, GPG key present"
echo

# --- 3. Create GPG-signed tag -------------------------------------------------

tag_message="${tag}"
if [ -n "$headline" ]; then
    tag_message="${tag} — ${headline}"
fi

echo "Creating GPG-signed tag $tag ..."
git -c gpg.format=openpgp \
    -c user.signingkey="$GPG_FINGERPRINT" \
    tag -s "$tag" -m "$tag_message"

# --- 4. Verify signature locally before pushing ------------------------------

echo "Verifying signature ..."
if ! git -c gpg.program=gpg verify-tag "$tag" 2>&1; then
    echo "ERROR: local signature verification failed — tag NOT pushed."
    git tag -d "$tag"
    exit 1
fi

echo "Signature OK"
echo

# --- 5. Push tag — triggers the publishers + auto-Release --------------------

echo "Pushing $tag to origin ..."
git push origin "$tag"

echo
echo "Tag pushed. All four publishers (PyPI, npm, GHCR, Cloudflare Worker) are"
echo "now running. When all four genuinely pass, release-notes.yml creates the"
echo "GitHub Release itself — you do not run gh release create (WOR-909)."
echo "Monitor at: https://github.com/oblangatas/worthless/actions"
echo
# WOR-873: the release scans BOTH architectures at severity-cutoff medium, but
# pull requests only ever scan amd64 — arm64 is checked weekly (Monday cron).
# So a release can fail on an arm64 CVE that no PR could have shown you, at the
# worst moment: the tag exists, the image does not, and the documented `docker
# pull` 404s until it is resolved.
echo "IF THE RELEASE FAILS ON A CVE:"
echo "  A fixable Medium+ blocks publish on either architecture. arm64 findings"
echo "  never appear on a PR — that scan runs weekly — so an arm64-only CVE can"
echo "  surface here for the first time."
echo
echo "  A re-run DOES help a transient failure (cosign 5xx, runner error)."
echo "  It does NOT help a CVE finding — that replays the same tree and fails"
echo "  identically. For a CVE:"
echo "    1. Check both architectures at the TAGGED commit — not main, which"
echo "       may already have moved past it:"
echo "       gh workflow run docker-security.yml --ref $tag"
echo "    2. Fix it — bump the pinned base image, or add a dated, argued entry"
echo "       to .grype.yaml. Prefer bumping the base over widening the waiver."
echo "    3. Delete the tag and re-push it at the new commit. That keeps the"
echo "       trigger on refs/tags/v*, which the cosign identity depends on."
echo
echo "YOU MUST APPROVE ONE STEP. Once all four publishers are green, the"
echo "'Create GitHub Release' run pauses for review (the 'release' environment)."
echo "Open Actions, find the waiting run, and click Review deployments → Approve."
echo "The Release page appears right after. Until you approve, it will NOT appear"
echo "— that is the gate working, not a failure."
echo
echo "If a publisher fails, re-run THAT RUN (Actions → the failed run → 'Re-run"
echo "failed jobs'). Do not use 'Run workflow' — a manual dispatch is a different"
echo "event and will not clear the gate. The Release is held until all four are"
echo "green, then created exactly once. (WOR-846)"
echo
# The fallback creates a DRAFT deliberately. Creating a published Release by hand
# bypasses release-fanin.sh, so it can ratify a tag whose PyPI or npm job actually
# failed — and release-notes.yml then sees a Release already exists, skips, and
# reports green forever. The manual path would poison the automated one, silently
# and irreversibly. A draft cannot be mistaken for a shipped release, and
# publishing it is a second, deliberate act by a human who has looked.
#
# The old text said "~15 min". That was wrong in a way that guaranteed the race:
# the release job waits on a protected environment, so no Release after fifteen
# minutes is the NORMAL state for as long as approval takes, not evidence that
# anything failed. Anyone following that timer would hit the hatch on every
# correctly-functioning release.
echo "FALLBACK — only when there is NO waiting run, NO pending approval, and every"
echo "publisher is green, yet no Release exists. That is the automation genuinely"
echo "not firing, and the watchdog files an issue for it. Until then, waiting is"
echo "the correct action. If you do need it, create a DRAFT — never a published"
echo "Release — so it cannot silently ratify a release the robots refused:"
if [ -n "$headline" ]; then
    echo "  gh release create $tag --draft --title \"$tag: $headline\" --verify-tag --generate-notes"
else
    echo "  gh release create $tag --draft --title \"$tag: <headline>\" --verify-tag --generate-notes"
fi
echo "Then look at why the automation did not fire before publishing the draft."

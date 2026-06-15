#!/bin/sh
# tag-release.sh — GPG-sign and push a release tag, then print the gh release command.
#
# NEVER create a GitHub Release before pushing the signed tag.  gh release create
# also creates the git tag (unsigned), which (a) fails the GPG gate in publish.yml
# and (b) tombstones the tag name in GitHub permanently — even after deleting both
# the release and the tag, the name cannot be recreated.  This script enforces the
# correct order:
#
#   1. GPG-sign the tag (openpgp, explicit fingerprint)
#   2. Verify the signature locally
#   3. Push the tag  →  publish.yml fires automatically
#   4. Print the gh release create command to run AFTER CI passes
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

# --- 5. Push tag — triggers publish.yml --------------------------------------

echo "Pushing $tag to origin ..."
git push origin "$tag"

echo
echo "Tag pushed. publish.yml is now running."
echo "Monitor at: https://github.com/shacharm2/worthless/actions"
echo
echo "WAIT for publish.yml to succeed, THEN create the GitHub Release:"
if [ -n "$headline" ]; then
    echo "  gh release create $tag --title \"$tag: $headline\" --generate-notes"
else
    echo "  gh release create $tag --title \"$tag: <headline>\" --generate-notes"
fi
echo
echo "DO NOT run gh release create before publish.yml passes — it creates an"
echo "unsigned tag and tombstones the name permanently."

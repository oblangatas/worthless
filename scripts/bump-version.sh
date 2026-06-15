#!/bin/sh
# bump-version.sh — bump worthless's version in all the places that need it
# atomically. Use BEFORE tagging a release.
#
# v0.3.4 shipped with a CI failure because pyproject.toml was bumped but
# SKILL.md wasn't. v0.3.8 shipped a CI failure because install.sh wasn't
# bumped. This script owns every version string so the tests never have to
# catch a release-day drift.
#
# Usage:
#     ./scripts/bump-version.sh 0.3.5
#     ./scripts/bump-version.sh 1.0.0
#
# What it does:
#   1. Validates the version arg (PEP 440-ish)
#   2. Updates pyproject.toml `version = "X.Y.Z"`
#   3. Updates SKILL.md `**Version**: X.Y.Z`
#   4. Updates install.sh `WORTHLESS_VERSION_PIN="X.Y.Z"`
#   5. Updates packages/worthless-mcp/package.json `"version": "X.Y.Z"`
#   6. Adds a `[X.Y.Z]: https://github.com/...releases/tag/vX.Y.Z` link
#      reference at the bottom of CHANGELOG.md (matches the existing
#      pattern). Does NOT touch the body of CHANGELOG — you still write
#      the release notes by hand or via a future release-please bot.
#   7. Runs `uv sync` so the venv reflects the new version
#   8. Prints a checklist of what to do next
#
# Idempotent: re-running with the same version is a no-op.
# Safe: makes no commits and no tags. You stage and commit yourself.

set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Clean up tempfiles on any exit. Without this, a sed/mv failure under
# `set -eu` would leave pyproject.toml.tmp / SKILL.md.tmp /
# CHANGELOG.md.tmp on disk for the user to clean up manually.
# docs/*.tmp uses find (not a named glob) because doc files live in subdirs
# (docs/install/, etc.) and docs/*.tmp only matches the root level.
trap 'rm -f pyproject.toml.tmp SKILL.md.tmp CHANGELOG.md.tmp install.sh.tmp package.json.tmp; find docs/ -name "*.tmp" -delete 2>/dev/null || true' EXIT

# --- 1. Validate input -------------------------------------------------------

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.3.5"
    exit 1
fi

new_version="$1"

# PEP 440-ish: MAJOR.MINOR.PATCH plus optional pre/dev/post suffix.
# Shell glob `*` matches any chars (so the old `[0-9]*.[0-9]*.[0-9]*`
# would accept `1abc.2.3`). Use a real regex via `grep -E` for actual
# validation.
if ! printf '%s' "$new_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([._-]?(a|b|rc|alpha|beta|dev|post)[0-9]+)?$'; then
    echo "ERROR: '$new_version' doesn't look like a semver/PEP-440 version."
    echo "Examples: 0.3.5 / 1.0.0 / 0.4.0rc1 / 1.2.3.dev1 / 2.0.0.post1"
    exit 1
fi

# --- 2. Discover current version --------------------------------------------

current_version=$(awk -F'"' '/^version =/ { print $2; exit }' pyproject.toml)
if [ -z "$current_version" ]; then
    echo "ERROR: could not parse current version from pyproject.toml"
    exit 1
fi

if [ "$current_version" = "$new_version" ]; then
    echo "Already at version $new_version. Nothing to do."
    exit 0
fi

echo "Bumping: $current_version -> $new_version"
echo

# --- 3. Update pyproject.toml -----------------------------------------------

# Use a tempfile + mv for atomic replace (BSD/GNU sed both work)
sed -E "s|^version = \"$current_version\"|version = \"$new_version\"|" pyproject.toml > pyproject.toml.tmp
mv pyproject.toml.tmp pyproject.toml
echo "  ✓ pyproject.toml: version = \"$new_version\""

# --- 4. Update SKILL.md -----------------------------------------------------

sed -E "s|^- \*\*Version\*\*: $current_version|- **Version**: $new_version|" SKILL.md > SKILL.md.tmp
mv SKILL.md.tmp SKILL.md
echo "  ✓ SKILL.md: **Version**: $new_version"

# --- 4b. Update install.sh version pin -------------------------------------

sed -E "s|^WORTHLESS_VERSION_PIN=\"$current_version\"|WORTHLESS_VERSION_PIN=\"$new_version\"|" install.sh > install.sh.tmp
mv install.sh.tmp install.sh
echo "  ✓ install.sh: WORTHLESS_VERSION_PIN=\"$new_version\""

# --- 4c. Update packages/worthless-mcp/package.json ------------------------

mcp_pkg="packages/worthless-mcp/package.json"
if [ -f "$mcp_pkg" ]; then
    sed -E "s|\"version\": \"$current_version\"|\"version\": \"$new_version\"|" "$mcp_pkg" > package.json.tmp
    mv package.json.tmp "$mcp_pkg"
    echo "  ✓ $mcp_pkg: \"version\": \"$new_version\""
else
    echo "  ⚠ $mcp_pkg not found — skipping npm package version bump"
fi

# --- 4d. Update docs/ Docker image tags ------------------------------------
# Sweeps pinned worthless-proxy:X.Y.Z tags across docs/ so check_docs_versions.py
# passes on the release PR itself rather than waiting for the next 3am cron run.
if [ ! -d docs/ ]; then
    echo "  ⚠ docs/: directory not found — skipping Docker image tag bump"
else
    # --include must come before the path: BSD grep (macOS) ignores it otherwise.
    docs_hits=$(grep -rlF --include="*.md" --include="*.mdx" "worthless-proxy:${current_version}" docs/ || true)
    if [ -n "$docs_hits" ]; then
        # Escape dots on the LHS so the sed pattern treats them as literals.
        escaped_current=$(printf '%s\n' "$current_version" | sed 's/[.]/\\./g')
        for f in $docs_hits; do
            sed -E "s|worthless-proxy:${escaped_current}|worthless-proxy:${new_version}|g" "$f" > "$f.tmp"
            mv "$f.tmp" "$f"
            echo "  ✓ $f: worthless-proxy:$new_version"
        done
    else
        echo "  ⚠ docs/: no pinned worthless-proxy:$current_version tags found — nothing to bump"
    fi
fi

# --- 5. Append CHANGELOG.md link reference ----------------------------------

if grep -q "^\[$new_version\]:" CHANGELOG.md; then
    echo "  ✓ CHANGELOG.md: [$new_version] link reference already present"
else
    # Derive the repo URL from `git remote get-url origin` rather than
    # hardcoding `shacharm2/worthless` — the org/owner can change (today
    # `shacharm2` is a personal account, not a `worthless` org). Falls
    # back to the historical hardcode if origin isn't a recognisable
    # GitHub URL.
    origin_url=$(git remote get-url origin 2>/dev/null || true)
    case "$origin_url" in
        git@github.com:*)
            owner_repo=${origin_url#git@github.com:}
            owner_repo=${owner_repo%.git}
            ;;
        https://github.com/*)
            owner_repo=${origin_url#https://github.com/}
            owner_repo=${owner_repo%.git}
            ;;
        *)
            owner_repo="shacharm2/worthless"
            ;;
    esac
    new_link="[$new_version]: https://github.com/$owner_repo/releases/tag/v$new_version"

    # Find the first existing [X.Y.Z]: link and insert above it
    if grep -q "^\[$current_version\]:" CHANGELOG.md; then
        # Insert the new link just before the current-version link
        sed -E "/^\[$current_version\]: /i\\
$new_link
" CHANGELOG.md > CHANGELOG.md.tmp
        mv CHANGELOG.md.tmp CHANGELOG.md
        echo "  ✓ CHANGELOG.md: added [$new_version] reference link"
    else
        echo "  ⚠ CHANGELOG.md: no existing [$current_version] reference link to anchor against."
        echo "    Appended [$new_version] link at the end. Verify position manually."
        printf '\n%s\n' "$new_link" >> CHANGELOG.md
    fi
fi

# --- 6. Re-sync uv so venv matches ------------------------------------------

if command -v uv >/dev/null 2>&1; then
    echo
    echo "Re-syncing uv ..."
    uv sync --reinstall-package worthless 2>&1 | tail -2
else
    echo "  ⚠ uv not on PATH — skipping uv sync. Re-sync manually before tagging."
fi

# --- 7. Tell the user what's left -------------------------------------------

cat <<EOF

Done. Next steps:

  1. Add a CHANGELOG body for $new_version under '## [Unreleased]'.
     (Convert the existing '## [Unreleased]' header to '## [$new_version] — $(date +%Y-%m-%d)'
     and add a fresh empty '## [Unreleased]' above it.)

  2. Verify:
     git diff pyproject.toml SKILL.md CHANGELOG.md docs/

  3. Run the version-drift test:
     uv run pytest tests/test_skill_md.py::TestVersionDrift -q

  4. Stage, commit (Conventional Commits), push:
     git add pyproject.toml SKILL.md CHANGELOG.md uv.lock install.sh packages/worthless-mcp/package.json docs/
     git commit -m "chore(release): v$new_version"
     git push

  5. After PR merges to main — tag FIRST, release SECOND:
     git checkout main && git pull --rebase
     ./scripts/tag-release.sh $new_version "<headline>"
     # ↑ GPG-signs the tag, verifies it locally, pushes it.
     # publish.yml fires automatically on the push → PyPI + npm.

     # WAIT for publish.yml to pass, then create the GitHub Release:
     # gh release create v$new_version --title "v$new_version: <headline>" --generate-notes
     #
     # WARNING: NEVER run gh release create before pushing the signed tag.
     # gh release create creates an unsigned tag that (a) fails the GPG gate
     # in publish.yml and (b) permanently tombstones the tag name in GitHub.

EOF

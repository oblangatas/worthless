#!/bin/sh
# verify-pypi-publisher.sh — confirm PyPI's Trusted Publisher still matches this
# repo's owner, and record that confirmation for tag-release.sh.
#
# WHY THIS EXISTS
#
# publish.yml uploads to PyPI with OIDC Trusted Publishing and no API token.
# PyPI matches the OIDC claim on repository_owner + repository + workflow
# filename + environment. GitHub emits the CURRENT owner in that claim, and
# PyPI does NOT follow a GitHub account rename:
#
#   "invalid-publisher for a previously-working project ... one example we've
#    seen is when a source repository is renamed, and the configuration on PyPI
#    continues to use the old repository name."
#   -- https://docs.pypi.org/trusted-publishers/troubleshooting/
#
# The account WAS renamed (shacharm2 -> oblangatas, Aug 2026, worthless-c478)
# and nothing exercised the release path afterwards, because publish.yml only
# ever runs on a v* tag push and WOR-892 decided against a rehearsal lane. So a
# broken publisher binding stays invisible until the release it breaks.
#
# WHAT THIS IS NOT
#
# This is an ATTESTATION, not a proof. Trusted Publisher configuration is not
# readable through any public API, and there is no TestPyPI lane here to
# rehearse OIDC against. This script cannot verify anything itself — it walks
# you to the page, tells you exactly what must be there, and records what you
# saw. It defends against FORGETTING to check. It does not defend against
# checking carelessly, and it proves nothing about what PyPI will actually do.
#
# The record it writes is bound to the owner it was confirmed for, so a future
# rename automatically invalidates it rather than silently vouching for the
# wrong account.
#
# Usage:
#     ./scripts/verify-pypi-publisher.sh          # interactive
#     ./scripts/verify-pypi-publisher.sh --check   # exit 1 if unconfirmed; no prompts

set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

RECORD=".pypi-publisher-confirmed"
SETTINGS_URL="https://pypi.org/manage/project/worthless/settings/publishing/"
WORKFLOW="publish.yml"
ENVIRONMENT="pypi"

# Derive owner/repo from origin. Matches bump-version.sh's arms, including the
# `git@<alias>:owner/repo` form used by per-account SSH host aliases.
origin_url=$(git remote get-url origin 2>/dev/null || true)
case "$origin_url" in
    *@*:*/*)       owner_repo=${origin_url##*:}; owner_repo=${owner_repo%.git} ;;
    https://*/*/*) owner_repo=${origin_url#https://*/}; owner_repo=${owner_repo%.git} ;;
    *)             echo "ERROR: cannot derive owner from origin ('$origin_url')."; exit 1 ;;
esac
owner=${owner_repo%%/*}
repo=${owner_repo##*/}

# --- --check mode: used by tag-release.sh's pre-flight ----------------------

if [ "${1:-}" = "--check" ]; then
    if [ ! -f "$RECORD" ]; then
        echo "ERROR: PyPI Trusted Publisher has never been confirmed for this repo."
        echo "  publish.yml uploads with OIDC and no token; if the publisher does not"
        echo "  match owner '$owner', the tag you are about to push fails at upload."
        echo "  Run: ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi
    confirmed_owner=$(awk -F= '/^owner=/ { print $2; exit }' "$RECORD")
    if [ "$confirmed_owner" != "$owner" ]; then
        echo "ERROR: PyPI publisher was confirmed for owner '$confirmed_owner',"
        echo "  but origin now says '$owner'. The account was renamed since that check."
        echo "  PyPI does NOT follow GitHub renames — re-confirm before tagging."
        echo "  Run: ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi
    echo "PyPI publisher: confirmed for '$owner' ($(awk -F= '/^date=/ { print $2; exit }' "$RECORD"))"
    exit 0
fi

# --- Interactive walkthrough ------------------------------------------------

echo
echo "PyPI Trusted Publisher check"
echo "============================"
echo
echo "This cannot be automated: the setting lives behind your PyPI login and is"
echo "not exposed by any public API. Two minutes now, or a failed release later."
echo
echo "STEP 1 — open the publisher settings:"
echo
echo "    $SETTINGS_URL"
echo
if command -v open >/dev/null 2>&1; then
    printf "Open it in your browser now? [Y/n] "
    read -r answer
    case "$answer" in [Nn]*) : ;; *) open "$SETTINGS_URL" ;; esac
fi
echo
echo "STEP 2 — find the list of EXISTING publishers."
echo
echo "  It is usually headed 'Manage current publishers'. Do NOT read the"
echo "  'Add a new publisher' form below it — those fields are always blank and"
echo "  are not your current configuration."
echo
echo "STEP 3 — the existing publisher must read EXACTLY:"
echo
echo "      Owner .............. $owner"
echo "      Repository ......... $repo"
echo "      Workflow ........... $WORKFLOW"
echo "      Environment ........ $ENVIRONMENT"
echo
echo "  'Workflow' includes the .yml extension. 'Environment' is lowercase and"
echo "  must match 'environment: $ENVIRONMENT' in .github/workflows/publish.yml."
echo
echo "IF THE OWNER IS WRONG (e.g. still a previous account name):"
echo
echo "  1. ADD a new publisher with the four values above."
echo "     PyPI allows several publishers per project; adding cannot break the"
echo "     existing one."
echo "  2. Do NOT delete the old publisher yet. It is your rollback if the new"
echo "     binding is wrong. Remove it only after a release has succeeded."
echo
printf "Does an existing publisher now match all four values above? [y/N] "
read -r confirmed
case "$confirmed" in
    [Yy]*) ;;
    *)
        echo
        echo "Not confirmed — nothing recorded."
        echo "tag-release.sh will keep refusing to tag until this passes."
        exit 1
        ;;
esac

cat > "$RECORD" <<EOF
# PyPI Trusted Publisher confirmation — see scripts/verify-pypi-publisher.sh
# An attestation that a human read the PyPI settings page, NOT a proof that
# the binding works. Automatically invalidated if the repo owner changes.
owner=$owner
repo=$repo
workflow=$WORKFLOW
environment=$ENVIRONMENT
date=$(date -u +%Y-%m-%d)
EOF

echo
echo "Recorded in $RECORD — commit it."
echo "tag-release.sh will now allow tagging while origin's owner stays '$owner'."

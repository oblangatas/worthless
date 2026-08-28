#!/bin/sh
# check_repo_owner_live.sh — ask GitHub whether this repo's declared owner is
# still its real one.
#
# WHY THIS EXISTS
#
# worthless-c478 (#546) added two guards against a stale GitHub owner:
# tests/test_repo_owner_refs.py (every reference must match pyproject.toml) and
# release-sync-check's A1c (docs image paths must resolve on GHCR). Both compare
# the repo against ITSELF, and that leaves a hole worthless-jjap was opened for.
#
# A GitHub account rename does not touch anything in the repository. pyproject
# keeps its old URL, every file keeps agreeing with it, and `git remote` keeps
# working because the old URL 301-redirects. So after a rename that nobody has
# applied, the static guard is GREEN, the remote is GREEN, and meanwhile
# ghcr.io/<old-owner>/worthless-proxy returns 403 for every user, because
# registries do NOT redirect a renamed account's packages.
#
# The guards catch a PARTIAL rename (some refs updated, some not) -- which is
# what actually happened in c478. They cannot see a total one. This closes that.
#
# HOW
#
# `gh api repos/<owner>/<repo>` follows the rename redirect and reports the
# CURRENT full_name. So asking GitHub about the owner we have on file is itself
# the detector: if the answer differs from what we asked, the account moved.
#
#     gh api repos/shacharm2/worthless --jq .full_name  ->  oblangatas/worthless
#
# FAILURE SEMANTICS -- deliberately asymmetric:
#   * GitHub answers and DISAGREES  -> exit 1. A definite rename must block.
#   * GitHub answers and agrees     -> exit 0.
#   * GitHub cannot be reached, or `gh` is missing -> exit 0 with a warning.
#     An unknown is not a disagreement. Blocking a release on a network blip
#     would be worse than the rare rename this catches.
#
# WHERE THIS RUNS: tag time only, via verify-pypi-publisher.sh --check, which
# tag-release.sh gates on. It used to also run daily as release-sync-check's
# A1d; that was removed as redundant -- A1c already fails on a total rename,
# because the docs keep naming the old owner and GHCR then refuses the pull.
# PyPI has no equivalent symptom to trip over, which is why the tag-time call
# stays.
#
# Usage:
#     ./scripts/check_repo_owner_live.sh          # human output
#     ./scripts/check_repo_owner_live.sh --quiet  # only speak on problems

set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

quiet=0
[ "${1:-}" = "--quiet" ] && quiet=1

say() { [ "$quiet" -eq 1 ] || echo "$@"; }

# Declared identity: pyproject.toml is the single source of truth the static
# guard already enforces every other reference against.
repo_url=$(sed -n 's/^Repository *= *"\(.*\)"/\1/p' pyproject.toml | head -n1)
declared=$(printf '%s' "$repo_url" | sed -E 's#^https://github\.com/##; s#/*$##')

if ! printf '%s' "$declared" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
    echo "ERROR: cannot read owner/repo from pyproject.toml [project.urls] Repository ('$repo_url')."
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    # Not `say`: --quiet is how the tag gate calls this, and an unverified owner
    # must never be silent there. --quiet suppresses the SUCCESS line only.
    echo "WARNING: gh not installed — cannot confirm '$declared' is still the live owner."
    echo "  A rename that nobody applied to this repo would be invisible here."
    exit 0
fi

# `|| true` so an API/network failure lands in the unknown branch below rather
# than tripping `set -e` and reading as a disagreement.
#
# CRITICAL: `gh api` writes HTTP-error BODIES to stdout, not stderr, and skips
# --jq on an error response. A 404 (repo deleted, or a token without access to a
# private repo), a 401, or a secondary rate-limit all yield a captured value like
#   {"message":"Not Found","status":"404"}
# So an empty-string check is NOT enough: without the shape test below, any of
# those compares unequal to the declared owner and hard-BLOCKS a release while
# telling the operator to set their repo URL to a JSON blob. Validate the shape
# and treat anything else as unknown.
actual=$(gh api "repos/$declared" --jq '.full_name' 2>/dev/null || true)

if ! printf '%s' "$actual" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
    # --quiet must NOT suppress this: the tag gate calls with --quiet, and a
    # silent unknown there is the one place the check most needs to speak.
    echo "WARNING: GitHub did not return a usable answer for '$declared' — unconfirmed."
    echo "  (no network, gh unauthenticated, rate-limited, or the repo is inaccessible)"
    echo "  Treating an unknown as OK on purpose; an outage must not wedge a release."
    exit 0
fi

if [ "$actual" != "$declared" ]; then
    echo "::error title=Repo owner moved::pyproject.toml declares '$declared' but GitHub now reports '$actual'."
    echo
    echo "The GitHub account or repository was renamed and this repo was never updated."
    echo "Nothing in the repo can notice this on its own: the old URL 301-redirects, so"
    echo "pyproject, every reference, and 'git remote' all still agree with each other."
    echo
    echo "What is ALREADY broken for users while this is true:"
    echo "  * ghcr.io/${declared%%/*}/worthless-proxy returns 403 — registries do not"
    echo "    redirect a renamed account's packages, so every documented docker pull fails."
    echo "  * PyPI Trusted Publishing matches on repository_owner and does not follow"
    echo "    renames, so the next v* tag fails at upload with invalid-publisher."
    echo
    echo "Fix: update [project.urls] Repository in pyproject.toml to"
    echo "  https://github.com/$actual"
    echo "then run the full test suite — tests/test_repo_owner_refs.py will list every"
    echo "other reference that needs to follow, and re-confirm the PyPI publisher with"
    echo "  ./scripts/verify-pypi-publisher.sh"
    exit 1
fi

say "Repo owner: '$declared' confirmed live with GitHub."

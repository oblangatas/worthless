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
# The record is bound to the owner it was confirmed for, and --check compares it
# against pyproject.toml -- so it fires as soon as a rename lands in the repo.
# check_repo_owner_live.sh covers the case where the rename never landed at all.
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

# Owner/repo come from pyproject.toml's [project.urls] Repository — the same
# single source of truth tests/test_repo_owner_refs.py enforces repo-wide.
#
# This deliberately does NOT read `git remote get-url origin`. A git remote does
# not update itself when a GitHub account is renamed (the old URL keeps working
# via 301), so a remote-anchored check compares stale to stale, agrees, and lets
# the tag through. pyproject is the artifact a rename actually has to touch, and
# the static guard fails the build until every other reference matches it — so
# the moment a rename lands in the repo, this attestation stops matching and
# --check demands a re-confirmation.
#
# A rename that nobody applied anywhere used to be invisible here -- pyproject
# would be stale, everything would agree with it, and --check would pass.
# scripts/check_repo_owner_live.sh now runs first and asks GitHub who this repo
# actually is (worthless-jjap). A definite disagreement blocks; an unreachable
# API only warns, so a network blip cannot wedge a release.
repo_url=$(sed -n 's/^Repository *= *"\(.*\)"/\1/p' pyproject.toml | head -n1)
owner_repo=$(printf '%s' "$repo_url" | sed -E 's#^https://github\.com/##; s#/*$##')
if ! printf '%s' "$owner_repo" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
    echo "ERROR: cannot read owner/repo from pyproject.toml [project.urls] Repository ('$repo_url')."
    exit 1
fi
owner=${owner_repo%%/*}
repo=${owner_repo##*/}

# --- --check mode: used by tag-release.sh's pre-flight ----------------------

if [ "${1:-}" = "--check" ]; then
    # Before comparing the attestation to pyproject, confirm pyproject itself is
    # not stale. Everything below compares the repo against itself, so a rename
    # that nobody applied would agree with itself and pass (worthless-jjap).
    # A definite disagreement exits 1; an unreachable API only warns.
    if ! ./scripts/check_repo_owner_live.sh --quiet; then
        echo "  PyPI publisher cannot be trusted while the declared owner is stale."
        exit 1
    fi
    if [ ! -f "$RECORD" ]; then
        echo "ERROR: PyPI Trusted Publisher has never been confirmed for this repo."
        echo "  publish.yml uploads with OIDC and no token; if the publisher does not"
        echo "  match owner '$owner' (from pyproject.toml), the tag fails at upload."
        echo "  Run: ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi
    confirmed_owner=$(awk -F= '/^owner=/ { print $2; exit }' "$RECORD")
    if [ "$confirmed_owner" != "$owner" ]; then
        echo "ERROR: PyPI publisher was confirmed for owner '$confirmed_owner',"
        echo "  but pyproject.toml now says '$owner'. The owner changed since that check."
        echo "  PyPI does NOT follow GitHub renames — re-confirm before tagging."
        echo "  Run: ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi
    # The attestation names four fields; PyPI matches on all four. Comparing
    # only the owner leaves the likelier drifts invisible: renaming the workflow
    # file, or changing `environment:` in it, breaks the binding while this
    # check keeps passing (raised on #546, folded in here per worthless-jjap).
    confirmed_workflow=$(awk -F= '/^workflow=/ { print $2; exit }' "$RECORD")
    confirmed_env=$(awk -F= '/^environment=/ { print $2; exit }' "$RECORD")

    if [ -z "$confirmed_workflow" ] || [ -z "$confirmed_env" ]; then
        echo "ERROR: $RECORD predates field checking (no workflow=/environment= lines)."
        echo "  Re-confirm so the record covers everything PyPI matches on:"
        echo "  ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi

    workflow_path=".github/workflows/$confirmed_workflow"
    if [ ! -f "$workflow_path" ]; then
        echo "ERROR: the attestation names workflow '$confirmed_workflow', which does not exist."
        echo "  PyPI matches the OIDC claim on the workflow FILENAME. If it was renamed,"
        echo "  the publisher on PyPI must be updated to match or the upload fails."
        exit 1
    fi

    # The environment the publish job actually requests, read from the workflow.
    actual_env=$(awk '/^[[:space:]]+environment:[[:space:]]/ { print $2; exit }' "$workflow_path")
    if [ -z "$actual_env" ]; then
        echo "ERROR: $workflow_path declares no 'environment:' — cannot confirm the binding."
        echo "  PyPI matches on it; a publisher configured with one will not match a job without."
        exit 1
    fi
    if [ "$actual_env" != "$confirmed_env" ]; then
        echo "ERROR: attestation says environment '$confirmed_env' but $workflow_path"
        echo "  now requests '$actual_env'. PyPI matches on this exactly — the next"
        echo "  v* tag fails at upload with invalid-publisher."
        echo "  Update the publisher on PyPI, then re-confirm:"
        echo "  ./scripts/verify-pypi-publisher.sh"
        exit 1
    fi

    echo "PyPI publisher: confirmed for '$owner' ($(awk -F= '/^date=/ { print $2; exit }' "$RECORD"))"
    echo "  workflow=$confirmed_workflow environment=$confirmed_env — both still match $workflow_path"
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
# the binding works. Invalidated when origin's owner changes -- which requires
# someone to repoint the remote; a rename alone does not trigger it.
owner=$owner
repo=$repo
workflow=$WORKFLOW
environment=$ENVIRONMENT
date=$(date -u +%Y-%m-%d)
EOF

echo
echo "Recorded in $RECORD — commit it."
echo "tag-release.sh will now allow tagging while origin's owner stays '$owner'."

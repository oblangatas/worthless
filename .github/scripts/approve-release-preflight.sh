#!/usr/bin/env bash
# Preflight for approve-release.yml (WOR-1167). Runs with the job's own
# GITHUB_TOKEN, before the owner is asked to approve `release-approver`.
#
# It shows the owner what the PAT is about to approve: the tag's full commit,
# GitHub's check of the tag signature, and every run waiting on an environment,
# each marked OK or WILL NOT BE APPROVED. The owner reads this summary, then taps
# Approve. It reads only; it approves nothing. The tag's signature is verified
# against the pinned maintainer key by a separate step of the same job, before
# this one. Pinned by TestApproveReleaseWiring in tests/test_deploy_static.py.
#
# Inputs (env): TAG, GH_REPO, GH_TOKEN, REF, ACTOR, OWNER. Writes the summary
# to $GITHUB_STEP_SUMMARY and `commit=<sha>` to $GITHUB_OUTPUT.
#
# The verdicts are NOT decided here: `scripts/approve-release.sh --list` runs the
# approve path's own selection and prints them. It also waits (up to
# PREFLIGHT_WAIT_MIN) until the three gated publishers reach their approval step,
# so the approve job's 80 minutes start with the gates present.
#
# What it does NOT do: it is a snapshot. The Create GitHub Release run only
# appears after the publishers finish, so it is usually not listed yet.
set -euo pipefail

readonly PREFLIGHT_WAIT_MIN=15

: "${TAG:?TAG is required}" "${GH_REPO:?GH_REPO is required}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
output="${GITHUB_OUTPUT:-/dev/null}"

# The approve job is skipped by its `if:` in these cases. Fail here so the run
# is red with a reason, instead of a quiet grey skip.
if [ "${REF:-}" != "refs/heads/main" ]; then
  echo "::error::run Approve release from main, not ${REF:-<unset>}. The approve job will be skipped."
  exit 1
fi
if [ -z "${OWNER:-}" ] || [ "${ACTOR:-}" != "$OWNER" ]; then
  echo "::error::only the repository owner may run Approve release. The approve job will be skipped."
  exit 1
fi

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::tag must look like v1.2.3"
  exit 1
fi

if [ ! -f scripts/approve-release.sh ]; then
  echo "::error::scripts/approve-release.sh is missing from this checkout of main."
  exit 1
fi

notes=""

# release-approver is the one gate in front of the PAT. Its settings live in the
# UI, so check them here: a required reviewer, and deployments from main only.
# Read with GITHUB_TOKEN (actions: read). If it cannot be read, warn and go on.
check_approver_env() {
  local env_json reviewers custom policies
  if ! env_json=$(gh api "repos/$GH_REPO/environments/release-approver" 2>/dev/null) ||
    ! policies=$(gh api "repos/$GH_REPO/environments/release-approver/deployment-branch-policies" \
      --jq '[.branch_policies[]? | "\(.type // "branch"):\(.name)"] | sort | join(",")
            | gsub("[[:cntrl:]]"; "")' 2>/dev/null); then
    echo "::warning::could not read the release-approver environment settings; check them by hand (RELEASING.md)"
    notes+="**WARNING:** could not read the \`release-approver\` settings. Check by hand that it has you as required reviewer and deploys from \`main\` only."$'\n\n'
    return 0
  fi
  reviewers=$(jq '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?] | length' <<<"$env_json")
  if [ "$reviewers" -lt 1 ]; then
    echo "::error::release-approver has no required reviewer, so nothing stands between this run and the PAT. Add yourself (RELEASING.md)."
    exit 1
  fi
  custom=$(jq -r '.deployment_branch_policy.custom_branch_policies // false' <<<"$env_json")
  if [ "$custom" != true ] || [ "$policies" != "branch:main" ]; then
    echo "::error::release-approver must deploy from main only (Selected branches and tags: main). Found: ${policies:-any branch}."
    exit 1
  fi
}
check_approver_env

# Resolve the tag to its commit. An annotated tag points at a tag object, which
# points at the commit; peel until we reach it (bounded, in case of a loop).
# The first tag object carries GitHub's signature check; it is shown, not enforced
# (the pinned-key check in the step before this is the gate).
ref=$(gh api "repos/$GH_REPO/git/ref/tags/$TAG")
type=$(jq -r .object.type <<<"$ref")
sha=$(jq -r .object.sha <<<"$ref")
sig="none"
sig_reason="lightweight tag, no tag object"
for _ in 1 2 3 4 5; do
  [ "$type" = tag ] || break
  obj=$(gh api "repos/$GH_REPO/git/tags/$sha")
  if [ "$sig" = none ]; then
    sig=$(jq -r 'if .verification.verified == true then "verified" else "unverified" end' <<<"$obj")
    sig_reason=$(jq -r '.verification.reason // "unknown" | gsub("[^a-z_]"; "")' <<<"$obj")
  fi
  type=$(jq -r .object.type <<<"$obj")
  sha=$(jq -r .object.sha <<<"$obj")
done
if [ "$type" != commit ] || ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::$TAG does not resolve to a commit"
  exit 1
fi

# The approve path's own verdicts. Exit codes are approve-release.sh's.
rc=0
list_out=$(bash scripts/approve-release.sh "$TAG" --list --expect-sha "$sha" \
  --timeout-min "$PREFLIGHT_WAIT_MIN" 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$list_out"
  case "$rc" in
    2) echo "::error::the publisher runs for $TAG did not all reach their approval step within ${PREFLIGHT_WAIT_MIN} min. Run Approve release again once they are waiting." ;;
    4) echo "::error::a GitHub call failed while listing what is waiting. Run Approve release again." ;;
    *) echo "::error::approve-release.sh --list stopped (exit $rc); nothing will be approved. See the lines above." ;;
  esac
  exit 1
fi
echo "commit=$sha" >>"$output"

# Markdown table cell: escape backslashes first, then pipes, so a name ending in
# `\` cannot turn the next `|` back into a column break.
md() {
  local s=${1//\\/\\\\}
  printf '%s' "${s//|/\\|}"
}

{
  echo "## Approve release $TAG"
  echo
  echo "Tag commit (all 40 characters): \`$sha\`"
  echo
  echo "Compare it in full with \`git rev-parse ${TAG}^{commit}\` on your machine before you approve."
  echo
  if [ "$sig" = verified ]; then
    echo "Tag signature: verified by GitHub (\`$sig_reason\`)."
  else
    echo "**WARNING: GitHub does not verify this tag's signature** (\`$sig_reason\`). The pinned-key check passed, so check the key on your own machine before you approve."
  fi
  echo
  printf '%s' "$notes"
  echo "| Run | Event | Head commit | Waiting on | Verdict |"
  echo "| --- | --- | --- | --- | --- |"
} >>"$summary"

n=0
while IFS=$'\x1f' read -r kind verdict env name url event head why; do
  [ "$kind" = row ] || continue
  if [ "$verdict" = ok ]; then
    v="OK"
  else
    v="**WILL NOT BE APPROVED** ($(md "$why"))"
  fi
  echo "| [$(md "$name")]($url) | $(md "$event") | \`$head\` | $(md "$env") | $v |" >>"$summary"
  n=$((n + 1))
done <<<"$list_out"

if [ "$n" -eq 0 ]; then
  echo "No run is waiting for approval yet. The approver waits for them." >>"$summary"
fi

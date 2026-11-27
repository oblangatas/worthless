#!/usr/bin/env bash
# Preflight for approve-release.yml (WOR-1167). Runs with the job's own
# GITHUB_TOKEN, before the owner is asked to approve `release-approver`.
#
# It shows the owner what the PAT is about to approve: the tag's commit and
# every run waiting on an environment, each marked OK or WILL NOT BE APPROVED.
# The owner reads this summary, then taps Approve. It reads only; it approves
# nothing. Pinned by TestApproveReleaseWiring in tests/test_deploy_static.py.
#
# Inputs (env): TAG, GH_REPO, GH_TOKEN, REF, ACTOR, OWNER. Writes the summary
# to $GITHUB_STEP_SUMMARY and `commit=<sha>` to $GITHUB_OUTPUT.
#
# The verdicts use scripts/approve-release.sh's own rules:
#   - a publisher run is a `push` on the tag's branch, at the tag's commit,
#     waiting only on the ONE environment its workflow owns (GATE_MAP below,
#     a copy of the script's; a test keeps them equal);
#   - the release run is release-notes.yml's `workflow_run` with the exact
#     "<prefix> <tag> <commit>" title, waiting only on `release`;
#   - anything else is never approved.
#
# What it does NOT do: it is a snapshot. The Create GitHub Release run only
# appears after the publishers finish, so it is usually not listed yet. The
# script, not this summary, decides what is approved.
set -euo pipefail

# release-notes.yml titles its runs "<prefix> <tag> <sha>" (its run-name).
readonly RELEASE_RUN_TITLE_PREFIX="Create GitHub Release"
readonly RELEASE_WORKFLOW="release-notes.yml"
readonly RELEASE_ENV="release"
# workflow file | workflow name | the one environment it may be approved for.
readonly GATE_MAP="publish.yml|Publish to PyPI|pypi
publish-npm.yml|Publish worthless-mcp to npm|npm-publish
deploy-worker.yml|Deploy Worker (worthless-sh)|worthless-sh-production"

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

gate_env() {
  local f n e
  while IFS='|' read -r f n e; do
    if [ "$f" = "$1" ] && [ "$n" = "$2" ]; then
      echo "$e"
      return 0
    fi
  done <<<"$GATE_MAP"
  return 1
}

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
# The first tag object carries GitHub's signature check; it is shown, not enforced.
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
echo "commit=$sha" >>"$output"

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
    echo "**WARNING: GitHub does not verify this tag's signature** (\`$sig_reason\`). Approve only if you checked the tag on your own machine."
  fi
  echo
  printf '%s' "$notes"
  echo "| Run | Event | Head commit | Waiting on | Verdict |"
  echo "| --- | --- | --- | --- | --- |"
} >>"$summary"

# \x1f, not tab: read collapses consecutive whitespace separators, so an empty
# field (a null head_branch) would shift every field after it. Control
# characters are stripped first: they could forge a separator or a line.
runs=$(gh api --paginate "repos/$GH_REPO/actions/runs?status=waiting&per_page=100" \
  --jq '.workflow_runs[] | [.id, .name, (.path // "" | split("/") | last), .event,
        .head_branch, .head_sha, .display_title, .html_url]
        | map(. // "" | tostring | gsub("[[:cntrl:]]"; "")) | join("\u001f")')

# approve-release.sh approves only the NEWEST push run per publisher workflow at
# the tag's commit, from every run on the tag (any status). Same list here.
tag_runs=$(gh api --paginate "repos/$GH_REPO/actions/runs?branch=$TAG&per_page=100" \
  --jq '.workflow_runs[] | select(.event == "push")
        | [(.path // "" | split("/") | last), .head_sha, .id] | map(tostring) | join(" ")')
newest_of() {
  awk -v w="$1" -v s="$sha" '$1 == w && $2 == s && $3 + 0 > m { m = $3 + 0 } END { print m + 0 }' \
    <<<"$tag_runs"
}

n=0
while IFS=$'\x1f' read -r id name wf event branch head title url; do
  [ -n "$id" ] || continue
  envs=$(gh api "repos/$GH_REPO/actions/runs/$id/pending_deployments" \
    --jq '[.[].environment.name] | join(", ") | gsub("[[:cntrl:]]"; "")')
  why=""
  expected=""
  if [ "$event" = push ]; then
    expected=$(gate_env "$wf" "$name") || why="not a release publisher"
    [ -n "$why" ] || [ "$branch" = "$TAG" ] || why="not this tag's push"
    [ -n "$why" ] || [ "$head" = "$sha" ] || why="a different commit"
    [ -n "$why" ] || [ "$id" = "$(newest_of "$wf")" ] || why="older run, will not be approved"
  elif [ "$event" = workflow_run ] && [ "$wf" = "$RELEASE_WORKFLOW" ]; then
    expected=$RELEASE_ENV
    [ "$title" = "$RELEASE_RUN_TITLE_PREFIX $TAG $sha" ] || why="a release run for another tag"
  else
    why="a $event run is never approved"
  fi
  if [ -z "$why" ]; then
    [ -n "$envs" ] || why="nothing pending"
    while read -r e; do
      [ -z "$e" ] || [ "$e" = "$expected" ] || why="waits on $e, not $expected"
    done < <(printf '%s\n' "$envs" | tr ',' '\n' | tr -d ' ')
  fi
  if [ -z "$why" ]; then
    verdict="OK"
  else
    verdict="**WILL NOT BE APPROVED** ($why)"
  fi
  # A `|` in a name would start a new table cell; escape it for Markdown.
  name_md=${name//|/\\|}
  envs_md=${envs//|/\\|}
  echo "| [$name_md]($url) | $event | \`${head:0:12}\` | $envs_md | $verdict |" >>"$summary"
  n=$((n + 1))
done <<<"$runs"

if [ "$n" -eq 0 ]; then
  echo "No run is waiting for approval yet. The approver waits for them." >>"$summary"
fi

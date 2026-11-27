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

# Resolve the tag to its commit. An annotated tag points at a tag object, which
# points at the commit; peel until we reach it (bounded, in case of a loop).
ref=$(gh api "repos/$GH_REPO/git/ref/tags/$TAG")
type=$(jq -r .object.type <<<"$ref")
sha=$(jq -r .object.sha <<<"$ref")
for _ in 1 2 3 4 5; do
  [ "$type" = tag ] || break
  obj=$(gh api "repos/$GH_REPO/git/tags/$sha")
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
  echo "Tag commit: \`$sha\`"
  echo
  echo "Compare with \`git rev-parse ${TAG}^{commit}\` on your machine before you approve."
  echo
  echo "| Run | Event | Head commit | Waiting on | Verdict |"
  echo "| --- | --- | --- | --- | --- |"
} >>"$summary"

# \x1f, not tab: read collapses consecutive whitespace separators, so an empty
# field (a null head_branch) would shift every field after it.
runs=$(gh api --paginate "repos/$GH_REPO/actions/runs?status=waiting&per_page=100" \
  --jq '.workflow_runs[] | [.id, .name, (.path // "" | split("/") | last), .event,
        .head_branch, .head_sha, .display_title, .html_url]
        | map(. // "" | tostring) | join("\u001f")')

n=0
while IFS=$'\x1f' read -r id name wf event branch head title url; do
  [ -n "$id" ] || continue
  envs=$(gh api "repos/$GH_REPO/actions/runs/$id/pending_deployments" \
    --jq '[.[].environment.name] | join(", ")')
  why=""
  expected=""
  if [ "$event" = push ]; then
    expected=$(gate_env "$wf" "$name") || why="not a release publisher"
    [ -n "$why" ] || [ "$branch" = "$TAG" ] || why="not this tag's push"
    [ -n "$why" ] || [ "$head" = "$sha" ] || why="a different commit"
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
  echo "| [$name]($url) | $event | \`${head:0:12}\` | $envs | $verdict |" >>"$summary"
  n=$((n + 1))
done <<<"$runs"

if [ "$n" -eq 0 ]; then
  echo "No run is waiting for approval yet. The approver waits for them." >>"$summary"
fi

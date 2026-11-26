#!/usr/bin/env bash
# Preflight for approve-release.yml (WOR-1167). Runs with the job's own
# GITHUB_TOKEN, before the owner is asked to approve `release-approver`.
#
# It shows the owner what the PAT is about to approve: the tag's commit and
# every run waiting on an environment, each marked OK or WILL NOT BE APPROVED.
# The owner reads this summary, then taps Approve. It reads only; it approves
# nothing. Pinned by TestApproveReleaseWiring in tests/test_deploy_static.py.
#
# Inputs (env): TAG, GH_REPO, GH_TOKEN. Writes the summary to
# $GITHUB_STEP_SUMMARY and `commit=<sha>` to $GITHUB_OUTPUT.
#
# What it does NOT do: it is a snapshot. The Create GitHub Release run only
# appears after the publishers finish, so it is usually not listed yet. The
# verdicts mirror approve-release.sh's filtering (WOR-1165: environment name,
# event, head_sha, release-run title); the script, not this summary, decides
# what is approved.
set -euo pipefail

# release-notes.yml titles its runs "<prefix> <tag> <sha>" (its run-name).
readonly RELEASE_RUN_TITLE_PREFIX="Create GitHub Release"

: "${TAG:?TAG is required}" "${GH_REPO:?GH_REPO is required}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
output="${GITHUB_OUTPUT:-/dev/null}"

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::tag must look like v1.2.3"
  exit 1
fi

if [ ! -f scripts/approve-release.sh ]; then
  echo "::error::scripts/approve-release.sh is missing. This workflow needs WOR-1165 merged first."
  exit 1
fi

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

runs=$(gh api --paginate "repos/$GH_REPO/actions/runs?status=waiting&per_page=100" \
  --jq '.workflow_runs[] | [.id, .name, .event, .head_sha, .display_title, .html_url] | @tsv')

n=0
while IFS=$'\t' read -r id name event head title url; do
  [ -n "$id" ] || continue
  envs=$(gh api "repos/$GH_REPO/actions/runs/$id/pending_deployments" \
    --jq '[.[].environment.name] | join(", ")')
  # Same rules as approve-release.sh (WOR-1165): only the four release
  # environments, push runs at the tag's commit, and the release run by title.
  env_ok=no
  [ -n "$envs" ] && env_ok=yes
  while read -r e; do
    case "$e" in pypi | npm-publish | worthless-sh-production | release) ;; *) env_ok=no ;; esac
  done < <(printf '%s\n' "$envs" | tr ',' '\n' | tr -d ' ')
  if [ "$env_ok" != yes ]; then
    verdict="**WILL NOT BE APPROVED**"
  elif [ "$event" = push ] && [ "$head" = "$sha" ]; then
    verdict="OK"
  elif [ "$event" = workflow_run ] && [ "$title" = "$RELEASE_RUN_TITLE_PREFIX $TAG $sha" ]; then
    # The release run runs from main, so its head is main's tip, not the tag.
    # Its title is the only link to the tag.
    verdict="OK (release run for this tag)"
  else
    verdict="**WILL NOT BE APPROVED**"
  fi
  echo "| [$name]($url) | $event | \`${head:0:12}\` | $envs | $verdict |" >>"$summary"
  n=$((n + 1))
done <<<"$runs"

if [ "$n" -eq 0 ]; then
  echo "No run is waiting for approval yet. The approver waits for them." >>"$summary"
fi

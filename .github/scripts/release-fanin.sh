#!/usr/bin/env bash
# release-fanin.sh — emit ready=true only when ALL publishers succeeded for this tag.
# WOR-846. Called by release-notes.yml on each publisher's workflow_run completion.
#
# The four publishers run as independent workflows on the same v* tag push, so
# `needs:` can't wait for them. This gate re-fires on each completion and asks the
# API: has every publisher got a successful run at THIS exact head_sha? Matching by
# workflow-file basename (not display name, which edits freely) on the sha means a
# stale/older run can't satisfy the gate. A failed or cancelled leg holds the
# release (ready=false + ::warning) rather than shipping a Release that claims a
# success that didn't happen.
#
# Reads from environment (set by the job): GH_TOKEN, GH_REPO, TAG, HEAD_SHA.
set -euo pipefail

PUBLISHERS="publish.yml publish-npm.yml publish-docker.yml deploy-worker.yml"
ready=true

for wf in $PUBLISHERS; do
  runs=$(gh api "/repos/${GH_REPO}/actions/workflows/${wf}/runs" \
    -f event=push -f branch="${TAG}" --paginate \
    --jq "[.workflow_runs[] | select(.head_sha==\"${HEAD_SHA}\")]")
  ok=$(printf '%s' "$runs" | jq '[.[] | select(.conclusion=="success")] | length')
  bad=$(printf '%s' "$runs" | jq '[.[] | select(.conclusion=="failure" or .conclusion=="cancelled" or .conclusion=="timed_out")] | length')
  if [ "$ok" -lt 1 ]; then
    ready=false
    if [ "$bad" -ge 1 ]; then
      echo "::warning title=Release held::${wf} did not succeed for ${TAG} — Release NOT created. Re-run that workflow to release."
    else
      echo "::notice::${wf} has no successful run yet for ${TAG} — waiting for a later completion."
    fi
  fi
done

echo "ready=${ready}" >>"$GITHUB_OUTPUT"

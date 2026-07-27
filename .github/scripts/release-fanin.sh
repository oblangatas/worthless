#!/usr/bin/env bash
# release-fanin.sh — emit ready=true only when ALL publishers succeeded for this tag,
# and fail LOUD (non-zero) when one of them finished without success. WOR-846.
# Called by release-notes.yml on each publisher's workflow_run completion.
#
# The four publishers run as independent workflows on the same v* tag push, so
# `needs:` can't wait for them. This gate re-fires on each completion and asks the
# API: has every publisher got a successful run at THIS exact head_sha? Matching by
# workflow-file basename (not display name, which edits freely) on the sha means a
# stale/older run can't satisfy the gate.
#
# Three states per publisher, not two:
#   * a SUCCESS run exists                  → this leg is done.
#   * a run finished WITHOUT success        → this leg failed. Matching on
#     `status=="completed" && conclusion!="success"` catches every terminal
#     non-success (failure, cancelled, timed_out, startup_failure, skipped,
#     stale, neutral, …) rather than a hand-listed few that silently misses one.
#   * only in-progress/queued runs, or none → still waiting; a later firing decides.
#
# A finished-without-success leg makes this script exit 1 so the release-notes run
# goes RED and GitHub actually notifies the maintainer — a held release must never
# sit green and silent (they were told to push the tag and walk away). A merely
# in-progress leg is not a failure and exits 0.
#
# Reads from environment (set by the job): GH_TOKEN, GH_REPO, TAG, HEAD_SHA.
set -euo pipefail

PUBLISHERS="publish.yml publish-npm.yml publish-docker.yml deploy-worker.yml"
ready=true
blocked=false

for wf in $PUBLISHERS; do
  # -X GET is REQUIRED: `gh api` silently switches to POST as soon as any -f field
  # is present, and there is no POST route for .../runs — it 404s, which under
  # `set -e` aborts the whole script and the Release is never created. Verified
  # against the live API on v0.3.10. Do not remove -X GET.
  runs=$(gh api "/repos/${GH_REPO}/actions/workflows/${wf}/runs" -X GET -f event=push -f branch="${TAG}")
  ok=$(printf '%s' "$runs" | jq --arg sha "$HEAD_SHA" \
    '[.workflow_runs[] | select(.head_sha==$sha and .conclusion=="success")] | length')
  bad=$(printf '%s' "$runs" | jq --arg sha "$HEAD_SHA" \
    '[.workflow_runs[] | select(.head_sha==$sha and .status=="completed" and .conclusion!="success")] | length')
  if [ "$ok" -lt 1 ]; then
    ready=false
    if [ "$bad" -ge 1 ]; then
      blocked=true
      echo "::warning title=Release held::${wf} finished without success for ${TAG} — Release NOT created. Re-run that workflow to release."
    else
      echo "::notice::${wf} has no successful run yet for ${TAG} — waiting for it to finish."
    fi
  fi
done

echo "ready=${ready}" >>"$GITHUB_OUTPUT"

if [ "$blocked" = "true" ]; then
  echo "::error title=Release blocked::A publisher finished without success for ${TAG}; the GitHub Release was not created. Re-run the failed workflow(s)."
  exit 1
fi

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

# Jobs allowed to be non-green without holding the Release, as "<workflow>::<job>",
# semicolon-separated. Keyed by workflow AND job name so an excuse cannot leak to a
# different workflow that happens to name a job the same way.
#
# publish-docker.yml sets continue-on-error on this job itself, with the stated
# reason that a visibility failure "keeps the RELEASE green (publish itself already
# succeeded)". It genuinely failed on the real v0.3.12 while the image remained
# publicly pullable. Blocking here would override a decision made deliberately in
# that file; if that decision changes, remove continue-on-error there — not here.
JOB_EXCUSES="publish-docker.yml::Flip GHCR package visibility to public"
ready=true
blocked=false

for wf in $PUBLISHERS; do
  # -X GET is REQUIRED: `gh api` silently switches to POST as soon as any -f field
  # is present, and there is no POST route for .../runs — it 404s, which under
  # `set -e` aborts the whole script and the Release is never created. Verified
  # against the live API on v0.3.10. Do not remove -X GET.
  # per_page=100: the default is 30. A hot tag with re-runs can push the
  # successful run past that window, and the gate then never clears — no
  # Release, and no alarm either, which is the exact silent failure this
  # whole workflow exists to remove. The jobs query below already pages.
  runs=$(gh api "/repos/${GH_REPO}/actions/workflows/${wf}/runs" -X GET -f event=push -f branch="${TAG}" -f per_page=100)
  ok=$(printf '%s' "$runs" | jq --arg sha "$HEAD_SHA" \
    '[.workflow_runs[] | select(.head_sha==$sha and .conclusion=="success")] | length')
  bad=$(printf '%s' "$runs" | jq --arg sha "$HEAD_SHA" \
    '[.workflow_runs[] | select(.head_sha==$sha and .status=="completed" and .conclusion!="success")] | length')
  # A run's conclusion is not the whole truth. A job marked continue-on-error can
  # be RED while the run reports success — publish-docker.yml does exactly that for
  # its visibility job, deliberately. So a green run still has to have its jobs
  # inspected before it counts as "really passed" (WOR-909 requirement 1).
  #
  # Allowlist by EXCEPTION, never enumeration. deploy-worker.yml's reusable-workflow
  # calls report as "<caller job> / <callee job>", and the callee half is named in a
  # different file — any expected-set of job names would break silently the moment
  # that file is edited. Measured against the real v0.3.12 runs.
  #
  # `skipped` and a null conclusion are not failures. Treating skipped as failure
  # would block a Release permanently the first time a conditional job is skipped.
  if [ "$ok" -ge 1 ]; then
    run_id=$(printf '%s' "$runs" | jq -r --arg sha "$HEAD_SHA" \
      '[.workflow_runs[] | select(.head_sha==$sha and .conclusion=="success")][0].id')
    jobs=$(gh api "/repos/${GH_REPO}/actions/runs/${run_id}/jobs?per_page=100" -X GET)
    bad_jobs=$(printf '%s' "$jobs" | jq -r --arg wf "$wf" --arg allow "$JOB_EXCUSES" '
      [ .jobs[]
        | select(.conclusion != null and .conclusion != "success" and .conclusion != "skipped")
        | select((($wf + "::" + .name) as $k | ($allow | split(";") | index($k))) == null)
        | .name
      ] | join(", ")')
    if [ -n "$bad_jobs" ]; then
      ok=0
      ready=false
      blocked=true
      echo "::warning title=Release held::${wf} reports success for ${TAG} but these jobs did not pass: ${bad_jobs}. A job marked continue-on-error can fail while its run stays green, so the Release is held. Re-run the failed jobs on that run."
    fi
  fi

  if [ "$ok" -lt 1 ]; then
    ready=false
    if [ "$bad" -ge 1 ]; then
      blocked=true
      # "Re-run failed jobs" on the ORIGINAL push run — not "Run workflow". A
      # manual dispatch is a different event and is filtered out by `-f event=push`
      # above, so it can never clear this gate.
      echo "::warning title=Release held::${wf} finished without success for ${TAG} — Release NOT created. Open that run in Actions and use 'Re-run failed jobs' (a manual 'Run workflow' dispatch will NOT clear this gate)."
    elif [ "$blocked" != "true" ]; then
      # Guarded on $blocked: when the job-level check above trips it sets ok=0
      # with bad=0, and without this guard the script printed "Release held"
      # and then "waiting for it to finish" in the same breath — telling the
      # maintainer to be patient about something that will never resolve.
      echo "::notice::${wf} has no successful run yet for ${TAG} — waiting for it to finish."
    fi
  fi
done

echo "ready=${ready}" >>"$GITHUB_OUTPUT"

if [ "$blocked" = "true" ]; then
  echo "::error title=Release blocked::A publisher finished without success for ${TAG}; the GitHub Release was not created. Re-run the failed workflow(s)."
  exit 1
fi

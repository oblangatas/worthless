#!/usr/bin/env bash
# release-watchdog.sh — a release tag whose GitHub Release never appears files an
# issue instead of staying silent. WOR-922. Run on a cron by release-watchdog.yml.
#
# release-notes.yml creates the Release, but only if it fires, all four publishers
# really passed, and a human approves. Each of those can stall without producing a
# failed run anyone sees. This looks from outside, on its own clock.
#
# Trust: decides from git tags and Actions run data only. It NEVER reads GitHub
# Release objects — they are mutable and ruleset-ungated, so a draft or a hand-made
# Release could silence it (TestReleaseSyncTrustAnchor; pinned by
# test_watchdog_never_trusts_release_objects).
#
# Per v* tag:
#   older than 14 days               -> ignored (also keeps pre-automation tags quiet)
#   the create step succeeded        -> released
#   younger than 24h                 -> too early; publishers need time
#   approval waiting, under 72h      -> the normal pause before the click
#   approval waiting, 72h or more    -> ALARM
#   a release run still in progress  -> next tick decides
#   fan-in ready=true                -> ALARM: the automation never created it
#   fan-in ready=false               -> ALARM: a publisher failed or never finished
#   fan-in wrote no verdict          -> this run FAILS, and scheduled-failure-alarm
#                                       files that — a broken check never reads as fine
#
# "Released" means the step "Create the GitHub Release" succeeded, not the job: when
# a Release or draft already exists the step is skipped and the job still goes green.
#
# ponytail: GitHub starts crons late (up to ~a day, measured on this repo) and disables
# them after 60 days without repo activity. Nothing alarms on a watchdog that never
# runs; add a tag-push self-check if that ever bites.
#
# Reads from environment: GH_TOKEN, GH_REPO. Run from a checkout that has the tags.

set -euo pipefail

# Shared with release-notes.yml; the contract tests fail if either side is renamed.
readonly RUN_TITLE_PREFIX="Create GitHub Release"
readonly CREATE_JOB="create-release"
readonly CREATE_STEP="Create the GitHub Release"
readonly LABEL="release-watchdog"
readonly MIN_AGE_H=24
readonly APPROVAL_GRACE_H=72
readonly MAX_AGE_H=336

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
now=$(date +%s)
since=$(jq -nr --argjson t "$((now - MAX_AGE_H * 3600))" '$t | todate')

# Every release-notes run in the window, one JSON object per line.
# -X GET: `gh api` silently turns -f into a POST (see release-fanin.sh).
# --paginate: a busy window spans pages; a run on page 2 would read as "never ran".
runs=$(gh api "/repos/${GH_REPO}/actions/workflows/release-notes.yml/runs" -X GET \
  -f created=">=${since}" -f per_page=100 --paginate \
  --jq '.workflow_runs[] | {id, status, title: .display_title}')

# One issue per tag, found by marker. Open -> leave it. Closed for this commit ->
# you acknowledged it; leave it. Closed for an older commit -> the tag moved and is
# still unreleased; reopen rather than duplicate.
alarm() {
  local tag=$1 sha=$2 why=$3
  local marker="<!-- release-watchdog:${tag} -->"
  local sha_marker="<!-- release-watchdog-sha:${sha} -->"
  local body
  body="${marker}
${sha_marker}
**${tag}** (commit \`${sha:0:12}\`) has no GitHub Release.

${why}

Filed by release-watchdog.yml (WOR-922). It stays quiet once the Release step succeeds. Closing this silences it for this commit only."

  local existing
  existing=$(gh api "/repos/${GH_REPO}/issues" -X GET -f state=all -f labels="$LABEL" -f per_page=100 \
    --paginate --jq '.[] | {number, state, body}' |
    jq -sc --arg m "$marker" 'map(select((.body // "") | contains($m))) | first // empty')

  if [ -z "$existing" ]; then
    gh label create "$LABEL" --color b60205 --description "A release tag has no GitHub Release (WOR-922)" --force >/dev/null
    gh api "/repos/${GH_REPO}/issues" -X POST -f title="Release ${tag} never appeared" -f body="$body" \
      -f "labels[]=${LABEL}" -f "assignees[]=${GH_REPO%%/*}" >/dev/null
    echo "::warning title=Release missing::${tag}: opened an issue."
    return
  fi

  local number state
  number=$(jq -r .number <<<"$existing")
  state=$(jq -r .state <<<"$existing")
  local same_commit=false
  if jq -e --arg s "$sha_marker" '.body | contains($s)' <<<"$existing" >/dev/null; then
    same_commit=true
  fi
  if [ "$state" = "open" ]; then
    # Keep the commit current, or closing it after a re-tag would reopen it once.
    if [ "$same_commit" = "false" ]; then
      gh api "/repos/${GH_REPO}/issues/${number}" -X PATCH -f body="$body" >/dev/null
    fi
    echo "${tag}: issue #${number} is already open."
    return
  fi
  if [ "$same_commit" = "true" ]; then
    echo "${tag}: issue #${number} was closed for this commit; leaving it closed."
    return
  fi
  gh api "/repos/${GH_REPO}/issues/${number}" -X PATCH -f state=open -f body="$body" >/dev/null
  gh api "/repos/${GH_REPO}/issues/${number}/comments" -X POST \
    -f body="The tag moved to \`${sha:0:12}\` and still has no Release, so this reopened." >/dev/null
  echo "::warning title=Release missing::${tag}: reopened issue #${number}."
}

watched=0
while read -r tag created <&3; do
  # Seconds, not whole hours: the run query starts exactly MAX_AGE_H back, so an
  # hour-rounded check would watch a tag whose first runs the query cannot see.
  if [ $((now - created)) -gt $((MAX_AGE_H * 3600)) ]; then
    continue
  fi
  age_h=$(((now - created) / 3600))
  watched=$((watched + 1))
  # A re-tag is a new tag object with a new date, so the clock restarts with it.
  sha=$(git rev-list -n 1 "refs/tags/${tag}")
  # Any sha: a Release created before a re-tag still counts as released.
  mine=$(jq -c --arg p "${RUN_TITLE_PREFIX} ${tag}@" 'select(.title | startswith($p))' <<<"$runs")

  released=false
  for id in $(jq -r 'select(.status == "completed") | .id' <<<"$mine"); do
    jobs=$(gh api "/repos/${GH_REPO}/actions/runs/${id}/jobs?per_page=100" -X GET)
    if jq -e --arg j "$CREATE_JOB" --arg s "$CREATE_STEP" \
      'any(.jobs[]; .name == $j and any(.steps[]?; .name == $s and .conclusion == "success"))' \
      <<<"$jobs" >/dev/null; then
      released=true
      break
    fi
  done
  if [ "$released" = "true" ]; then
    echo "${tag}: released."
    continue
  fi
  if [ "$age_h" -lt "$MIN_AGE_H" ]; then
    echo "${tag}: ${age_h}h old, too early to judge."
    continue
  fi

  waiting=$(jq -rs 'map(select(.status == "waiting")) | first | .title // empty' <<<"$mine")
  if [ -n "$waiting" ]; then
    if [ "$age_h" -lt "$APPROVAL_GRACE_H" ]; then
      echo "${tag}: waiting for approval (${age_h}h), which is normal."
      continue
    fi
    if [ "$waiting" = "${RUN_TITLE_PREFIX} ${tag}@${sha}" ]; then
      why="The release run has waited ${age_h}h for your approval. Before approving, check it was built from commit ${sha}, the one your signed tag points at. If you do not recognise it, reject it."
    else
      why="A release run is waiting for approval for an OLD commit (${waiting##*@}), but the tag now points at ${sha}. Approving it will fail the tag re-bind check. Reject that run so the current commit can release."
    fi
    alarm "$tag" "$sha" "$why"
    continue
  fi

  if jq -se 'any(.[]; .status != "completed")' <<<"$mine" >/dev/null; then
    echo "${tag}: a release run is still in progress."
    continue
  fi

  # Read fan-in's ready= line, never its exit code: it exits 1 both for a blocked
  # publisher (an alarm) and for a crash (a broken watchdog).
  out=$(mktemp)
  log=$(mktemp)
  GITHUB_OUTPUT="$out" TAG="$tag" HEAD_SHA="$sha" bash "${here}/release-fanin.sh" >"$log" 2>&1 || true
  ready=$(sed -n 's/^ready=//p' "$out" | tail -n 1)
  case "$ready" in
    true)
      if [ -n "$mine" ]; then
        why="All four publishers passed, but the release run's \"${CREATE_STEP}\" step never succeeded: it was rejected, failed, or skipped because a Release or draft already existed. If you created the Release by hand, close this."
      else
        why="All four publishers passed, but the release automation never ran for this tag (or ran before this watchdog existed). Check that release-notes.yml's workflow_run trigger still names the publishers."
      fi
      ;;
    false)
      why="Not all four publishers passed for this commit (one failed, is stuck, or never started). Fan-in said:
$(grep -E '^::(warning|notice)' "$log" | sed -E 's/^::[a-z]+( title=[^:]*)?::/- /' || true)"
      ;;
    *)
      echo "::error title=Release watchdog broken::release-fanin.sh gave no verdict for ${tag}, so the release cannot be judged."
      cat "$log"
      rm -f "$out" "$log"
      exit 1
      ;;
  esac
  rm -f "$out" "$log"
  alarm "$tag" "$sha" "$why"
done 3< <(git for-each-ref --format='%(refname:short) %(creatordate:unix)' 'refs/tags/v*')
echo "Watched ${watched} tag(s) from the last $((MAX_AGE_H / 24)) days."

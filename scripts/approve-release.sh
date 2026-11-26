#!/usr/bin/env bash
# approve-release.sh — one `y` approves a whole release. WOR-1165.
#
# A pushed tag starts four publishers. Three wait on protected environments
# (pypi, npm-publish, worthless-sh-production); when all four pass, release-notes.yml
# ("Create GitHub Release <tag> <sha>") waits on a fourth (release). That was four
# clicks in the GitHub UI. This lists what is waiting, asks once, approves exactly
# what it showed you, then approves the release run with no second prompt and waits
# for the Release to appear.
#
# Usage: scripts/approve-release.sh <tag> [--timeout-min N]
#        scripts/approve-release.sh <tag> --yes --expect-sha SHA [--timeout-min N]
#   (no --yes)     asks on the terminal (/dev/tty, never stdin: `yes |` cannot answer)
#                  and first checks the tag's signature with git verify-tag
#   --yes          no prompt. ONLY with --expect-sha: the WOR-1167 Action passes both
#                  after a human approved its gate and saw the preflight summary.
#   --expect-sha   refuse unless the tag's commit is exactly this one. It replaces
#                  the local signature check, because CI never holds the signing key.
#   --timeout-min  default 80, counted from your y: publish-docker.yml's job timeouts
#                  chain to 45 min (build-push 35, then smoke 10) and release-notes.yml's
#                  to 20 (gate, then create-release), so 65 before any queueing.
#                  test_default_timeout_outlasts_the_slowest_publisher pins the margin.
#
# Exit: 0 Release live
#       1 a publisher or the release run failed, an approval you are not allowed to
#         give, the tag's signature or commit is wrong — nothing more is approved
#       2 timed out (prints the command to resume)
#       3 you did not answer y, nothing approved
#       4 a GitHub call failed mid-approval (prints what was approved; safe to re-run)
#       64 usage, no terminal to ask on, or the tag is not in this checkout
#
# What gets approved — ALL of these, nothing else:
#   - the commit is the LOCAL tag's (git rev-parse <tag>^{commit}), and GitHub's copy
#     of the tag must point at the same commit;
#   - a publisher run is a `push` of that tag at that commit, and the environment is
#     the one its workflow owns (pypi <-> Publish to PyPI, npm-publish <-> Publish
#     worthless-mcp to npm, worthless-sh-production <-> Deploy Worker (worthless-sh));
#   - only the (run, environment) pairs shown at the prompt. A pair that appears later
#     (a re-pushed tag makes a new run) is printed and NOT approved;
#   - plus the single `release` environment on the release-notes.yml `workflow_run`
#     titled exactly "Create GitHub Release <tag> <sha>", once it is waiting.
# Anything else waiting is printed as "skipped:" and never approved.
# This NEVER creates a Release, dispatches a workflow or files an issue.
#
# Reads from environment: GH_REPO (default: gh repo view), GH_TOKEN (optional),
# APPROVE_POLL_SECONDS (default 10), APPROVE_TIMEOUT_SECONDS (overrides --timeout-min).

set -euo pipefail

readonly EXIT_FAILED=1 EXIT_TIMEOUT=2 EXIT_DECLINED=3 EXIT_GH=4 EXIT_USAGE=64
# Publisher workflow files, matched by basename like release-fanin.sh.
readonly PUBLISHERS="publish.yml publish-npm.yml publish-docker.yml deploy-worker.yml"
# The three that wait on an environment, each with its workflow name and the ONE
# environment it may be approved for. The GHCR image needs no approval.
readonly GATE_MAP="publish.yml|Publish to PyPI|pypi
publish-npm.yml|Publish worthless-mcp to npm|npm-publish
deploy-worker.yml|Deploy Worker (worthless-sh)|worthless-sh-production"
readonly GATED="publish.yml publish-npm.yml deploy-worker.yml"
# Shared with release-notes.yml run-name and release-watchdog.sh.
readonly RUN_TITLE_PREFIX="Create GitHub Release"
readonly RELEASE_ENV="release"
readonly NOT_OURS="(not this tag's push)"

usage() {
  echo "Usage: $0 <tag> [--timeout-min N]" >&2
  echo "       $0 <tag> --yes --expect-sha SHA [--timeout-min N]" >&2
  exit "$EXIT_USAGE"
}

tag=""
assume_yes=false
timeout_min=80
expect_sha=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes) assume_yes=true ;;
    --timeout-min)
      [ "$#" -ge 2 ] || usage
      timeout_min=$2
      shift
      ;;
    --expect-sha)
      [ "$#" -ge 2 ] || usage
      expect_sha=$2
      shift
      ;;
    -*) usage ;;
    *)
      [ -z "$tag" ] || usage
      tag=$1
      ;;
  esac
  shift
done
[ -n "$tag" ] || usage
case "$timeout_min" in '' | *[!0-9]*) usage ;; esac
timeout_s=${APPROVE_TIMEOUT_SECONDS:-$((timeout_min * 60))}

if [ "$assume_yes" = true ] && [ -z "$expect_sha" ]; then
  echo "--yes needs --expect-sha <commit>: an unattended approval must name the commit it approves." >&2
  exit "$EXIT_USAGE"
fi
if [ "$assume_yes" != true ] && ! { : </dev/tty; } 2>/dev/null; then
  echo "No terminal to ask on. Run this in a terminal, or pass --yes with --expect-sha." >&2
  exit "$EXIT_USAGE"
fi

if [ -z "${GH_REPO:-}" ]; then
  GH_REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
fi
export GH_REPO
poll=${APPROVE_POLL_SECONDS:-10}

# The commit comes from the tag on THIS machine, not from GitHub: GitHub's copy of a
# tag can be moved by anyone with push access.
if ! sha=$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}"); then
  if [ -n "$expect_sha" ]; then
    echo "Tag ${tag} is not in this checkout. Run git fetch --tags first." >&2
  else
    echo "Tag ${tag} is not in this checkout. Run this in the checkout where you signed it." >&2
  fi
  exit "$EXIT_USAGE"
fi
if [ -n "$expect_sha" ] && [ "$expect_sha" != "$sha" ]; then
  echo "Refusing: ${tag} points at ${sha:0:12}, but ${expect_sha:0:12} was expected. Nothing approved."
  exit "$EXIT_FAILED"
fi
if [ -z "$expect_sha" ] && ! git verify-tag "$tag" >/dev/null 2>&1; then
  echo "Refusing: the signature on ${tag} does not verify here (git verify-tag ${tag}). Nothing approved."
  exit "$EXIT_FAILED"
fi
# -X GET everywhere: `gh api` silently turns -f into a POST (see release-fanin.sh).
remote_sha=$(gh api "/repos/${GH_REPO}/commits/${tag}" -X GET --jq .sha)
if [ "$remote_sha" != "$sha" ]; then
  echo "Refusing: ${tag} is ${sha:0:12} here but ${remote_sha:0:12} on GitHub. Nothing approved."
  exit "$EXIT_FAILED"
fi
echo "Release ${tag} at commit ${sha:0:12} (${GH_REPO})."

# Every run GitHub lists for the tag, any event, any commit. One JSON array. No
# server-side event filter: a dispatched run must be SEEN, so it can be named as skipped.
all_runs() {
  gh api "/repos/${GH_REPO}/actions/runs" -X GET -f branch="$tag" -f per_page=100 --paginate \
    --jq '.workflow_runs[] | {id, name, path, event, status, conclusion, head_sha, html_url}' |
    jq -sc 'map(.wf = (.path | split("/") | last))'
}

# Newest push run per publisher workflow, at the tag's commit only.
publisher_runs() {
  jq -c --arg sha "$sha" --arg pubs "$PUBLISHERS" '
    map(select(.event == "push" and .head_sha == $sha and (.wf as $w | $pubs | split(" ") | index($w))))
    | group_by(.wf) | map(max_by(.id))' <<<"$1"
}

# The one environment a gated run may be approved for: matched on workflow file AND name.
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

# Pending deployments of one run: {eid, env, can} per line.
pending() {
  gh api "/repos/${GH_REPO}/actions/runs/$1/pending_deployments" -X GET \
    --jq '.[] | {eid: .environment.id, env: .environment.name, can: .current_user_can_approve}'
}

# Release-notes runs carrying this exact tag+commit title, as a JSON array.
release_runs() {
  gh api "/repos/${GH_REPO}/actions/workflows/release-notes.yml/runs" -X GET \
    -f event=workflow_run -f per_page=100 \
    --jq '.workflow_runs[] | {id, event, status, conclusion, title: .display_title, html_url}' |
    jq -sc --arg t "${RUN_TITLE_PREFIX} ${tag} ${sha}" \
      'map(select(.event == "workflow_run" and .title == $t))'
}

readonly RESUME_CMD="scripts/approve-release.sh ${tag}"
consent=""  # "run_id env_id env" per line: exactly what the prompt showed
approved="" # env names approved so far, for the exit-4 report
noted=""    # "run_id env_id" pairs already reported as not approved

# The 422 body GitHub sends when a POST finds nothing to review. GitHub's REST
# reference documents only 200 for this endpoint
# (https://docs.github.com/en/rest/actions/workflow-runs#review-pending-deployments-for-a-workflow-run),
# so the text is from observed responses: open-security-tools/ost-environment-gate
# (src/github/deployments.rs, an idempotent-422 test fixture) and Kludex/release-gate
# (docs/rollout.md). The latter got the same message when the caller MAY NOT approve,
# so the message alone proves nothing: approve_env also re-reads that the environment
# is no longer pending before calling it "already approved".
readonly GH_NO_PENDING_MSG="No pending deployment requests to approve or reject"

still_pending() {
  pending "$1" | jq -e --argjson e "$2" 'select(.eid == $e)' >/dev/null
}

approve_env() {
  local run_id=$1 eid=$2 env=$3 err left="" e
  if err=$(gh api -X POST "repos/${GH_REPO}/actions/runs/${run_id}/pending_deployments" \
    -F "environment_ids[]=${eid}" -f state=approved \
    -f comment="Approved with scripts/approve-release.sh for ${tag} at ${sha:0:12}" 2>&1 </dev/null >/dev/null); then
    echo "Approved ${env}."
  elif grep -qF "(HTTP 422)" <<<"$err" && grep -qF "$GH_NO_PENDING_MSG" <<<"$err" && ! still_pending "$run_id" "$eid"; then
    # Approved already (by you in the UI, or by an earlier run of this script).
    echo "${env} was already approved."
  else
    if grep -qF "$GH_NO_PENDING_MSG" <<<"$err"; then
      echo "GitHub says nothing is pending, but ${env} is still waiting: you may not be allowed to approve it."
    fi
    while read -r _ _ e; do
      [ -n "$e" ] || continue
      case ", ${approved}, " in *", ${e}, "*) ;; *) left+="${e}, " ;; esac
    done <<<"$consent"
    echo "GitHub call failed while approving ${env}: ${err}"
    echo "Approved so far: ${approved:-nothing}"
    echo "Not approved: ${left}${RELEASE_ENV}"
    echo "It is safe to run again: ${RESUME_CMD}"
    exit "$EXIT_GH"
  fi
  approved="${approved:+${approved}, }${env}"
}

# Before the prompt: print what would be approved and record it as the consent.
# Returns 1 if any of it is an approval you are not allowed to give.
record_consent() {
  local runs=$1 all=$2 id url name wf want line eid env can bad=0
  while IFS=$'\t' read -r id url name wf; do
    want=$(gate_env "$wf" "$name") || continue
    while read -r line; do
      [ -n "$line" ] || continue
      eid=$(jq -r .eid <<<"$line")
      env=$(jq -r .env <<<"$line")
      can=$(jq -r .can <<<"$line")
      if [ "$env" != "$want" ]; then
        echo "  skipped: ${env}  ${name}  ${url} (not this workflow's environment)"
      elif [ "$can" != "true" ]; then
        echo "cannot approve ${env} (you are not a reviewer): ${name}  ${url}"
        bad=1
      else
        echo "  waiting: ${env}  ${name}  ${url}"
        consent+="${id} ${eid} ${env}"$'\n'
      fi
    done < <(pending "$id")
  done < <(jq -r --arg g "$GATED" \
    '.[] | select(.status == "waiting" and (.wf as $w | $g | split(" ") | index($w)))
      | [.id, .html_url, .name, .wf] | @tsv' <<<"$runs")
  jq -r --argjson mine "$(jq -c 'map(.id)' <<<"$runs")" --arg why "$NOT_OURS" \
    '.[] | select(.status == "waiting" and (.id as $i | $mine | index($i) | not))
      | "  skipped: \(.name)  \(.html_url) \($why)"' <<<"$all"
  return "$bad"
}

# After the y: approve only the consented pairs still pending; report anything new.
approve_consented() {
  local runs=$1 id eid env line url name
  while read -r id eid env; do
    [ -n "$id" ] || continue
    if pending "$id" | jq -e --argjson e "$eid" 'select(.eid == $e)' >/dev/null; then
      approve_env "$id" "$eid" "$env"
    fi
  done <<<"$consent"
  while IFS=$'\t' read -r id url name; do
    while read -r line; do
      [ -n "$line" ] || continue
      eid=$(jq -r .eid <<<"$line")
      env=$(jq -r .env <<<"$line")
      if grep -qx "${id} ${eid} .*" <<<"$consent" || grep -qx "${id} ${eid}" <<<"$noted"; then
        continue
      fi
      echo "Not approved: ${env}  ${name}  ${url} (appeared after you answered; run ${RESUME_CMD} to review it)"
      noted+="${id} ${eid}"$'\n'
    done < <(pending "$id")
  done < <(jq -r --arg g "$GATED" \
    '.[] | select(.status == "waiting" and (.wf as $w | $g | split(" ") | index($w)))
      | [.id, .html_url, .name] | @tsv' <<<"$runs")
}

check_failures() {
  local failed
  failed=$(jq -r '.[] | select(.status == "completed" and .conclusion != "success")
    | "\(.name) \(.conclusion): \(.html_url)"' <<<"$1")
  if [ -n "$failed" ]; then
    echo "A publisher did not succeed, so the release cannot go out:"
    printf '%s\n' "$failed" | sed 's/^/  /'
    echo "Nothing more was approved. Fix it, re-run that run (Actions -> the run -> Re-run failed jobs), then run ${RESUME_CMD}."
    exit "$EXIT_FAILED" # a publisher failed
  fi
}

timed_out() {
  echo "Timed out after $((timeout_s / 60)) min ($1)."
  echo "Still waiting or running:"
  jq -r '.[] | select(.status != "completed") | "  \(.name) (\(.status)): \(.html_url)"' <<<"${runs:-[]}"
  jq -r '.[]? | select(.status != "completed") | "  \(.title) (\(.status)): \(.html_url)"' <<<"${rn_cur:-[]}"
  echo "Resume with: ${RESUME_CMD}"
  exit "$EXIT_TIMEOUT"
}

# Release-notes runs that already finished before this started belong to an earlier
# attempt (a re-run after a fix); only newer ones say anything about this one.
baseline=$(release_runs | jq -r 'map(select(.status == "completed") | .id) | max // 0' || echo 0)

asked=false
release_done=false
rn_cur="[]"
deadline=$(($(date +%s) + timeout_s))
while :; do
  runs=""
  if all=$(all_runs); then
    runs=$(publisher_runs "$all")
  else
    echo "Could not read the runs for ${tag}; trying again." >&2
  fi

  if [ -n "$runs" ]; then
    # Every pass — including the first one after your y, before anything is approved.
    check_failures "$runs"

    if [ "$asked" = false ]; then
      ready=$(jq -r --arg g "$GATED" '
        ($g | split(" ")) as $gated
        | [.[] | select(.wf as $w | $gated | index($w)) | select(.status == "waiting" or .status == "completed")]
        | length == ($gated | length)' <<<"$runs")
      if [ "$ready" = true ]; then
        echo "Waiting for approval:"
        if ! record_consent "$runs" "$all"; then
          echo "Nothing approved. Ask a required reviewer of that environment to approve it."
          exit "$EXIT_FAILED"
        fi
        echo "  then: ${RELEASE_ENV}  ${RUN_TITLE_PREFIX}  (once all four publishers pass)"
        if [ "$assume_yes" != "true" ]; then
          printf 'Approve all? [y/N] '
          answer=""
          read -r answer </dev/tty || true
          case "$answer" in
            y | Y) ;;
            *)
              echo "Nothing approved."
              exit "$EXIT_DECLINED"
              ;;
          esac
        fi
        asked=true
        deadline=$(($(date +%s) + timeout_s))
        continue # re-read the runs before approving anything
      fi
    else
      approve_consented "$runs"
    fi
  fi

  if [ "$asked" = true ]; then
    rn_cur=$(release_runs | jq -c --argjson b "$baseline" '[map(select(.id > $b)) | max_by(.id) // empty]' || echo "[]")
    if jq -e '.[0] | .status == "completed" and .conclusion != "success"' <<<"$rn_cur" >/dev/null; then
      echo "${RUN_TITLE_PREFIX} for ${tag} failed: $(jq -r '.[0].html_url' <<<"$rn_cur")"
      echo "Nothing more was approved. Read that run's log, fix it, then run ${RESUME_CMD}."
      exit "$EXIT_FAILED" # the release run failed
    fi
    rn_wait=$(jq -r '.[0] | select(.status == "waiting") | .id' <<<"$rn_cur")
    if [ "$release_done" = false ] && [ -n "$rn_wait" ]; then
      rel=$(pending "$rn_wait" | jq -r --arg e "$RELEASE_ENV" 'select(.env == $e) | if .can == true then .eid else "cannot" end' | head -n 1)
      if [ "$rel" = cannot ]; then
        echo "cannot approve release (you are not a reviewer): $(jq -r '.[0].html_url' <<<"$rn_cur")"
        exit "$EXIT_FAILED"
      elif [ -n "$rel" ]; then
        approve_env "$rn_wait" "$rel" release
        release_done=true
      fi
    fi
    if [ "$release_done" = true ]; then
      if url=$(gh release view "$tag" --json url,isDraft --jq 'select(.isDraft == false) | .url' 2>/dev/null) &&
        [ -n "$url" ]; then
        echo "Release ${tag} is live: ${url}"
        exit 0
      fi
    fi
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    if [ "$asked" = false ]; then
      timed_out "the publishers never all reached their approval step; nothing approved"
    fi
    timed_out "waiting for ${tag} to be released"
  fi
  sleep "$poll"
done

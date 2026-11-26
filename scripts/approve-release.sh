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
# APPROVE_POLL_SECONDS (default 20), APPROVE_TIMEOUT_SECONDS (overrides --timeout-min),
# APPROVE_RETRY_DELAYS (default "2 5 10": a failed read is retried after each delay,
# then exits 4; an approve POST is never retried).

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
poll=${APPROVE_POLL_SECONDS:-20}
RETRY_DELAYS=${APPROVE_RETRY_DELAYS:-2 5 10}
case "$RETRY_DELAYS" in *[!0-9\ ]*)
  echo "APPROVE_RETRY_DELAYS must be whole numbers of seconds, separated by spaces." >&2
  exit "$EXIT_USAGE"
  ;;
esac
# Digits only, before either reaches $(( )): bash arithmetic evaluates `x[$(cmd)]`.
case "$timeout_s" in '' | *[!0-9]*)
  echo "APPROVE_TIMEOUT_SECONDS must be a whole number of seconds." >&2
  exit "$EXIT_USAGE"
  ;;
esac
case "$poll" in '' | *[!0-9]*)
  echo "APPROVE_POLL_SECONDS must be a whole number of seconds." >&2
  exit "$EXIT_USAGE"
  ;;
esac

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
readonly RESUME_CMD="scripts/approve-release.sh ${tag}"
consent=""  # "run_id env_id env" per line: exactly what the prompt showed
approved="" # env names approved so far, for the exit-4 report
noted=""    # "run_id env_id" pairs already reported as not approved
settled=""  # "run_id env_id" consented pairs already approved (or gone): never re-read

run_url() { echo "https://github.com/${GH_REPO}/actions/runs/$1"; }

# Any GitHub call that fails — a read or an approval — ends here: what was approved,
# what was not, and that running again is safe (approvals already given drop out).
gh_failed() {
  local left="" e
  while read -r _ _ e; do
    [ -n "$e" ] || continue
    case ", ${approved}, " in *", ${e}, "*) ;; *) left+="${e}, " ;; esac
  done <<<"$consent"
  echo "$1"
  echo "Approved so far: ${approved:-nothing}"
  echo "Not approved: ${left}${RELEASE_ENV}"
  echo "It is safe to run again: ${RESUME_CMD}"
  exit "$EXIT_GH"
}

# retry_read <what> <command...>: run a READ, output into $READ_OUT. A failure is
# retried after each of $RETRY_DELAYS, so a GitHub blip does not end an 80-minute
# wait; after the last one it is exit 4. Call it directly, never inside $( ) or
# < <( ): there a failure would read as "nothing" and the exit-4 report would vanish.
retry_read() {
  local what=$1 d
  shift
  for d in $RETRY_DELAYS; do
    if READ_OUT=$("$@"); then
      return 0
    fi
    echo "Reading ${what} failed; retrying in ${d}s." >&2
    sleep "$d"
  done
  READ_OUT=$("$@") || gh_failed "GitHub call failed reading ${what}, after retrying."
}

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
tag_commit() { gh api "/repos/${GH_REPO}/commits/${tag}" -X GET --jq .sha </dev/null; }
retry_read "where ${tag} points" tag_commit
remote_sha=$READ_OUT
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
    --jq '.[] | {eid: .environment.id, env: .environment.name, can: .current_user_can_approve}' </dev/null
}

# The same into $PEND, but a failed read stops with exit 4 naming the run. Call it
# directly, never inside $( ) or < <( ): there a failure reads as "nothing pending"
# (or the exit-4 report vanishes into the subshell).
read_pending() {
  retry_read "what is waiting on $(run_url "$1")" pending "$1"
  PEND=$READ_OUT
}

# Status and conclusion of one run, as {status, conclusion}.
run_state() { gh api "/repos/${GH_REPO}/actions/runs/$1" -X GET --jq '{status, conclusion}' </dev/null; }

# The tag's Release as JSON, or nothing when there is none yet. Any other failure is
# a failed read (retried, then exit 4) — never "no Release".
release_json() {
  local out
  if out=$(gh release view "$tag" --json url,isDraft,tagName 2>&1 </dev/null); then
    printf '%s' "$out"
    return 0
  fi
  grep -qi "release not found" <<<"$out" && return 0
  printf '%s\n' "$out" >&2
  return 1
}

release_noted=false
# "Live" means shipped: a non-draft Release, every publisher green at this commit, and
# the tag still on this commit. Then we are done, however the approvals were given (the
# UI, the Action, or an approve POST that landed but answered with an error). It reads
# a Release object only to STOP: it never approves anything because of one.
release_live() {
  local rel url not_done rel_commit
  retry_read "the GitHub Release for ${tag}" release_json
  rel=$READ_OUT
  [ -n "$rel" ] || return 0
  jq -e '.isDraft == false' <<<"$rel" >/dev/null || return 0
  url=$(jq -r .url <<<"$rel")
  not_done=$(jq -r --arg p "$PUBLISHERS" '. as $r | $p | split(" ") | .[] as $w
    | ($r | map(select(.wf == $w)) | first) as $run
    | if $run == null then "  \($w): no run at this commit yet"
      elif $run.status == "completed" and $run.conclusion == "success" then empty
      else "  \($run.name) (\($run.status)\(if $run.conclusion then ", " + $run.conclusion else "" end)): \($run.html_url)"
      end' <<<"${1:-[]}")
  if [ -n "$not_done" ]; then
    if [ "$release_noted" = false ]; then
      echo "A Release for ${tag} exists (${url}), but not every publisher has shipped:"
      printf '%s\n' "$not_done"
      release_noted=true
    fi
    return 0
  fi
  retry_read "where ${tag} points" tag_commit
  rel_commit=$READ_OUT
  if [ "$rel_commit" != "$sha" ]; then
    echo "Release ${tag} points at ${rel_commit:0:12}, expected ${sha:0:12}. Nothing more approved."
    exit "$EXIT_FAILED"
  fi
  echo "Release ${tag} is live: ${url}"
  exit 0
}

# Release-notes runs carrying this exact tag+commit title, as a JSON array.
release_runs() {
  gh api "/repos/${GH_REPO}/actions/workflows/release-notes.yml/runs" -X GET \
    -f event=workflow_run -f per_page=100 \
    --jq '.workflow_runs[] | {id, event, status, conclusion, title: .display_title, html_url}' |
    jq -sc --arg t "${RUN_TITLE_PREFIX} ${tag} ${sha}" \
      'map(select(.event == "workflow_run" and .title == $t))'
}

# The 422 body GitHub sends when a POST finds nothing to review. GitHub's REST
# reference documents only 200 for this endpoint
# (https://docs.github.com/en/rest/actions/workflow-runs#review-pending-deployments-for-a-workflow-run),
# so the text is from observed responses: open-security-tools/ost-environment-gate
# (src/github/deployments.rs, an idempotent-422 test fixture) and Kludex/release-gate
# (docs/rollout.md). The latter got the same message when the caller MAY NOT approve,
# so the message alone proves nothing: approve_env also re-reads that the environment
# is no longer pending before calling it "already approved".
readonly GH_NO_PENDING_MSG="No pending deployment requests to approve or reject"

approve_env() {
  local run_id=$1 eid=$2 env=$3 err recheck state
  # The approve POST is never retried: the first non-422 error is exit 4.
  if err=$(gh api -X POST "repos/${GH_REPO}/actions/runs/${run_id}/pending_deployments" \
    -F "environment_ids[]=${eid}" -f state=approved \
    -f comment="Approved with scripts/approve-release.sh for ${tag} at ${sha:0:12}" 2>&1 </dev/null >/dev/null); then
    echo "Approved ${env}."
  elif grep -qF "(HTTP 422)" <<<"$err" && grep -qF "$GH_NO_PENDING_MSG" <<<"$err"; then
    # Re-read before believing it: a failed re-read is exit 4, never "approved".
    retry_read "whether ${env} is still waiting on $(run_url "$run_id")" pending "$run_id"
    recheck=$READ_OUT
    if jq -e --argjson e "$eid" 'select(.eid == $e)' <<<"$recheck" >/dev/null; then
      gh_failed "GitHub says nothing is pending, but ${env} is still waiting: you may not be allowed to approve it. ${err}"
    fi
    # Gone from pending is not the same as approved: a rejected or cancelled run drops
    # out too. Its failure then ends the run on the next poll.
    retry_read "the status of $(run_url "$run_id")" run_state "$run_id"
    state=$READ_OUT
    if jq -e '.status == "completed" and .conclusion != "success"' <<<"$state" >/dev/null; then
      echo "${env} was not approved: $(run_url "$run_id") ended $(jq -r .conclusion <<<"$state")."
      return 0
    fi
    # Approved already (by you in the UI, or by an earlier run of this script).
    echo "${env} was already approved."
  else
    gh_failed "GitHub call failed while approving ${env}: ${err}"
  fi
  approved="${approved:+${approved}, }${env}"
}

# Before the prompt: print what would be approved and record it as the consent.
# Returns 1 if any of it is an approval you are not allowed to give.
record_consent() {
  local runs=$1 all=$2 id url name wf want line eid env can bad=0
  while IFS=$'\t' read -r id url name wf; do
    want=$(gate_env "$wf" "$name") || continue
    read_pending "$id" # before the prompt
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
    done <<<"$PEND"
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
  local runs=$1 id eid env line url name mine
  while read -r id eid env; do
    [ -n "$id" ] || continue
    grep -qx "${id} ${eid}" <<<"$settled" && continue # dealt with: no more reads
    read_pending "$id" # consented run, after the y
    if jq -e --argjson e "$eid" 'select(.eid == $e)' <<<"$PEND" >/dev/null; then
      approve_env "$id" "$eid" "$env"
    fi
    settled+="${id} ${eid}"$'\n'
  done <<<"$consent"
  # Waiting runs you were NOT shown (a re-pushed tag makes new ones): report, never approve.
  mine=$(awk '{print $1}' <<<"$consent" | jq -Rsc 'split("\n") | map(select(. != "") | tonumber)')
  while IFS=$'\t' read -r id url name; do
    read_pending "$id" # newly waiting run, after the y
    while read -r line; do
      [ -n "$line" ] || continue
      eid=$(jq -r .eid <<<"$line")
      env=$(jq -r .env <<<"$line")
      if grep -qx "${id} ${eid} .*" <<<"$consent" || grep -qx "${id} ${eid}" <<<"$noted"; then
        continue
      fi
      echo "Not approved: ${env}  ${name}  ${url} (appeared after you answered; run ${RESUME_CMD} to review it)"
      noted+="${id} ${eid}"$'\n'
    done <<<"$PEND"
  done < <(jq -r --arg g "$GATED" --argjson mine "$mine" \
    '.[] | select(.status == "waiting" and (.wf as $w | $g | split(" ") | index($w)))
      | select(.id as $i | $mine | index($i) | not)
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
retry_read "the ${RUN_TITLE_PREFIX} runs for ${tag}" release_runs
baseline=$(jq -r 'map(select(.status == "completed") | .id) | max // 0' <<<"$READ_OUT")

asked=false
release_done=false
rn_cur="[]"
deadline=$(($(date +%s) + timeout_s))
while :; do
  retry_read "the runs for ${tag}" all_runs
  all=$READ_OUT
  runs=$(publisher_runs "$all")
  release_live "$runs" # every pass, from the very first: it may already be out

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
          # A terminal that closes while asking (window shut, ssh dropped) is no answer.
          trap 'echo; echo "The terminal closed before you answered. Nothing approved."; exit "$EXIT_DECLINED"' HUP
          read -r answer </dev/tty || true
          trap - HUP
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
    retry_read "the ${RUN_TITLE_PREFIX} runs for ${tag}" release_runs
    rn_all=$READ_OUT
    # Every exact-title run newer than the baseline. release-notes.yml runs once per
    # publisher completion in one concurrency group (cancel-in-progress: false): one
    # run can wait on `release` while a newer, equally ready one sits pending behind
    # it, and a pending run replaced by a newer one ends "cancelled" — superseded,
    # not failed. So: approve whichever run is waiting, and judge failure on the
    # newest run that was not cancelled or skipped.
    rn_cur=$(jq -c --argjson b "$baseline" 'map(select(.id > $b))' <<<"$rn_all")
    rn_judge=$(jq -c 'map(select(.conclusion != "cancelled" and .conclusion != "skipped")) | max_by(.id) // empty' <<<"$rn_cur")
    if [ -n "$rn_judge" ] && jq -e '.status == "completed" and .conclusion != "success"' <<<"$rn_judge" >/dev/null; then
      rn_url=$(jq -r .html_url <<<"$rn_judge")
      echo "${RUN_TITLE_PREFIX} for ${tag} failed: ${rn_url}"
      echo "Nothing more was approved. Read its log, re-run the failed jobs of ${rn_url}, then resume with ${RESUME_CMD}."
      exit "$EXIT_FAILED" # the release run failed
    fi
    rn_wait=$(jq -r 'map(select(.status == "waiting")) | first | .id // empty' <<<"$rn_cur")
    if [ "$release_done" = false ] && [ -n "$rn_wait" ]; then
      read_pending "$rn_wait" # the release run
      rel=$(jq -r --arg e "$RELEASE_ENV" 'select(.env == $e) | if .can == true then .eid else "cannot" end' <<<"$PEND" | head -n 1)
      if [ "$rel" = cannot ]; then
        echo "cannot approve release (you are not a reviewer): $(run_url "$rn_wait")"
        exit "$EXIT_FAILED"
      elif [ -n "$rel" ]; then
        approve_env "$rn_wait" "$rel" release
        release_done=true
        release_live "$runs"
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

#!/usr/bin/env bash
# approve-release.sh — one `y` approves a whole release. WOR-1165.
#
# A pushed tag starts four publishers. Three wait on protected environments
# (pypi, npm-publish, worthless-sh-production); when all four pass, release-notes.yml
# ("Create GitHub Release <tag> <sha>") waits on a fourth (release). That was four
# clicks in the GitHub UI. This lists what is waiting, asks once, approves the
# publishers, then approves the release run with no second prompt and waits for the
# Release to appear.
#
# Usage: scripts/approve-release.sh <tag> [--yes] [--timeout-min N] [--expect-sha SHA]
#   --yes          no prompt (for automation; GH_TOKEN is used if set)
#   --timeout-min  default 60: publish-docker.yml's job timeouts alone chain to 45 min
#                  (build-push 35, then smoke 10), and the release waits on it.
#                  test_default_timeout_outlasts_the_slowest_publisher pins this.
#   --expect-sha   refuse unless the tag's commit is exactly this one
#
# Exit: 0 Release live | 1 a publisher (or the release run) failed, or the tag's
#       commit is not the expected one | 2 timed out | 3 you did not answer y,
#       nothing approved | 64 usage, or the tag is not in this checkout
#
# What gets approved — ALL of these, nothing else:
#   - the commit is the LOCAL signed tag's (git rev-parse <tag>^{commit}), and GitHub's
#     copy of the tag must point at the same commit, or nothing is approved;
#   - a publisher run is a `push` of that tag at that commit (newest per workflow);
#     the release run is the release-notes.yml `workflow_run` titled exactly
#     "Create GitHub Release <tag> <sha>";
#   - the environment is one of pypi, npm-publish, worthless-sh-production, release.
# Anything else waiting (a dispatched preview, a replayed or older-commit run, an
# unknown environment) is printed as "skipped:" and never approved.
# This NEVER creates a Release, dispatches a workflow or files an issue.
#
# Run it from a checkout that has the tag (tag-release.sh does). Reads from
# environment: GH_REPO (default: gh repo view), GH_TOKEN (optional),
# APPROVE_POLL_SECONDS (default 10).

set -euo pipefail

readonly EXIT_FAILED=1 EXIT_TIMEOUT=2 EXIT_DECLINED=3 EXIT_USAGE=64
# Publisher workflow files, matched by basename like release-fanin.sh.
readonly PUBLISHERS="publish.yml publish-npm.yml publish-docker.yml deploy-worker.yml"
# The three that wait on an environment; the GHCR image needs no approval.
readonly GATED="publish.yml publish-npm.yml deploy-worker.yml"
# Shared with release-notes.yml run-name and release-watchdog.sh.
readonly RUN_TITLE_PREFIX="Create GitHub Release"
readonly RELEASE_ENV="release"
# The only environments a publisher run may be approved for.
readonly PUBLISHER_ENVS="pypi npm-publish worthless-sh-production"
readonly NOT_OURS="(not this tag's push)"

usage() {
  echo "Usage: $0 <tag> [--yes] [--timeout-min N] [--expect-sha SHA]" >&2
  exit "$EXIT_USAGE"
}

tag=""
assume_yes=false
timeout_min=60
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

if [ -z "${GH_REPO:-}" ]; then
  GH_REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
fi
export GH_REPO
poll=${APPROVE_POLL_SECONDS:-10}
deadline=$(($(date +%s) + timeout_min * 60))

# The commit comes from the signed tag on THIS machine, not from GitHub: GitHub's
# copy of a tag can be moved by anyone with push access.
if ! sha=$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}"); then
  echo "Tag ${tag} is not in this checkout. Run this where the tag was signed, or git fetch --tags." >&2
  exit "$EXIT_USAGE"
fi
if [ -n "$expect_sha" ] && [ "$expect_sha" != "$sha" ]; then
  echo "Refusing: ${tag} points at ${sha:0:12}, but ${expect_sha:0:12} was expected. Nothing approved."
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

allowed_env() {
  case " $PUBLISHER_ENVS " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# Pending deployments of one run: {eid, env, can} per line.
pending() {
  gh api "/repos/${GH_REPO}/actions/runs/$1/pending_deployments" -X GET \
    --jq '.[] | {eid: .environment.id, env: .environment.name, can: .current_user_can_approve}'
}

approve_env() {
  local run_id=$1 eid=$2 env=$3
  gh api -X POST "repos/${GH_REPO}/actions/runs/${run_id}/pending_deployments" \
    -F "environment_ids[]=${eid}" -f state=approved \
    -f comment="Approved with scripts/approve-release.sh for ${tag} at ${sha:0:12}" </dev/null >/dev/null
  echo "Approved ${env}."
}

# Approve every pending deployment on the waiting gated runs. With $1=list, only print.
sweep_publishers() {
  local mode=$1 runs=$2 id name url line eid env can
  while IFS=$'\t' read -r id url name; do
    while read -r line; do
      [ -n "$line" ] || continue
      eid=$(jq -r .eid <<<"$line")
      env=$(jq -r .env <<<"$line")
      can=$(jq -r .can <<<"$line")
      if ! allowed_env "$env"; then
        [ "$mode" != list ] || echo "  skipped: ${env}  ${name}  ${url} (not a release environment)"
      elif [ "$mode" = list ]; then
        echo "  waiting: ${env}  ${name}  ${url}"
      elif [ "$can" != "true" ]; then
        echo "Cannot approve ${env} (${name}): you are not one of its reviewers. ${url}"
      else
        approve_env "$id" "$eid" "$env"
      fi
    done < <(pending "$id")
  done < <(jq -r --arg g "$GATED" \
    '.[] | select(.status == "waiting" and (.wf as $w | $g | split(" ") | index($w)))
      | [.id, .html_url, .name] | @tsv' <<<"$runs")
}

asked=false
rn_id=""
while :; do
  runs=""
  if all=$(all_runs); then
    runs=$(publisher_runs "$all")
  else
    echo "Could not read the runs for ${tag}; trying again." >&2
  fi

  if [ -n "$runs" ]; then
    failed=$(jq -r '.[] | select(.status == "completed" and .conclusion != "success")
      | "\(.name) \(.conclusion): \(.html_url)"' <<<"$runs")
    if [ -n "$failed" ]; then
      echo "A publisher did not succeed, so the release cannot go out:"
      printf '%s\n' "$failed" | sed 's/^/  /'
      echo "Fix it and re-run that run (Actions -> the run -> Re-run failed jobs), then run this again."
      exit "$EXIT_FAILED" # a publisher failed
    fi

    ready=$(jq -r --arg g "$GATED" '
      ($g | split(" ")) as $gated
      | [.[] | select(.wf as $w | $gated | index($w)) | select(.status == "waiting" or .status == "completed")]
      | length == ($gated | length)' <<<"$runs")

    if [ "$asked" = false ] && [ "$ready" = true ]; then
      echo "Waiting for approval:"
      sweep_publishers list "$runs"
      jq -r --argjson mine "$(jq -c 'map(.id)' <<<"$runs")" --arg why "$NOT_OURS" \
        '.[] | select(.status == "waiting" and (.id as $i | $mine | index($i) | not))
          | "  skipped: \(.name)  \(.html_url) \($why)"' <<<"$all"
      echo "  then: ${RELEASE_ENV}  ${RUN_TITLE_PREFIX}  (once all four publishers pass)"
      if [ "$assume_yes" != "true" ]; then
        printf 'Approve all? [y/N] '
        answer=""
        read -r answer || true
        case "$answer" in
          y | Y) ;;
          *)
            echo "Nothing approved."
            exit "$EXIT_DECLINED"
            ;;
        esac
      fi
      asked=true
    fi

    if [ "$asked" = true ]; then
      sweep_publishers approve "$runs"
    fi
  fi

  if [ "$asked" = true ]; then
    # Title is "<prefix> <tag> <sha>": the exact title pins both tag and commit.
    rn=$(gh api "/repos/${GH_REPO}/actions/workflows/release-notes.yml/runs" -X GET \
      -f event=workflow_run -f per_page=100 \
      --jq '.workflow_runs[] | {id, event, status, conclusion, title: .display_title, html_url}' || true)
    if [ -z "$rn_id" ]; then
      rn_wait=$(jq -sr --arg t "${RUN_TITLE_PREFIX} ${tag} ${sha}" \
        'map(select(.event == "workflow_run" and .title == $t and .status == "waiting"))
          | max_by(.id) | .id // empty' <<<"$rn")
      if [ -n "$rn_wait" ]; then
        rel_eid=$(pending "$rn_wait" | jq -r --arg e "$RELEASE_ENV" 'select(.env == $e and .can == true) | .eid' | head -n 1)
        if [ -n "$rel_eid" ]; then
          rn_id=$rn_wait
          approve_env "$rn_id" "$rel_eid" release
        fi
      fi
    fi
    if [ -n "$rn_id" ]; then
      rn_bad=$(jq -r --argjson id "$rn_id" \
        'select(.id == $id and .status == "completed" and .conclusion != "success") | .html_url' <<<"$rn")
      if [ -n "$rn_bad" ]; then
        echo "${RUN_TITLE_PREFIX} failed after approval: ${rn_bad}"
        exit "$EXIT_FAILED"
      fi
      if url=$(gh release view "$tag" --json url,isDraft --jq 'select(.isDraft == false) | .url' 2>/dev/null) &&
        [ -n "$url" ]; then
        echo "Release ${tag} is live: ${url}"
        exit 0
      fi
    fi
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    if [ "$asked" = false ]; then
      echo "Timed out after ${timeout_min} min: the publishers never all reached their approval step. Nothing approved."
    else
      echo "Timed out after ${timeout_min} min waiting for ${tag} to be released. Check Actions: https://github.com/${GH_REPO}/actions"
    fi
    exit "$EXIT_TIMEOUT"
  fi
  sleep "$poll"
done

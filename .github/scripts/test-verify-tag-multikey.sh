#!/usr/bin/env bash
# Regression test for .github/scripts/verify-tag.sh.
#
# The verify-tag script is the single source of truth for the fatal
# GPG-tag verification used by deploy-worker.yml's `verify` and `deploy`
# jobs (WOR-333). This test stubs out `git verify-tag` (which needs real
# signed tags we don't sign here), runs the script against 7 input cases,
# and asserts each behaves as expected. The load-bearing cases are the
# multi-key armor decoy attack (cases 5 + 6) and fingerprint mismatches
# (cases 4 + 7).
#
# Run locally:
#   bash .github/scripts/test-verify-tag-multikey.sh
# Run in CI:
#   .github/workflows/verify-tag-test.yml invokes this on every PR that
#   touches the verify script, this test, or the deploy workflow.
#
# Why this exists:
# A future PR that "simplifies" the awk pattern in verify-tag.sh, drops
# the PUB_COUNT check, or reorders the fingerprint-vs-multi-key guards
# could silently re-open the multi-key decoy attack. This test proves
# the on-disk script defeats it.

# Deliberately NOT using `set -e` — the script-under-test returns non-zero
# for invalid-input cases by design, and we capture each exit via $?.
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel)}"
SCRIPT="${VERIFY_TAG_SCRIPT:-${REPO_ROOT}/.github/scripts/verify-tag.sh}"
# Absolute, because the mutation gate re-invokes this file after the cases have
# cd'd away from the repo. A relative path would fail to launch, and every
# mutation would then report "suite went red" for the wrong reason — a vacuous
# gate checking vacuous tests.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
# The fixture cases cd out of the repo and land on `/`. The mutation gate runs
# after them and re-invokes this file, so it must restore the starting directory
# first: cases 1-7 resolve HEAD in the current repo, and from `/` they all fail
# closed for a reason that has nothing to do with the mutation under test.
START_CWD=$(pwd)

if [ ! -f "$SCRIPT" ]; then
  echo "ERROR: $SCRIPT not found"
  exit 1
fi

# Sanity: the script must contain the load-bearing defense markers.
# If any of these don't match, the script has been edited in a way that
# drops a defense; fail loud.
declare -a REQUIRED=(
  "set -euo pipefail"
  "PUB_COUNT"
  "MAINTAINER_GPG_FINGERPRINT"
  "git -c gpg.program=gpg -c gpg.format=openpgp verify-tag"
  # The WOR-864 fix itself. Its absence is what this whole file exists to catch,
  # and it had no marker at all until a review deleted the line and watched the
  # suite report 10/10.
  "git fetch --force origin"
  # Both post-verify bindings: a good signature proves the maintainer signed SOME
  # tag, not this release at this revision.
  "TAG_TARGET"
  "EMBEDDED_TAG_NAME"
)
# Strip comments before matching. A whole-file grep is satisfied by the marker
# appearing ANYWHERE — including in a comment left behind by the change that
# deleted the code. That was demonstrated twice: once by comments naming the
# flags they guarded, and again by parking both binding comparisons in a
# replacement comment while removing the blocks entirely.
#
# These markers are deliberately coarse (variable names, not comparisons) so that
# an INVERTED defense still satisfies them. Text presence and correct behaviour
# are different questions; the mutation gate at the end of this file owns the
# second one, and coarse markers keep the two from collapsing into each other.
SCRIPT_CODE=$(grep -v '^[[:space:]]*#' "$SCRIPT")
for marker in "${REQUIRED[@]}"; do
  if ! printf '%s' "$SCRIPT_CODE" | grep -qF "$marker"; then
    echo "ERROR: verify-tag.sh is missing required marker: $marker"
    echo "       A required defense was removed."
    exit 1
  fi
done
echo "OK: verify-tag.sh contains all required defense markers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Build a runnable wrapper: stub git verify-tag so we exercise the
# pre-verify guards in isolation. The script-under-test is sourced
# inside a subshell so its `set -euo pipefail` and `exit` calls don't
# kill the test harness.
{
  cat <<PROLOGUE
#!/usr/bin/env bash
git() {
  # Match verify-tag as the SUBCOMMAND — skip -c pairs and options, then compare
  # the first bare token.
  #
  # A fixed position was wrong (the real call carries several -c pins, and gained
  # another when gpg.format was pinned). But the substring fix that replaced it
  # was worse: it also swallowed
  #
  #     git config user.name "verify-tag fixture"
  #
  # returning 0 without setting anything, so every fixture repo had an empty
  # ident and every fixture commit died with "empty ident name". That only shows
  # up on CI, where there is no global identity to fall back on — which is why
  # cases 8-10 passed on two machines and failed on the runner.
  #
  # The fixture user.name below still contains "verify-tag" ON PURPOSE: it is the
  # canary. Re-broaden this match and the suite breaks loudly instead of silently.
  local sub="" i=1
  while [ \$i -le \$# ]; do
    case "\${!i}" in
      -c) i=\$((i + 2)); continue ;;
      -*) i=\$((i + 1)); continue ;;
      *)  sub="\${!i}"; break ;;
    esac
  done
  if [ "\$sub" = "verify-tag" ]; then
    return 0
  fi
  # Cases 1-7 drive a synthetic tag name that does not exist in this repo, so
  # the post-verify bindings (tag peels to HEAD, embedded name matches the ref)
  # would refuse for a reason unrelated to the key handling they test. Make
  # those two lookups agree. Cases 8-10 exercise the real git behaviour.
  case "\$*" in
    *"v0.0.0-harness-never-pushed^{commit}"*)
      command git rev-parse --verify --quiet "HEAD^{commit}"; return \$? ;;
    "cat-file -t v0.0.0-harness-never-pushed")
      echo "tag"; return 0 ;;
    "cat-file tag v0.0.0-harness-never-pushed")
      echo "tag v0.0.0-harness-never-pushed"; return 0 ;;
  esac
  command git "\$@"
}
export -f git

verify_logic() {
  export MAINTAINER_PUBKEY="\$1"
  export MAINTAINER_FINGERPRINT="\$2"
  export GITHUB_REF_NAME="\${3:-v0.0.0-harness-never-pushed}"
  ( bash "$SCRIPT" )
}
PROLOGUE
} > "$WORK/runnable.sh"

# 4. Generate two fixture ed25519 keys + four armor variants.
export GNUPGHOME="$WORK/keygen"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

gpg --batch --gen-key >/dev/null 2>&1 <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Name-Real: TestKey1
Name-Email: test1@example.com
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key >/dev/null 2>&1 <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Name-Real: TestKey2
Name-Email: test2@example.com
Expire-Date: 0
%commit
EOF

KEY1_FPR=$(gpg --batch --with-colons --fingerprint test1@example.com | awk -F: '/^fpr:/ {print $10; exit}')
KEY2_FPR=$(gpg --batch --with-colons --fingerprint test2@example.com | awk -F: '/^fpr:/ {print $10; exit}')

SINGLE1=$(gpg --batch --armor --export test1@example.com)
MULTI_1FIRST=$(gpg --batch --armor --export test1@example.com test2@example.com)
MULTI_2FIRST=$(gpg --batch --armor --export test2@example.com test1@example.com)
SINGLE2=$(gpg --batch --armor --export test2@example.com)

# Unset GNUPGHOME so verify_logic creates its own fresh one (matches the
# YAML's behavior — the verify step uses mktemp -d for isolation).
unset GNUPGHOME

# shellcheck disable=SC1090
source "$WORK/runnable.sh"

# 5. Run the 7 cases.
PASS=0; FAIL=0

assert_exit() {
  local label="$1"
  local expected_exit="$2"
  local actual="$3"
  if [ "$actual" -eq "$expected_exit" ]; then
    echo "OK   $label → exit $actual"
    PASS=$((PASS + 1))
  else
    echo "FAIL $label → got exit $actual, expected $expected_exit"
    FAIL=$((FAIL + 1))
  fi
}

# Run a real-git fixture case, and on failure PRINT WHAT GIT SAID.
#
# The cases used to run with output sent to /dev/null. When cases 8-10 failed on
# the runner but passed on two other machines, that left one number and no
# stderr, and each guess cost a CI round-trip — one of them reproduced the same
# exit codes from an unrelated cause and looked like a fix. A test that only
# reports a number cannot be debugged remotely, so keep the output on failure.
run_case() {
  local label="$1" expected="$2" fn="$3" rc
  "$fn" >"$WORK/$fn.log" 2>&1; rc=$?
  assert_exit "$label" "$expected" "$rc"
  if [ "$rc" -ne "$expected" ] && [ -s "$WORK/$fn.log" ]; then
    echo "     --- $fn output ---"
    sed 's/^/     | /' "$WORK/$fn.log"
    echo "     --- git env ---"
    echo "     | git $(git --version 2>&1 | cut -d' ' -f3)  uid=$(id -u)  HOME=${HOME:-<unset>}  TMPDIR=${TMPDIR:-<unset>}"
    git config --list --show-origin 2>&1 | grep -Ei 'sign|template|hook|safe|default' | sed 's/^/     | /' | head -8
  fi
}

# Case 1: empty pubkey + fingerprint → fail (var unset)
verify_logic "" "" >/dev/null 2>&1; assert_exit "var unset" 1 $?

# Case 2: bad fingerprint length → fail (40-char check)
verify_logic "$SINGLE1" "abc" >/dev/null 2>&1; assert_exit "bad fingerprint length" 1 $?

# Case 3: single key, correct pin → pass (verify-tag stubbed)
verify_logic "$SINGLE1" "$KEY1_FPR" >/dev/null 2>&1; assert_exit "single key, correct pin" 0 $?

# Case 4: single key, wrong pin → fail (fingerprint mismatch)
verify_logic "$SINGLE1" "$KEY2_FPR" >/dev/null 2>&1; assert_exit "single key, wrong pin" 1 $?

# Case 5: MULTI-KEY DECOY (key1 first), pinned key1 → fail (PUB_COUNT != 1)
# This is the load-bearing case. Without the multi-key check, this passes
# (first fpr matches pin), and git verify-tag accepts a signature from
# EITHER imported key.
verify_logic "$MULTI_1FIRST" "$KEY1_FPR" >/dev/null 2>&1; assert_exit "multi-key (key1 first) → DECOY DEFENSE" 1 $?

# Case 6: MULTI-KEY DECOY inverse (key2 first), pinned key1 → fail
verify_logic "$MULTI_2FIRST" "$KEY1_FPR" >/dev/null 2>&1; assert_exit "multi-key (key2 first) → DECOY DEFENSE" 1 $?

# Case 7: single key2, pinned key1 → fail (fingerprint mismatch)
verify_logic "$SINGLE2" "$KEY1_FPR" >/dev/null 2>&1; assert_exit "single key2, pinned key1" 1 $?

# Case 8: the tag OBJECT must be fetched when only the commit is present.
#
# `actions/checkout` with `fetch-depth: 0` stopped leaving the annotated tag
# object on disk after the action bump in #469. Without the object there is no
# signature to check and git reports "cannot verify a non-tag object of type
# commit" — which failed every publisher on the real v0.3.12 tag (WOR-864).
#
# Uses real git (no stub): build an origin carrying an annotated tag, clone it
# without tags, point a LIGHTWEIGHT ref at the commit to reproduce exactly what
# the new checkout leaves, then run the guard and assert the object became a
# tag. Unsigned annotated tag is enough — this pins the FETCH, not the GPG check
# (cases 1-7 cover that).
# Identity AND signing, set on the fixture repo. Identity because `git tag -a`
# needs a tagger. Signing OFF because this repo signs its real commits and tags,
# and a runner has no maintainer key — an inherited commit.gpgsign made every
# fixture `git commit` fail, which is exactly what sank cases 8-10 on the runner
# while they passed locally and in a root container. The fixtures exercise ref
# plumbing, never signatures (cases 1-7 own that), so inheriting signing config
# is pure hazard with no upside. Defined before its first caller.
_fixture_identity() {
  git config user.email fixture@example.com
  git config user.name "verify-tag fixture"
  git config commit.gpgsign false
  git config tag.gpgsign false
}

# --------------------------------------------------------------------------
# Cases 8-10: drive the REAL verify-tag.sh and assert ITS exit code.
#
# These used to re-implement the guard inline ("verbatim from verify-tag.sh")
# and assert git's behaviour. That is a test of the copy, not of the code, and
# it showed: deleting the entire WOR-864 fetch fix from verify-tag.sh left this
# suite reporting 10/10. Same for both post-verify bindings — replacing their
# `exit 1` with `:` stayed green. The only thing tying the script to this file
# was a grep.
#
# Now each case builds a fixture, cds into it, and runs `bash "$SCRIPT"` through
# verify_logic with the pinned fixture key, so the key handling passes and the
# tag plumbing is what decides the exit code. Only `git verify-tag` remains
# stubbed: these cases pin the fetch and the two bindings, not gpg — cases 1-7
# own gpg, and signing fixtures would test gpg twice and the plumbing never.
# --------------------------------------------------------------------------

# Build an origin carrying an annotated tag, then clone it the way
# actions/checkout v6 now leaves a tag push: the commit is present, the tag
# OBJECT is not. Leaves the caller cd'd inside the clone.
#   $1 = scratch dir   $2 = name the tag is created under   $3 = ref it is served as
# Distinct exit codes: the cases run with output captured, and a single shared
# code points at four lines at once.
_tag_fixture() {
  local root="$1" made="$2" served="$3"
  # -b main on BOTH: the bare repo's HEAD defaults to the local git's
  # init.defaultBranch, and pushing `main` into a repo whose HEAD says `master`
  # produces a clone with nothing checked out ("remote HEAD refers to nonexistent
  # ref"). Developer machines with init.defaultBranch=main never see it.
  git init -q -b main --bare "$root/origin.git" || return 91
  git init -q -b main "$root/src" || return 91
  cd "$root/src" || return 91
  _fixture_identity
  git commit -q --allow-empty -m init || return 92
  git tag -a "$made" -m "$made" || return 93
  git remote add origin "$root/origin.git" || return 91
  git push -q origin HEAD:refs/heads/main "refs/tags/${made}:refs/tags/${served}" || return 94
  git clone -q --no-tags "$root/origin.git" "$root/work" || return 95
  cd "$root/work" || return 95
  # A broken fixture must never look like a passing test. Cases 9 and 10 expect
  # exit 1, and a fixture that failed to check anything out ALSO yields exit 1 —
  # so both reported OK against a repo with no commits. Fail with a code no case
  # expects instead.
  # (the tag ref is deliberately absent here — the clone is --no-tags, and each
  # case creates the lightweight ref itself to reproduce the checkout state)
  git rev-parse --verify --quiet HEAD >/dev/null || return 96
}

# Case 8: the tag ref is present but LIGHTWEIGHT — exactly what the new checkout
# leaves, and exactly what failed the real v0.3.12. The script must fetch the
# object and succeed. Delete the fetch and this case is the one that goes red.
tagfetch_case() {
  local root rc; root=$(mktemp -d) || return 90
  _tag_fixture "$root" v9.9.9 v9.9.9 || { rc=$?; cd / || true; rm -rf "$root"; return $rc; }
  git update-ref refs/tags/v9.9.9 "$(git rev-parse HEAD)"
  [ "$(git cat-file -t v9.9.9)" = "commit" ] || { cd / || true; rm -rf "$root"; return 96; }
  verify_logic "$SINGLE1" "$KEY1_FPR" v9.9.9; rc=$?
  cd / || true; rm -rf "$root"
  return $rc
}
run_case "lightweight tag ref → real script publishes" 0 tagfetch_case

# Case 9: the tag object names v0.1.0 but is served under refs/tags/v9.9.9. The
# signature is genuine; it just authorises a different release. The script must
# refuse. Neuter the embedded-name binding and this case goes green.
tagname_case() {
  local root rc; root=$(mktemp -d) || return 90
  _tag_fixture "$root" v0.1.0 v9.9.9 || { rc=$?; cd / || true; rm -rf "$root"; return $rc; }
  git update-ref refs/tags/v9.9.9 "$(git rev-parse HEAD)"
  verify_logic "$SINGLE1" "$KEY1_FPR" v9.9.9; rc=$?
  cd / || true; rm -rf "$root"
  return $rc
}
run_case "tag names a different release → real script refuses" 1 tagname_case

# Case 10: HEAD moves after checkout, so the verified tag no longer describes the
# code being run — the re-tag race. The script must refuse. Neuter the revision
# binding and this case goes green.
tagpeel_case() {
  local root rc; root=$(mktemp -d) || return 90
  _tag_fixture "$root" v9.9.9 v9.9.9 || { rc=$?; cd / || true; rm -rf "$root"; return $rc; }
  _fixture_identity
  git commit -q --allow-empty -m two || { cd / || true; rm -rf "$root"; return 97; }
  git update-ref refs/tags/v9.9.9 "$(git rev-parse HEAD)"
  verify_logic "$SINGLE1" "$KEY1_FPR" v9.9.9; rc=$?
  cd / || true; rm -rf "$root"
  return $rc
}
run_case "tag no longer peels to HEAD → real script refuses" 1 tagpeel_case

echo ""
echo "Pass: $PASS  Fail: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1

# --------------------------------------------------------------------------
# Mutation gate: every defense above must be LOAD-BEARING.
#
# Four separate assertions in this file's own history passed against code that
# no longer worked — a substring match that swallowed its own fixture setup,
# guards sharing one exit code, output sent to /dev/null, and whole-file greps
# satisfied by a comment. Each looked green. The only check that catches that
# class is asserting the suite goes RED when a defense is removed.
#
# Each mutation below keeps the REQUIRED markers satisfied and kills only the
# BEHAVIOUR, so a pass here means the executed cases have real detection power —
# not that the grep found a string.
# --------------------------------------------------------------------------
if [ -z "${VERIFY_TAG_MUTATION_CHILD:-}" ]; then
  echo ""
  echo "Mutation gate — each defense must be load-bearing:"
  MUT_FAIL=0
  _mutate() {
    local label="$1" expr="$2" dir
    dir=$(mktemp -d)
    sed "$expr" "$SCRIPT" > "$dir/verify-tag.sh"
    if cmp -s "$SCRIPT" "$dir/verify-tag.sh"; then
      echo "  STALE    $label — the mutation changed nothing; its pattern no longer matches"
      MUT_FAIL=$((MUT_FAIL + 1)); rm -rf "$dir"; return
    fi
    if (cd "$START_CWD" && VERIFY_TAG_MUTATION_CHILD=1 \
          VERIFY_TAG_SCRIPT="$dir/verify-tag.sh" bash "$SELF") >/dev/null 2>&1; then
      echo "  VACUOUS  $label — suite still PASSED with this defense disabled"
      MUT_FAIL=$((MUT_FAIL + 1))
    else
      echo "  OK       $label — suite went red"
    fi
    rm -rf "$dir"
  }

  # CONTROL FIRST. A cosmetic edit must leave the suite GREEN. If this reports
  # red, the gate is broken (bad path, missing env, child dying on startup) and
  # every "OK … went red" below would be meaningless — a vacuous gate policing
  # vacuous tests. Run it before trusting a single result.
  _control() {
    local dir; dir=$(mktemp -d)
    sed 's/^# Fatal GPG-tag verification/# Fatal GPG-tag verification (control mutation)/' \
      "$SCRIPT" > "$dir/verify-tag.sh"
    if cmp -s "$SCRIPT" "$dir/verify-tag.sh"; then
      echo "  STALE    control — pattern no longer matches; gate cannot be trusted"
      MUT_FAIL=$((MUT_FAIL + 1)); rm -rf "$dir"; return
    fi
    if (cd "$START_CWD" && VERIFY_TAG_MUTATION_CHILD=1 \
          VERIFY_TAG_SCRIPT="$dir/verify-tag.sh" bash "$SELF") >/dev/null 2>&1; then
      echo "  OK       control — cosmetic edit stays green, so the gate can run"
    else
      echo "  BROKEN   control — a comment-only edit turned the suite red."
      echo "           The gate is not measuring the mutations. Fix before trusting it."
      MUT_FAIL=$((MUT_FAIL + 1))
    fi
    rm -rf "$dir"
  }
  _control

  # Invert the object-type guard so the fetch never fires for a lightweight ref.
  # The `git fetch` line stays in the file, so the marker check still passes.
  _mutate "fetch the tag object"        '/cat-file -t/s/!= "tag"/= "tag"/'
  # Compare TAG_TARGET to itself: the binding can never fire. TAG_TARGET remains.
  _mutate "bind tag to checked-out rev" '/TAG_TARGET.*!=.*HEAD_COMMIT/s/HEAD_COMMIT/TAG_TARGET/g'
  # Same for the release-name binding. EMBEDDED_TAG_NAME remains.
  # Pattern follows the variable rename to TAG_REF. When it did not, this gate
  # reported STALE rather than OK — refusing to certify a defense it could no
  # longer mutate. That is the gate working; the rename had silently removed this
  # defense's only behavioural test.
  _mutate "bind tag to release name"    '/EMBEDDED_TAG_NAME.*!=.*TAG_REF/s/TAG_REF/EMBEDDED_TAG_NAME/g'

  echo ""
  if [ "$MUT_FAIL" -ne 0 ]; then
    echo "MUTATION GATE FAILED: $MUT_FAIL defense(s) are not actually tested."
    echo "A green suite against a disabled defense is worse than no test."
    exit 1
  fi
  echo "Mutation gate: all defenses load-bearing."
fi

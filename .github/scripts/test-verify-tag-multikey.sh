#!/usr/bin/env bash
# Regression test for .github/scripts/verify-tag.sh.
#
# The verify-tag script is the single source of truth for the fatal
# GPG-tag verification used by deploy-worker.yml's `verify` and `deploy`
# jobs (WOR-323). This test stubs out `git verify-tag` (which needs real
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
SCRIPT="${REPO_ROOT}/.github/scripts/verify-tag.sh"

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
  "git -c gpg.program=gpg verify-tag"
)
for marker in "${REQUIRED[@]}"; do
  if ! grep -q "$marker" "$SCRIPT"; then
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
  if [ "\$1" = "-c" ] && [ "\$2" = "gpg.program=gpg" ] && [ "\$3" = "verify-tag" ]; then
    return 0
  fi
  command git "\$@"
}
export -f git

verify_logic() {
  export MAINTAINER_PUBKEY="\$1"
  export MAINTAINER_FINGERPRINT="\$2"
  export GITHUB_REF_NAME="\${3:-v0.0.0-test}"
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

echo ""
echo "Pass: $PASS  Fail: $FAIL"
[ "$FAIL" -eq 0 ]

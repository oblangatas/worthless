#!/usr/bin/env bash
# Fatal GPG-tag verification with fingerprint pinning + multi-key armor
# rejection. WOR-323.
#
# Reads from environment:
#   MAINTAINER_PUBKEY      — ASCII-armored public key (repo Variable)
#   MAINTAINER_FINGERPRINT — 40-char hex fingerprint (repo Variable)
#   GITHUB_REF_NAME        — tag to verify (set automatically by GHA)
#
# Defense layers (each fails closed):
#   1. Both Variables must be set.
#   2. Fingerprint must normalize to exactly 40 hex chars.
#   3. Pubkey must import successfully into a fresh GNUPGHOME.
#   4. Imported keyring must contain exactly one primary key (rejects
#      multi-key armor decoy attack — see WOR-323 expert review).
#   5. Imported key's fingerprint must match the pinned fingerprint.
#   6. `git verify-tag` must succeed against the single-key keyring.
#
# What this DOES NOT defend against:
#   - A full Variable-swap by an attacker who can write BOTH Variables
#     atomically. The fingerprint pin and multi-key rejection raise the
#     bar (each Variable change shows up in the GitHub audit log) but
#     are not cryptographic defense against repo-admin compromise.
#     See workers/worthless-sh/DEPLOY.md §"Known residual risks".
#
# Single source of truth — called from both `verify` and `deploy` jobs
# in deploy-worker.yml so the deploy job re-verifies independently
# rather than transitively trusting the verify job's outputs. Tested
# by .github/scripts/test-verify-tag-multikey.sh (run on every PR via
# .github/workflows/verify-tag-test.yml).

set -euo pipefail

if [ -z "${MAINTAINER_PUBKEY:-}" ] || [ -z "${MAINTAINER_FINGERPRINT:-}" ]; then
  echo "::error title=Missing maintainer trust anchors::Both MAINTAINER_GPG_PUBKEY and MAINTAINER_GPG_FINGERPRINT repo Variables must be set. See workers/worthless-sh/DEPLOY.md §'Set up signed tags'."
  exit 1
fi

# Normalize the pinned fingerprint: gpg --fingerprint default output is
# space-separated and mixed-case; the colon-format output we compare
# against is no-spaces upper-case. Strip whitespace and uppercase so
# either input form works.
NORMALIZED_FINGERPRINT=$(printf '%s' "${MAINTAINER_FINGERPRINT}" | tr -d '[:space:]' | tr 'a-f' 'A-F')
if [ "${#NORMALIZED_FINGERPRINT}" -ne 40 ]; then
  echo "::error title=Bad fingerprint::MAINTAINER_GPG_FINGERPRINT must be 40 hex chars after stripping whitespace; got ${#NORMALIZED_FINGERPRINT}."
  exit 1
fi

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
chmod 700 "$GNUPGHOME"
# Clean up the temp keyring on any exit path. Without this, every verify
# invocation (verify job + deploy job + every PR run of the test harness)
# leaves a directory in /tmp; on long-running runners this accumulates.
trap 'rm -rf "$GNUPGHOME"' EXIT
printf '%s' "${MAINTAINER_PUBKEY}" | gpg --batch --import

# Reject multi-key armor (decoy attack). If MAINTAINER_GPG_PUBKEY is
# swapped to ASCII-armor `[pinned_key, attacker_key]` in either order,
# importing produces a keyring where git verify-tag would accept
# signatures from EITHER key, while the simple "first imported
# fingerprint matches pin" check still passes. Enforcing exactly one
# primary key blocks this.
PUB_COUNT=$(gpg --batch --with-colons --list-keys | awk -F: '/^pub:/ {n++} END {print n+0}')
if [ "${PUB_COUNT}" -ne 1 ]; then
  echo "::error title=Multi-key armor rejected::MAINTAINER_GPG_PUBKEY must contain exactly one primary key; found ${PUB_COUNT}. Multi-key armor is rejected to prevent decoy-key attacks."
  exit 1
fi

IMPORTED_FINGERPRINT=$(gpg --batch --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')
if [ "${IMPORTED_FINGERPRINT}" != "${NORMALIZED_FINGERPRINT}" ]; then
  echo "::error title=Fingerprint mismatch::Imported key fingerprint ${IMPORTED_FINGERPRINT} does not match pinned MAINTAINER_GPG_FINGERPRINT ${NORMALIZED_FINGERPRINT}. Variable was tampered with, or rotated without updating both Variables atomically."
  exit 1
fi

# Pin gpg.program defensively: a future runner image change could ship
# a wrapper or alternative gpg path; we want git to invoke the same
# gpg (and inherit our GNUPGHOME) as we used for import.
# Make sure the ANNOTATED TAG OBJECT is on disk, not just the commit it points
# at. `actions/checkout` with `fetch-depth: 0` used to leave the tag object
# behind; after the action bump in #469 it does not, so `git verify-tag` reports
#
#     error: v0.3.12: cannot verify a non-tag object of type commit
#
# and every publisher fails closed — which is exactly what happened to the
# v0.3.12 tag (WOR-864). A signature cannot be checked if the object carrying it
# was never fetched.
#
# Guarded on the object type so this is a no-op when the tag is already present
# (the offline harness in test-verify-tag-multikey.sh builds its own tags and
# must not reach the network). Failure to fetch is not fatal here: verify-tag
# below is the real gate and still fails closed with a signature error.
if [ "$(git cat-file -t "${GITHUB_REF_NAME}" 2>/dev/null || true)" != "tag" ]; then
  git fetch --force origin "refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}" 2>/dev/null || true
fi

if ! git -c gpg.program=gpg verify-tag "${GITHUB_REF_NAME}"; then
  echo "::error title=Unsigned or untrusted tag::Tag ${GITHUB_REF_NAME} did not verify against MAINTAINER_GPG_PUBKEY (fingerprint ${NORMALIZED_FINGERPRINT})."
  exit 1
fi

# A good signature alone is not enough — it proves the maintainer signed SOME
# tag, not that they signed THIS release at THIS revision. Two bindings close
# that gap. Reaching here implies the object exists and is a properly signed
# tag, since verify-tag above fails closed otherwise.
#
# 1. Bind to the checked-out revision. The fetch above rewrites the local tag
#    ref AFTER checkout, so a tag-ref writer could repoint the remote to a
#    different, also-validly-signed tag between the two. verify-tag would then
#    bless that object while the job keeps executing the earlier, unverified
#    HEAD. Refuse when the tag does not peel to what we are running.
# 2. Bind to this release name. The tag object carries its own `tag <name>`
#    header, independent of the ref it is served under — so a genuine signature
#    for v0.1.0 could be replayed under the ref v9.9.9 and still verify. Refuse
#    when the embedded name is not the one we were triggered for.
TAG_TARGET=$(git rev-parse --verify --quiet "${GITHUB_REF_NAME}^{commit}" || true)
HEAD_COMMIT=$(git rev-parse --verify --quiet "HEAD^{commit}" || true)
if [ -n "${HEAD_COMMIT}" ] && [ "${TAG_TARGET}" != "${HEAD_COMMIT}" ]; then
  echo "::error title=Tag does not match the checked-out revision::${GITHUB_REF_NAME} points at ${TAG_TARGET:-<none>} but this job is running ${HEAD_COMMIT}. The tag moved after checkout; refusing to publish code that was never verified."
  exit 1
fi

EMBEDDED_TAG_NAME=$(git cat-file tag "${GITHUB_REF_NAME}" 2>/dev/null | sed -n 's/^tag //p' | head -1)
if [ -n "${EMBEDDED_TAG_NAME}" ] && [ "${EMBEDDED_TAG_NAME}" != "${GITHUB_REF_NAME}" ]; then
  echo "::error title=Tag name mismatch::The signed tag object names '${EMBEDDED_TAG_NAME}' but is served under '${GITHUB_REF_NAME}'. A signature for one release cannot authorise another."
  exit 1
fi

echo "Tag ${GITHUB_REF_NAME} verified against pinned fingerprint ${NORMALIZED_FINGERPRINT}."

#!/bin/sh
# install-git-hooks.sh -- install the repo's hand-managed git hooks.
#
# Only `reference-transaction` lives here.  pre-commit owns commit-msg / pre-commit /
# pre-push and regenerates them; it cannot manage reference-transaction at all -- that
# name is not in its HOOK_TYPES -- which is precisely why the tag guard is safe here.
#
# Deliberately does NOT call `pre-commit init-templatedir`: that rewrites the shared
# pre-commit hook with --skip-on-missing-config, which makes it exit 0 (silently, no
# error) in any checkout lacking .pre-commit-config.yaml -- muting gitleaks and
# detect-private-key.  It also cannot install this hook.  See RELEASING.md (WOR-908).
set -eu

repo_root=$(git rev-parse --show-toplevel)
hooks_dir=$(git config --get core.hooksPath || true)
[ -n "$hooks_dir" ] || hooks_dir="$(git rev-parse --git-common-dir)/hooks"

mkdir -p "$hooks_dir"
install -m 755 "$repo_root/scripts/hooks/reference-transaction" "$hooks_dir/reference-transaction"

echo "Installed: $hooks_dir/reference-transaction"
echo "  Refuses to create a v* release tag that is not OpenPGP-signed."
echo "  This hooks dir is shared by every worktree of this repo."

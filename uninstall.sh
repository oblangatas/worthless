#!/bin/sh
# Worthless uninstaller — https://worthless.sh/uninstall
# Usage:         curl -sSL https://worthless.sh/uninstall | sh
# Non-interactive: curl -sSL https://worthless.sh/uninstall | sh -s -- --yes
# Inspect first: curl -sSL 'https://worthless.sh/uninstall?explain=1' | less
#
# Two modes:
#   1. The 'worthless' binary works  → delegate to `worthless uninstall`, which
#      restores your real key into every locked .env, THEN remove the tool.
#   2. The binary is broken/missing  → best-effort wipe of ~/.worthless, the OS
#      keychain entry, and the installed tool. A plain script CANNOT unscramble
#      your split keys (that needs the program's crypto), so it cannot restore
#      them — you must rotate those keys at your provider.
#
# Exit codes (UX contract):
#   0   removed cleanly
#   1   refused (no --yes in a non-interactive shell, or the user declined)
#   20  unsupported platform (Windows native)
#   40  wipe failed (something could not be removed; manual cleanup needed)

set -eu

EXIT_REFUSED=1
EXIT_PLATFORM=20
EXIT_INTERNAL=40

UNINSTALL_DOCS_URL="https://docs.wless.io/uninstall"

# Where Worthless keeps its state. Honored so two installs (staging/prod) or a
# test sandbox can target a specific home; mirrors the CLI's WORTHLESS_HOME.
WORTHLESS_HOME_DIR="${WORTHLESS_HOME:-$HOME/.worthless}"

# --yes / -y (or WORTHLESS_UNINSTALL_YES=1) skips the confirmation prompt.
ASSUME_YES=0
PRINT_ACCT=0
[ "${WORTHLESS_UNINSTALL_YES:-}" = "1" ] && ASSUME_YES=1
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        # Read-only introspection: print the OS-keychain entry this would remove,
        # then exit. Lets you (or a test) confirm it targets the right entry
        # before running for real. Removes nothing.
        --print-keychain-account) PRINT_ACCT=1 ;;
        *) ;;  # curl|sh passes no args; ignore anything unexpected
    esac
done

# Hermetic: ignore caller env. A poisoned PATH or loader var turns every
# external call we make (rm, security, uv, sha256sum, sqlite3) into RCE — the
# exact same curl|sh threat model install.sh defends against. Same scrub list.
unset \
    UV_INDEX UV_INDEX_URL UV_DEFAULT_INDEX UV_EXTRA_INDEX_URL UV_INDEX_STRATEGY \
    UV_FIND_LINKS \
    PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_FIND_LINKS PIP_NO_INDEX \
    UV_CONFIG_FILE PIP_CONFIG_FILE \
    UV_NO_CACHE UV_OFFLINE \
    PIP_TRUSTED_HOST UV_INSECURE_HOST UV_NATIVE_TLS \
    SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE \
    PIP_CERT PIP_CLIENT_CERT \
    UV_PYTHON_INSTALL_MIRROR UV_PYTHON_PREFERENCE \
    UV_KEYRING_PROVIDER PIP_KEYRING_PROVIDER \
    UV_INSTALL_DIR UV_UNMANAGED_INSTALL INSTALLER_DOWNLOAD_URL \
    PYTHONPATH PYTHONSTARTUP \
    BASH_ENV ENV CDPATH GLOBIGNORE \
    LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH \
    DYLD_FRAMEWORK_PATH DYLD_FORCE_FLAT_NAMESPACE \
    ALL_PROXY all_proxy http_proxy https_proxy \
    2>/dev/null || true

# Caller PATH lockdown — system dirs + ~/.local/bin (where uv puts the tool)
# outrank any caller-controlled prefix. Strict: only literal "1" disables it
# (test harness sets that to point at a sandbox without the real binary).
if [ "${WORTHLESS_TRUST_PATH:-}" != "1" ]; then
    home_for_path="${HOME:-/root}"
    [ "$home_for_path" = "/" ] && home_for_path="/root"
    PATH="/usr/bin:/bin:/usr/local/bin:${home_for_path}/.local/bin:${PATH:-}"
    export PATH
fi

# --- Output helpers (same vocabulary as install.sh) --------------------------

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
        BOLD='\033[1m'; RESET='\033[0m'
    else
        RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
    fi
}
info() { printf "${BOLD}%s${RESET}\n" "$1"; }
ok()   { printf "${GREEN}%s${RESET}\n" "$1"; }
warn() { printf "${YELLOW}%s${RESET}\n" "$1" >&2; }
err()  { printf "${RED}error: %s${RESET}\n" "$1" >&2; }
die() {
    code="$1"; shift
    err "$1"; shift
    while [ "$#" -gt 0 ]; do printf "       %s\n" "$1" >&2; shift; done
    exit "$code"
}

# --- Platform ----------------------------------------------------------------

detect_os() {
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    case "$uname_s" in
        Darwin) OS="macos" ;;
        Linux)  OS="linux" ;;
        CYGWIN*|MINGW*|MSYS*)
            die "$EXIT_PLATFORM" "Windows native shells are not supported." \
                "Uninstall from the Linux subsystem you installed in (WSL2)." ;;
        *) OS="unknown"
           warn "Unrecognized OS '${uname_s}' — wiping files, but the keychain step may be skipped." ;;
    esac
}

# --- Confirmation ------------------------------------------------------------
# With `curl | sh`, fd 0 is the SCRIPT, not the terminal — so read from /dev/tty.
# No tty available (CI/automation) and no --yes => refuse rather than guess.
confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    if [ -e /dev/tty ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
        if printf "This removes Worthless from this machine. Continue? [y/N] " > /dev/tty 2>/dev/null \
            && read reply < /dev/tty 2>/dev/null; then
            case "$reply" in
                y|Y|yes|YES|Yes) return 0 ;;
                *) die "$EXIT_REFUSED" "Aborted — nothing was removed." ;;
            esac
        fi
    fi
    die "$EXIT_REFUSED" "Refusing to uninstall unattended without confirmation." \
        "Re-run with --yes:" \
        "  curl -sSL https://worthless.sh/uninstall | sh -s -- --yes"
}

# --- Helpers -----------------------------------------------------------------

sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
    else printf ''; fi
}

# Replicate the CLI's keyring account: fernet-key-<sha256(realpath(home))[:12]>.
# `printf '%s'` (no newline) matches Python's str(path).encode() exactly.
keyring_account() {
    if command -v realpath >/dev/null 2>&1; then
        resolved="$(realpath -m "$WORTHLESS_HOME_DIR" 2>/dev/null)" || resolved="$WORTHLESS_HOME_DIR"
    elif [ -d "$WORTHLESS_HOME_DIR" ]; then
        resolved="$(cd "$WORTHLESS_HOME_DIR" 2>/dev/null && pwd -P)" || resolved="$WORTHLESS_HOME_DIR"
    else
        resolved="$WORTHLESS_HOME_DIR"
    fi
    digest="$(printf '%s' "$resolved" | sha256_hex | cut -c1-12)"
    [ -n "$digest" ] && printf 'fernet-key-%s' "$digest"
}

delete_keychain_entry() {
    acct="$(keyring_account || true)"
    [ -n "${acct:-}" ] || { warn "Could not compute the keychain entry name (no sha256 tool); skipping."; return 0; }
    case "${OS:-}" in
        macos)
            # Delete every matching item (there can be duplicates). Non-zero just
            # means "no more entries" — never an error for us.
            while security delete-generic-password -s worthless -a "$acct" >/dev/null 2>&1; do : ; done
            ;;
        linux)
            if command -v secret-tool >/dev/null 2>&1; then
                secret-tool clear service worthless username "$acct" >/dev/null 2>&1 || true
            fi
            # The file-fallback key lives inside ~/.worthless and is removed by the wipe.
            ;;
    esac
    return 0
}

# env_path is stored in PLAINTEXT in the enrollments table (only shard-B is
# encrypted), so a plain script can read which .env files held locked keys —
# the ones whose keys the user now needs to rotate. Best-effort: needs sqlite3.
list_affected_envs() {
    db="$WORTHLESS_HOME_DIR/worthless.db"
    [ -f "$db" ] || return 0
    command -v sqlite3 >/dev/null 2>&1 || return 0
    sqlite3 "$db" "SELECT DISTINCT env_path FROM enrollments WHERE env_path IS NOT NULL;" 2>/dev/null || true
}

remove_tool() {
    if command -v uv >/dev/null 2>&1; then
        uv tool uninstall worthless >/dev/null 2>&1 || true
    fi
    # Legacy: a pipx-installed worthless (install.sh refuses to coexist, but an
    # older box may have one). Best-effort.
    if command -v pipx >/dev/null 2>&1; then
        pipx uninstall worthless >/dev/null 2>&1 || true
    fi
}

# --- Tiers -------------------------------------------------------------------

# Tier 1: the binary runs → let it do the real work (restore keys, then wipe),
# and we just remove the installed tool afterwards.
tier1_delegate() {
    command -v worthless >/dev/null 2>&1 || return 1
    worthless --version >/dev/null 2>&1 || return 1
    info "Found a working 'worthless' — using it to restore your keys first."
    if worthless uninstall --yes; then
        remove_tool
        printf "\n"
        ok "Done. Worthless removed; your real keys were restored to your .env files."
        exit 0
    fi
    warn "'worthless uninstall' did not finish cleanly — falling back to a best-effort wipe."
    return 1
}

# Tier 2: no working binary → wipe what a script safely can, and be honest that
# the keys cannot be restored.
tier2_wipe() {
    warn "No working 'worthless' binary found."
    warn "A plain script can't unscramble your split keys — only the program can — so"
    warn "your real keys can't be restored here. Wiping the leftovers anyway."
    printf "\n"

    envs="$(list_affected_envs || true)"
    delete_keychain_entry

    if [ -d "$WORTHLESS_HOME_DIR" ]; then
        rm -rf "$WORTHLESS_HOME_DIR" 2>/dev/null || true
    fi
    remove_tool

    if [ -d "$WORTHLESS_HOME_DIR" ]; then
        die "$EXIT_INTERNAL" "Could not fully remove ${WORTHLESS_HOME_DIR}." \
            "Delete it manually:  rm -rf ${WORTHLESS_HOME_DIR}"
    fi

    ok "Worthless removed from this machine."
    printf "\n"
    warn "Your real API keys could NOT be restored automatically — rotate them at your provider."
    if [ -n "${envs:-}" ]; then
        printf "\n  These .env files still hold an inert key half (rotate the keys they used):\n" >&2
        printf '%s\n' "$envs" | sed 's/^/    /' >&2
    fi
    printf "\n  Docs: %s\n" "$UNINSTALL_DOCS_URL"
}

# --- Main --------------------------------------------------------------------

main() {
    setup_colors
    if [ "$PRINT_ACCT" = "1" ]; then
        printf '%s\n' "$(keyring_account || true)"
        exit 0
    fi
    printf "\n"
    info "Worthless uninstaller"
    printf "\n"
    detect_os
    confirm
    tier1_delegate || tier2_wipe
}

OS=""
reply=""
main "$@"

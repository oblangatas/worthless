#!/bin/sh
# Worthless installer — https://worthless.sh
# Usage:         curl -sSL https://worthless.sh | sh
# Inspect first: curl -sSL 'https://worthless.sh?explain=1' | less
#
# Exit codes (UX contract):
#   0   success
#   10  network failure (curl/Astral CDN/PyPI unreachable)
#   20  unsupported platform (Windows native, macOS <11, glibc <2.17)
#   30  conflicting pipx-installed worthless detected
#   40  unexpected internal failure (uv install crash, smoke-test failed)

set -eu

EXIT_NETWORK=10
EXIT_PLATFORM=20
EXIT_PIPX_CONFLICT=30
EXIT_INTERNAL=40

UV_VERSION="0.11.7"

# Default worthless version. Hand-bumped per release like UV_VERSION above,
# kept at the latest version ALREADY published on PyPI — a CI drift check
# (release-sync-check.yml) fails if it falls behind the latest release.
# install.sh installs `worthless==$WORTHLESS_VERSION_PIN`, NOT unpinned `latest`.
#
# Why this matters (WOR-559, threat-model F-06/F-49): a `curl|sh` ending in
# `uv tool install worthless` (unpinned) auto-runs whatever PyPI calls latest.
# A release compromised AFTER ours (stolen maintainer token) would then get
# RCE on every fresh install — the highest-impact, previously-undefended hop.
# Real analogues: ctx (2022), Ultralytics (2024), ua-parser-js (2021).
#
# HONEST SCOPE: pinning selects WHICH release; it does NOT verify the package
# BYTES (`uv tool install` has no --require-hashes). It shrinks the window to
# "compromise this exact pinned release" instead of "publish any malicious
# latest", and does NOT defend against a compromised Worker/origin (which
# would serve a bad script AND a bad pin together). Wheel-hash verification is
# a tracked follow-up. Override with `WORTHLESS_VERSION=x.y.z curl … | sh`.
WORTHLESS_VERSION_PIN="0.3.7"

# SHA256 of https://astral.sh/uv/${UV_VERSION}/install.sh — bump with UV_VERSION.
ASTRAL_INSTALLER_SHA256="efed99618cb5c31e4e36a700ab7c3698e83c0ae0f3c336714043d0f932c8d32c"

ASTRAL_INSTALLER_URL="https://astral.sh/uv/${UV_VERSION}/install.sh"
DOCS_URL="https://docs.wless.io"
WINDOWS_DOCS_URL="https://docs.wless.io/install/wsl"

# Force uv to use its own managed Python for fresh-box reproducibility.
export UV_PYTHON_PREFERENCE="${UV_PYTHON_PREFERENCE:-only-managed}"
ORIGINAL_PATH="${PATH:-}"

# --- Output helpers ----------------------------------------------------------

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BOLD='\033[1m'
        RESET='\033[0m'
    else
        RED='' GREEN='' YELLOW='' BOLD='' RESET=''
    fi
}

info()  { printf "${BOLD}%s${RESET}\n" "$1"; }
ok()    { printf "${GREEN}%s${RESET}\n" "$1"; }
warn()  { printf "${YELLOW}%s${RESET}\n" "$1" >&2; }
err()   { printf "${RED}error: %s${RESET}\n" "$1" >&2; }

# die <exit-code> <message> [<hint-line>...]
die() {
    code="$1"; shift
    err "$1"; shift
    while [ "$#" -gt 0 ]; do
        printf "       %s\n" "$1" >&2
        shift
    done
    exit "$code"
}

proxy_hints() {
    printf "       Behind a proxy or corporate network? Try:\n" >&2
    printf "         export HTTPS_PROXY=https://your-proxy:port\n" >&2
    printf "         export UV_PYTHON_INSTALL_MIRROR=https://your-mirror/python-build-standalone\n" >&2
    printf "         export SSL_CERT_FILE=/path/to/corp-bundle.pem\n" >&2
}

# --- Platform detection ------------------------------------------------------

detect_os() {
    uname_s="$(uname -s 2>/dev/null || echo unknown)"
    case "$uname_s" in
        Darwin)
            OS="macos"
            check_macos_version
            ;;
        Linux)
            OS="linux"
            detect_linux_subenv
            ;;
        CYGWIN*|MINGW*|MSYS*)
            die "$EXIT_PLATFORM" "Windows native shells are not supported." \
                "Run inside a Linux subsystem instead:" \
                "  ${WINDOWS_DOCS_URL} (or see worthless.sh docs) for the full guide."
            ;;
        *)
            die "$EXIT_PLATFORM" "Unsupported OS: ${uname_s}" \
                "macOS >=11 and Linux (glibc >=2.17) are supported." \
                "  Docs: ${DOCS_URL}/install"
            ;;
    esac
}

check_macos_version() {
    # uv's python-build-standalone needs macOS 11 (Big Sur) minimum.
    if ! command -v sw_vers >/dev/null 2>&1; then
        warn "sw_vers not found; skipping macOS version check"
        return 0
    fi
    macos_ver="$(sw_vers -productVersion 2>/dev/null || echo "")"
    macos_major="$(echo "$macos_ver" | cut -d. -f1)"
    case "$macos_major" in
        ''|*[!0-9]*)
            die "$EXIT_PLATFORM" "Could not parse macOS version (got '${macos_ver}')." \
                "Big Sur (11) or newer is required." \
                "  Docs: ${DOCS_URL}/install"
            ;;
    esac
    if [ "$macos_major" -lt 11 ]; then
        die "$EXIT_PLATFORM" "macOS ${macos_ver} is too old — Big Sur (11) or newer required." \
            "uv's bundled Python (python-build-standalone) needs macOS >=11." \
            "  Upgrade macOS, or install via Homebrew: brew install pipx && pipx install worthless"
    fi
}

detect_linux_subenv() {
    # WSL2 is a fully supported Linux environment. Allow it; only warn when the
    # user is running from a Windows-mounted path, where Python tooling is slow.
    if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=1
        case "$(pwd)" in
            /mnt/*)
                warn "WSL detected, running from a Windows-mounted path (/mnt/...)."
                warn "Install will succeed but uv operations from /mnt/c are slow."
                warn "For best performance, install from your Linux home (~)."
                ;;
        esac
    fi
}

# --- Conflict detection ------------------------------------------------------

check_pipx_conflict() {
    # Stop early: a pipx shim on PATH would mask the uv-installed binary.
    if command -v pipx >/dev/null 2>&1; then
        if pipx list 2>/dev/null | grep -qi "package worthless "; then
            die "$EXIT_PIPX_CONFLICT" "Detected a pipx-installed worthless." \
                "uv and pipx both manage tool isolation; running both is confusing." \
                "Remove the pipx version, then re-run this installer:" \
                "  pipx uninstall worthless"
        fi
    fi
}

# --- uv install --------------------------------------------------------------

ensure_uv() {
    # Skip Astral installer entirely if uv is already at the pinned version.
    if command -v uv >/dev/null 2>&1; then
        existing_ver="$(uv --version 2>/dev/null | awk '{print $2}')"
        if [ "$existing_ver" = "$UV_VERSION" ]; then
            ok "  uv ${UV_VERSION} already installed"
            return 0
        fi
        info "  uv ${existing_ver} found; bootstrapping pinned uv ${UV_VERSION}"
    else
        info "  Installing uv ${UV_VERSION}..."
    fi

    tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t worthless-uv-XXXXXX)"
    trap 'rm -rf "$tmpdir"' EXIT INT TERM
    installer="$tmpdir/uv-installer.sh"

    if ! curl --fail --silent --show-error --location \
              --retry 3 --retry-delay 2 --max-time 30 \
              --output "$installer" \
              "$ASTRAL_INSTALLER_URL"; then
        err "Failed to download Astral installer from ${ASTRAL_INSTALLER_URL}"
        proxy_hints
        exit "$EXIT_NETWORK"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$installer" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$installer" | awk '{print $1}')"
    else
        die "$EXIT_INTERNAL" "Neither sha256sum nor shasum found." \
            "Cannot verify Astral installer integrity. Aborting for safety."
    fi
    if [ "$actual" != "$ASTRAL_INSTALLER_SHA256" ]; then
        die "$EXIT_INTERNAL" "SHA256 mismatch on Astral installer ${UV_VERSION}." \
            "expected: ${ASTRAL_INSTALLER_SHA256}" \
            "actual:   ${actual}" \
            "Refusing to execute. Re-run later or report at ${DOCS_URL}."
    fi

    UV_INSTALL_VERSION="$UV_VERSION" sh "$installer" >/dev/null 2>&1 || {
        err "Astral uv installer failed."
        proxy_hints
        exit "$EXIT_NETWORK"
    }

    PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    export PATH

    if ! command -v uv >/dev/null 2>&1; then
        die "$EXIT_INTERNAL" "uv installed but not on PATH after bootstrap." \
            "Open a new shell and re-run, or add ~/.local/bin to PATH manually."
    fi
}

install_or_upgrade_worthless() {
    # Resolve the version to install. Precedence:
    #   1. WORTHLESS_VERSION   — explicit user override
    #   2. WORTHLESS_VERSION_PIN — baked into this script at release time
    # There is deliberately NO unpinned `latest` fallback: installing whatever
    # PyPI calls latest is the F-06/F-49 supply-chain window (a compromised
    # release auto-runs on every fresh install). If neither is set we FAIL
    # CLOSED rather than reach for latest.
    effective_version="${WORTHLESS_VERSION:-$WORTHLESS_VERSION_PIN}"

    # Strip whitespace a mangled checkout or env could smuggle past a bare
    # `-n` test (e.g. a stray CR from a CRLF edit, or "  ").
    effective_version="$(printf '%s' "$effective_version" | tr -d '[:space:]')"

    if [ -z "$effective_version" ]; then
        die "$EXIT_INTERNAL" \
            "This installer has no pinned worthless version and WORTHLESS_VERSION is unset." \
            "Refusing to install an unpinned 'latest' from PyPI (supply-chain safety)." \
            "Pin a version explicitly:" \
            "  WORTHLESS_VERSION=<version> curl -sSL https://worthless.sh | sh"
    fi

    # Validate the effective version (whatever its source) against a
    # PEP-440-ish charset before it reaches `uv tool install`. Catches:
    #   WORTHLESS_VERSION="; rm -rf /"  → shell-metachar (rejected)
    #   WORTHLESS_VERSION="-e ."        → leading-`-` arg-confusion (rejected)
    #   WORTHLESS_VERSION="latest"      → rejected here as non-PEP-440
    # Defense-in-depth also covers a malformed baked pin (we control it, but
    # the static test guards repo state, not the running script).
    case "$effective_version" in
        *[!0-9A-Za-z.+!-]*)
            die "$EXIT_INTERNAL" \
                "Invalid worthless version '${effective_version}' — must match [0-9A-Za-z.+!-]+." \
                "Check WORTHLESS_VERSION, or report a bad release pin at ${DOCS_URL}."
            ;;
    esac

    spec="worthless==${effective_version}"

    # WOR-317 idempotency fast-path: if the resolved version is already the
    # installed one, short-circuit. `uv tool install --force` rewrites tool
    # metadata even on a no-op, breaking byte-for-byte idempotency for
    # repeated `curl ... | sh` runs. Keyed on effective_version (pin OR
    # override) so it fires on the common default path too, not just when the
    # user sets WORTHLESS_VERSION.
    installed_ver="$(uv tool list 2>/dev/null \
        | awk '/^worthless / {sub("^v", "", $2); print $2; exit}')"
    if [ -n "$installed_ver" ] && [ "$installed_ver" = "$effective_version" ]; then
        ok "  worthless ${installed_ver} already installed"
        return 0
    fi

    # Single PINNED install path. `--force` makes it idempotent whether the
    # box is fresh OR has a different version (a pin bump) — and crucially
    # keeps the install pinned to $spec. The previous fallback ran bare
    # `uv tool upgrade worthless`, which resolves PyPI *latest* and silently
    # re-opened the F-06/F-49 supply-chain window on every re-run (WOR-559
    # security review). Never call `uv tool upgrade` with no version.
    #
    # Capture stderr to a tempfile so we can SHOW it on failure. Pre-fix this
    # block did `2>&1 >/dev/null` and the user only ever saw a generic "Failed
    # to install" + proxy hint banner — masking the actual uv error (bad
    # version, dep conflict, deleted cwd, disk full, etc.). worthless-nrl1.
    #
    # `mktemp -t TEMPLATE` portability: BSD treats the arg as a prefix and appends
    # random chars; modern GNU coreutils tolerate a bare prefix but emit a stderr
    # warning. Pass an explicit `.XXXXXX` template so both backends behave
    # quietly. (CodeRabbit catch on PR #148.)
    uv_install_err="$(mktemp 2>/dev/null || mktemp -t worthless-uv-install-err.XXXXXX)"
    # POSIX trap REPLACES rather than chains, so re-include ensure_uv's
    # tmpdir cleanup here. Without this, ensure_uv's downloaded installer
    # tmpdir leaks every time install_or_upgrade_worthless runs (the common
    # path for any non-fresh box). `${tmpdir:-}` guards the case where
    # ensure_uv short-circuited (uv already at pinned version → never set
    # tmpdir → `set -u` would barf without the default). (CodeRabbit catch.)
    # shellcheck disable=SC2064  # expand uv_install_err NOW; tmpdir resolves at trap-fire time
    trap "rm -rf \"\${tmpdir:-}\"; rm -f \"$uv_install_err\"" EXIT INT TERM

    if ! uv tool install --force "$spec" >/dev/null 2>"$uv_install_err"; then
        err "Failed to install ${spec}."
        if [ -s "$uv_install_err" ]; then
            printf "\n       uv tool install reported:\n" >&2
            sed 's/^/         /' "$uv_install_err" >&2
        fi
        printf "\n       If this looks like a network issue:\n" >&2
        proxy_hints
        exit "$EXIT_NETWORK"
    fi
    # Success message is emitted by smoke_test, which already invokes the
    # binary — folding the version-display there saves a redundant
    # `uv run` cold start (~300ms on a fresh box).
}

smoke_test() {
    # `uv run` works even before the user activates PATH — uv knows where
    # it put the binary. Capture output so we can both verify the install
    # AND display the resolved version without a second invocation.
    if ! version_output="$(uv run --no-project worthless --version 2>/dev/null)"; then
        die "$EXIT_INTERNAL" "worthless installed but failed to run." \
            "Try: uv run --no-project worthless --version" \
            "Or:  worthless doctor"
    fi
    actual_ver="$(printf '%s' "$version_output" | awk '{print $2}' | head -1)"
    ok "  worthless ${actual_ver:-installed}"
}

# --- Per-shell PATH activation guidance --------------------------------------

# True iff the user's rc file already references ~/.local/bin, i.e. a new
# shell will find `worthless` without us telling them to edit anything.
# Conservative: returns false on unknown shells so we always print the hint.
path_is_persistent() {
    user_shell="$(basename "${SHELL:-/bin/sh}")"
    case "$user_shell" in
        bash)
            for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
                [ -f "$rc" ] && grep -q "\.local/bin" "$rc" 2>/dev/null && return 0
            done
            return 1
            ;;
        zsh)
            for rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv"; do
                [ -f "$rc" ] && grep -q "\.local/bin" "$rc" 2>/dev/null && return 0
            done
            return 1
            ;;
        fish)
            fish_config="$HOME/.config/fish/config.fish"
            [ -f "$fish_config" ] && grep -q "\.local/bin" "$fish_config" 2>/dev/null && return 0
            fish_vars="$HOME/.config/fish/fish_variables"
            [ -f "$fish_vars" ] && grep -q "\.local/bin" "$fish_vars" 2>/dev/null && return 0
            return 1
            ;;
        *)
            return 1
            ;;
    esac
}

command_in_original_path() {
    name="$1"
    current_path="${PATH:-}"
    PATH="$ORIGINAL_PATH"
    if command -v "$name" >/dev/null 2>&1; then
        PATH="$current_path"
        return 0
    fi
    PATH="$current_path"
    return 1
}

# mode: "full" (default) prints both current-shell + make-permanent hints;
# "activate" prints only the current-shell activation command.
print_activation_hint() {
    mode="${1:-full}"
    user_shell="$(basename "${SHELL:-/bin/sh}")"
    case "$user_shell" in
        bash|zsh)
            if [ "$mode" = "full" ] || [ "$mode" = "activate" ]; then
                printf "  Activate in this shell: %s\n" 'export PATH="$HOME/.local/bin:$PATH"'
            fi
            if [ "$mode" = "full" ]; then
                printf "  Make permanent:         %s\n" \
                    "echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.${user_shell}rc"
            fi
            ;;
        fish)
            if [ "$mode" = "full" ] || [ "$mode" = "activate" ]; then
                printf "  Activate in this shell: %s\n" 'set -gx PATH $HOME/.local/bin $PATH'
            fi
            if [ "$mode" = "full" ]; then
                printf "  Make permanent:         %s\n" \
                    'fish_add_path $HOME/.local/bin'
            fi
            ;;
        *)
            if [ "$mode" = "full" ] || [ "$mode" = "activate" ]; then
                printf "  Activate in this shell: %s\n" 'export PATH="$HOME/.local/bin:$PATH"'
            fi
            if [ "$mode" = "full" ]; then
                printf "  (Detected shell: %s — adapt for your rc file)\n" "$user_shell"
            fi
            ;;
    esac
}

# --- Main --------------------------------------------------------------------

main() {
    setup_colors
    printf "\n"
    info "Worthless installer (uv-bootstrap)"
    printf "\n"

    detect_os
    ok "  Platform: ${OS}${IS_WSL:+ (WSL2)}"

    check_pipx_conflict

    ensure_uv
    install_or_upgrade_worthless
    smoke_test

    printf "\n"
    if command_in_original_path worthless; then
        ok "Done! 'worthless' is on your PATH."
    else
        ok "Done! 'worthless' is installed."
        printf "\n"
        warn "Heads up: this terminal will not find 'worthless' until PATH is updated."
        printf "\n"
        if path_is_persistent; then
            printf "  Open a new terminal, or activate this one now:\n"
            print_activation_hint activate
        else
            print_activation_hint
        fi
    fi
    printf "\n"
    if command_in_original_path worthless; then
        printf "  ${BOLD}Try it:${RESET}        cd your-project && worthless lock\n"
    else
        printf "  ${BOLD}Try after PATH:${RESET} cd your-project && worthless lock\n"
    fi
    printf "  ${BOLD}Audit script:${RESET}  curl worthless.sh?explain=1 | less\n"
    printf "  ${BOLD}Source:${RESET}        https://github.com/shacharm2/worthless\n"
    printf "\n"
    printf "  worthless lock rewrites .env, splits your API keys, and starts a\n"
    printf "  local proxy. Your app code doesn't change.\n"
    printf "\n"
    printf "  Docs: %s\n\n" "$DOCS_URL"
}

IS_WSL=""
main "$@"

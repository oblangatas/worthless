"""Subprocess-level behavioral tests for install.sh.

These run the actual install.sh under sh(1) with a mocked PATH so we can
assert exit codes and stderr/stdout patterns without touching the network
or the user's real environment. Heavier integration coverage lives in
test_install_docker.py (marked 'docker').
"""

from __future__ import annotations

from pathlib import Path

from tests._install_helpers import (
    EXIT_INTEGRITY,
    EXIT_INTERNAL,
    EXIT_NETWORK,
    EXIT_PIPX_CONFLICT,
    EXIT_PLATFORM,
    INSTALL_SH,
    install_sh_with_pin,
    read_install_pin,
    run_install,
    write_happy_path_stubs,
    write_stub,
)


# ---------------------------------------------------------------------------
# WOR-559: default install pins a baked version (never unpinned `latest`)
# ---------------------------------------------------------------------------


def test_default_install_pins_baked_version(tmp_path: Path) -> None:
    """With no WORTHLESS_VERSION, install.sh must install `worthless==<pin>`,
    never bare `worthless` (which would resolve PyPI latest — F-06/F-49) and
    never via `uv tool upgrade` (also resolves latest)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)

    result = run_install(bin_dir)
    assert result.returncode == 0, f"stderr: {result.stderr}"

    pin = read_install_pin()
    log = (tmp_path / "uv-invocations.log").read_text()
    assert f"tool install --force worthless=={pin}" in log, (
        f"default install must pin to worthless=={pin}.\nuv log:\n{log}"
    )
    assert "tool upgrade" not in log, (
        "must not run bare `uv tool upgrade` — it resolves PyPI latest and "
        f"re-opens the supply-chain window on re-runs.\nuv log:\n{log}"
    )


def test_install_succeeds_when_uv_installs_outside_home_local_bin(tmp_path: Path) -> None:
    """A customised uv bin dir must not turn a successful install into a failure.

    uv resolves its entry-point directory as ``UV_TOOL_BIN_DIR`` → ``XDG_BIN_HOME``
    → ``~/.local/bin``, and install.sh scrubs neither variable. Guessing
    ``~/.local/bin`` means that on such a box ``command -v`` comes back empty, the
    guess points at a path that does not exist, and the installer dies
    ``EXIT_INTERNAL`` — on an install that actually worked.

    Asking uv where it put the binary is the only answer that survives this.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)

    # The scenario is "uv installed somewhere else entirely", so ~/.local/bin must
    # hold nothing — otherwise the guessed path happens to work and the bug hides.
    home_local = tmp_path / ".local" / "bin" / "worthless"
    if home_local.exists():
        home_local.unlink()

    # uv installs here, and this directory is deliberately NOT on PATH.
    custom_bin = tmp_path / "uv-tools" / "bin"
    custom_bin.mkdir(parents=True)
    write_stub(custom_bin, "worthless", 'echo "worthless 9.9.9"')

    result = run_install(bin_dir, env_extra={"UV_TOOL_BIN_DIR": str(custom_bin)})

    combined = result.stdout + result.stderr
    assert result.returncode == 0, (
        "a successful install must not fail just because uv's bin dir is customised.\n"
        f"exit={result.returncode}\n{combined}"
    )
    assert "9.9.9" in combined, f"must report the version of the binary uv installed.\n{combined}"


def test_banner_reports_the_installed_binary_not_a_stale_uv_run(tmp_path: Path) -> None:
    """The version banner must come from the artifact we actually installed.

    install.sh installs with ``uv tool install worthless==<pin>`` (entry point at
    ~/.local/bin/worthless) but reported the version with ``uv run --no-project
    worthless --version`` — a different resolution that builds an *ephemeral*
    environment and can answer from a stale cache. Observed live on a real Mac:
    the banner printed ``worthless 0.3.9`` while ``0.3.10`` had just been
    installed and ``which``/``--version``/the pin all agreed on 0.3.10
    (worthless-dc26).

    The stock fixture cannot catch this: ``write_happy_path_stubs`` makes both
    oracles answer ``0.3.0``, so asking the wrong one is invisible. Here they
    deliberately disagree — the number in the banner tells you which oracle
    install.sh trusted.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)

    # Three oracles, three different answers, so the banner names which one won.
    # Only asserting "not the uv-run version" would pass even if the installer
    # ignored `uv tool dir --bin` and fell back to PATH.

    # 1. `uv run …` — stale ephemeral env. Must NOT win.
    uv_stub = bin_dir / "uv"
    uv_stub.write_text(
        uv_stub.read_text(encoding="utf-8").replace(
            'run) echo "worthless 0.3.0"', 'run) echo "worthless 0.3.9"'
        ),
        encoding="utf-8",
    )
    # 2. A shadowing binary earlier on PATH. Must NOT win — install.sh's own PATH
    #    lockdown puts /usr/local/bin ahead of the uv bin dir, so this is real.
    write_stub(bin_dir, "worthless", 'echo "worthless 0.3.7"')
    # 3. The entry point uv actually installed, in the dir `uv tool dir --bin`
    #    reports. This is what the user runs, so this is what must be reported.
    tool_bin = tmp_path / ".local" / "bin"
    tool_bin.mkdir(parents=True, exist_ok=True)
    write_stub(tool_bin, "worthless", 'echo "worthless 0.3.10"')

    result = run_install(bin_dir)
    assert result.returncode == 0, f"stderr: {result.stderr}"

    combined = result.stdout + result.stderr
    assert "0.3.9" not in combined, (
        "the banner reported a stale `uv run` resolution instead of the installed "
        f"binary — the user is told the wrong version.\n{combined}"
    )
    assert "0.3.7" not in combined, (
        "the banner reported a `worthless` shadowing us on PATH instead of the one "
        f"uv installed — the same wrong-version bug by another route.\n{combined}"
    )
    assert "0.3.10" in combined, (
        f"the banner must report the version uv actually installed.\n{combined}"
    )


def test_user_override_beats_pin(tmp_path: Path) -> None:
    """WORTHLESS_VERSION overrides the baked pin."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)

    result = run_install(bin_dir, env_extra={"WORTHLESS_VERSION": "9.9.9"})
    assert result.returncode == 0, f"stderr: {result.stderr}"

    log = (tmp_path / "uv-invocations.log").read_text()
    assert "worthless==9.9.9" in log, f"override ignored.\nuv log:\n{log}"
    assert f"worthless=={read_install_pin()}" not in log, (
        f"baked pin must not also be installed when overridden.\nuv log:\n{log}"
    )


def test_empty_pin_fails_closed(tmp_path: Path) -> None:
    """An installer with no baked pin AND no override must FAIL CLOSED with an
    internal error — never silently install latest."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    patched = install_sh_with_pin(tmp_path, "")

    result = run_install(bin_dir, install_sh=patched)

    assert result.returncode == EXIT_INTERNAL, (
        f"empty pin must fail closed with exit {EXIT_INTERNAL}, "
        f"got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "unpinned" in result.stderr.lower(), (
        f"must explain it refuses unpinned latest.\nstderr: {result.stderr}"
    )
    log_path = tmp_path / "uv-invocations.log"
    log = log_path.read_text() if log_path.exists() else ""
    assert "tool install" not in log, (
        f"must not attempt any install on the fail-closed path.\nuv log:\n{log}"
    )


def test_whitespace_only_pin_fails_closed(tmp_path: Path) -> None:
    """A pin that is whitespace-only (e.g. a CRLF-mangled checkout) must not
    slip past the `-n` guard — it trims to empty and fails closed."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    patched = install_sh_with_pin(tmp_path, "   ")

    result = run_install(bin_dir, install_sh=patched)
    assert result.returncode == EXIT_INTERNAL, (
        f"whitespace pin must fail closed, got {result.returncode}\nstderr: {result.stderr}"
    )


def test_invalid_pin_rejected(tmp_path: Path) -> None:
    """A malformed baked pin (shell metacharacters) is rejected before it can
    reach `uv tool install`."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    patched = install_sh_with_pin(tmp_path, "; rm -rf /")

    result = run_install(bin_dir, install_sh=patched)
    assert result.returncode == EXIT_INTERNAL, (
        f"malformed pin must be rejected, got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "invalid" in result.stderr.lower()


def test_leading_dash_pin_is_not_arg_injection(tmp_path: Path) -> None:
    """A pin starting with `-` PASSES the PEP-440 charset (which allows `-`),
    so the charset is NOT what stops arg-injection — the `worthless==` prefix
    is. A value like `-rf` must reach uv glued to the package name
    (`worthless==-rf`), never as a standalone `-rf` flag. Lock the prefix in
    so a future refactor that drops it gets caught here."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    patched = install_sh_with_pin(tmp_path, "-rf")

    run_install(bin_dir, install_sh=patched)
    log = (tmp_path / "uv-invocations.log").read_text()
    assert "--force worthless==-rf" in log, (
        f"pin must be passed as `worthless==<pin>`, never a standalone "
        f"argument uv could interpret as a flag.\nuv log:\n{log}"
    )


def test_windows_native_exits_20_with_link(tmp_path: Path) -> None:
    """Windows native (MINGW/CYGWIN) must die with exit 20 + helpful link (UX)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", 'echo "MINGW64_NT-10.0"')

    result = run_install(bin_dir)

    assert result.returncode == EXIT_PLATFORM, (
        f"expected exit {EXIT_PLATFORM} (unsupported platform), got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "windows" in result.stderr.lower(), (
        "stderr must mention Windows so user understands the failure"
    )
    assert "worthless.sh" in result.stderr, (
        "stderr must include a worthless.sh docs link, not a generic die message"
    )


def test_macos_below_11_exits_20(tmp_path: Path) -> None:
    """macOS <11 must die with exit 20 + version mention (OS reviewer)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "10.15.7"')

    result = run_install(bin_dir)

    assert result.returncode == EXIT_PLATFORM, (
        f"expected exit {EXIT_PLATFORM} (unsupported platform) on macOS 10.15, "
        f"got {result.returncode}\nstderr: {result.stderr}"
    )
    # Must pin the version requirement specifically, not just say "macOS".
    assert "11" in result.stderr, "stderr must cite the macOS 11 minimum version"
    assert "big sur" in result.stderr.lower() or "macos" in result.stderr.lower(), (
        "stderr must name the OS/release so the user knows what to upgrade"
    )


def test_pipx_conflict_warns_and_exits_30(tmp_path: Path) -> None:
    """Pre-existing pipx-installed worthless triggers exit 30 with uninstall hint.

    WOR-709: pipx must be in a TRUSTED system dir for install.sh to invoke it.
    Trusted dirs are /usr/bin, /bin, /usr/local/bin, $HOME/.local/bin. Test
    HOME is tmp_path, so $HOME/.local/bin/pipx is trusted — place the stub
    there (mirrors how pipx is actually installed via `python -m pip install`).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    # Place pipx in HOME/.local/bin (a trusted dir per WOR-709's gate).
    local_bin = tmp_path / ".local" / "bin"
    local_bin.mkdir(parents=True)
    write_stub(
        local_bin,
        "pipx",
        """case "$1" in
  list) echo "package worthless 0.3.0, installed using Python 3.12.0" ;;
  *) echo "pipx stub: $@" ;;
esac
exit 0""",
    )

    # Add HOME/.local/bin to PATH so `command -v pipx` finds it.
    result = run_install(
        bin_dir,
        env_extra={"PATH": f"{bin_dir}:{local_bin}:/usr/bin:/bin:/usr/sbin:/sbin"},
    )

    assert result.returncode == EXIT_PIPX_CONFLICT, (
        f"expected exit {EXIT_PIPX_CONFLICT} (pipx conflict) when pipx has worthless, "
        f"got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "pipx uninstall worthless" in result.stderr, (
        "stderr must include the exact 'pipx uninstall worthless' command"
    )


def test_pipx_in_untrusted_dir_is_not_invoked(tmp_path: Path) -> None:
    """An attacker-controlled `pipx` in an untrusted PATH dir must NOT be
    invoked by install.sh. Empirically demonstrated 2026-06-07 on real macOS:
    install.sh A2-extended (PR #281) called attacker's pipx during the
    conflict check, executing arbitrary code in install.sh's process BEFORE
    any uv invocation. WOR-709 closes the gap by gating the conflict check
    on pipx resolving from a trusted system dir.

    Test sets up an attacker pipx in `tmp_path/evil` (not in any trusted
    dir), then runs install.sh under PATH that puts evil-bin first. Asserts:
    (a) install.sh exits 0 (skip-and-continue, not crash);
    (b) attacker pipx is NOT invoked (its scream log stays empty);
    (c) stderr names the skip reason so the user knows the conflict surface
        wasn't checked.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    # Attacker pipx — appends to a scream log + exits 1. If install.sh
    # invokes it, the log gains a line.
    scream_log = tmp_path / "attacker-pipx.log"
    write_stub(
        evil_dir,
        "pipx",
        f'echo "ATTACKER_PIPX_CALLED: $*" >> "{scream_log}"; exit 1',
    )

    # PATH puts attacker dir FIRST, then the stub bin_dir (test harness
    # convention). install.sh's PATH prepend would normally put system dirs
    # ahead, but pipx isn't in /usr/bin so the trusted-dir gate is the only
    # defense.
    result = run_install(
        bin_dir,
        env_extra={"PATH": f"{evil_dir}:{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin"},
    )

    assert result.returncode == 0, (
        f"install must succeed even when an untrusted pipx is on PATH "
        f"(skip-and-continue, not crash).\nstderr: {result.stderr}"
    )
    scream = scream_log.read_text() if scream_log.exists() else ""
    assert scream == "", (
        f"attacker pipx was invoked by install.sh — WOR-709 defense failed. "
        f"This is the empirically-demonstrated RCE; the trusted-dir gate "
        f"must prevent it.\nscream log:\n{scream}"
    )
    assert "outside trusted dirs" in result.stderr, (
        f"stderr must explain WHY the pipx conflict check was skipped "
        f"(user needs to know).\nstderr: {result.stderr}"
    )


def test_env_scrub_strips_poisoned_uv_pip_vars(tmp_path: Path) -> None:
    """A poisoned shell rc setting UV_INDEX_URL (or any of its cousins) must
    NOT propagate to any uv invocation. install.sh ships its own pinned
    default index, certificate trust, and config; a caller-supplied
    redirect is an attack vector (WOR-673 / A2 of WOR-669).

    Threat: compromised dotfiles / hostile VS Code workspace env / poisoned
    `direnv` `.envrc` redirects the entire install to an attacker mirror
    while install.sh's banner, the Astral SHA pin, and the worthless pin
    all still look pristine.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    # uv stub that dumps every env var it actually receives, so we can assert
    # against every namespace install.sh scrubs.
    # Unhandled subcommands exit 99 (NOT 1) — exit 1 collides with install.sh's
    # set -e propagation and looks like EXIT_INTERNAL=40, misdirecting diagnosis.
    # 99 is unmistakably "test stub gap" (Panel C FIX-NOW).
    write_stub(
        bin_dir,
        "uv",
        'env >> "$HOME/uv-env.log" || true\n'
        'case "$1" in\n'
        '  --version) echo "uv 0.11.7" ;;\n'
        '  tool) shift; case "$1" in\n'
        '    install|upgrade) echo "ok" ;;\n'
        "    list) ;;\n"
        # smoke_test asks uv where it installed the entry point rather than
        # guessing ~/.local/bin (worthless-dc26). Echo a path that does not
        # exist so the fallback to `command -v` runs — this test is about env
        # scrubbing, not about which binary answers.
        '    dir) echo "$HOME/nonexistent-uv-bin" ;;\n'
        '    *) echo "UNHANDLED_UV_CALL (test stub gap): uv tool $*" >&2; exit 99 ;;\n'
        "  esac ;;\n"
        '  run) echo "worthless 0.3.7" ;;\n'
        '  *) echo "UNHANDLED_UV_CALL (test stub gap): uv $*" >&2; exit 99 ;;\n'
        "esac",
    )
    write_stub(bin_dir, "worthless", 'echo "worthless 0.3.7"')

    poisoned = "http://evil.example/index"
    result = run_install(
        bin_dir,
        env_extra={
            # Index URL class
            "UV_INDEX_URL": poisoned,
            "UV_DEFAULT_INDEX": poisoned + "/default",
            "UV_EXTRA_INDEX_URL": poisoned + "/extra",
            "UV_FIND_LINKS": poisoned + "/links",
            "PIP_INDEX_URL": poisoned + "/pip",
            "PIP_FIND_LINKS": poisoned + "/pip-links",
            # Config-file class
            "UV_CONFIG_FILE": "/tmp/poisoned.toml",  # noqa: S108
            "PIP_CONFIG_FILE": "/tmp/poisoned-pip.conf",  # noqa: S108
            # Cache / offline class
            "UV_OFFLINE": "1",
            "UV_NO_CACHE": "1",
            # TLS / cert-bundle class
            "PIP_TRUSTED_HOST": "evil.example",
            "UV_INSECURE_HOST": "evil.example",
            "UV_NATIVE_TLS": "rustls",
            "SSL_CERT_FILE": "/tmp/attacker-ca.pem",  # noqa: S108
            "REQUESTS_CA_BUNDLE": "/tmp/attacker-ca.pem",  # noqa: S108
            "PIP_CERT": "/tmp/attacker.pem",  # noqa: S108
            # Python source class — Panel B BLOCKER. UV_PYTHON_PREFERENCE=system
            # would force install onto a user-controllable Python (sitecustomize
            # hijack). UV_PYTHON_INSTALL_MIRROR points uv at attacker's tarball.
            "UV_PYTHON_PREFERENCE": "system",
            "UV_PYTHON_INSTALL_MIRROR": poisoned + "/python",
            # Astral installer redirect class — controls where the uv binary
            # lands. Combined with PATH, attacker overwrites our pinned uv.
            "UV_INSTALL_DIR": "/tmp/attacker-install",  # noqa: S108
            "UV_UNMANAGED_INSTALL": "1",
            "INSTALLER_DOWNLOAD_URL": poisoned + "/installer",
            # Python hijack class — PYTHONPATH + PYTHONSTARTUP get inherited by
            # any python invoked under uv (smoke test, sitecustomize).
            "PYTHONPATH": "/tmp/attacker-pkg",  # noqa: S108
            "PYTHONSTARTUP": "/tmp/attacker-startup.py",  # noqa: S108
            # Shell init class — BASH_ENV is sourced before line 1 when sh→bash
            # invokes the Astral installer as `sh "$installer"`.
            "BASH_ENV": "/tmp/attacker-bashenv.sh",  # noqa: S108
            "ENV": "/tmp/attacker-env.sh",  # noqa: S108
            "CDPATH": "/tmp/attacker-cd",  # noqa: S108
            "GLOBIGNORE": "/tmp/attacker-glob",  # noqa: S108
            # Dynamic loader class — Panel B re-review BLOCKER. .so/.dylib
            # loads into curl's process, intercepts open() to serve different
            # bytes to sha256sum vs sh — SHA pin bypassed.
            "LD_PRELOAD": "/tmp/attacker.so",  # noqa: S108
            "LD_AUDIT": "/tmp/attacker-audit.so",  # noqa: S108
            "LD_LIBRARY_PATH": "/tmp/attacker-libs",  # noqa: S108
            "DYLD_INSERT_LIBRARIES": "/tmp/attacker.dylib",  # noqa: S108
            "DYLD_LIBRARY_PATH": "/tmp/attacker-libs",  # noqa: S108
            "DYLD_FORCE_FLAT_NAMESPACE": "1",
            # Auth / keyring class
            "UV_KEYRING_PROVIDER": "/tmp/attacker-keyring",  # noqa: S108
            "PIP_KEYRING_PROVIDER": "/tmp/attacker-keyring",  # noqa: S108
            # Remaining index-class vars Panel C flagged missing
            "UV_INDEX": poisoned + "/uv_index_single",
            "UV_INDEX_STRATEGY": "first-index",
            "PIP_EXTRA_INDEX_URL": poisoned + "/pip-extra",
            "PIP_NO_INDEX": "1",
            # Remaining cert/MitM-class vars Panel C flagged missing
            "SSL_CERT_DIR": "/tmp/attacker-ca-dir",  # noqa: S108
            "CURL_CA_BUNDLE": "/tmp/attacker-curl-ca",  # noqa: S108
            "PIP_CLIENT_CERT": "/tmp/attacker-client.pem",  # noqa: S108
            # Proxy alias class — Panel B re-review FIX-NOW. curl honors
            # lowercase + ALL_PROXY in addition to documented uppercase.
            "ALL_PROXY": "http://attacker.example:8080",
            "all_proxy": "http://attacker.example:8080",
            "http_proxy": "http://attacker.example:8080",
            "https_proxy": "http://attacker.example:8080",
        },
    )
    assert result.returncode == 0, (
        f"install must succeed under env scrub (poisoned vars should be "
        f"silently dropped, not raise).\nstderr: {result.stderr}"
    )

    env_log = tmp_path / "uv-env.log"
    log = env_log.read_text() if env_log.exists() else ""
    forbidden = [
        # Index URL class (all 8)
        "UV_INDEX=",
        "UV_INDEX_URL=",
        "UV_DEFAULT_INDEX=",
        "UV_EXTRA_INDEX_URL=",
        "UV_INDEX_STRATEGY=",
        "UV_FIND_LINKS=",
        "PIP_INDEX_URL=",
        "PIP_EXTRA_INDEX_URL=",
        "PIP_FIND_LINKS=",
        "PIP_NO_INDEX=",
        # Config-file class
        "UV_CONFIG_FILE=",
        "PIP_CONFIG_FILE=",
        # Cache / offline class
        "UV_OFFLINE=",
        "UV_NO_CACHE=",
        # TLS / cert-bundle class (all 9)
        "PIP_TRUSTED_HOST=",
        "UV_INSECURE_HOST=",
        "UV_NATIVE_TLS=",
        "SSL_CERT_FILE=",
        "SSL_CERT_DIR=",
        "REQUESTS_CA_BUNDLE=",
        "CURL_CA_BUNDLE=",
        "PIP_CERT=",
        "PIP_CLIENT_CERT=",
        # Python source class (UV_PYTHON_PREFERENCE asserted separately below)
        "UV_PYTHON_INSTALL_MIRROR=",
        # Auth / keyring class
        "UV_KEYRING_PROVIDER=",
        "PIP_KEYRING_PROVIDER=",
        # Astral installer redirect class
        "UV_INSTALL_DIR=",
        "UV_UNMANAGED_INSTALL=",
        "INSTALLER_DOWNLOAD_URL=",
        # Python hijack class
        "PYTHONPATH=",
        "PYTHONSTARTUP=",
        # Shell init class (Panel C BLOCKER: was missing entirely)
        "BASH_ENV=",
        "ENV=",
        "CDPATH=",
        "GLOBIGNORE=",
        # Dynamic loader class (Panel B re-review BLOCKER)
        "LD_PRELOAD=",
        "LD_AUDIT=",
        "LD_LIBRARY_PATH=",
        "DYLD_INSERT_LIBRARIES=",
        "DYLD_LIBRARY_PATH=",
        "DYLD_FALLBACK_LIBRARY_PATH=",
        "DYLD_FRAMEWORK_PATH=",
        "DYLD_FORCE_FLAT_NAMESPACE=",
        # Proxy alias class (Panel B re-review FIX-NOW)
        "ALL_PROXY=",
        "all_proxy=",
        "http_proxy=",
        "https_proxy=",
    ]
    log_lines = log.splitlines()
    # Line-prefix matching — substring `ENV=` could false-match inside
    # WORTHLESS_KEYRING_BACKEND=... etc. We want exact var-name leak detection.
    leaked = [v for v in forbidden if any(line.startswith(v) for line in log_lines)]
    assert not leaked, (
        f"these poisoned env vars leaked through to uv despite the scrub: "
        f"{leaked}\nuv-env.log:\n{log}"
    )

    # UV_PYTHON_PREFERENCE is special: scrubbed then re-set unconditionally.
    # The attacker's hostile value ("system") must NOT reach uv; the value uv
    # sees must be "only-managed" — proves the `:-default` bypass is closed.
    assert not any(line.startswith("UV_PYTHON_PREFERENCE=system") for line in log_lines), (
        f"UV_PYTHON_PREFERENCE=system bypassed the scrub via `${{VAR:-default}}` "
        f"semantics (Panel B BLOCKER). Must be hard-set to only-managed.\n"
        f"uv-env.log:\n{log}"
    )
    assert any(line.startswith("UV_PYTHON_PREFERENCE=only-managed") for line in log_lines), (
        f"UV_PYTHON_PREFERENCE must be set to only-managed before uv runs.\nuv-env.log:\n{log}"
    )


def test_astral_installer_sha_mismatch_exits_50(tmp_path: Path) -> None:
    """A poisoned/corrupted Astral installer download must exit EXIT_INTEGRITY (50),
    NOT EXIT_INTERNAL (40). CI retry policies treat 40 as transient and 50 as
    permanent — conflating them lets an attacker brute-force a CDN poison window
    via infinite retries (WOR-679 / A8 of WOR-669).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    # curl "succeeds" — writes arbitrary bytes to the --output path so install.sh
    # proceeds past the network check and into the SHA verification branch.
    write_stub(
        bin_dir,
        "curl",
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in --output) printf "poisoned" > "$2"; shift 2 ;; *) shift ;; esac\n'
        "done\n"
        "exit 0",
    )
    # Force the SHA computation to a value that cannot match the pinned constant
    # in install.sh — deterministic across Linux (sha256sum) and macOS (shasum).
    bogus = "0000000000000000000000000000000000000000000000000000000000000000"
    write_stub(bin_dir, "sha256sum", f'echo "{bogus}  $1"')
    write_stub(bin_dir, "shasum", f'echo "{bogus}  $2"')

    result = run_install(bin_dir)

    assert result.returncode == EXIT_INTEGRITY, (
        f"corrupt Astral installer must exit {EXIT_INTEGRITY} (byte-integrity), "
        f"NOT {EXIT_INTERNAL} (generic internal). got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    assert "SHA256 mismatch" in result.stderr, (
        f"stderr should name the integrity failure clearly.\nstderr: {result.stderr}"
    )
    # Honest framing: an exit code that says "do not retry" must NOT be paired
    # with a message that says "Re-run later" — that contradicts the contract
    # and trains operators / CI to ignore the new exit code.
    assert "Re-run later" not in result.stderr, (
        "stderr must NOT suggest retrying — EXIT_INTEGRITY (50) means do-not-retry.\n"
        f"stderr: {result.stderr}"
    )
    assert "Do NOT retry" in result.stderr, (
        f"stderr must state the do-not-retry contract explicitly.\nstderr: {result.stderr}"
    )


def test_curl_network_failure_exits_10(tmp_path: Path) -> None:
    """curl failing (network) must exit 10 (UX exit-code contract)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    # curl always fails — simulates network outage
    write_stub(bin_dir, "curl", 'echo "curl: (6) Could not resolve host" >&2; exit 6')

    result = run_install(bin_dir)

    assert result.returncode == EXIT_NETWORK, (
        f"expected exit {EXIT_NETWORK} (network failure) when curl fails, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )


def test_success_with_persistent_rc_shows_clean_done_message(tmp_path: Path) -> None:
    """Happy path + rc references ~/.local/bin → "on your PATH", no extra hints.

    This is the "already set up" user (e.g. upgrading). They don't need noise
    about making PATH permanent — their rc file already did it.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    # Simulate a zsh user whose .zshrc already adds ~/.local/bin to PATH.
    (tmp_path / ".zshrc").write_text('export PATH="$HOME/.local/bin:$PATH"\n')

    result = run_install(bin_dir)

    assert result.returncode == 0, (
        f"happy path must exit 0, got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "is on your PATH" in result.stdout, (
        f"stdout must confirm worthless is on PATH.\nstdout: {result.stdout}"
    )
    assert "works in this shell" not in result.stdout, (
        "must not nag persistent users about 'this shell only' — they're already set up"
    )
    assert "Heads up" not in result.stdout, (
        "must not warn persistent users about new terminals — their rc handles it"
    )


def test_success_without_persistent_rc_warns_and_shows_persistence_hint(
    tmp_path: Path,
) -> None:
    """Happy path + no rc persistence → warn + activation/persistence hints.

    This mirrors the real `curl | sh` shape: the installer subprocess can
    verify the uv tool, but the parent terminal cannot inherit PATH changes.
    We must not tell users `worthless` works before they update PATH.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    # No rc files — simulates a fresh user account.

    result = run_install(bin_dir)

    assert result.returncode == 0, (
        f"happy path must exit 0, got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "is installed" in result.stdout, (
        f"must confirm install without claiming parent-shell PATH.\nstdout: {result.stdout}"
    )
    assert "works in this shell" not in result.stdout, (
        f"must not claim the parent shell can run worthless after curl|sh.\nstdout: {result.stdout}"
    )
    assert "is on your PATH" not in result.stdout, (
        f"must not claim worthless is on the user's PATH.\nstdout: {result.stdout}"
    )
    # warn() routes to stderr, so the "Heads up" banner lives there.
    assert "Heads up" in result.stderr, (
        f"must warn explicitly that this terminal won't find worthless.\nstderr: {result.stderr}"
    )
    assert "Activate in this shell" in result.stdout, (
        "must print the activation one-liner so the user can use worthless now"
    )
    assert "Make permanent" in result.stdout, (
        "must print the make-permanent one-liner so the user can fix it"
    )


def test_success_with_persistent_rc_but_missing_parent_path_says_open_terminal(
    tmp_path: Path,
) -> None:
    """If rc is updated but the parent shell PATH lacks worthless, say so.

    This is the actual `curl -sSL https://worthless.sh | sh` product shape on
    a fresh macOS shell after uv's installer has edited rc files: a new
    terminal may work, but the current parent terminal still cannot run
    `worthless` until the user opens a new shell or exports PATH manually.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    (tmp_path / ".zshrc").write_text('export PATH="$HOME/.local/bin:$PATH"\n')

    result = run_install(bin_dir)

    assert result.returncode == 0, (
        f"happy path must exit 0, got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "is installed" in result.stdout
    assert "is on your PATH" not in result.stdout
    assert "works in this shell" not in result.stdout
    assert "Open a new terminal" in result.stdout
    assert "Activate in this shell" in result.stdout
    assert "Make permanent" not in result.stdout, (
        "rc already contains ~/.local/bin, so don't tell the user to append it again"
    )


# ---------------------------------------------------------------------------
# worthless-nrl1: failure path surfaces uv's actual stderr above the proxy hint
# ---------------------------------------------------------------------------


def _failing_uv_stub(install_stderr: str = "") -> str:
    """Build a uv stub whose `tool install` fails with the given stderr."""
    return f"""case "$1" in
  --version) echo "uv 0.11.7" ;;
  tool) shift; case "$1" in
    list) ;;  # empty → fast-path miss; forces the install attempt
    install)
      printf '%b' {install_stderr!r} >&2
      exit 1 ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac"""


def test_install_failure_surfaces_uv_stderr(tmp_path: Path) -> None:
    """When uv tool install fails, the user sees uv's actual error message —
    not just a generic "Failed to install" + proxy hint banner that masks
    the real cause. (worthless-nrl1)
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    write_stub(
        bin_dir,
        "uv",
        _failing_uv_stub(
            install_stderr="× No solution found when resolving dependencies\n",
        ),
    )

    result = run_install(bin_dir)

    assert result.returncode == EXIT_NETWORK, (
        f"failure path must exit {EXIT_NETWORK}, got {result.returncode}\nstderr: {result.stderr}"
    )
    # The install error MUST appear — that's the actionable diagnostic.
    assert "No solution found" in result.stderr, (
        f"uv's actual install error must surface to stderr, "
        f"not be hidden behind the generic banner.\nstderr: {result.stderr}"
    )
    assert "uv tool install reported:" in result.stderr, (
        "install stderr must be fenced under a clear header so injected "
        f"text in uv output looks like uv, not install.sh.\nstderr: {result.stderr}"
    )
    # Banner is still there (not removed, just demoted).
    assert "Failed to install" in result.stderr
    # Proxy hint is still there.
    assert "HTTPS_PROXY" in result.stderr


def test_install_failure_proxy_hint_is_secondary(tmp_path: Path) -> None:
    """The proxy hint must come AFTER uv's stderr, not before — uv's actual
    error is the primary diagnostic; proxy is the fallback suggestion.
    (worthless-nrl1)
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    write_stub(
        bin_dir,
        "uv",
        _failing_uv_stub(
            install_stderr="× No solution found\n",
        ),
    )

    result = run_install(bin_dir)
    stderr = result.stderr

    no_sol_idx = stderr.find("No solution found")
    proxy_hint_idx = stderr.find("HTTPS_PROXY")
    assert no_sol_idx >= 0, f"install stderr missing from output:\n{stderr}"
    assert proxy_hint_idx >= 0, f"proxy hint missing from output:\n{stderr}"
    assert no_sol_idx < proxy_hint_idx, (
        f"uv's stderr must come BEFORE the proxy hint (it's the primary "
        f"diagnostic, hint is the fallback). "
        f"Got: install_err at {no_sol_idx}, proxy_hint at {proxy_hint_idx}.\n{stderr}"
    )
    # The "If this looks like a network issue" framing demotes the proxy
    # hint from "this IS the cause" to "this MIGHT be the cause".
    assert "If this looks like a network issue" in stderr, (
        f"proxy hint must be reframed as conditional fallback:\n{stderr}"
    )


def test_install_failure_empty_stderr_still_shows_banner(tmp_path: Path) -> None:
    """If uv exits 1 with empty stderr (rare but possible), the failure banner
    + proxy hint still print — and we don't emit an empty 'uv reported:'
    block that would be more confusing than useful. (worthless-nrl1)
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    write_stub(
        bin_dir,
        "uv",
        _failing_uv_stub(install_stderr=""),
    )

    result = run_install(bin_dir)

    assert result.returncode == EXIT_NETWORK
    assert "Failed to install" in result.stderr
    assert "HTTPS_PROXY" in result.stderr
    # No empty "uv reported:" block — guard against showing
    # "uv reported:\n\n" with no content underneath.
    assert "uv tool install reported:" not in result.stderr, (
        f"empty-stderr path must not show an empty 'uv tool install reported:' "
        f"block — that's noise, not signal.\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Trap chaining — guards against silently dropping prior cleanups
# ---------------------------------------------------------------------------


def test_install_registers_signal_traps_once_and_they_abort() -> None:
    """Replaces test_install_trap_preserves_ensure_uv_tmpdir_cleanup (worthless-ixca).

    THE OLD INVARIANT, and why it is gone. POSIX `trap CMD SIGNAL` REPLACES (not
    chains) the previous trap for that signal. install.sh used to register traps
    in TWO places — ensure_uv and install_or_upgrade_worthless — so the second
    silently discarded the first, and the tmpdir leaked on every non-fresh box.
    The old test guarded that by asserting the second directive re-included the
    first's cleanup. It was a correct guard on a fragile arrangement.

    That fragility is now removed rather than guarded: cleanup is one function and
    the traps are registered ONCE near the top. There is no second registration to
    forget to chain. So the assertion changes from "the two directives agree" to
    "there is only one registration site, and it aborts".

    WHAT THE HANDLERS MUST DO, each proven in
    tests/user_flows/test_install_sigint_live.py against the real script under a
    real PTY:

    * `trap -` FIRST in each handler. Without it the EXIT trap fires too and
      cleanup runs twice under /bin/sh (dash runs it once — this also erases that
      divergence).
    * INT RE-RAISES the signal instead of `exit 130`. Both stop this script, but
      only signal death propagates: a caller running `for … do sh install.sh; done`
      continues to the next iteration after a plain exit, and aborts after a
      re-raise. The trailing `exit 130` is an unreachable fallback.
    * HUP is trapped. A dropped SSH session mid `curl | sh` is common and
      previously leaked the temp dir, since only EXIT/INT/TERM were handled.

    Static check (per feedback_extract_and_test): read the real on-disk install.sh
    rather than restating it, so this cannot drift from the script.
    """
    install_sh = INSTALL_SH.read_text()
    trap_lines = [ln.strip() for ln in install_sh.splitlines() if ln.strip().startswith("trap ")]

    # One registration site: every trap directive sits in the same contiguous block.
    idxs = [i for i, ln in enumerate(install_sh.splitlines()) if ln.strip().startswith("trap ")]
    assert idxs, "install.sh registers no traps at all"
    assert idxs[-1] - idxs[0] == len(idxs) - 1, (
        "trap directives are no longer contiguous — install.sh has gone back to "
        f"registering in more than one place, which POSIX trap REPLACES silently. "
        f"lines: {idxs}"
    )

    # Parse the SIGNAL LIST — the tokens after the handler's closing quote — not
    # the whole line. The INT handler contains "trap - EXIT INT HUP" in its own
    # disarm list, so a naive `"HUP" in line` reports HUP as handled even when the
    # HUP trap has been deleted. That false pass was caught by mutation testing.
    def _signals(line: str) -> set[str]:
        body_end = line.rfind("'")
        return set(line[body_end + 1 :].split()) if body_end != -1 else set()

    handled = {sig for ln in trap_lines for sig in _signals(ln)}
    assert handled == {"EXIT", "INT", "TERM", "HUP"}, (
        f"expected EXIT/INT/TERM/HUP to be handled; got {sorted(handled)}. "
        "Dropping HUP leaks the temp dir when an SSH session dies mid-install."
    )

    # Each signal handler must disarm itself first, then abort. EXIT must NOT exit.
    for ln in trap_lines:
        if ln.endswith(" EXIT"):
            assert "exit" not in ln.replace("EXIT", ""), (
                f"the EXIT trap must not exit — it fires on normal completion too: {ln}"
            )
            continue
        assert ln.startswith("trap 'trap - "), (
            f"signal handler must disarm itself first or cleanup double-fires: {ln}"
        )
        assert "cleanup" in ln, f"signal handler must still clean up: {ln}"

    int_line = next(ln for ln in trap_lines if ln.endswith(" INT"))
    assert "kill -INT $$" in int_line, (
        "the INT handler must RE-RAISE the signal, not merely `exit 130`. An exit "
        "code stops this script but does not propagate: a caller looping over "
        f"installs runs the next iteration anyway. got: {int_line}"
    )

    # Cleanup still covers both temporaries the two old directives covered.
    cleanup_def = install_sh[install_sh.index("cleanup() {") :].split("\n", 1)[0]
    for var in ("tmpdir", "uv_install_err"):
        assert var in cleanup_def, (
            f"cleanup() dropped ${var} — that is the leak the old two-directive "
            f"chaining test existed to prevent. got: {cleanup_def}"
        )

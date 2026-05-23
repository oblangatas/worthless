"""Subprocess-level behavioral tests for install.sh.

These run the actual install.sh under sh(1) with a mocked PATH so we can
assert exit codes and stderr/stdout patterns without touching the network
or the user's real environment. Heavier integration coverage lives in
test_install_docker.py (marked 'docker').
"""

from __future__ import annotations

from pathlib import Path

from tests._install_helpers import (
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
    """Pre-existing pipx-installed worthless triggers exit 30 with uninstall hint."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    # pipx list reports an existing worthless install
    write_stub(
        bin_dir,
        "pipx",
        """case "$1" in
  list) echo "package worthless 0.3.0, installed using Python 3.12.0" ;;
  *) echo "pipx stub: $@" ;;
esac
exit 0""",
    )

    result = run_install(bin_dir)

    assert result.returncode == EXIT_PIPX_CONFLICT, (
        f"expected exit {EXIT_PIPX_CONFLICT} (pipx conflict) when pipx has worthless, "
        f"got {result.returncode}\nstderr: {result.stderr}"
    )
    assert "pipx uninstall worthless" in result.stderr, (
        "stderr must include the exact 'pipx uninstall worthless' command"
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


def test_install_trap_preserves_ensure_uv_tmpdir_cleanup() -> None:
    """install_or_upgrade_worthless's trap must keep ensure_uv's tmpdir cleanup.

    POSIX `trap CMD SIGNAL` REPLACES (not chains) the previously registered
    trap for that signal. ensure_uv() registers an EXIT trap that cleans up
    the downloaded-installer tmpdir; if install_or_upgrade_worthless()
    registers a fresh EXIT trap without re-including that cleanup, the
    tmpdir leaks every time install_or_upgrade_worthless runs (i.e. always,
    on the common path of any non-fresh box).

    Static check (per feedback_extract_and_test): grep the actual on-disk
    install.sh and assert the install_or_upgrade_worthless trap line
    references BOTH tmpdir AND uv_*_err. The functional repro would need
    to force ensure_uv through the full mktemp-d path (no uv on PATH at
    all) — heavy stub setup for a 1-line invariant. Static check catches
    every regression mode that matters: someone re-overwriting the trap
    without chaining. (CodeRabbit catch on PR #148.)
    """
    install_sh = INSTALL_SH.read_text()

    # Find the trap line inside install_or_upgrade_worthless. The function
    # contains a single trap directive; locate it by searching for the
    # uv_install_err reference (unique to install_or_upgrade_worthless).
    trap_lines = [
        line
        for line in install_sh.splitlines()
        if line.lstrip().startswith("trap ") and "uv_install_err" in line
    ]
    assert len(trap_lines) == 1, (
        f"expected exactly one trap directive referencing uv_install_err in "
        f"install.sh; found {len(trap_lines)}: {trap_lines!r}"
    )
    trap_line = trap_lines[0]

    # Both cleanups must be present in the same directive.
    assert "tmpdir" in trap_line, (
        f"install_or_upgrade_worthless's EXIT trap dropped ensure_uv's "
        f"tmpdir cleanup — POSIX trap REPLACES, must chain explicitly. "
        f"got: {trap_line!r}"
    )
    assert "uv_install_err" in trap_line, (
        f"trap must clean the uv stderr tempfile. got: {trap_line!r}"
    )

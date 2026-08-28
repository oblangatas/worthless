"""WOR-597 — install.sh tells the truth when a stale copy shadows the install.

`install.sh` resolves the binary it just installed via `uv tool dir --bin`
(install.sh:450, worthless-dc26) but then announces success with
`command_in_original_path worthless` (:559), which returns true for ANY
`worthless` on the caller's PATH. A user whose PATH already holds an older
copy is therefore told "Done! 'worthless' is on your PATH." and then handed
`Try it: ... worthless lock` (:573) — a command that runs the wrong binary.

That is an affirmative false claim, not a missing nicety, which is why these
tests assert on the *absence* of the success sentence as well as the presence
of the warning.

Design constraints these tests encode, each rejected alternative having its
own guard below:

  * never execute the shadowing binary (it is of unknown provenance) —
    `test_shadow_warning_never_executes_the_shadowing_binary`
  * never exit non-zero; a shadow does not break the install —
    `test_shadow_still_exits_zero`
  * never warn when the two paths are the same file reached by different
    names — `test_symlinked_alias_is_not_reported_as_a_shadow`
"""

from __future__ import annotations

from pathlib import Path

from tests._install_helpers import (
    _UV_VERSION,
    run_install,
    write_happy_path_stubs,
    write_stub,
)

# The installed-entry-point version. Deliberately not 0.3.7/0.3.9: those two
# strings are forbidden anywhere in installer output by
# test_install_logic.py::test_banner_reports_the_installed_binary_not_a_stale_uv_run.
REAL_VERSION = "0.3.10"
SHADOW_VERSION = "0.3.7"

# Substrings that indicate the warning fired. Matching on several keeps the
# tests from locking exact copy — asserting a full sentence would turn red on
# every wording tweak while catching no bug.
_SHADOW_MARKERS = ("Heads up", "different, older copy")
_SUCCESS_SENTENCE = "is on your PATH"


def _combined(result) -> str:
    return result.stdout + result.stderr


def _shadow_warned(text: str) -> bool:
    return all(marker in text for marker in _SHADOW_MARKERS)


def _install_real_entry_point(home: Path, version: str = REAL_VERSION) -> Path:
    """Put a stub where `uv tool dir --bin` will point, so it resolves -x.

    The uv stub answers `dir --bin` with $HOME/.local/bin unless
    UV_TOOL_BIN_DIR/XDG_BIN_HOME override it (_install_helpers.py:92).
    """
    target = home / ".local" / "bin"
    target.mkdir(parents=True, exist_ok=True)
    return write_stub(target, "worthless", f'echo "worthless {version}"')


def test_shadowed_worthless_warns_and_names_both_paths(tmp_path: Path) -> None:
    """The whole point: name what runs, name what was installed.

    Catches the false-success bug. Without the fix install.sh prints
    "Done! 'worthless' is on your PATH." and never mentions the shadow, so a
    user has no way to discover why their new install appears to do nothing.

    Both paths must appear. Naming only the installed one leaves the user
    unable to find the file in the way; naming only the shadow leaves them
    unable to run the right binary.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    real = _install_real_entry_point(tmp_path)

    result = run_install(bin_dir)
    combined = _combined(result)

    assert _shadow_warned(combined), f"no shadow warning in:\n{combined}"
    assert str(real) in combined, "the installed binary's path is not named"
    assert str(bin_dir / "worthless") in combined, "the shadowing path is not named"
    assert _SUCCESS_SENTENCE not in result.stdout, (
        "install.sh still claims 'worthless' is on your PATH while a different "
        "copy is what actually runs"
    )


def test_shadow_warning_reaches_stdout_not_only_stderr(tmp_path: Path) -> None:
    """`curl worthless.sh | sh 2>/dev/null` must still show the warning.

    install.sh's warn() writes to stderr (:138). A warning routed only there
    vanishes for anyone who silences stderr on a piped installer — which is
    common, because uv and curl are chatty. The warning is the payload of
    this feature, so it goes to stdout.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    _install_real_entry_point(tmp_path)

    result = run_install(bin_dir)

    assert _shadow_warned(result.stdout), (
        "shadow warning is not on stdout; it would disappear under "
        f"`| sh 2>/dev/null`. stdout was:\n{result.stdout}"
    )


def test_shadow_warning_never_executes_the_shadowing_binary(tmp_path: Path) -> None:
    """The rejected design ran the shadow to report its version.

    The shadowing binary is by definition a file of unknown provenance,
    sitting somewhere writable enough to precede the install on PATH.
    Executing it to produce a nicer message runs unknown code as the user,
    during setup, on a script piped from the network.

    Two independent detectors, because they fail differently:
      * the sentinel fires even if the shadow's output is swallowed by
        `>/dev/null`, which a version-string assertion cannot see;
      * the version assertion ties into the existing contract in
        test_install_logic.py that forbids 0.3.7 anywhere in output.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    sentinel = tmp_path / "shadow-was-executed"
    write_stub(
        bin_dir,
        "worthless",
        f'echo executed >> "{sentinel}"\necho "worthless {SHADOW_VERSION}"',
    )
    _install_real_entry_point(tmp_path)

    result = run_install(bin_dir)
    combined = _combined(result)

    assert not sentinel.exists(), (
        "install.sh executed the shadowing binary; it must be identified by path alone, never run"
    )
    assert SHADOW_VERSION not in combined, (
        f"the shadow's version {SHADOW_VERSION} appears in output, so it was "
        "invoked (or its version was probed some other way)"
    )


def test_shadow_still_exits_zero(tmp_path: Path) -> None:
    """A shadow is a configuration problem, not an install failure.

    smoke_test already bypasses the shadow via the absolute path (:450), so
    the install genuinely succeeded. Exiting non-zero here would break
    `curl ... | sh` for every user with a leftover Homebrew or pipx copy, and
    would fail any CI step that installs Worthless.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    _install_real_entry_point(tmp_path)

    result = run_install(bin_dir)

    assert result.returncode == 0, (
        f"shadow made the installer exit {result.returncode}; stderr:\n{result.stderr}"
    )


def test_try_it_line_points_at_the_installed_binary_when_shadowed(
    tmp_path: Path,
) -> None:
    """:573 re-tests PATH separately from :559 — fixing one is not enough.

    install.sh asks `command_in_original_path worthless` a second time to
    choose between "Try it:" and "Try after PATH:". Left alone, a shadowed
    user is told to run a bare `worthless lock`, which invokes the shadow —
    the precise thing the new warning just told them not to trust.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    real = _install_real_entry_point(tmp_path)

    result = run_install(bin_dir)
    combined = _combined(result)

    try_lines = [ln for ln in combined.splitlines() if "lock" in ln and "Try" in ln]
    assert try_lines, f"no 'Try it'/'Try after PATH' line found in:\n{combined}"
    assert all(str(real) in ln for ln in try_lines), (
        "the try-it line still tells a shadowed user to run a bare `worthless`, "
        f"which resolves to the shadow. Lines were: {try_lines}"
    )


def test_happy_path_emits_no_shadow_warning(tmp_path: Path) -> None:
    """No false positives on the ordinary install.

    Guards the `:451` fallback: when `uv tool dir --bin` has no executable
    there, worthless_bin becomes `command -v worthless`, and a naive
    comparison of two differently-spelled-but-identical resolutions would
    warn on a perfectly healthy install.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    # Deliberately the FULLY-ARMED happy path: the entry point exists where
    # `uv tool dir --bin` points (so worthless_bin is authoritative) AND that
    # directory is on PATH (so the user-side lookup is non-empty). Every guard
    # in shadowing_worthless_path is therefore reached, and only the final
    # path comparison can keep this quiet. A weaker fixture — no .local/bin
    # entry point — exits at the authoritative check and would still pass with
    # the comparison deleted entirely, proving nothing.
    real = _install_real_entry_point(tmp_path)

    result = run_install(bin_dir, env_extra={"PATH": f"{real.parent}:{bin_dir}:/usr/bin:/bin"})
    combined = _combined(result)

    assert not _shadow_warned(combined), f"spurious shadow warning:\n{combined}"
    assert _SUCCESS_SENTENCE in result.stdout
    assert result.returncode == 0


def test_no_shadow_warning_when_worthless_is_not_on_path_at_all(
    tmp_path: Path,
) -> None:
    """The legitimate "open a new terminal" case must stay untouched.

    With `command -v worthless` empty, an unguarded string comparison sees
    "" != "/path/to/worthless" and fires — hijacking the existing
    activation-hint branch with a shadow message that is both frightening and
    wrong. The fixture shape is real:
    test_install_logic.py::test_install_succeeds_when_uv_installs_outside_home_local_bin.

    HONEST LIMIT — like the uv-failure test above, this does not isolate the
    empty-string guard specifically. Removing `[ -n "$_sw_user" ]` leaves this
    green, because canonical_path("") then produces a value that differs from
    ours and the function returns the empty `$_sw_user` regardless, which the
    caller's own `-n` check rejects. Three layers each independently suppress
    the warning here. The guard is kept for legibility at the point where the
    condition is actually meaningful.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    custom_bin = tmp_path / "custom-bin"
    custom_bin.mkdir()
    write_stub(custom_bin, "worthless", f'echo "worthless {REAL_VERSION}"')

    result = run_install(bin_dir, env_extra={"UV_TOOL_BIN_DIR": str(custom_bin)})
    combined = _combined(result)

    assert not _shadow_warned(combined), (
        f"shadow warning fired when worthless is simply not on PATH:\n{combined}"
    )
    assert result.returncode == 0


def test_uv_tool_dir_failure_does_not_warn(tmp_path: Path) -> None:
    """An unknown install location must produce silence, not a guess.

    If `uv tool dir --bin` fails or prints nothing, install.sh's `:450`
    concatenation yields the bare string "/worthless". Comparing that against
    the user's real path differs, so an unguarded implementation would warn
    and name a file that does not exist. Fail closed: no authoritative path,
    no claim.

    HONEST LIMIT — this test does not isolate the `worthless_bin_authoritative`
    guard. Deleting that guard leaves this test green, because the fallback
    then resolves `command -v worthless` under install.sh's own PATH, which
    the harness makes identical to ORIGINAL_PATH via WORTHLESS_TRUST_PATH=1
    (_install_helpers.py:144). The two sides come out equal and the final
    comparison keeps things quiet anyway.

    In production those PATHs are NOT identical — the lockdown at install.sh
    :104-118 prepends system dirs — so the fallback can resolve a different
    binary than the user's shell would, which is the divergence the flag
    exists to catch. The guard is therefore kept deliberately as defence the
    harness cannot reach, not deleted for being unprovable here.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    # Re-stub uv exactly as _install_helpers does, but with `tool dir` answering
    # nothing. Anything less faithful breaks `uv tool install` instead, and the
    # test then passes for the wrong reason (install dies at EXIT_NETWORK=10).
    write_stub(
        bin_dir,
        "uv",
        f"""case "$1" in
  --version) echo "uv {_UV_VERSION}" ;;
  tool) shift; case "$1" in
    install|upgrade) echo "ok" ;;
    list) ;;
    dir) echo "" ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  run) echo "worthless 0.3.0" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
    )
    write_stub(bin_dir, "worthless", f'echo "worthless {REAL_VERSION}"')

    result = run_install(bin_dir)
    combined = _combined(result)

    assert not _shadow_warned(combined), (
        f"warned despite not knowing where the install went:\n{combined}"
    )
    assert "//worthless" not in combined, "a bogus concatenated path leaked into output"
    assert result.returncode == 0


def test_symlinked_alias_is_not_reported_as_a_shadow(tmp_path: Path) -> None:
    """A symlink to the installed binary is not a shadow — it is a shortcut.

    `/opt/homebrew/bin/worthless -> ~/.local/bin/worthless` is the single most
    likely real-world configuration, and it is benign: following it runs the
    binary we just installed. Warning here would cry wolf at the largest
    group of correctly-configured users.

    This is why the implementation resolves both sides with `cd && pwd -P`
    rather than comparing strings. `-ef` is not POSIX and `realpath` is absent
    on older macOS, so neither is available in install.sh.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    real = _install_real_entry_point(tmp_path)
    (bin_dir / "worthless").symlink_to(real)

    result = run_install(bin_dir)
    combined = _combined(result)

    assert not _shadow_warned(combined), (
        "a symlink pointing at the installed binary was reported as a shadow; "
        f"running it runs the right binary:\n{combined}"
    )
    assert result.returncode == 0


def test_shadow_warning_strips_terminal_control_bytes(tmp_path: Path) -> None:
    """A crafted directory name must not be able to erase the warning.

    install.sh prints with printf '%s', so there is no format-string
    injection — but raw control bytes in a path pass through verbatim. A
    directory named with ESC[2K ESC[1A scrolls the terminal up and wipes the
    line above, letting whoever planted the shadow suppress the very message
    that exposes it. Not new code execution: they already own a PATH
    directory. It is the warning's integrity that is at stake.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    _install_real_entry_point(tmp_path)
    hostile = tmp_path / "evil\x1b[2K\x1b[1Abin"
    hostile.mkdir()
    write_stub(hostile, "worthless", f'echo "worthless {SHADOW_VERSION}"')

    result = run_install(bin_dir, env_extra={"PATH": f"{hostile}:{bin_dir}:/usr/bin:/bin"})
    combined = _combined(result)

    assert "\x1b[2K" not in combined and "\x1b[1A" not in combined, (
        "raw terminal control bytes from a hostile path reached the terminal; "
        "they can erase the warning that names them"
    )
    assert result.returncode == 0

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

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests._install_helpers import (
    INSTALL_SH,
    _UV_VERSION,
    read_install_pin,
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
_SHADOW_MARKERS = ("Heads up", "another copy")
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


def test_shadow_warning_offers_no_path_edit_or_lock(tmp_path: Path) -> None:
    """Removing the old copy is the fix; the warning must not suggest anything else.

    The earlier design printed `export PATH=...`, a fish `set -gx` line, and
    `<path> lock`. Pasted as a block, the fish line changes shell options in zsh
    and the bash line wipes PATH in fish. And `lock` run before the old copy is
    gone writes state that every new terminal and agent then reads with the old
    copy. The only command offered is `command -v worthless`, which runs nothing
    and shows which copy wins.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    _install_real_entry_point(tmp_path)

    out = run_install(bin_dir).stdout

    assert "Heads up" in out, f"shadow warning did not fire:\n{out}"
    assert "command -v worthless" in out
    # bash, dash and busybox remember where they last found a command, so in the
    # same terminal `command -v` still names the copy the user just deleted.
    assert "open a new terminal" in out.lower(), (
        f"check step must say to open a new terminal:\n{out}"
    )
    assert out.lower().index("open a new terminal") < out.index("command -v worthless")
    for banned in ("export PATH=", "set -gx PATH", "Run the new one now", "Try it:"):
        assert banned not in out, f"shadowed output still offers {banned!r}:\n{out}"


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

    There is no separate empty-path guard to isolate: with `-ef`, an empty user
    path is never "the same file", so the function prints the empty string and
    the caller's `-n` check stays silent. A dedicated guard would be an
    equivalent mutant no test could kill, so it was removed.
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

    This test does not isolate the `worthless_bin_authoritative` guard —
    deleting that guard leaves it green, because WORTHLESS_TRUST_PATH=1
    collapses install.sh's PATH onto ORIGINAL_PATH and the final comparison
    keeps things quiet anyway. An earlier version of this note concluded the
    guard was therefore untestable. That was wrong: dropping the flag restores
    the production divergence, and
    `test_no_warning_when_install_location_is_unknown_and_paths_diverge`
    below now kills that mutant.
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

    This is why install.sh compares the files with `[ a -ef b ]` (same device
    and inode) rather than comparing path strings.
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
    injection — but raw control bytes would pass through verbatim, so
    sanitize_for_display shows them as \\xNN codes instead. A
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


def test_shadow_warning_fires_on_the_already_installed_fast_path(
    tmp_path: Path,
) -> None:
    """The branch most real users hit had no shadow coverage at all.

    Every other test here goes through `uv tool install --force`, because
    write_happy_path_stubs answers `uv tool list` with nothing
    (_install_helpers.py:87). But anyone re-running the installer — the common
    case, not the edge — takes worthless-mb6l's fast path instead, which
    returns early from install_or_upgrade_worthless.

    That early return is safe today only because main() calls smoke_test
    unconditionally on the next line, so worthless_bin_authoritative is always
    set before the shadow check reads it. Nothing tested that. Moving the
    assignment into install_or_upgrade_worthless above its `return 0` is a
    plausible refactor that would silently disable the warning for exactly the
    users most likely to have an old copy lying around.

    The `install|upgrade` trap is the anti-vacuity guard: without it this test
    would silently degrade into a duplicate of the first one the moment the
    fast path stopped being taken.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    pin = read_install_pin()
    write_stub(
        bin_dir,
        "uv",
        f"""case "$1" in
  --version) echo "uv {_UV_VERSION}" ;;
  tool) shift; case "$1" in
    list) echo "worthless v{pin}" ;;
    install|upgrade) echo "UNEXPECTED_REINSTALL" >&2; exit 1 ;;
    dir) echo "${{UV_TOOL_BIN_DIR:-${{XDG_BIN_HOME:-$HOME/.local/bin}}}}" ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  run) echo "worthless {pin}" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
    )
    real = _install_real_entry_point(tmp_path, version=pin)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')

    result = run_install(bin_dir)
    combined = _combined(result)

    assert "UNEXPECTED_REINSTALL" not in combined, (
        "the fast path was not taken, so this test proves nothing about it"
    )
    assert _shadow_warned(combined), f"no shadow warning on the already-installed path:\n{combined}"
    assert str(real) in combined
    assert str(bin_dir / "worthless") in combined
    assert _SUCCESS_SENTENCE not in result.stdout
    assert result.returncode == 0


def test_no_warning_when_install_location_is_unknown_and_paths_diverge(
    tmp_path: Path,
) -> None:
    """Isolates the authoritative guard — which I wrongly called untestable.

    An earlier note in this file claimed the worthless_bin_authoritative guard
    could not be mutation-tested, because WORTHLESS_TRUST_PATH=1 makes
    install.sh's PATH identical to ORIGINAL_PATH. The collapse is real, but the
    conclusion was wrong: the fix is to drop the flag, not to give up.

    Without it install.sh prepends $HOME/.local/bin AHEAD of the caller's
    bin_dir — the production divergence. With `uv tool dir --bin` empty, the
    :451 fallback then resolves the entry point under install.sh's own PATH
    while ORIGINAL_PATH still resolves the shadow. Two different files, so
    deleting the guard makes the warning fire on an install that is fine.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    local_bin = tmp_path / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    # resolve_uv scans $HOME/.local/bin first, so uv is still found without
    # the trusted-PATH shortcut.
    write_stub(
        local_bin,
        "uv",
        f"""case "$1" in
  --version) echo "uv {_UV_VERSION}" ;;
  tool) shift; case "$1" in
    install|upgrade) echo "ok" ;;
    list) ;;
    dir) echo "" ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  run) echo "worthless {REAL_VERSION}" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
    )
    write_stub(local_bin, "worthless", f'echo "worthless {REAL_VERSION}"')
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')

    result = run_install(bin_dir, env_extra={"WORTHLESS_TRUST_PATH": ""})
    combined = _combined(result)

    assert not _shadow_warned(combined), (
        "warned about a shadow while the install location was unknown, so the "
        f"comparison had nothing authoritative to compare against:\n{combined}"
    )
    assert result.returncode == 0


# --- Paste safety (WOR-597 / CodeRabbit) --------------------------------------
#
# The warning prints paths a user will copy: the old copy's path (they are told
# to remove it) and the install path. Both can be attacker- or user-influenced.
# These tests paste the installer's real output into real shells and check that
# no folder name can make a pasted line run anything.

_NOTE = "some characters shown as codes"

# Payloads that DO execute when the raw path is pasted, in at least one shell.
# Pure quote payloads (x';... , x";...) are inert raw in every shell tried, so
# they cannot prove anything here; test_sanitize_for_display_escapes covers them.
_LIVE_PAYLOADS = {
    "command_substitution": "p$(touch PWN);x",
    "backtick": "x`touch PWN`y",
    "semicolon": "x;touch PWN;#",
    "pipe": "x|touch PWN;#",
    "and_list": "x&&touch PWN;#",
    "redirect": "x >PWN;#",
    "escaped_quote": "x\\';touch PWN;#'",
    "cyrillic_wrapped": "Андрей$(touch PWN)東京",
    "newline": "x\ntouch PWN #",
}

_PASTE_SHELLS = {
    "sh": ("sh", "-c"),
    "bash": ("bash", "--norc", "--noprofile", "-c"),
    "dash": ("dash", "-c"),
    "zsh": ("zsh", "-f", "-c"),
    "fish": ("fish", "--no-config", "-c"),
    "busybox": ("busybox", "sh", "-c"),
}


def _paste_shells() -> dict[str, tuple[str, ...]]:
    """Installed paste shells, as absolute argv prefixes.

    A shell missing locally is skipped, but CI names the ones it must have in
    WORTHLESS_PASTE_SHELLS_REQUIRED so a missing shell fails instead of quietly
    shrinking coverage.
    """
    found: dict[str, tuple[str, ...]] = {}
    for name, argv in _PASTE_SHELLS.items():
        exe = shutil.which(argv[0])
        if exe:
            found[name] = (exe, *argv[1:])
    required = {s for s in os.environ.get("WORTHLESS_PASTE_SHELLS_REQUIRED", "").split(",") if s}
    missing = required - found.keys()
    assert not missing, f"required paste shells are not installed: {sorted(missing)}"
    return found


def _paste(argv: tuple[str, ...], script: str, box: Path, touch_dir: Path) -> None:
    """Run pasted text in a locked-down shell: no startup files, only `touch` on PATH."""
    subprocess.run(  # noqa: S603
        [*argv, script],
        cwd=box,
        env={"HOME": str(box), "PATH": str(touch_dir)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        start_new_session=True,
    )


def _install_with_hostile_dir(tmp_path: Path, position: str, name: str) -> tuple[str, Path]:
    """Run the real installer with a hostile folder name in one position.

    shadow  — the old copy lives in the hostile folder
    install — uv installs into the hostile folder (UV_TOOL_BIN_DIR)
    home    — HOME itself is the hostile folder
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    hostile = tmp_path / name
    benign = tmp_path / "benign"
    env: dict[str, str] = {}
    if position == "shadow":
        _install_real_entry_point(tmp_path)
        hostile.mkdir()
        write_stub(hostile, "worthless", f'echo "worthless {SHADOW_VERSION}"')
        first = hostile
    elif position == "install":
        hostile.mkdir()
        write_stub(hostile, "worthless", f'echo "worthless {REAL_VERSION}"')
        env["UV_TOOL_BIN_DIR"] = str(hostile)
        first = benign
    else:
        home = hostile / "home"
        _install_real_entry_point(home)
        env["HOME"] = str(home)
        first = benign
    if first is benign:
        benign.mkdir()
        write_stub(benign, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    env["PATH"] = f"{first}:{bin_dir}:/usr/bin:/bin"
    return run_install(bin_dir, env_extra=env).stdout, hostile / "worthless"


@pytest.mark.flaky(reruns=0)
@pytest.mark.parametrize("position", ["shadow", "install", "home"])
@pytest.mark.parametrize("payload", list(_LIVE_PAYLOADS))
def test_pasting_warning_output_never_runs_code(
    tmp_path: Path, position: str, payload: str
) -> None:
    """Paste every line, and the whole block, into every shell — nothing runs.

    A positive control comes first in each shell: the raw hostile path is pasted
    on its own. If that does not fire, the payload is inert in that shell and the
    shell is skipped for it, so "nothing fired" can never mean "nothing ran".
    """
    shells = _paste_shells()
    out, raw = _install_with_hostile_dir(tmp_path, position, _LIVE_PAYLOADS[payload])
    assert "Heads up" in out, f"shadow warning did not fire, so nothing was tested:\n{out}"

    touch_dir = tmp_path / "touchbin"
    touch_dir.mkdir()
    (touch_dir / "touch").symlink_to(shutil.which("touch"))
    live = []
    for shell, argv in shells.items():
        box = tmp_path / f"paste-{shell}"
        box.mkdir()
        sentinel = box / "PWN"
        _paste(argv, f": {raw}", box, touch_dir)
        if not sentinel.exists():
            continue
        sentinel.unlink()
        live.append(shell)
        for line in out.split("\n"):
            if line.strip():
                _paste(argv, line, box, touch_dir)
        _paste(argv, out, box, touch_dir)
        assert not sentinel.exists(), (
            f"pasting the installer's output ran code in {shell} ({position} / {payload}):\n{out}"
        )
    assert live, f"{payload!r} fired in no installed shell, so this case proves nothing"


def test_machine_paths_appear_only_in_prose_lines(tmp_path: Path) -> None:
    """No path from the machine is ever printed inside a command.

    Escaping cannot be safe for every shell a user might paste into, so a command
    must contain no path at all. Only the "Done!" line and the indented old-copy
    line may show one.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir)
    write_stub(bin_dir, "worthless", f'echo "worthless {SHADOW_VERSION}"')
    _install_real_entry_point(tmp_path)

    out = run_install(bin_dir).stdout

    assert "Heads up" in out, f"shadow warning did not fire:\n{out}"
    offenders = [
        line
        for line in out.split("\n")
        if str(tmp_path) in line and not line.lstrip().startswith(("Done!", str(tmp_path)))
    ]
    assert not offenders, "a machine path is inside a non-prose line:\n" + "\n".join(offenders)


@pytest.mark.parametrize(("folder", "noted"), [("old", False), ("old copy", True)])
def test_codes_note_appears_only_when_codes_are_shown(
    tmp_path: Path, folder: str, noted: bool
) -> None:
    """A path shown with codes says why; a plain path doesn't clutter the warning."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    _install_real_entry_point(tmp_path)
    shadow = tmp_path / folder
    shadow.mkdir()
    write_stub(shadow, "worthless", f'echo "worthless {SHADOW_VERSION}"')

    out = run_install(bin_dir, env_extra={"PATH": f"{shadow}:{bin_dir}:/usr/bin:/bin"}).stdout

    assert "Heads up" in out, f"shadow warning did not fire:\n{out}"
    assert (_NOTE in out) is noted, f"codes note presence should be {noted}:\n{out}"


# --- sanitize_for_display, tested directly ------------------------------------
#
# Direct, not through run_install: macOS refuses folder names that aren't valid
# UTF-8, so the byte cases can't be built as real directories there.

_SANITIZE_RE = re.compile(r"^sanitize_for_display\s*\(\)\s*\{(.*?)^\}", re.S | re.M)
_UTF8_LOCALE = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
_ALLOWED = rb"[A-Za-z0-9._/+@:,=%-]"


def _sanitize(raw: bytes, locale: str) -> bytes:
    match = _SANITIZE_RE.search(INSTALL_SH.read_text(encoding="utf-8"))
    assert match, "sanitize_for_display() not found in install.sh"
    script = f'sanitize_for_display() {{{match.group(1)}}}\nsanitize_for_display "$1"\n'
    result = subprocess.run(  # noqa: S603
        ["sh", "-c", script, "sh", raw],  # noqa: S607
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": locale},
        timeout=10,
        check=False,
    )
    return result.stdout


_SANITIZE_CASES = {
    "plain": (b"/opt/homebrew/bin/worthless", b"/opt/homebrew/bin/worthless"),
    "space": (b"/Users/John Smith/bin", rb"/Users/John\x20Smith/bin"),
    "command_substitution": (b"/b/p$(touch X);x", rb"/b/p\x24\x28touch\x20X\x29\x3bx"),
    "single_quote": (b"/b/x';y", rb"/b/x\x27\x3by"),
    "backslash": (b"/a\\b", rb"/a\x5cb"),
    "newline": (b"/a\nb", rb"/a\x0ab"),
    "invalid_byte": (b"/opt/homebrew\xff/bin/worthless", rb"/opt/homebrew\xff/bin/worthless"),
    "cyrillic": ("/home/Ан".encode(), rb"/home/\xd0\x90\xd0\xbd"),
    "rtl_override": ("/opt/\u202ex".encode(), rb"/opt/\xe2\x80\xaex"),
}


@pytest.mark.flaky(reruns=0)
@pytest.mark.parametrize("locale", ["C", _UTF8_LOCALE])
@pytest.mark.parametrize("case", list(_SANITIZE_CASES))
def test_sanitize_for_display_escapes(case: str, locale: str) -> None:
    """Only characters that can't run, chain, or disguise text print as themselves.

    Everything else prints as \\xNN — including spaces (`rm /a b` would delete
    `/a`) and every non-ASCII byte (lookalikes and text-flipping characters can't
    pass a blocklist). The old `tr | cut` truncated macOS paths at the first
    invalid byte, so `/opt/homebrew\\xff/bin` displayed as `/opt/homebrew`.
    """
    raw, want = _SANITIZE_CASES[case]
    assert case == "plain" or raw != want, "a non-plain case must actually need escaping"
    assert _sanitize(raw, locale) == want


def test_sanitized_long_path_never_splits_a_code() -> None:
    """A truncated path ends on a whole character or code, never half of `\\xNN`."""
    out = _sanitize(("/" + "東" * 120).encode(), "C")
    assert len(out) <= 243, f"not truncated: {len(out)} bytes"
    assert re.fullmatch(rb"(?:" + _ALLOWED + rb"|\\x[0-9a-f]{2})*", out), out


# --- Same file, different spelling (the -ef check) ----------------------------


def test_link_inside_a_symlinked_folder_is_not_a_shadow(tmp_path: Path) -> None:
    """A link whose `../` climbs above a symlinked folder still runs our copy.

    The shell resolves `..` by name, the kernel by the real folder. Here those
    disagree: by name the PATH entry points at a decoy; for real it points at the
    installed binary. Resolving paths as text warned about a shadow that isn't.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    installed = tmp_path / "deep" / "real"
    installed.mkdir(parents=True)
    write_stub(installed, "worthless", f'echo "worthless {REAL_VERSION}"')
    (tmp_path / "deep" / "phys" / "bin").mkdir(parents=True)
    (tmp_path / "deep" / "phys" / "bin" / "worthless").symlink_to("../../real/worthless")
    (tmp_path / "logical").symlink_to(tmp_path / "deep" / "phys")
    decoy = tmp_path / "real"
    decoy.mkdir()
    write_stub(decoy, "worthless", f'echo "worthless {SHADOW_VERSION}"')

    out = run_install(
        bin_dir,
        env_extra={
            "UV_TOOL_BIN_DIR": str(installed),
            "PATH": f"{tmp_path / 'logical' / 'bin'}:{bin_dir}:/usr/bin:/bin",
        },
    ).stdout

    assert _SUCCESS_SENTENCE in out, f"fixture did not put worthless on PATH:\n{out}"
    assert "Heads up" not in out, f"warned about a link that runs our own copy:\n{out}"


def test_mixed_case_path_entry_is_not_a_shadow(tmp_path: Path) -> None:
    """On a case-insensitive disk, `/USERS/x` and `/Users/x` are one folder.

    macOS's /bin/sh (bash 3.2) keeps the typed case in `pwd -P`, so comparing
    resolved paths as text warned about the user's own install.
    """
    (tmp_path / "CaseProbe").mkdir()
    if not (tmp_path / "caseprobe").exists():
        pytest.skip("filesystem is case-sensitive; this case cannot occur here")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    real = _install_real_entry_point(tmp_path)

    out = run_install(
        bin_dir, env_extra={"PATH": f"{str(real.parent).upper()}:{bin_dir}:/usr/bin:/bin"}
    ).stdout

    assert _SUCCESS_SENTENCE in out, f"fixture did not put worthless on PATH:\n{out}"
    assert "Heads up" not in out, f"warned about the same folder spelled differently:\n{out}"


def test_trailing_slash_install_dir_is_not_a_shadow(tmp_path: Path) -> None:
    """`UV_TOOL_BIN_DIR=.../bin/` and PATH `.../bin` name the same binary."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_happy_path_stubs(bin_dir, with_worthless=False)
    real = _install_real_entry_point(tmp_path)

    out = run_install(
        bin_dir,
        env_extra={
            "UV_TOOL_BIN_DIR": f"{real.parent}/",
            "PATH": f"{real.parent}:{bin_dir}:/usr/bin:/bin",
        },
    ).stdout

    assert _SUCCESS_SENTENCE in out, f"fixture did not put worthless on PATH:\n{out}"
    assert "Heads up" not in out, f"warned about a trailing slash:\n{out}"

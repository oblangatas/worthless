"""Behavior tests for the standalone uninstall.sh (WOR-694).

`curl worthless.sh/uninstall | sh` is the companion to the install one-liner —
for removing Worthless when the binary itself is broken/gone. Two modes:

  Tier 1 — a working `worthless` is on PATH → delegate to `worthless uninstall`
           (restores keys), then remove the installed tool.
  Tier 2 — no working binary → best-effort wipe of ~/.worthless + keychain +
           tool. Keys CANNOT be restored (no crypto in shell); tell the user to
           rotate them.

Every test runs against a sandbox HOME/WORTHLESS_HOME — never the real install.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from tests._install_helpers import run_uninstall, write_stub


def _seed_home(home: Path, env_paths: list[str]) -> None:
    """Create a fake ~/.worthless with a key file + a DB of locked .env paths."""
    home.mkdir(parents=True, exist_ok=True)
    (home / "fernet.key").write_text("fake-fernet-key\n")
    con = sqlite3.connect(str(home / "worthless.db"))
    try:
        con.execute("CREATE TABLE enrollments (key_alias TEXT, var_name TEXT, env_path TEXT)")
        for i, path in enumerate(env_paths):
            con.execute(
                "INSERT INTO enrollments VALUES (?, ?, ?)",
                (f"alias{i}", "OPENAI_API_KEY", path),
            )
        con.commit()
    finally:
        con.close()


def test_tier2_wipes_a_broken_install(tmp_path: Path) -> None:
    """No `worthless` on PATH → the home is wiped and the user is told to rotate."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    result = run_uninstall(bin_dir, worthless_home=home)

    assert result.returncode == 0, result.stderr
    assert not home.exists(), "Tier 2 must wipe ~/.worthless"
    combined = (result.stdout + result.stderr).lower()
    assert "rotate" in combined, "must tell the user to rotate their keys"


def test_tier2_wipes_even_without_a_database(tmp_path: Path) -> None:
    """A half-broken install (stray dir, no readable DB) is still removed cleanly."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    home.mkdir()
    (home / "fernet.key").write_text("x\n")

    result = run_uninstall(bin_dir, worthless_home=home)

    assert result.returncode == 0, result.stderr
    assert not home.exists()


@pytest.mark.skipif(
    shutil.which("sqlite3") is None,
    reason="sqlite3 CLI needed to read the (plaintext) env_path list",
)
def test_tier2_lists_affected_env_files(tmp_path: Path) -> None:
    """env_path is plaintext in the DB, so the script can name which .env files
    held locked keys — the ones the user now needs to rotate."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env", "/proj/b/.env"])

    result = run_uninstall(bin_dir, worthless_home=home)

    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "/proj/a/.env" in combined
    assert "/proj/b/.env" in combined


def test_tier1_delegates_to_a_working_binary_then_removes_the_tool(tmp_path: Path) -> None:
    """A working installed `worthless` → the script delegates to
    `worthless uninstall` (which restores keys) and then removes the tool via uv.

    The binary lives where `uv tool dir --bin` reports, not merely on PATH:
    since WOR-597 a PATH hit alone is not proof it is the copy we installed.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.8" ;;\n'
        '  uninstall) echo "STUB_RESTORED_KEYS" ;;\n'
        '  *) echo "stub: $*" ;;\n'
        "esac",
    )
    _write_uv_stub(bin_dir, real_bin_dir)

    result = run_uninstall(bin_dir, worthless_home=home)

    assert result.returncode == 0, result.stderr
    out = result.stdout + result.stderr
    assert "STUB_RESTORED_KEYS" in out, "Tier 1 must delegate to the working binary"
    assert str(real_bin_dir / "worthless") in out, (
        "the binary being handed `uninstall --yes` must be named, so a redirected "
        "lookup is visible rather than silent"
    )
    uv_log = tmp_path / "uv.log"
    assert uv_log.exists() and "tool uninstall worthless" in uv_log.read_text(), (
        "Tier 1 must remove the installed tool after delegating"
    )


def _write_uv_stub(bin_dir: Path, tool_bin_dir: Path) -> None:
    """A uv stub that answers `tool dir --bin` and logs `tool uninstall`."""
    write_stub(
        bin_dir,
        "uv",
        'printf "uv %s\\n" "$*" >> "$HOME/uv.log"\n'
        'case "$1 $2 $3" in\n'
        f'  "tool dir --bin") echo "{tool_bin_dir}" ;;\n'
        '  "tool uninstall worthless") echo "removed" ;;\n'
        "  *) ;;\n"
        "esac",
    )


def test_uninstall_never_runs_a_shadowing_copy(tmp_path: Path) -> None:
    """WOR-597. The copy PATH resolves may not be the one we installed.

    uninstall.sh delegates the key restoration to `worthless uninstall` — the
    only thing that can unscramble the shards. Resolving that binary through
    PATH hands the job to whatever sits earliest: a stale Homebrew or pip copy
    that knows nothing about this install. It "succeeds", the real tool is then
    deleted, and the user is told their keys were restored while the shards are
    still on disk and the stale copy still wins `command -v`.

    The installed binary is what uv reports, so that is what must run. A stale
    copy is never executed: it is a file of unknown provenance, and running it
    is the thing this test exists to forbid.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    sentinel = tmp_path / "shadow-was-executed"
    write_stub(
        bin_dir,
        "worthless",
        f'echo executed >> "{sentinel}"\n'
        'case "$1" in\n'
        '  --version) echo "worthless 0.0.1-shadow" ;;\n'
        '  uninstall) echo "SHADOW_RESTORED_NOTHING" ;;\n'
        "esac",
    )
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.12" ;;\n'
        '  uninstall) echo "REAL_RESTORED_KEYS" ;;\n'
        "esac",
    )
    _write_uv_stub(bin_dir, real_bin_dir)

    result = run_uninstall(bin_dir, worthless_home=home)
    out = result.stdout + result.stderr

    assert not sentinel.exists(), (
        f"uninstall.sh executed the shadowing copy; it must run the binary uv installed:\n{out}"
    )
    assert "REAL_RESTORED_KEYS" in out, f"the installed binary did not do the uninstall:\n{out}"
    assert "SHADOW_RESTORED_NOTHING" not in out
    assert result.returncode == 0, result.stderr


def test_uninstall_delegates_to_a_pipx_install(tmp_path: Path) -> None:
    """A pipx-installed worthless still gets to restore the user's keys.

    `pipx install worthless` is a documented install path, so requiring uv would
    send those users to the tier 2 wipe — which deletes ~/.worthless and the
    keychain entry, leaving keys unrecoverable while a working program that
    could have unscrambled them sits on disk. pipx knows where it put the
    binary, so ask pipx, exactly as we ask uv.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pipx_bin_dir = tmp_path / "pipx" / "bin"
    pipx_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    sentinel = tmp_path / "shadow-was-executed"
    write_stub(
        bin_dir,
        "worthless",
        f'echo executed >> "{sentinel}"\necho "worthless 0.0.1-shadow"',
    )
    write_stub(
        pipx_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.12" ;;\n'
        '  uninstall) echo "PIPX_RESTORED_KEYS" ;;\n'
        "esac",
    )
    # uv exists but has no such tool — the pipx cohort's exact shape.
    _write_uv_stub(bin_dir, tmp_path / "uv-tools" / "bin")
    write_stub(
        bin_dir,
        "pipx",
        'case "$1 $2 $3" in\n'
        f'  "environment --value PIPX_BIN_DIR") echo "{pipx_bin_dir}" ;;\n'
        "  *) ;;\n"
        "esac",
    )

    result = run_uninstall(bin_dir, worthless_home=home)
    out = result.stdout + result.stderr

    assert "PIPX_RESTORED_KEYS" in out, f"a pipx install must still restore keys:\n{out}"
    assert not sentinel.exists(), "the PATH copy was executed instead of the pipx one"
    assert result.returncode == 0, result.stderr


def test_a_refusal_from_the_program_does_not_become_a_wipe(tmp_path: Path) -> None:
    """`worthless uninstall` exiting non-zero means "I kept your keys" — honour it.

    The CLI refuses rather than force-wipe when an install is still recoverable
    (a busy DB, an IPC blip): it exits non-zero having destroyed nothing. The
    script used to read any non-zero as "didn't finish cleanly" and fall into
    the tier 2 wipe, which deletes the keychain entry and rm -rf's ~/.worthless —
    the fernet key and the database the restore needs. A recoverable install
    became an unrecoverable one, which is the outcome the CLI refused to cause.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.12" ;;\n'
        '  uninstall) echo "refusing: database is busy" >&2; exit 1 ;;\n'
        "esac",
    )
    _write_uv_stub(bin_dir, real_bin_dir)
    # The keychain half of the state is as load-bearing as the files.
    keychain_log = tmp_path / "security.log"
    write_stub(bin_dir, "security", f'echo "$*" >> "{keychain_log}"')

    result = run_uninstall(bin_dir, worthless_home=home)
    out = result.stdout + result.stderr

    assert not keychain_log.exists(), f"a refusal deleted the keychain entry:\n{out}"
    assert home.exists(), f"a refusal wiped the home the restore needs:\n{out}"
    assert (home / "fernet.key").exists(), "the key that can unscramble the shards was deleted"
    assert result.returncode != 0, "a refused uninstall must not report success"
    assert "nothing was deleted" in out.lower(), (
        f"the user must be told the state is intact:\n{out}"
    )


def test_a_partial_restore_removes_the_tool_and_says_which_keys_are_stranded(
    tmp_path: Path,
) -> None:
    """Exit 73 means the CLI finished and wiped, but could not restore every .env.

    It is not a refusal: claiming "nothing was deleted" there would be false,
    and leaving the tool installed would contradict the CLI's own state. The
    tool goes, and the user is told to rotate what could not be restored.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.12" ;;\n'
        '  uninstall) echo "could not restore /proj/a/.env"; exit 73 ;;\n'
        "esac",
    )
    _write_uv_stub(bin_dir, real_bin_dir)

    result = run_uninstall(bin_dir, worthless_home=home)
    out = (result.stdout + result.stderr).lower()

    assert result.returncode == 73, f"the CLI's partial-restore code must survive:\n{out}"
    assert "nothing was deleted" not in out, "the wipe already happened; that claim is false"
    assert "rotate" in out, "the user must be told to rotate what could not be restored"
    uv_log = tmp_path / "uv.log"
    assert uv_log.exists() and "tool uninstall worthless" in uv_log.read_text(), (
        "the tool must still be removed after a partial restore"
    )


def test_force_wipes_after_a_refusal(tmp_path: Path) -> None:
    """--force is the escape hatch: wipe anyway, and say keys are not restored."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n  --version) echo "worthless 0.3.12" ;;\n  uninstall) exit 1 ;;\nesac',
    )
    _write_uv_stub(bin_dir, real_bin_dir)

    result = run_uninstall(bin_dir, worthless_home=home, args=("--yes", "--force"))
    out = (result.stdout + result.stderr).lower()

    assert not home.exists(), "--force must still wipe"
    assert "rotate" in out, "a forced wipe must tell the user to rotate their keys"
    uv_log = tmp_path / "uv.log"
    assert uv_log.exists() and "tool uninstall worthless" in uv_log.read_text(), (
        "a forced wipe must still remove the installed tool"
    )
    assert result.returncode == 0, result.stderr


def test_a_poisoned_uv_tool_bin_dir_does_not_beat_a_real_install(tmp_path: Path) -> None:
    """WOR-597 through the environment instead of PATH.

    UV_TOOL_BIN_DIR / XDG_BIN_HOME steer `uv tool dir --bin`, so a hostile value
    would hand `uninstall --yes` to a binary of the attacker's choosing — the
    same defeat as a stale copy on PATH. Resolution therefore asks uv with those
    variables unset first; only if that finds nothing do we honour them, because
    install.sh honours them too and the tool may genuinely live there.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_bin_dir = tmp_path / "uv-tools" / "bin"
    real_bin_dir.mkdir(parents=True)
    evil_bin_dir = tmp_path / "evil"
    evil_bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    sentinel = tmp_path / "evil-was-executed"
    write_stub(evil_bin_dir, "worthless", f'echo executed >> "{sentinel}"\necho "worthless 9.9.9"')
    write_stub(
        real_bin_dir,
        "worthless",
        'case "$1" in\n'
        '  --version) echo "worthless 0.3.12" ;;\n'
        '  uninstall) echo "REAL_RESTORED_KEYS" ;;\n'
        "esac",
    )
    # uv honours UV_TOOL_BIN_DIR when set, and reports the real dir when it is not.
    write_stub(
        bin_dir,
        "uv",
        'printf "uv %s\\n" "$*" >> "$HOME/uv.log"\n'
        'case "$1 $2 $3" in\n'
        '  "tool dir --bin")\n'
        f'    if [ -n "${{UV_TOOL_BIN_DIR:-}}" ]; then echo "$UV_TOOL_BIN_DIR"; '
        f'else echo "{real_bin_dir}"; fi ;;\n'
        '  "tool uninstall worthless") echo "removed" ;;\n'
        "  *) ;;\n"
        "esac",
    )

    result = run_uninstall(
        bin_dir,
        worthless_home=home,
        env_extra={"UV_TOOL_BIN_DIR": str(evil_bin_dir)},
    )
    out = result.stdout + result.stderr

    assert not sentinel.exists(), f"a hostile UV_TOOL_BIN_DIR got its binary executed:\n{out}"
    assert "REAL_RESTORED_KEYS" in out, f"the real install should have done the work:\n{out}"


def test_an_unverifiable_copy_stops_the_script_instead_of_wiping(tmp_path: Path) -> None:
    """WOR-597. A `worthless` we cannot vouch for is neither run nor wiped around.

    Neither uv nor pipx claims this install, yet something answers PATH. It may
    be the user's own install in a custom bin dir (install.sh honours
    UV_TOOL_BIN_DIR; this script scrubs it, so we cannot see it) or a leftover
    copy. Running it is out — unknown provenance. Wiping is also out: it would
    delete the key and database that copy could still use to restore. So stop,
    tell the user how to do it themselves, and leave --force as the way out.

    A genuinely broken install — nothing on PATH at all — still gets the tier 2
    wipe (test_tier2_wipes_a_broken_install).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    sentinel = tmp_path / "shadow-was-executed"
    write_stub(
        bin_dir,
        "worthless",
        f'echo executed >> "{sentinel}"\necho "worthless 0.0.1-shadow"',
    )

    result = run_uninstall(bin_dir, worthless_home=home)
    out = (result.stdout + result.stderr).lower()

    assert not sentinel.exists(), "a PATH-resolved copy was executed with no way to verify it"
    assert "restored to your .env files" not in out, "claimed a restoration that never happened"
    assert home.exists(), "the home a recoverable copy needs was wiped"
    assert (home / "fernet.key").exists(), "the key that unscrambles the shards was deleted"
    assert "nothing was deleted" in out, f"the user must be told the state is intact:\n{out}"
    assert "--force" in out, "the escape hatch must be offered"
    assert result.returncode == 41, f"a refusal needs its own exit code, got {result.returncode}"


def test_force_wipes_when_the_copy_cannot_be_verified(tmp_path: Path) -> None:
    """--force is how a user says "I know, wipe it anyway" — keys stay locked."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])
    write_stub(bin_dir, "worthless", 'echo "worthless 0.0.1-shadow"')

    result = run_uninstall(bin_dir, worthless_home=home, args=("--yes", "--force"))
    out = (result.stdout + result.stderr).lower()

    assert not home.exists(), "--force must wipe"
    assert "rotate" in out, "a forced wipe must tell the user to rotate their keys"
    assert result.returncode == 0, result.stderr


def test_refuses_without_yes_when_noninteractive(tmp_path: Path) -> None:
    """No --yes and no terminal => refuse (exit 1) and destroy nothing.

    ``run_uninstall`` starts a new session (no controlling tty), so the
    confirm()'s /dev/tty read can't block — it must refuse deterministically.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "wless-home"
    _seed_home(home, ["/proj/a/.env"])

    result = run_uninstall(bin_dir, worthless_home=home, args=())

    assert result.returncode == 1, f"must refuse without --yes; got {result.returncode}"
    assert home.exists(), "a refusal must not wipe anything"


def test_keychain_account_matches_the_python_keystore(tmp_path: Path) -> None:
    """The keychain entry the shell targets must be byte-identical to the one the
    CLI writes — otherwise Tier 2 would delete the wrong entry (or nothing)."""
    from worthless.cli import keystore

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / ".worthless"
    home.mkdir()

    expected = keystore._keyring_username(home)
    result = run_uninstall(bin_dir, worthless_home=home, args=("--print-keychain-account",))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected, (
        f"shell account {result.stdout.strip()!r} != python {expected!r}"
    )

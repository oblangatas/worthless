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


def test_uninstall_is_honest_when_it_cannot_find_the_installed_binary(tmp_path: Path) -> None:
    """WOR-597. No authoritative answer → never guess with PATH, never claim restoration.

    Without uv there is no way to tell our binary from a stale one, so the
    script must not run either. It falls back to the honest wipe, which says
    the keys could not be restored and to rotate them — a recoverable truth,
    unlike a false "your keys were restored".
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
    assert "rotate" in out, "must tell the user to rotate their keys"
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

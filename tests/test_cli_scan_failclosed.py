"""Fail-closed contract for ``worthless scan`` (worthless-c5kc).

If the scan can't read every file end-to-end — a timeout, an oversized file,
an unreadable file — the command must:
  * surface the skipped file(s) in --json under a ``skipped`` array;
  * exit NON-ZERO (code 2) even when no unprotected keys were found;
  * never echo file content in a skip notice (file path + reason only).

These tests are CLI-level (via Typer's ``CliRunner``) so they pin the contract
a pre-commit hook depends on: "a hung scan must not silently pass".
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from worthless.cli.app import app

runner = CliRunner()


def test_truncated_file_exits_nonzero_and_appears_in_json(tmp_path: Path, monkeypatch) -> None:
    """A file padded past the cap → JSON ``skipped`` carries it + exit ≠ 0.

    Uses a tiny ``MAX_SCAN_FILE_BYTES`` so we don't have to write 5 MB to disk
    in CI. The padded prefix contains NO key (so ``unprotected`` is empty and
    only the fail-closed-on-skip rule can drive a non-zero exit).
    """
    import worthless.cli.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "MAX_SCAN_FILE_BYTES", 256)

    # Isolate WORTHLESS_HOME so an existing dev DB doesn't leak orphans into
    # our JSON envelope and confuse assertions.
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "worthless-home"))
    monkeypatch.chdir(tmp_path)
    env = tmp_path / ".env"
    # No key — pure padding. The skip itself must drive the exit code.
    env.write_bytes(b"# placeholder\n" + b"x" * 1024)

    result = runner.invoke(app, ["scan", "--json"])

    assert result.exit_code == 2, (
        f"truncated file must fail-closed (exit 2). got {result.exit_code!r}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    assert "skipped" in payload
    assert any(s["reason"] == "truncated" for s in payload["skipped"]), (
        f"truncated entry missing from JSON skipped list: {payload['skipped']!r}"
    )
    # Fail-closed contract: skip notice carries the path + reason only.
    for s in payload["skipped"]:
        assert set(s.keys()) == {"file", "reason"}


def test_clean_small_env_exits_zero_with_empty_skipped(tmp_path: Path, monkeypatch) -> None:
    """A normal small tree behaves the same as before: exit 0, no skips."""
    # Isolate WORTHLESS_HOME so an existing dev DB doesn't leak orphans into
    # our JSON envelope and confuse assertions.
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "worthless-home"))
    monkeypatch.chdir(tmp_path)
    # No .env, no keys → "No API keys found." path. ``skipped`` must be empty
    # and exit code must be 0 — proves we didn't regress the happy path.
    result = runner.invoke(app, ["scan", "--json"])

    assert result.exit_code == 0, (
        f"clean tree must exit 0. got {result.exit_code!r}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    assert payload["skipped"] == []


def test_human_path_emits_skip_block_without_file_contents(tmp_path: Path, monkeypatch) -> None:
    """Human stderr block lists the path + reason — never file contents.

    A hostile oversized file could itself contain a leaked key; the skip
    notice must NOT echo any file bytes.
    """
    import worthless.cli.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "MAX_SCAN_FILE_BYTES", 256)

    # Isolate WORTHLESS_HOME so an existing dev DB doesn't leak orphans into
    # our JSON envelope and confuse assertions.
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "worthless-home"))
    monkeypatch.chdir(tmp_path)
    env = tmp_path / ".env"
    secret_marker = "this-text-must-not-leak-into-stderr"  # noqa: S105 — test sentinel
    env.write_bytes(secret_marker.encode() + b"x" * 1024)

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Skipped" in result.stderr
    assert ".env" in result.stderr
    assert "[truncated]" in result.stderr
    assert secret_marker not in result.stderr, (
        "skip notice must not echo file contents — possible leak vector"
    )


class TestPreCommitWithNoFilesFailsClosed:
    """worthless-2kuy step 1: the hook must never report all-clear on nothing.

    ``scan --install-hook`` writes ``worthless scan --pre-commit "$@"`` into
    ``.git/hooks/pre-commit``. Git invokes pre-commit hooks with ZERO
    arguments, and ``--pre-commit`` mode only scans explicitly-passed paths —
    so the hook inspected no files, printed "No API keys found." and exited 0.
    A real key committed clean while the user was told they were protected.

    Step 1 does not make the hook work. It stops it lying: a hook that
    resolved no files must fail loudly so the user reinstalls it, rather than
    manufacturing confidence. Steps 2-3 add real staged-file scanning.
    """

    def test_pre_commit_with_no_paths_does_not_report_all_clear(self) -> None:
        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split())

        # Exit 0 is the "your commit is clean" signal. Emitting it after
        # inspecting nothing is a fabricated verdict.
        assert result.exit_code != 0, (
            f"scan --pre-commit reported success without inspecting any file; output:\n{out}"
        )

        assert "No API keys found" not in out, (
            f"scan --pre-commit claimed a clean result over zero files; output:\n{out}"
        )

    def test_pre_commit_with_no_paths_tells_the_user_what_to_do(self) -> None:
        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split()).lower()

        # Failing closed is only useful if the user learns why and what to do.
        assert "no files" in out or "received no files" in out, (
            f"scan --pre-commit must say it received no files; output:\n{out}"
        )
        assert "hook" in out, f"scan --pre-commit must point the user at the hook; output:\n{out}"

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

from tests.helpers import fake_openai_key

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

    def test_pre_commit_with_no_paths_does_not_report_all_clear(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # Outside a git work tree scan cannot learn what is being committed.
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GIT_DIR", raising=False)
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

    def test_pre_commit_with_no_paths_tells_the_user_what_to_do(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GIT_DIR", raising=False)
        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split()).lower()

        # Failing closed is only useful if the user learns why and what to do.
        assert "not verified" in out, (
            f"scan --pre-commit must say the commit was not verified; output:\n{out}"
        )
        assert "hook" in out, f"scan --pre-commit must point the user at the hook; output:\n{out}"


def _git_repo(path: Path) -> None:
    """Init a throwaway git repo at *path*."""
    import subprocess

    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@t.t"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S607


def _stage(path: Path, name: str, content: str) -> None:
    import subprocess

    (path / name).write_text(content)
    subprocess.run(["git", "-C", str(path), "add", name], check=True, capture_output=True)  # noqa: S607


class TestPreCommitScansStagedFiles:
    """worthless-2kuy step 2: the hook scans what is actually being committed.

    Git passes no arguments, so ``--pre-commit`` must collect the staged set
    itself. Step 1 made the zero-file case fail closed; now that scan resolves
    files on its own, an empty staged set becomes legitimate again (an empty or
    merge commit is not a broken hook) and only a FAILED collection fails hard.
    """

    def test_staged_file_with_a_key_is_caught(self, tmp_path: Path, monkeypatch) -> None:
        _git_repo(tmp_path)
        _stage(tmp_path, "leak.txt", f"OPENAI_API_KEY={fake_openai_key()}\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split())

        assert result.exit_code == 1, (
            f"a staged file holding a real key must block the commit; output:\n{out}"
        )
        assert "leak.txt" in out, f"scan must name the offending file; output:\n{out}"

    def test_staged_clean_file_passes(self, tmp_path: Path, monkeypatch) -> None:
        _git_repo(tmp_path)
        _stage(tmp_path, "ok.txt", "nothing secret here\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 0, (
            f"a clean staged file must not block the commit; output:\n"
            f"{result.stdout}{result.stderr}"
        )

    def test_unstaged_key_is_not_scanned(self, tmp_path: Path, monkeypatch) -> None:
        # Only what is being COMMITTED matters. A key sitting in the working
        # tree unstaged is not entering history on this commit.
        _git_repo(tmp_path)
        _stage(tmp_path, "ok.txt", "clean\n")
        (tmp_path / "untracked.txt").write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 0, (
            f"an unstaged key must not block a clean commit; output:\n"
            f"{result.stdout}{result.stderr}"
        )

    def test_empty_staged_set_is_allowed(self, tmp_path: Path, monkeypatch) -> None:
        # Revises step 1: once scan collects the set itself, "nothing staged"
        # is an empty/merge commit, not a broken hook.
        _git_repo(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 0, (
            f"an empty staged set is a legitimate commit, not a broken hook; "
            f"output:\n{result.stdout}{result.stderr}"
        )

    def test_collection_failure_still_fails_closed(self, tmp_path: Path, monkeypatch) -> None:
        # Not a git repo at all -> scan cannot determine what is being
        # committed. It must refuse rather than report a clean commit.
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GIT_DIR", raising=False)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split())
        assert result.exit_code == 2, (
            f"scan must fail closed when it cannot determine the staged set; output:\n{out}"
        )
        assert "No API keys found" not in out, (
            f"scan claimed a clean result it could not substantiate; output:\n{out}"
        )


class TestPreCommitReadsTheIndexNotTheWorkingTree:
    """worthless-2kuy follow-up: scope AND content must come from the index.

    The first fix took scope from `git diff --cached` but read CONTENT off
    disk. Those disagree, and each disagreement let a key reach a commit past a
    green hook — the exact symptom the ticket exists to kill. All three were
    measured on real repos before this guard existed.
    """

    def _repo(self, path: Path) -> None:
        import subprocess

        for args in (
            ["init", "-q"],
            ["config", "user.email", "t@t.t"],
            ["config", "user.name", "t"],
        ):
            subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S607

    def _git(self, path: Path, *args: str) -> None:
        import subprocess

        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S607

    def test_staged_then_deleted_from_disk_is_caught(self, tmp_path: Path, monkeypatch) -> None:
        # The blob is in the index and WILL be committed; the file is gone from
        # disk, so an is_file() check would skip it.
        self._repo(tmp_path)
        (tmp_path / "s.py").write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        self._git(tmp_path, "add", "s.py")
        (tmp_path / "s.py").unlink()
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 1, (
            f"a staged key whose file was deleted from disk still enters history; "
            f"output:\n{result.stdout}{result.stderr}"
        )

    def test_staged_then_cleaned_on_disk_is_caught(self, tmp_path: Path, monkeypatch) -> None:
        # Classic index/worktree divergence: stage the secret, then tidy the
        # file. The commit carries the secret; the disk copy is innocent.
        self._repo(tmp_path)
        (tmp_path / "c.py").write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        self._git(tmp_path, "add", "c.py")
        (tmp_path / "c.py").write_text("nothing secret here\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 1, (
            f"scan read the clean disk copy instead of the staged blob; "
            f"output:\n{result.stdout}{result.stderr}"
        )

    def test_renamed_file_with_appended_key_is_caught(self, tmp_path: Path, monkeypatch) -> None:
        # --diff-filter=ACM excludes R, so a rename+append returned an EMPTY
        # file list: the hook scanned nothing and reported clean.
        self._repo(tmp_path)
        (tmp_path / "big.txt").write_text("line\n" * 40)
        self._git(tmp_path, "add", "big.txt")
        self._git(tmp_path, "commit", "-qm", "base")
        self._git(tmp_path, "mv", "big.txt", "renamed.txt")
        with (tmp_path / "renamed.txt").open("a") as fh:
            fh.write(f"OPENAI_API_KEY={fake_openai_key()}\n")
        self._git(tmp_path, "add", "renamed.txt")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = " ".join((result.stdout + result.stderr).split())
        assert result.exit_code == 1, (
            f"a renamed file's appended key slipped through; output:\n{out}"
        )
        assert "renamed.txt" in out, (
            f"the finding must name the staged path, not the temp copy; output:\n{out}"
        )


# Characters an attacker can legally put in a filename that a terminal will
# ACT ON: a bidi override reverses displayed text, a line separator can push
# following output onto its own line. Same set the audit-gate suite pins.
_RLO = "\u202e"  # RIGHT-TO-LEFT OVERRIDE (escape, never the literal byte)
_LINE_SEP = "\u2028"  # LINE SEPARATOR (escape, never the literal byte)


class TestStagedFilenameCannotHijackTheTerminal:
    """Cross-cutting: the staged FILENAME is attacker-controlled and printed.

    Two changes combine here, and neither could be tested alone:

    * the pre-commit hook now scans the STAGED SET, so a filename chosen by
      whoever wrote the repo reaches scan's output path (worthless-2kuy);
    * the verdict line now NAMES that file rather than saying ".env".

    So a hostile filename reaches a terminal on every blocked commit. It is
    sanitised — this pins that end to end, on a real repo with a really staged
    file, rather than on a ScanFinding constructed in memory.

    Limitation, stated rather than hidden: this asserts the dangerous
    characters are absent from the output bytes. It does not render the output
    in a terminal emulator and assert the screen is intact — `pyte` is not a
    dependency here. Absence of the control characters is one altitude below
    the real promise.
    """

    def _repo(self, path: Path) -> None:
        import subprocess

        for args in (
            ["init", "-q"],
            ["config", "user.email", "t@t.t"],
            ["config", "user.name", "t"],
        ):
            subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S607

    def test_hostile_staged_filename_is_scrubbed_from_output(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        self._repo(tmp_path)
        hostile = f"{_RLO}evil{_LINE_SEP}app.py"
        (tmp_path / hostile).write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

        import subprocess

        subprocess.run(
            ["git", "-C", str(tmp_path), "add", hostile],  # noqa: S607
            check=True,
            capture_output=True,
        )
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--pre-commit"])
        out = result.stdout + result.stderr

        # Not vacuous: the commit really was blocked and the file really named.
        assert result.exit_code == 1, f"the staged key must still be caught; output:\n{out}"
        # A scrubber that dropped the filename entirely would satisfy a bare
        # absence check, so require the readable parts individually.
        assert "evil" in out, (
            f"the readable stem of the filename must survive scrubbing; output:\n{out}"
        )
        assert "app.py" in out, (
            f"the readable suffix of the filename must survive scrubbing; output:\n{out}"
        )

        for ch, name in ((_RLO, "RIGHT-TO-LEFT OVERRIDE"), (_LINE_SEP, "LINE SEPARATOR")):
            assert ch not in out, (
                f"a staged filename carried {name} into terminal output; a crafted "
                f"repo could rewrite what the user believes they are committing"
            )

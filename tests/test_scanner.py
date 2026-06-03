"""Tests for scanner — file scanning, entropy thresholding, decoy suppression."""

from __future__ import annotations

from pathlib import Path


class TestScanFinding:
    def test_dataclass_fields(self):
        from worthless.cli.scanner import ScanFinding

        f = ScanFinding(
            file="test.env",
            line=1,
            var_name="KEY",
            provider="openai",
            is_protected=False,
            value_preview="sk-****",
        )
        assert f.file == "test.env"
        assert f.line == 1
        assert f.provider == "openai"
        assert f.is_protected is False


class TestScanFiles:
    def test_detects_api_key_in_file(self, tmp_path: Path):
        from worthless.cli.scanner import scan_files

        f = tmp_path / ".env"
        f.write_text("OPENAI_API_KEY=sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2\n")
        findings = scan_files([f])
        assert len(findings) >= 1
        assert findings[0].provider == "openai"

    def test_skips_low_entropy(self, tmp_path: Path):
        from worthless.cli.scanner import scan_files

        f = tmp_path / ".env"
        f.write_text("OPENAI_API_KEY=sk-your-key-here\n")
        findings = scan_files([f])
        assert len(findings) == 0

    def test_decoy_low_entropy_skipped(self, tmp_path: Path):
        """Low-entropy decoys (WRTLS pattern) are filtered by entropy threshold."""
        from worthless.cli.scanner import scan_files

        f = tmp_path / ".env"
        # Decoy with low entropy — repeating WRTLS pattern after prefix
        decoy_value = "sk-proj-a1b2c3d4WRTLSWRTLSWRTLSWRTLSWRTLSWRTLSWRTLSWRTLS"
        f.write_text(f"OPENAI_API_KEY={decoy_value}\n")
        findings = scan_files([f])
        assert len(findings) == 0  # filtered by entropy

    def test_multiple_files(self, tmp_path: Path):
        from worthless.cli.scanner import scan_files

        f1 = tmp_path / "a.env"
        f2 = tmp_path / "b.env"
        f1.write_text("KEY1=sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2\n")
        f2.write_text("KEY2=sk-ant-api03-x9Y8w7V6u5T4s3R2q1P0o9N8m7L6k5J4i3H2g1F0e9\n")
        findings = scan_files([f1, f2])
        assert len(findings) == 2

    def test_non_env_file(self, tmp_path: Path):
        from worthless.cli.scanner import scan_files

        f = tmp_path / "config.py"
        f.write_text('API_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2"\n')
        findings = scan_files([f])
        assert len(findings) >= 1


class TestSarifOutput:
    def test_sarif_format(self, tmp_path: Path):
        from worthless.cli.scanner import ScanFinding, format_sarif

        findings = [
            ScanFinding(
                file="test.env",
                line=1,
                var_name="KEY",
                provider="openai",
                is_protected=False,
                value_preview="sk-****",
            ),
        ]
        sarif = format_sarif(findings, tool_version="0.1.0")
        assert (
            sarif["$schema"]
            == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        )
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1


class TestEnrollmentDataRemoved:
    def test_load_enrollment_data_removed(self):
        """load_enrollment_data was dead code (shard_a is binary, not text) and has been removed."""
        import worthless.cli.scanner as scanner_mod

        assert not hasattr(scanner_mod, "load_enrollment_data")


class TestScanGuards:
    """Hang-guards for scan_files (worthless-c5kc).

    A pre-commit hook calling ``worthless scan`` must NOT silently freeze on
    a huge / slow / unreadable file. The contract these tests pin:
      * oversize file → its prefix is still scanned + flagged ``truncated``
        (so a key padded past the cap is still caught);
      * past-deadline → scanning stops, findings so far are returned, and a
        ``timeout`` skip is recorded (caller's job to fail-closed on it);
      * unreadable file → recorded as ``unreadable`` instead of being silently
        ``except OSError: continue``-d;
      * normal small tree → no skips, behaviour unchanged.
    """

    # A high-entropy key that KEY_PATTERN + entropy threshold both accept.
    REAL_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2"

    def test_oversize_file_prefix_still_scanned_and_flagged_truncated(self, tmp_path: Path):
        from worthless.cli.scanner import SkippedFile, scan_files

        # Put the key in the FIRST 1 KB, then pad past a tiny cap. The prefix
        # read must still yield a finding AND record ``truncated``.
        f = tmp_path / "huge.env"
        f.write_bytes(f"OPENAI_API_KEY={self.REAL_KEY}\n".encode() + b"x" * (8 * 1024))

        skipped: list[SkippedFile] = []
        findings = scan_files([f], max_file_bytes=2048, skipped=skipped)

        assert any(x.provider == "openai" for x in findings), (
            "prefix-scan must still catch a key in the first ``max_file_bytes`` bytes"
        )
        assert [(s.file, s.reason) for s in skipped] == [(str(f), "truncated")]

    def test_past_deadline_returns_partial_and_records_timeout(self, tmp_path: Path):
        import time

        from worthless.cli.scanner import SkippedFile, scan_files

        a = tmp_path / "a.env"
        b = tmp_path / "b.env"
        a.write_text(f"OPENAI_API_KEY={self.REAL_KEY}\n")
        b.write_text(f"ANTHROPIC_API_KEY={self.REAL_KEY}\n")

        # Deadline already in the past — first iteration must short-circuit
        # before reading a.env. ``findings`` is empty, ``skipped`` carries
        # exactly ONE timeout entry (the file that would have been scanned next).
        past = time.monotonic() - 1.0
        skipped: list[SkippedFile] = []
        findings = scan_files([a, b], deadline=past, skipped=skipped)

        assert findings == []
        assert len(skipped) == 1
        assert skipped[0].reason == "timeout"

    def test_partial_findings_when_deadline_hits_mid_loop(self, tmp_path: Path, monkeypatch):
        """First file scanned, deadline trips before second → 1 finding + 1 timeout skip."""
        import worthless.cli.scanner as scanner_mod
        from worthless.cli.scanner import SkippedFile, scan_files

        a = tmp_path / "a.env"
        b = tmp_path / "b.env"
        a.write_text(f"OPENAI_API_KEY={self.REAL_KEY}\n")
        b.write_text(f"ANTHROPIC_API_KEY={self.REAL_KEY}\n")

        # Fake clock: first call (a's deadline check) returns 0.0, every later
        # call returns 100.0 — so b's deadline check trips no matter how many
        # ``time.monotonic()`` calls scanner.py adds in the future (logging,
        # telemetry, etc.). Robust to refactors.
        calls = {"n": 0}

        def fake_monotonic() -> float:
            calls["n"] += 1
            return 0.0 if calls["n"] == 1 else 100.0

        monkeypatch.setattr(scanner_mod.time, "monotonic", fake_monotonic)

        skipped: list[SkippedFile] = []
        findings = scan_files([a, b], deadline=1.0, skipped=skipped)

        assert len(findings) == 1, "first file must have been scanned before deadline trip"
        assert findings[0].file == str(a)
        assert [s.reason for s in skipped] == ["timeout"]
        assert skipped[0].file == str(b)

    def test_nonexistent_file_silently_skipped(self, tmp_path: Path):
        """A path that doesn't exist (typo or git-rm'd in pre-commit) is NOT a
        hang risk — it's just absent. Stays silent so the pre-commit flow over
        deleted files is unchanged."""
        from worthless.cli.scanner import SkippedFile, scan_files

        missing = tmp_path / "does-not-exist.env"
        skipped: list[SkippedFile] = []
        findings = scan_files([missing], skipped=skipped)

        assert findings == []
        assert skipped == []

    def test_directory_path_silently_skipped(self, tmp_path: Path):
        """``worthless scan <dir>`` used to be a silent no-op pre-c5kc. Preserve
        that contract — passing a directory is a user mistake, not a fail-closed
        concern (the user-flow journey at tests/user_flows/test_native_cli_journeys
        relies on this)."""
        from worthless.cli.scanner import SkippedFile, scan_files

        a_dir = tmp_path / "subdir"
        a_dir.mkdir()
        skipped: list[SkippedFile] = []
        findings = scan_files([a_dir], skipped=skipped)

        assert findings == []
        assert skipped == []

    def test_unreadable_existing_file_recorded(self, tmp_path: Path):
        """A regular file the OS refuses to read (here: chmod 000) IS a fail-
        closed concern — we don't know what we missed. Recorded as ``unreadable``."""
        import sys

        from worthless.cli.scanner import SkippedFile, scan_files

        if sys.platform.startswith("win"):
            import pytest

            pytest.skip("chmod-based unreadable test is POSIX-only")

        f = tmp_path / "no-read.env"
        f.write_text(f"OPENAI_API_KEY={self.REAL_KEY}\n")
        f.chmod(0o000)
        try:
            skipped: list[SkippedFile] = []
            findings = scan_files([f], skipped=skipped)
        finally:
            f.chmod(0o600)  # restore so tmp_path teardown can clean up

        assert findings == []
        assert [(s.file, s.reason) for s in skipped] == [(str(f), "unreadable")]

    def test_read_text_capped_rejects_negative_max_bytes(self, tmp_path: Path):
        """A negative ``max_bytes`` would silently read to EOF in Python
        (``fh.read(-1)``), defeating the cap. The helper must reject it loudly
        — fail-closed → fail-open is the very thing this PR fixes."""
        import pytest

        from worthless.cli.scanner import read_text_capped

        f = tmp_path / ".env"
        f.write_text("anything")

        with pytest.raises(ValueError, match="max_bytes must be >= 0"):
            read_text_capped(f, -1)

    def test_normal_small_tree_no_skips(self, tmp_path: Path):
        """Happy path: a small file with a real key returns one finding and no
        skip entries. Pins that the new guards don't regress the common case."""
        from worthless.cli.scanner import SkippedFile, scan_files

        f = tmp_path / ".env"
        f.write_text(f"OPENAI_API_KEY={self.REAL_KEY}\n")

        skipped: list[SkippedFile] = []
        findings = scan_files([f], skipped=skipped)

        assert len(findings) == 1
        assert skipped == [], "a normal small file must not produce any skip entries"


class TestSourceScannerGuards:
    """Same fail-closed guards on ``scan_source_for_hardcoded_provider_urls``
    (called by ``worthless lock``). Carve-out for vanished / directory paths
    must match :func:`scan_files` so ``lock`` doesn't fail-close on benign input.
    """

    def test_vanished_file_silently_skipped(self, tmp_path: Path, monkeypatch):
        """If the walker yields a path that disappears before read, no skip
        entry is recorded — matches scan_files' FileNotFoundError carve-out."""
        from pathlib import Path as _P

        from worthless.cli import scanner as scanner_mod
        from worthless.cli.scanner import (
            SkippedFile,
            scan_source_for_hardcoded_provider_urls,
        )

        ghost = tmp_path / "ghost.py"

        def fake_walk(_root: _P):
            yield ghost  # never created on disk → FileNotFoundError on read

        monkeypatch.setattr(scanner_mod, "_walk_source_files", fake_walk)

        skipped: list[SkippedFile] = []
        findings = scan_source_for_hardcoded_provider_urls(tmp_path, skipped=skipped)

        assert findings == []
        assert skipped == []

    def test_directory_path_silently_skipped(self, tmp_path: Path, monkeypatch):
        """If the walker yields a directory (TOCTOU: file replaced by a dir),
        no fail-close — silent skip, matches scan_files contract."""
        from pathlib import Path as _P

        from worthless.cli import scanner as scanner_mod
        from worthless.cli.scanner import (
            SkippedFile,
            scan_source_for_hardcoded_provider_urls,
        )

        a_dir = tmp_path / "subdir"
        a_dir.mkdir()

        def fake_walk(_root: _P):
            yield a_dir

        monkeypatch.setattr(scanner_mod, "_walk_source_files", fake_walk)

        skipped: list[SkippedFile] = []
        findings = scan_source_for_hardcoded_provider_urls(tmp_path, skipped=skipped)

        assert findings == []
        assert skipped == []

    def test_past_deadline_records_timeout(self, tmp_path: Path, monkeypatch):
        """A past deadline must short-circuit the source scanner before reading
        the next candidate, recording a ``timeout`` skip — the lock-time hang
        guard advertised by c5kc."""
        import time as _time
        from pathlib import Path as _P

        from worthless.cli import scanner as scanner_mod
        from worthless.cli.scanner import (
            SkippedFile,
            scan_source_for_hardcoded_provider_urls,
        )

        srcfile = tmp_path / "anything.py"
        srcfile.write_text("# unused — deadline trips first\n")

        def fake_walk(_root: _P):
            yield srcfile

        monkeypatch.setattr(scanner_mod, "_walk_source_files", fake_walk)
        past = _time.monotonic() - 1.0

        skipped: list[SkippedFile] = []
        findings = scan_source_for_hardcoded_provider_urls(tmp_path, deadline=past, skipped=skipped)

        assert findings == []
        assert [s.reason for s in skipped] == ["timeout"]

    def test_oversize_file_flagged_truncated(self, tmp_path: Path, monkeypatch):
        """An oversize source file is read up to the cap, prefix scanned, and
        flagged ``truncated`` — mirrors the same guarantee on .env scanning."""
        from pathlib import Path as _P

        from worthless.cli import scanner as scanner_mod
        from worthless.cli.scanner import (
            SkippedFile,
            scan_source_for_hardcoded_provider_urls,
        )

        srcfile = tmp_path / "big.py"
        srcfile.write_bytes(b"# nothing to find here\n" + b"x" * 4096)

        def fake_walk(_root: _P):
            yield srcfile

        monkeypatch.setattr(scanner_mod, "_walk_source_files", fake_walk)

        skipped: list[SkippedFile] = []
        findings = scan_source_for_hardcoded_provider_urls(
            tmp_path, max_file_bytes=256, skipped=skipped
        )

        assert findings == []
        assert [(s.file, s.reason) for s in skipped] == [(str(srcfile), "truncated")]


class TestCodeScannerOuterDeadline:
    """The ``--code`` source scanner outer timeout-break: when the deadline
    trips mid-walk, both inner and outer loops must exit cleanly and the
    candidate that would have been scanned next is recorded as ``timeout``."""

    def test_past_deadline_breaks_outer_root_loop(self, tmp_path: Path, monkeypatch):
        import time as _time

        from worthless.cli import code_scanner as cs_mod
        from worthless.cli.scanner import SkippedFile

        # One candidate so we can pin which file the timeout skip names.
        # Use the real bundled registry — mocking ProviderEntry is brittle
        # (its constructor signature is owned by the providers module).
        srcfile = tmp_path / "anything.py"
        srcfile.write_text("# unused — deadline trips first\n")

        monkeypatch.setattr(cs_mod, "_candidate_files", lambda *a, **k: [srcfile])

        skipped: list[SkippedFile] = []
        findings = cs_mod.scan_for_hardcoded_provider_urls(
            [tmp_path], deadline=_time.monotonic() - 1.0, skipped=skipped
        )

        assert findings == []
        assert [s.reason for s in skipped] == ["timeout"]
        assert skipped[0].file == str(srcfile)

    def test_oversize_source_file_truncated_in_one_file(self, tmp_path: Path):
        """``_scan_one_file`` truncated branch: file longer than the cap returns
        no findings (key not in prefix) and records a ``truncated`` skip."""
        from worthless.cli.code_scanner import _scan_one_file
        from worthless.cli.scanner import SkippedFile

        srcfile = tmp_path / "big.py"
        srcfile.write_bytes(b"# header\n" + b"x" * 4096)

        skipped: list[SkippedFile] = []
        findings = _scan_one_file(
            srcfile,
            {"https://example.com": object()},
            max_file_bytes=256,
            skipped=skipped,
        )

        assert findings == []
        assert [(s.file, s.reason) for s in skipped] == [(str(srcfile), "truncated")]


class TestCodeScannerOneFileGuards:
    """Same fail-closed guards on ``code_scanner._scan_one_file`` (the
    ``worthless scan --code`` path). FileNotFoundError must be silent so a
    TOCTOU-vanished file doesn't trip exit 2."""

    def test_vanished_file_silently_skipped(self, tmp_path: Path):
        from worthless.cli.code_scanner import _scan_one_file
        from worthless.cli.scanner import SkippedFile

        ghost = tmp_path / "ghost.py"  # never created
        skipped: list[SkippedFile] = []

        findings = _scan_one_file(ghost, {}, skipped=skipped)

        assert findings == []
        assert skipped == []

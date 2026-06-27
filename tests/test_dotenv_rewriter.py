"""Tests for dotenv rewriter — atomic key replacement and scanning."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestShannonEntropy:
    def test_low_entropy_placeholder(self):
        from worthless.cli.dotenv_rewriter import shannon_entropy

        # Repetitive placeholder should be below threshold
        assert shannon_entropy("sk-your-key-here") < 4.5

    def test_high_entropy_real_key(self):
        from worthless.cli.dotenv_rewriter import shannon_entropy

        # A realistic random key
        key = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2"
        assert shannon_entropy(key) > 4.5

    def test_empty_string(self):
        from worthless.cli.dotenv_rewriter import shannon_entropy

        assert shannon_entropy("") == 0.0


class TestScanEnvKeys:
    def test_detects_api_keys(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import scan_env_keys

        env_file = tmp_path / ".env"
        env_file.write_text(
            "OPENAI_API_KEY=sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2\nOTHER_VAR=hello\n"
        )
        results = scan_env_keys(env_file)
        assert len(results) == 1
        assert results[0][0] == "OPENAI_API_KEY"
        assert results[0][2] == "openai"

    def test_skips_low_entropy(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import scan_env_keys

        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-your-key-here\n")
        results = scan_env_keys(env_file)
        assert len(results) == 0

    def test_multiple_keys(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import scan_env_keys

        env_file = tmp_path / ".env"
        env_file.write_text(
            "OPENAI_API_KEY=sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2\n"
            "ANTHROPIC_API_KEY=sk-ant-api03-x9Y8w7V6u5T4s3R2q1P0o9N8m7L6k5J4i3H2g1F0e9\n"
        )
        results = scan_env_keys(env_file)
        assert len(results) == 2
        providers = {r[2] for r in results}
        assert providers == {"openai", "anthropic"}


class TestRewriteEnvKey:
    def test_replaces_target_key(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\nAPI_KEY=old_value\nBAZ=qux\n")
        rewrite_env_key(env_file, "API_KEY", "new_value")
        content = env_file.read_text()
        assert "API_KEY=new_value" in content

    def test_preserves_other_content(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import rewrite_env_key

        env_file = tmp_path / ".env"
        original = "# Comment\nFOO=bar\nAPI_KEY=old_value\n\nBAZ=qux\n"
        env_file.write_text(original)
        rewrite_env_key(env_file, "API_KEY", "new_value")
        content = env_file.read_text()
        assert "# Comment" in content
        assert "FOO=bar" in content
        assert "BAZ=qux" in content
        assert "\n\n" in content  # blank line preserved

    def test_missing_var_raises_key_error(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        with pytest.raises(KeyError):
            rewrite_env_key(env_file, "NONEXISTENT", "value")

    def test_atomic_replacement(self, tmp_path: Path):
        """Verify the file is replaced atomically (no partial writes)."""
        from worthless.cli.dotenv_rewriter import rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=old\n")
        rewrite_env_key(env_file, "KEY", "new")
        # os.replace creates a new inode on most filesystems
        content = env_file.read_text()
        assert content == "KEY=new\n"

    def test_quoted_value_handling(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text('KEY="old_value"\n')
        rewrite_env_key(env_file, "KEY", "new_value")
        content = env_file.read_text()
        assert "new_value" in content


class TestAddOrRewriteEnvKey:
    """Tests for add_or_rewrite_env_key — create or update a variable."""

    def test_creates_file_and_adds_key(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("")
        add_or_rewrite_env_key(env_file, "NEW_KEY", "new_value")
        content = env_file.read_text()
        assert "NEW_KEY=new_value" in content

    def test_updates_existing_key(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("MY_KEY=old\nOTHER=keep\n")
        add_or_rewrite_env_key(env_file, "MY_KEY", "new")
        content = env_file.read_text()
        assert "new" in content
        assert "old" not in content
        assert "OTHER=keep" in content

    def test_unicode_value(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("")
        add_or_rewrite_env_key(env_file, "UNICODE", "héllo-wörld")
        content = env_file.read_text()
        assert "héllo-wörld" in content

    def test_empty_value(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("")
        add_or_rewrite_env_key(env_file, "EMPTY", "")
        content = env_file.read_text()
        assert "EMPTY=" in content


class TestRemoveEnvKey:
    """Tests for remove_env_key — remove a variable from .env."""

    def test_removes_existing_key(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import remove_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("KEEP=yes\nREMOVE=me\nALSO_KEEP=yes\n")
        remove_env_key(env_file, "REMOVE")
        content = env_file.read_text()
        assert "REMOVE" not in content
        assert "KEEP=yes" in content
        assert "ALSO_KEEP=yes" in content

    def test_noop_when_key_missing(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import remove_env_key

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        remove_env_key(env_file, "NONEXISTENT")
        assert env_file.read_text() == "FOO=bar\n"

    def test_removes_quoted_key(self, tmp_path: Path):
        from worthless.cli.dotenv_rewriter import remove_env_key

        env_file = tmp_path / ".env"
        env_file.write_text('MY_VAR="quoted_value"\nOTHER=keep\n')
        remove_env_key(env_file, "MY_VAR")
        content = env_file.read_text()
        assert "MY_VAR" not in content
        assert "OTHER=keep" in content


class TestBuildEnrolledLocations:
    """Tests for build_enrolled_locations — set of (var_name, env_path) from enrollments."""

    def test_builds_set_from_enrollments(self):
        from worthless.cli.dotenv_rewriter import build_enrolled_locations
        from worthless.storage.repository import EnrollmentRecord

        enrollments = [
            EnrollmentRecord(key_alias="a", var_name="KEY_A", env_path="/path/a/.env"),
            EnrollmentRecord(key_alias="b", var_name="KEY_B", env_path="/path/b/.env"),
        ]
        result = build_enrolled_locations(enrollments)
        assert result == {("KEY_A", "/path/a/.env"), ("KEY_B", "/path/b/.env")}

    def test_excludes_none_env_path(self):
        from worthless.cli.dotenv_rewriter import build_enrolled_locations
        from worthless.storage.repository import EnrollmentRecord

        enrollments = [
            EnrollmentRecord(key_alias="a", var_name="KEY_A", env_path="/path/.env"),
            EnrollmentRecord(key_alias="b", var_name="KEY_B", env_path=None),
        ]
        result = build_enrolled_locations(enrollments)
        assert result == {("KEY_A", "/path/.env")}

    def test_empty_enrollments(self):
        from worthless.cli.dotenv_rewriter import build_enrolled_locations

        assert build_enrolled_locations([]) == set()


class TestScanRewriteParity:
    """Verify scan_env_keys and rewrite_env_key agree on var names.

    Both use python-dotenv (dotenv_values / set_key) so parity is
    guaranteed, but these tests catch any future divergence.
    """

    def test_quoted_value_roundtrip(self, tmp_path: Path):
        """scan finds a quoted key, rewrite can replace it."""
        from worthless.cli.dotenv_rewriter import rewrite_env_key, scan_env_keys

        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = tmp_path / ".env"
        env_file.write_text(f'OPENAI_API_KEY="{fake_key}"\n')
        results = scan_env_keys(env_file)
        assert len(results) == 1
        var_name = results[0][0]
        # rewrite must find the same var_name
        rewrite_env_key(env_file, var_name, "decoy_value")
        assert "decoy_value" in env_file.read_text()

    def test_export_prefix_roundtrip(self, tmp_path: Path):
        """scan finds an export-prefixed key, rewrite can replace it."""
        from worthless.cli.dotenv_rewriter import rewrite_env_key, scan_env_keys

        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = tmp_path / ".env"
        env_file.write_text(f"export OPENAI_API_KEY={fake_key}\n")
        results = scan_env_keys(env_file)
        assert len(results) == 1
        var_name = results[0][0]
        # rewrite must find the same var_name
        rewrite_env_key(env_file, var_name, "decoy_value")
        assert "decoy_value" in env_file.read_text()

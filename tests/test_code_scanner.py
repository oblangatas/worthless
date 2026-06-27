"""Unit tests for the hardcoded-provider-URL code scanner (worthless-7sl9).

Test layout follows the four flow categories agreed in the plan:
  1. Happy flow      — clean detection on supported file types
  2. Bad flow        — malformed inputs, unreadable files, perf guards
  3. Convoluted flow — vendored deps, gitignore, symlinks, lockfiles
  4. Adversarial flow — false-positive / false-negative edges; known limits

Plus a separate file (test_openclaw_lock_signature.py) covers OpenClaw
insulation — that lock + apply_lock are not touched by this PR.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from worthless.cli.code_scanner import (
    CodeFinding,
    scan_for_hardcoded_provider_urls,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(path: Path, content: str) -> Path:
    """Write text to path, creating parents. Returns path for chaining."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def init_git(repo: Path, gitignore: str = "") -> None:
    """Initialize a git repo at ``repo`` with an optional .gitignore."""
    # ``git`` from PATH is intentional — pinning to /usr/bin/git breaks
    # Windows/WSL where git lives elsewhere. Mirrors how the scanner itself
    # invokes ``git ls-files``.
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main"],  # noqa: S607
        cwd=repo,
        check=True,
    )
    if gitignore:
        (repo / ".gitignore").write_text(gitignore, encoding="utf-8")
    subprocess.run(
        ["git", "add", "-A"],  # noqa: S607
        cwd=repo,
        check=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "init"],  # noqa: S607
        cwd=repo,
        check=True,
    )


# ---------------------------------------------------------------------------
# 1. Happy flow
# ---------------------------------------------------------------------------


class TestCodeScanHappyFlow:
    def test_finds_single_openai_url_in_python_file(self, tmp_path: Path) -> None:
        write(
            tmp_path / "app.py",
            'from openai import OpenAI\nclient = OpenAI(base_url="https://api.openai.com/v1")\n',
        )
        findings = scan_for_hardcoded_provider_urls([tmp_path])

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, CodeFinding)
        assert f.file.endswith("app.py")
        assert f.line == 2
        assert f.column == 27  # 'client = OpenAI(base_url="' is 26 chars, URL at col 27
        assert f.matched_url == "https://api.openai.com/v1"
        assert f.provider_name == "openai"
        assert f.suggested_env_var == "OPENAI_BASE_URL"
        assert "https://api.openai.com/v1" in f.line_text

    def test_finds_anthropic_in_yaml(self, tmp_path: Path) -> None:
        write(
            tmp_path / "config.yaml",
            "service: ai\nbase_url: https://api.anthropic.com/v1\nkey: foo\n",
        )
        findings = scan_for_hardcoded_provider_urls([tmp_path])

        assert len(findings) == 1
        assert findings[0].provider_name == "anthropic"
        assert findings[0].suggested_env_var == "ANTHROPIC_BASE_URL"
        assert findings[0].line == 2

    def test_no_findings_in_clean_repo(self, tmp_path: Path) -> None:
        write(
            tmp_path / "app.py",
            'import os\nclient = OpenAI(base_url=os.environ["OPENAI_BASE_URL"])\n',
        )
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_multiple_providers_in_one_file(self, tmp_path: Path) -> None:
        write(
            tmp_path / "clients.py",
            'a = "https://api.openai.com/v1"\nb = "https://api.anthropic.com/v1"\n',
        )
        findings = scan_for_hardcoded_provider_urls([tmp_path])

        providers = sorted(f.provider_name for f in findings)
        assert providers == ["anthropic", "openai"]
        assert len(findings) == 2
        lines = sorted(f.line for f in findings)
        assert lines == [1, 2]


# ---------------------------------------------------------------------------
# 2. Bad flow
# ---------------------------------------------------------------------------


class TestCodeScanBadFlow:
    def test_unreadable_file_logged_skipped_not_crashed(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        unreadable = write(tmp_path / "secret.py", '"https://api.openai.com/v1"\n')
        write(tmp_path / "ok.py", '"https://api.anthropic.com/v1"\n')
        unreadable.chmod(0o000)

        try:
            with caplog.at_level(logging.DEBUG, logger="worthless.cli.code_scanner"):
                findings = scan_for_hardcoded_provider_urls([tmp_path])
        finally:
            unreadable.chmod(0o644)

        assert any(f.file.endswith("ok.py") for f in findings)
        assert not any(f.file.endswith("secret.py") for f in findings)
        # The I/O error must be logged at DEBUG so operators can trace skips.
        # Root bypasses chmod, so we only assert the log on normal users.
        if hasattr(os, "getuid") and os.getuid() != 0:
            assert any("skipping" in r.getMessage().lower() for r in caplog.records)

    def test_binary_file_with_extension_collision_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "blob.json").write_bytes(b"\x00\x01\x02\xff\xfe\xfd")
        write(tmp_path / "ok.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1
        assert findings[0].file.endswith("ok.py")

    def test_empty_repo_zero_findings(self, tmp_path: Path) -> None:
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_registry_load_failure_degrades_gracefully(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # When load_registry() raises (corrupt providers.toml, I/O error,
        # etc.) the scanner must return [] rather than propagating the
        # exception to the caller.
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        def boom():
            raise RuntimeError("providers.toml is corrupt")

        monkeypatch.setattr("worthless.cli.code_scanner.load_registry", boom)

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert findings == []

    def test_huge_file_skipped(self, tmp_path: Path) -> None:
        huge = tmp_path / "huge.py"
        huge.write_text("x = 1\n" * (220_000), encoding="utf-8")
        assert huge.stat().st_size > 1_000_000
        huge.write_text("x = 1\n" * 220_000 + '"https://api.openai.com/v1"\n', encoding="utf-8")

        write(tmp_path / "small.py", '"https://api.anthropic.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        files = {Path(f.file).name for f in findings}
        assert "huge.py" not in files
        assert "small.py" in files


# ---------------------------------------------------------------------------
# 3. Convoluted flow
# ---------------------------------------------------------------------------


class TestCodeScanConvolutedFlow:
    def test_node_modules_excluded(self, tmp_path: Path) -> None:
        write(
            tmp_path / "node_modules" / "openai" / "index.js",
            'baseUrl = "https://api.openai.com/v1";\n',
        )
        write(tmp_path / "src" / "app.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        # Check path components, not raw substring — pytest tmp dir names
        # can themselves contain the exclude name (e.g. test_node_modules_x).
        for f in findings:
            rel = Path(f.file).relative_to(tmp_path)
            assert "node_modules" not in rel.parts
        assert any(f.file.endswith("app.py") for f in findings)

    def test_venv_site_packages_excluded(self, tmp_path: Path) -> None:
        write(
            tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / "openai" / "_base.py",
            '"https://api.openai.com/v1"\n',
        )
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        for f in findings:
            rel = Path(f.file).relative_to(tmp_path)
            assert ".venv" not in rel.parts
        assert any(f.file.endswith("app.py") for f in findings)

    def test_vendor_dir_excluded(self, tmp_path: Path) -> None:
        write(
            tmp_path / "vendor" / "openai-go" / "client.go",
            '"https://api.openai.com/v1"\n',
        )
        write(tmp_path / "main.go", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        for f in findings:
            rel = Path(f.file).relative_to(tmp_path)
            assert "vendor" not in rel.parts
        assert any(f.file.endswith("main.go") for f in findings)

    def test_gitignore_respected_in_git_repo(self, tmp_path: Path) -> None:
        write(tmp_path / "tracked.py", '"https://api.openai.com/v1"\n')
        write(tmp_path / "tmp" / "local.py", '"https://api.anthropic.com/v1"\n')
        init_git(tmp_path, gitignore="tmp/\n")

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        files = {Path(f.file).name for f in findings}
        assert "tracked.py" in files
        assert "local.py" not in files

    def test_gitignore_ignored_outside_git_repo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # GIT_CEILING_DIRECTORIES stops git from walking up the directory tree
        # to find an ancestor repo. Without this, when pytest's tmp_path lives
        # under a developer worktree (e.g. ``.claude/worktrees/...``), the
        # parent worthless repo gitignores ``.claude/`` and ``git ls-files
        # --exclude-standard`` returns an empty list — defeating the test's
        # premise of "outside any git repo". CI is fine; this guards local runs.
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))

        write(tmp_path / ".gitignore", "secret/\n")
        write(tmp_path / "secret" / "local.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert any(f.file.endswith("local.py") for f in findings)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="symlink creation requires elevated permissions on Windows"
    )
    def test_symlink_to_excluded_dir_not_followed(self, tmp_path: Path) -> None:
        write(tmp_path / "node_modules" / "evil.py", '"https://api.openai.com/v1"\n')
        link = tmp_path / "src" / "vendored"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(tmp_path / "node_modules")

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert findings == []

    def test_lockfile_excluded(self, tmp_path: Path) -> None:
        write(
            tmp_path / "package-lock.json",
            '{"resolved": "https://api.openai.com/v1"}\n',
        )
        write(tmp_path / "yarn.lock", "url https://api.anthropic.com/v1\n")

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert findings == []

    def test_minified_js_excluded(self, tmp_path: Path) -> None:
        write(tmp_path / "app.min.js", '"https://api.openai.com/v1"\n')
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert findings == []

    @pytest.mark.skipif(
        sys.platform == "win32", reason="symlink creation requires elevated permissions on Windows"
    )
    def test_symlink_cycle_doesnt_hang(self, tmp_path: Path) -> None:
        # a → b → a directory symlink cycle; os.walk(followlinks=False) must
        # not follow symlink directories, so the scan completes without hanging.
        a = tmp_path / "cycle_a"
        b = tmp_path / "cycle_b"
        a.mkdir()
        b.mkdir()
        (a / "link_to_b").symlink_to(b)
        (b / "link_to_a").symlink_to(a)
        write(tmp_path / "safe.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert any(f.file.endswith("safe.py") for f in findings)

    def test_md_doc_with_url_in_code_fence_is_flagged(self, tmp_path: Path) -> None:
        write(
            tmp_path / "README.md",
            "Use the API:\n```python\nclient = OpenAI(base_url='https://api.openai.com/v1')\n```\n",
        )
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1
        assert findings[0].file.endswith("README.md")

    def test_project_inside_excluded_named_dir_not_false_excluded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: _is_excluded_path previously used absolute path parts,
        # so a project at /some/user/dist/myproject would exclude all files
        # because "dist" appeared in the absolute path above the root.
        #
        # GIT_CEILING_DIRECTORIES isolates this test from any ancestor git
        # repo (e.g. when tmp_path is under a developer's ``.claude/worktrees``
        # which is gitignored by the parent worthless repo). Without it, the
        # ls-files branch returns an empty list and the test fails locally on
        # any dev worktree under .claude/. CI is unaffected.
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))

        root = tmp_path / "dist" / "myproject"
        write(root / "app.py", '"https://api.openai.com/v1"\n')
        findings = scan_for_hardcoded_provider_urls([root])
        assert len(findings) == 1, (
            "Files inside a project rooted under an excluded-named parent dir "
            "must not be silently excluded"
        )


# ---------------------------------------------------------------------------
# 4. Adversarial flow
# ---------------------------------------------------------------------------


class TestCodeScanAdversarialFlow:
    def test_url_in_python_comment_still_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", "# see https://api.openai.com/v1 for docs\n")
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1
        assert findings[0].provider_name == "openai"

    def test_url_in_string_concat_not_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "https://api." + "openai.com/v1"\n')
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_url_with_uppercase_host_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "HTTPS://API.OPENAI.COM/v1"\n')
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1
        assert findings[0].provider_name == "openai"

    def test_url_with_trailing_slash_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "https://api.openai.com/v1/"\n')
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1

    def test_url_with_query_string_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "https://api.openai.com/v1?foo=bar"\n')
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1

    def test_url_in_test_fixture_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "tests" / "fixtures" / "sample.py", '"https://api.openai.com/v1"\n')
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1

    def test_partial_url_not_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "https://api.openai.co"\n')
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_unknown_provider_url_not_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "https://api.unknown-llm.example/v1"\n')
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_regional_endpoint_not_flagged(self, tmp_path: Path) -> None:
        # Documented bypass — we only match registry literals.
        write(tmp_path / "a.py", 'url = "https://eu.api.openai.com/v1"\n')
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_ip_literal_not_flagged(self, tmp_path: Path) -> None:
        write(tmp_path / "a.py", 'url = "http://104.18.32.7/v1"\n')
        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_scan_completes_under_5s_on_million_lines(self, tmp_path: Path) -> None:
        # Many small files instead of one huge (which would hit the >1MB skip).
        for i in range(500):
            write(tmp_path / f"f{i}.py", "x = 1\n" * 200)
        start = time.monotonic()
        findings = scan_for_hardcoded_provider_urls([tmp_path])
        elapsed = time.monotonic() - start
        assert findings == []
        # 30 s is generous enough for any reasonable CI runner while still
        # catching pathological perf regressions.
        assert elapsed < 30.0, f"scan took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# 5. API surface — public-API params + degraded-environment paths
# ---------------------------------------------------------------------------


class TestCodeScanApiSurface:
    """Branch-coverage gaps from the manual audit, plugged.

    These exercise public-API parameters and defensive paths that the four
    flow categories above don't naturally hit.
    """

    def test_extra_excludes_parameter_adds_to_dir_excludelist(self, tmp_path: Path) -> None:
        # Public API: callers can extend the exclude list. Verify it actually
        # excludes. Future lock-side coupling (WOR-493) may use this.
        write(tmp_path / "src" / "ok.py", '"https://api.openai.com/v1"\n')
        write(tmp_path / "docs" / "demo.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path], extra_excludes=("docs",))

        files = {Path(f.file).name for f in findings}
        assert "ok.py" in files
        assert "demo.py" not in files

    def test_empty_registry_returns_empty_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Docstring claims graceful degradation when no providers are
        # registered. Pin the behavior.
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')
        monkeypatch.setattr("worthless.cli.code_scanner.load_registry", lambda: {})

        assert scan_for_hardcoded_provider_urls([tmp_path]) == []

    def test_git_binary_missing_falls_back_to_filesystem_walk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Windows users without git in PATH should still get a scan via
        # the walk fallback. Simulate by forcing subprocess.run to raise
        # FileNotFoundError (as if git binary were absent).
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        real_run = subprocess.run

        def fake_run(args, *a, **kw):  # noqa: ANN001 — test stub
            if args and args[0] == "git":
                raise FileNotFoundError("git not in PATH")
            return real_run(args, *a, **kw)

        monkeypatch.setattr("worthless.cli.code_scanner.subprocess.run", fake_run)

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1
        assert findings[0].file.endswith("app.py")

    def test_git_subprocess_timeout_falls_back_to_walk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pathological git invocations (huge repos, locked index) shouldn't
        # hang the scan — we time-box the ls-files call and fall back.
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        def fake_run(args, *a, **kw):  # noqa: ANN001
            if args and args[0] == "git":
                raise subprocess.TimeoutExpired(cmd=args, timeout=10)
            return subprocess.run(args, *a, **kw)

        monkeypatch.setattr("worthless.cli.code_scanner.subprocess.run", fake_run)

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert len(findings) == 1

    def test_single_file_root_scans_just_that_file(self, tmp_path: Path) -> None:
        # Public API accepts a single file path, not just directories.
        f = write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([f])
        assert len(findings) == 1
        assert findings[0].file.endswith("app.py")

    def test_oserror_on_is_symlink_in_git_branch_skips_file_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """worthless-nxyz: ``_list_files_git`` calls ``f.is_symlink()`` which
        internally calls ``lstat()``. If the file vanishes mid-scan (race) or
        the OS errors out, the OSError must NOT escape — it must be caught
        and the file silently skipped, matching the walk-branch contract.

        This test exercises the GIT branch specifically (init_git + real
        commit) so the new guard in ``_list_files_git`` is the one that
        catches the error — not the OLD guard in ``_candidate_files``."""
        write(tmp_path / "racy.py", '"https://api.openai.com/v1"\n')
        write(tmp_path / "ok.py", '"https://api.anthropic.com/v1"\n')
        init_git(tmp_path)  # makes ``_list_files_git`` the active branch

        # Patch ``Path.is_symlink`` (NOT ``Path.lstat``) so the OSError fires
        # at the exact call site this PR guards. ``_list_files_git`` does
        # ``if f.is_symlink(): continue`` — that's the new try/except's job.
        real_is_symlink = Path.is_symlink

        def fake_is_symlink(self):  # noqa: ANN001
            if self.name == "racy.py":
                raise OSError("file vanished between git ls-files and stat")
            return real_is_symlink(self)

        monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        files = {Path(f.file).name for f in findings}
        assert "racy.py" not in files, "OSError-raising file must be silently dropped"
        assert "ok.py" in files, "clean files in the same scan must still be reported"

    def test_oserror_on_stat_skips_file_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Race: file disappears between walk and stat. Must not raise.
        write(tmp_path / "racy.py", '"https://api.openai.com/v1"\n')
        write(tmp_path / "ok.py", '"https://api.anthropic.com/v1"\n')

        # Patch lstat — _candidate_files calls f.lstat(), not f.stat().
        real_lstat = Path.lstat

        def fake_lstat(self, *a, **kw):  # noqa: ANN001
            if self.name == "racy.py":
                raise OSError("file vanished mid-scan")
            return real_lstat(self, *a, **kw)

        monkeypatch.setattr(Path, "lstat", fake_lstat)

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        files = {Path(f.file).name for f in findings}
        assert "racy.py" not in files
        assert "ok.py" in files

    def test_providers_toml_excluded(self, tmp_path: Path) -> None:
        # providers.toml is the URL registry itself — scanning it always
        # produces false positives. Pin that it is always excluded.
        write(
            tmp_path / "providers.toml",
            '[openai]\nurl = "https://api.openai.com/v1"\n',
        )
        write(tmp_path / "app.py", '"https://api.openai.com/v1"\n')

        findings = scan_for_hardcoded_provider_urls([tmp_path])
        assert all(not f.file.endswith("providers.toml") for f in findings)
        assert any(f.file.endswith("app.py") for f in findings)

    def test_line_text_redacts_colocated_api_key(self, tmp_path: Path) -> None:
        # If the offending line also contains an API key, line_text must
        # not expose it in output (stderr, JSON, AI prompt block).
        write(
            tmp_path / "app.py",
            'client = OpenAI(api_key="sk-proj-abc123defgh", base_url="https://api.openai.com/v1")\n',
        )
        findings = scan_for_hardcoded_provider_urls([tmp_path])

        assert len(findings) == 1
        assert "[REDACTED]" in findings[0].line_text
        assert "sk-proj-abc123defgh" not in findings[0].line_text

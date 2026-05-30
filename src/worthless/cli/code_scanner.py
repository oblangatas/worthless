"""Hardcoded-provider-URL code scanner (worthless-7sl9).

Detects literal LLM provider base URLs (drawn from ``providers.toml``)
embedded in project source. The scan is opt-in via ``worthless scan
--code`` and is warn-only — it never fails the command. The CLI emits
a copy-pasteable AI-agent prompt block so the user can hand the fix
to whatever agent they already have running (Claude Code, Cursor, etc.).

Lock-side coupling is explicitly deferred (WOR-493 / worthless-8a5d).

Output surfaces:
- text (default) — human-readable; AI prompt block appended when findings exist
- json (``--json``) — adds top-level ``code_findings`` array
- sarif (``--format sarif``) — **omits code findings by design**; SARIF
  output remains the .env-key surface only. Adding a hardcoded-provider-url
  SARIF rule is an additive future change, not a current gap.
"""

from __future__ import annotations

import logging
import os
import stat as _stat
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Iterable

from worthless.cli.key_patterns import KEY_PATTERN
from worthless.cli.providers import ProviderEntry, load_registry
from worthless.cli.scanner import SkippedFile, read_text_capped

logger = logging.getLogger(__name__)

# File-type allowlist. Anything outside this set is skipped — most user
# repos contain build artifacts, binaries, and locale files that would
# otherwise produce noise.
_SCANNED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".kt",
        ".swift",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".md",
    }
)

# Directory names anywhere in the path → exclude.
_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",  # Rust
        "site-packages",
        ".next",
        ".nuxt",
    }
)

# File suffixes that get skipped even when the extension is allowed.
_EXCLUDED_FILE_SUFFIXES: tuple[str, ...] = (
    ".min.js",
    ".min.css",
    ".lock",
    ".lockfile",
)

_EXCLUDED_FILE_BASENAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
        "providers.toml",  # source-of-truth registry — scanning it is always a false positive
    }
)

# Cap bytes read per file. Files larger than this are scanned up to the cap
# (their prefix) and reported via the ``skipped`` list as ``truncated`` — never
# silently dropped. The cap bounds worst-case read time on generated/vendored
# bundles while still catching a URL pasted into the first MB.
#
# Smaller than scanner.MAX_SCAN_FILE_BYTES (5 MB) intentionally — source files
# don't need 5 MB of headroom and the tighter cap keeps ``scan --code`` fast
# on large repos. The two constants are independent on purpose.
_MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class CodeFinding:
    """A single hardcoded provider URL detected in project source.

    All positions are 1-indexed (line + column) to match how editors
    display them.
    """

    file: str
    line: int
    column: int
    matched_url: str
    provider_name: str
    suggested_env_var: str
    line_text: str


def _is_excluded_path(path: Path, excluded_dirs: frozenset[str]) -> bool:
    """True if any path component is in the directory excludelist or the
    basename matches an excluded file pattern."""
    name = path.name
    return (
        not excluded_dirs.isdisjoint(path.parts)
        or name in _EXCLUDED_FILE_BASENAMES
        or name.endswith(_EXCLUDED_FILE_SUFFIXES)
    )


def _list_files_git(root: Path) -> list[Path] | None:
    """Return tracked + untracked-but-not-ignored files via ``git ls-files``.

    Returns ``None`` if ``root`` is not inside a git working tree (caller
    falls back to a filesystem walk).
    """
    try:
        # ``git`` from PATH is intentional — pinning to /usr/bin/git breaks
        # Windows/WSL (the target-user happy path per project_target_users).
        result = subprocess.run(  # nosec B603,B607
            [  # noqa: S607
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            capture_output=True,
            text=False,  # bytes; -z gives NUL-delimited output → handles non-ASCII filenames
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            f = root / os.fsdecode(raw)
        except (UnicodeDecodeError, ValueError):
            logger.debug("code_scanner: skipping non-decodable git path %r", raw)
            continue
        if f.is_symlink():
            continue
        files.append(f)
    return files


def _list_files_walk(root: Path, excluded_dirs: frozenset[str] = _EXCLUDED_DIRS) -> list[Path]:
    """Recursive filesystem walk that does not follow symlinks and prunes
    excluded directories in-place."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # In-place mutation prunes the descent — must be a list assignment.
        dirnames[:] = [d for d in dirnames if d not in excluded_dirs]
        files.extend(Path(dirpath) / name for name in filenames)
    return files


def _candidate_files(root: Path, excluded_dirs: frozenset[str] = _EXCLUDED_DIRS) -> list[Path]:
    """All files under ``root`` that should be scanned. Honors .gitignore
    when ``root`` is a git working tree."""
    if not root.exists():
        return []

    git_files = _list_files_git(root) if root.is_dir() else None
    files = (
        git_files
        if git_files is not None
        else (_list_files_walk(root, excluded_dirs) if root.is_dir() else [root])
    )

    candidates: list[Path] = []
    for f in files:
        # Cheap path-based checks first (no syscall), then a single stat(2)
        # that covers both the is-regular-file and size guard. OSError on
        # any of these means the file vanished or is unreadable — skip it.
        try:
            # Use the path *relative* to root so parent directories above the
            # scan root (e.g. /home/user/dist/myproject → "dist" in root's
            # ancestors) don't incorrectly match the excludelist.
            f_rel = f.relative_to(root)
            if _is_excluded_path(f_rel, excluded_dirs):
                continue
            if f.suffix.lower() not in _SCANNED_EXTENSIONS:
                continue
            # lstat: skip symlinks in walk-mode without following them.
            st = f.lstat()
            if not _stat.S_ISREG(st.st_mode):
                continue
            # NOTE: oversize files are NOT pre-filtered here — they're handled
            # in :func:`_scan_one_file` via the bounded read so the caller sees
            # a ``truncated`` skip entry instead of a silent drop.
        except (OSError, ValueError):
            continue
        candidates.append(f)
    return candidates


def _scan_one_file(
    path: Path,
    registry_lower: dict[str, ProviderEntry],
    *,
    max_file_bytes: int | None = None,
    skipped: list[SkippedFile] | None = None,
) -> list[CodeFinding]:
    """Return findings for a single file.

    Reads up to *max_file_bytes* via :func:`read_text_capped`. Oversize files
    contribute a ``truncated`` entry to *skipped* (the prefix is still scanned).
    Unreadable / undecodable files contribute an ``unreadable`` entry. Nothing
    is silently dropped.
    """
    cap = _MAX_FILE_BYTES if max_file_bytes is None else max_file_bytes
    try:
        text, truncated = read_text_capped(path, cap)
    except FileNotFoundError:
        # Vanished between candidate enumeration and the read — silent skip,
        # matches :func:`worthless.cli.scanner.scan_files` carve-out.
        logger.debug("code_scanner: skipping vanished %s", path)
        return []
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("code_scanner: skipping %s (%s)", path, exc)
        if skipped is not None:
            skipped.append(SkippedFile(file=str(path), reason="unreadable"))
        return []
    if truncated and skipped is not None:
        skipped.append(SkippedFile(file=str(path), reason="truncated"))

    text_lower = text.casefold()
    if not any(url in text_lower for url in registry_lower):
        return []

    findings: list[CodeFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line_lower = line.casefold()
        for url_lower, entry in registry_lower.items():
            idx = line_lower.find(url_lower)
            if idx < 0:
                continue
            findings.append(
                CodeFinding(
                    file=str(path),
                    line=lineno,
                    column=idx + 1,
                    matched_url=entry.url,
                    provider_name=entry.name,
                    suggested_env_var=f"{entry.name.upper()}_BASE_URL",
                    # KEY_PATTERN covers OpenAI/Anthropic/Google/xAI prefixes;
                    # keys from other providers (AWS, GitHub, HF, Groq) appear
                    # unredacted. Known gap — not a security boundary.
                    line_text=KEY_PATTERN.sub("[REDACTED]", line),
                )
            )
    return findings


def scan_for_hardcoded_provider_urls(
    roots: Iterable[Path],
    *,
    extra_excludes: Iterable[str] = (),
    max_file_bytes: int | None = None,
    deadline: float | None = None,
    skipped: list[SkippedFile] | None = None,
) -> list[CodeFinding]:
    """Scan one or more roots for hardcoded provider base URLs.

    Each entry in ``providers.toml`` (via ``load_registry()``) becomes a
    case-insensitive substring matcher applied line-by-line to every
    candidate source file under each root.

    Args:
        roots: directories (or single files) to scan.
        extra_excludes: directory names to add to the built-in excludelist.
        max_file_bytes: cap bytes read per file (default ~1 MB). Larger files
            scan their prefix and contribute a ``truncated`` skip entry.
        deadline: a ``time.monotonic()`` value. Once passed, scanning stops
            and returns findings gathered so far, recording a ``timeout``
            entry in *skipped*. Keeps an oversized tree from wedging.
        skipped: collector for files that couldn't be fully scanned. Caller
            should surface this to the user — never silently drop.

    Returns:
        Findings in (file, line) order across all roots. Empty when no
        provider registry is configured or no candidates match.
    """
    try:
        registry = load_registry()
    except Exception as exc:
        logger.warning(
            "code_scanner: failed to load provider registry (%s); skipping code scan", exc
        )
        return []
    if not registry:
        return []

    # registry maps url → ProviderEntry. Index by case-folded url for
    # case-insensitive matching while preserving the canonical entry.
    registry_lower: dict[str, ProviderEntry] = {
        url.casefold(): entry for url, entry in registry.items()
    }

    # extra_excludes flows into the dir excludelist for this call only.
    extras = frozenset(extra_excludes)
    excluded_dirs = _EXCLUDED_DIRS | extras

    findings: list[CodeFinding] = []
    for root in roots:
        # Resolve to absolute so part-based exclude checks are stable.
        root_path = Path(root).resolve()
        for candidate in _candidate_files(root_path, excluded_dirs):
            if deadline is not None and time.monotonic() > deadline:
                if skipped is not None:
                    skipped.append(SkippedFile(file=str(candidate), reason="timeout"))
                # Outer loop will see the same deadline and break too.
                break
            findings.extend(
                _scan_one_file(
                    candidate,
                    registry_lower,
                    max_file_bytes=max_file_bytes,
                    skipped=skipped,
                )
            )
        else:
            # Inner loop ran to completion — proceed to the next root.
            continue
        # Inner loop was broken (timeout) — stop scanning further roots too.
        break

    # Stable ordering: by file, then line, then column.
    findings.sort(key=lambda f: (f.file, f.line, f.column))
    return findings

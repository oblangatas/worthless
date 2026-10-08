"""Key pattern detection with entropy and enrollment awareness."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from worthless.cli.dotenv_rewriter import shannon_entropy
from worthless.cli.key_patterns import (
    ENTROPY_THRESHOLD,
    KEY_PATTERN,
    ENV_LOGIN_REMEDY,
    LEAKED_LOGIN_REMEDY,
    UNSHARDABLE_REMEDY,
    detect_provider,
    is_oauth_token,
)
from worthless.cli.redaction import mask_secret
from worthless.cli.safe_rewrite import _BASENAME_ALLOWLIST

_VAR_NAME_RE = re.compile(r"(\w+)\s*$")

# Cap bytes read per file. A file larger than this is scanned up to the cap
# (its prefix) and flagged ``truncated`` — never silently skipped. Fail-closed:
# a key padded just past the cap is still caught in the prefix.
MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024


@dataclass
class SkippedFile:
    """A file that could not be fully scanned. Surfaced to the user — never
    dropped silently — so a leaked key can't slip through an unscanned file.

    reason: ``truncated`` (exceeded the byte cap; prefix was scanned),
    ``unreadable`` (OSError), or ``timeout`` (scan deadline hit before this
    file; nothing after it was scanned).
    """

    file: str
    reason: str


def read_text_capped(path: Path, max_bytes: int) -> tuple[str, bool]:
    """Read up to ``max_bytes`` of *path* as text. Returns (text, truncated).

    Streams a bounded read rather than stat-then-read so a file sized just over
    the cap still yields its prefix for scanning (you can't pad past the cap to
    evade detection). Raises OSError to the caller (handled as ``unreadable``).
    """
    # Guard against negative caps. ``fh.read(-1)`` reads to EOF in Python,
    # which would silently defeat the byte cap (fail-closed → fail-open).
    if max_bytes < 0:
        raise ValueError(f"max_bytes must be >= 0, got {max_bytes!r}")
    with path.open("rb") as fh:
        data = fh.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated


# Source file extensions to scan for hardcoded provider URLs.
_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rb",
        ".java",
        ".cs",
        ".rs",
        ".php",
        ".kt",
        ".swift",
    }
)

# Directory names that are never user code — skip them entirely.
_NOISE_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".eggs",
        "htmlcov",
        ".ruff_cache",
        ".next",
        ".nuxt",
        "target",
        "vendor",
    }
)

# Provider hostnames that route to localhost are already local — not a bypass.
_LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})

# Backreference ensures closing quote matches opening — prevents mismatched-quote false positives.
# Group 1 = quote char, group 2 = content between the matched quotes.
_QUOTED_STR_RE = re.compile(r"""(['"])([^"'\n]+)\1""")


@dataclass
class HardcodedUrlFinding:
    """A provider URL hardcoded in a source file — potential proxy bypass."""

    file: str
    line: int
    url: str
    provider: str


def scan_source_for_hardcoded_provider_urls(
    project_root: Path,
    *,
    max_file_bytes: int | None = None,
    deadline: float | None = None,
    skipped: list[SkippedFile] | None = None,
) -> list[HardcodedUrlFinding]:
    """Walk source files under *project_root*, return any hardcoded provider URLs.

    Uses the bundled provider registry so the list of flagged hostnames stays
    in sync with what worthless actually knows about. Localhost providers
    (e.g. Ollama on 127.0.0.1) are excluded — they're already local.

    Robustness (mirrors :func:`scan_files`):
    * *deadline* — a ``time.monotonic()`` value; once passed, scanning stops
      and returns findings gathered SO FAR, recording a ``timeout`` entry in
      *skipped*. A pre-commit / lock-time gate must still flag URLs already
      found.
    * Files larger than *max_file_bytes* are scanned up to the cap and flagged
      ``truncated``; unreadable files are flagged ``unreadable``. Nothing is
      silently dropped — that would let a hardcoded URL slip past ``lock``.
    """
    from worthless.cli.providers import load_bundled  # deferred — avoids circular at module init

    registry = load_bundled()
    hostnames: dict[str, str] = {}  # hostname → provider name
    for entry in registry.values():
        hostname = urlparse(entry.url).hostname or ""
        if hostname and hostname not in _LOCAL_HOSTNAMES:
            hostnames[hostname] = entry.name

    if not hostnames:
        return []

    cap = MAX_SCAN_FILE_BYTES if max_file_bytes is None else max_file_bytes
    combined = re.compile("|".join(re.escape(h) for h in hostnames))
    findings: list[HardcodedUrlFinding] = []
    for src_file in _walk_source_files(project_root):
        if deadline is not None and time.monotonic() > deadline:
            if skipped is not None:
                skipped.append(SkippedFile(file=str(src_file), reason="timeout"))
            break
        try:
            text, truncated = read_text_capped(src_file, cap)
        except (FileNotFoundError, IsADirectoryError):
            # Same carve-out as :func:`scan_files`: a file that vanished between
            # enumeration and read (or an accidental directory) is not a fail-
            # closed concern.
            continue
        except OSError:
            if skipped is not None:
                skipped.append(SkippedFile(file=str(src_file), reason="unreadable"))
            continue
        if truncated and skipped is not None:
            skipped.append(SkippedFile(file=str(src_file), reason="truncated"))
        for line_no, line in enumerate(text.splitlines(), start=1):
            for m in _QUOTED_STR_RE.finditer(line):
                value = m.group(2)  # group 1 is the quote char; group 2 is content
                host_match = combined.search(value)
                if host_match:
                    findings.append(
                        HardcodedUrlFinding(
                            file=str(src_file),
                            line=line_no,
                            url=value,
                            provider=hostnames[host_match.group(0)],
                        )
                    )
    return findings


def _walk_source_files(root: Path) -> Iterator[Path]:
    """Yield source files under *root*, pruning noise directories without descending into them."""
    stack = [root]
    while stack:
        try:
            entries = list(stack.pop().iterdir())
        except OSError:
            continue
        for item in entries:
            if item.is_dir() and not item.is_symlink():
                if item.name not in _NOISE_DIRS and not item.name.endswith(".egg-info"):
                    stack.append(item)
            elif item.suffix in _SOURCE_EXTENSIONS:
                yield item


@dataclass
class ScanFinding:
    """A detected API key occurrence in a scanned file."""

    file: str
    line: int
    var_name: str | None
    provider: str
    is_protected: bool
    value_preview: str  # fully masked by default
    # 0-indexed offset of the match within its line. Lets --show-suffix
    # fingerprint THIS finding's key rather than the line's first match, which
    # would show one shared fingerprint for every key on a minified JSON line.
    column: int | None = None
    # worthless-p55g: a Claude Code OAuth login token. `lock` refuses these by
    # design, wherever they sit. Decided here, while the raw value is still in
    # hand — after this only the masked preview exists.
    is_login_token: bool = False
    # A login token that stays on this machine: an untracked, non-symlink
    # .env-family file. Not "unprotected" — lock can't fix it and nothing else
    # will, so scan must not fail the build over it. Anywhere else (in git, a
    # non-.env file, a symlink, the environment) the token is plain exposed.
    is_unshardable: bool = False
    # Found in the scan --deep dump of the process environment, not in a file
    # anyone wrote. A CI secret belongs there, so the advice differs.
    from_environment: bool = False


def _is_git_tracked(path: Path) -> bool:
    """True if git tracks *path* — or if git can't say.

    Fails closed: only git's own "not tracked" (exit 1) or "not a git
    repository" counts as untracked. No git, a timeout, or any other refusal
    (e.g. "dubious ownership" in a CI container) is treated as tracked, so a
    token can't pass because the check couldn't run.
    """
    try:
        result = subprocess.run(  # nosec B603,B607
            [  # noqa: S607
                "git",
                "-C",
                str(path.parent),
                "ls-files",
                "--error-unmatch",
                "--",
                path.name,
            ],
            capture_output=True,
            check=False,
            timeout=10,
            # Ask the repo that holds *path*. Git sets GIT_DIR for hooks run in a
            # linked worktree; inherited, it points this probe at another repo.
            env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        )
    except (subprocess.TimeoutExpired, OSError):  # OSError covers no-git
        return True
    if result.returncode == 1:
        return False
    if result.returncode == 128 and b"not a git repository" in result.stderr:
        return False
    return True


def stays_local(path: Path) -> bool:
    """A .env-family file lock manages, that isn't a symlink and isn't in git."""
    return path.name in _BASENAME_ALLOWLIST and not path.is_symlink() and not _is_git_tracked(path)


def _stays_local_cached(path: Path, cache: dict[Path, bool]) -> bool:
    """stays_local, asked once per file: a .env with several tokens gets one git
    call, which keeps the pre-commit hook inside its time budget."""
    if path not in cache:
        cache[path] = stays_local(path)
    return cache[path]


def remediation_for(f: ScanFinding) -> str | None:
    """The fix that exists for a login token — never "run worthless lock"."""
    if f.is_protected or not f.is_login_token:
        return None
    if f.is_unshardable:
        return UNSHARDABLE_REMEDY
    if f.from_environment:
        return ENV_LOGIN_REMEDY
    return LEAKED_LOGIN_REMEDY


def finding_to_dict(f: ScanFinding) -> dict[str, object]:
    """One finding as JSON — shared by `scan --json` and the MCP scan tool."""
    item: dict[str, object] = {
        "file": f.file,
        "line": f.line,
        "var_name": f.var_name,
        "provider": f.provider,
        "is_protected": f.is_protected,
        # worthless-p55g: additive (no schema bump). Lets a consumer tell
        # "lock can't fix this" from "not protected yet".
        "is_unshardable": f.is_unshardable,
        "value_preview": f.value_preview,
    }
    if remedy := remediation_for(f):
        item["remediation"] = remedy
    return item


def scan_files(
    paths: list[Path],
    *,
    enrolled_locations: set[tuple[str, str]] | None = None,
    max_file_bytes: int | None = None,
    deadline: float | None = None,
    skipped: list[SkippedFile] | None = None,
    env_dump: Path | None = None,
) -> list[ScanFinding]:
    """Scan files for API key patterns.

    *env_dump*: the temp file holding the `--deep` dump of the process
    environment, so its findings are marked ``from_environment``.

    Each file is read (up to ``max_file_bytes``) line-by-line. Matches with
    entropy below the threshold are skipped (likely placeholders). If
    *enrolled_locations* is provided, matching (var_name, file_path) tuples are
    marked ``is_protected=True``.

    Robustness (the caller owns the policy, this honours it):
    * *deadline* — a ``time.monotonic()`` value. Once passed, scanning stops and
      returns the findings gathered SO FAR (a pre-commit hook must still block
      on keys already found), recording a ``timeout`` entry in *skipped*.
    * Files exceeding ``max_file_bytes`` or unreadable are recorded in *skipped*
      (``truncated`` / ``unreadable``) — never silently dropped.
    """
    cap = MAX_SCAN_FILE_BYTES if max_file_bytes is None else max_file_bytes
    findings: list[ScanFinding] = []
    local_cache: dict[Path, bool] = {}  # git is asked at most once per file

    # Deadline is checked BETWEEN files, not mid-file. A single file inside
    # ``cap`` bytes is bounded by the size cap + linear regex — slow but never
    # unbounded — so per-file granularity is the right portable trade-off.
    for path in paths:
        if deadline is not None and time.monotonic() > deadline:
            if skipped is not None:
                skipped.append(SkippedFile(file=str(path), reason="timeout"))
            break
        try:
            text, truncated = read_text_capped(path, cap)
        except (FileNotFoundError, IsADirectoryError):
            # File deleted between caller's enumeration and our read (the common
            # ``git rm``-then-pre-commit case), a typo'd path, or the caller
            # passing a directory by mistake. None of these are hang risks and
            # the pre-c5kc UX silently no-op'd them — preserve that contract so
            # a hook that runs ``worthless scan <dir>`` doesn't suddenly fail
            # closed on a known-benign input.
            continue
        except OSError:
            # File exists, is a regular file, but we couldn't read it
            # (permission denied, I/O error, etc.). That IS a fail-closed
            # concern: we don't know what we missed.
            if skipped is not None:
                skipped.append(SkippedFile(file=str(path), reason="unreadable"))
            continue
        if truncated and skipped is not None:
            skipped.append(SkippedFile(file=str(path), reason="truncated"))
        file_str = str(path.resolve())
        from_env = path == env_dump  # a None dump never equals a real path
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in KEY_PATTERN.finditer(line):
                value = match.group(0)
                if shannon_entropy(value) < ENTROPY_THRESHOLD:
                    continue
                provider = detect_provider(value)
                if provider is None:
                    continue

                # Try to extract var_name from KEY=VALUE or KEY = "VALUE"
                var_name = _extract_var_name(line, match.start())

                # worthless-p55g: lock never shards a Claude Code OAuth token, so
                # one can't be a worthless shard — even under a variable name
                # that was locked before and later pasted over.
                token = is_oauth_token(value)
                is_protected = not token and bool(
                    enrolled_locations and var_name and (var_name, file_str) in enrolled_locations
                )

                findings.append(
                    ScanFinding(
                        file=str(path),
                        line=line_no,
                        var_name=var_name,
                        provider=provider,
                        is_protected=is_protected,
                        value_preview=_mask(value),
                        column=match.start(),
                        is_login_token=token,
                        is_unshardable=token and _stays_local_cached(path, local_cache),
                        from_environment=from_env,
                    )
                )
    return findings


def _extract_var_name(line: str, value_start: int) -> str | None:
    """Try to find a variable name before the value in the line."""
    prefix = line[:value_start].rstrip()
    if prefix.endswith("="):
        prefix = prefix[:-1].rstrip().strip('"').strip("'")
        m = _VAR_NAME_RE.search(prefix)
        return m.group(1) if m else None
    return None


def _mask(value: str) -> str:
    """Return an output-safe placeholder for a matched key value.

    SR-04 (WOR-655): a flat ``****`` — no prefix, no suffix, no length hint.
    Previously emitted ``value[:4] + "****"``, leaking the first four real
    bytes into every scan preview (human + JSON).
    """
    return mask_secret(value)


EXPOSED_RULE_ID = "worthless/exposed-api-key"
UNSHARDABLE_RULE_ID = "worthless/unshardable-oauth-token"


def _sarif_verdict(f: ScanFinding) -> tuple[str, str, str]:
    """(ruleId, level, message) for one finding."""
    in_var = f" in variable {f.var_name}" if f.var_name else ""
    remedy = remediation_for(f)
    if remedy and f.is_unshardable:
        # worthless-p55g: GitHub code scanning reads the level, not scan's exit
        # code — "error" here would keep the gate red over a token lock refuses.
        # "note" keeps it visible without blocking.
        lead = f"Claude Code login token{in_var} — worthless can't protect it."
        return UNSHARDABLE_RULE_ID, "note", f"{lead} {remedy}"
    if remedy:
        return EXPOSED_RULE_ID, "error", f"Exposed Claude Code login token{in_var}. {remedy}"
    if f.is_protected:
        return (
            EXPOSED_RULE_ID,
            "warning",
            f"Exposed {f.provider} API key{in_var} (protected by worthless)",
        )
    return EXPOSED_RULE_ID, "error", f"Exposed {f.provider} API key{in_var}"


def format_sarif(findings: list[ScanFinding], tool_version: str) -> dict:
    """Format findings as SARIF v2.1.0.

    Returns a dict suitable for ``json.dumps()``.
    """
    results = []
    for f in findings:
        rule_id, level, text = _sarif_verdict(f)
        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "worthless",
                        "version": tool_version,
                        "rules": [
                            {
                                "id": EXPOSED_RULE_ID,
                                "shortDescription": {"text": "Exposed API key detected"},
                            },
                            {
                                "id": UNSHARDABLE_RULE_ID,
                                "shortDescription": {"text": "API key worthless can't protect"},
                                "defaultConfiguration": {"level": "note"},
                            },
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

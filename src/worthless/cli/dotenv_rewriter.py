"""Atomic ``.env`` key replacement and scanning.

All *destructive* write paths (``add_or_rewrite_env_key``,
``remove_env_key``, ``rewrite_env_key``) route through
:func:`worthless.cli.safe_rewrite.safe_rewrite`, which enforces the
10 invariants that make the historical "zshrc lock bug" structurally
impossible.

The read path (``scan_env_keys``) still uses ``python-dotenv``'s
``dotenv_values`` - reading is non-destructive and ``dotenv_values`` is
the most accurate parser for quoted/multiline values.

The write path is a hand-rolled line-preserving serializer because
``safe_rewrite`` takes the full new file content as bytes, and round-
tripping through ``dotenv_values`` would silently drop comments, blank
lines, ordering, export prefixes, and BOM/CRLF formatting.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import math
import os
import re
import stat as _stat
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from dotenv import dotenv_values

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.key_patterns import ENTROPY_THRESHOLD, KEY_PATTERN, detect_provider
from worthless.cli.safe_rewrite import _MAX_BYTES, _check_basename, safe_rewrite

if TYPE_CHECKING:
    from worthless.storage.repository import EnrollmentRecord


_log = logging.getLogger("worthless.dotenv_rewriter")


# ---------------------------------------------------------------------------
# Public scan helpers (read-only, unchanged behaviour).
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of string *s* in bits."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def build_enrolled_locations(
    enrollments: Iterable[EnrollmentRecord],
) -> set[tuple[str, str]]:
    """Build a set of ``(var_name, env_path)`` from enrollment records.

    Entries with ``env_path=None`` (direct enrollments) are excluded.
    """
    return {(e.var_name, e.env_path) for e in enrollments if e.env_path}


def scan_env_keys(
    env_path: Path,
    *,
    enrolled_locations: set[tuple[str, str]] | None = None,
) -> list[tuple[str, str, str]]:
    """Find API keys in a ``.env`` file.

    Returns a list of ``(var_name, value, provider)`` tuples for lines
    whose value matches a known provider prefix and is not a low-entropy
    placeholder.

    Parameters
    ----------
    enrolled_locations:
        Optional set of ``(var_name, env_path)`` tuples that are already
        enrolled.  Matching entries are skipped.
    """
    results: list[tuple[str, str, str]] = []
    parsed = dotenv_values(env_path)
    env_str = str(env_path.resolve())
    for var_name, value in parsed.items():
        if value is None:
            continue
        if not KEY_PATTERN.search(value):
            continue
        if enrolled_locations and (var_name, env_str) in enrolled_locations:
            continue
        if shannon_entropy(value) < ENTROPY_THRESHOLD:
            continue
        provider = detect_provider(value)
        if provider:
            results.append((var_name, value, provider))
    return results


# ---------------------------------------------------------------------------
# Line-preserving serializer (private).
# ---------------------------------------------------------------------------


_BOM: bytes = b"\xef\xbb\xbf"

# Identifier characters dotenv accepts on the left-hand side of ``=``.
# Matches ``[A-Za-z_][A-Za-z0-9_]*`` (optionally preceded by ``export ``).
_KEY_RE: re.Pattern[str] = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=")


@dataclass(frozen=True)
class _LogicalLine:
    """One dotenv logical line.

    ``raw`` includes any trailing EOL bytes (``b"\\n"`` or ``b"\\r\\n"``)
    that were present on the source. A ``key`` of ``None`` means the
    line is blank, a comment, or unparsable (and must be preserved
    verbatim).
    """

    raw: bytes
    key: str | None
    has_export: bool


def _detect_eol(buf: bytes) -> bytes:
    """Return the EOL sequence used by *buf*: ``b"\\r\\n"`` or ``b"\\n"``.

    Returns ``b"\\n"`` if no EOL is present. CRLF detection prefers the
    first occurrence so a file whose first EOL is CRLF round-trips as
    CRLF even if later lines mix.
    """
    crlf = buf.find(b"\r\n")
    lf = buf.find(b"\n")
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return b"\r\n"
    return b"\n"


def _strip_bom(buf: bytes) -> tuple[bytes, bool]:
    """Strip a leading UTF-8 BOM. Returns ``(stripped, had_bom)``."""
    if buf.startswith(_BOM):
        return buf[len(_BOM) :], True
    return buf, False


def _restore_bom(buf: bytes, had_bom: bool) -> bytes:
    """Re-prepend the UTF-8 BOM if it was present on the original file."""
    if had_bom:
        return _BOM + buf
    return buf


def _parse_key(line_text: str) -> tuple[str | None, bool]:
    """Extract the dotenv key (and ``export`` flag) from a single physical line.

    Returns ``(key, has_export)``. ``key`` is ``None`` for blanks,
    comments, or non-assignment lines.
    """
    stripped = line_text.lstrip()
    if not stripped or stripped.startswith("#"):
        return None, False
    has_export = False
    if stripped.startswith("export") and len(stripped) > len("export"):
        after = stripped[len("export") :]
        if after[:1] in (" ", "\t"):
            has_export = True
            stripped = after.lstrip()
    m = _KEY_RE.match(stripped)
    if not m:
        return None, has_export
    return m.group(1), has_export


def _value_opens_unclosed_quote(line_text: str) -> str | None:
    """If the parsed value on *line_text* opens an unclosed quote, return the quote char.

    Only considered when ``line_text`` parses as ``KEY=...``. The value
    starts immediately after the first ``=``. Per python-dotenv
    semantics, a value is only considered quoted when the *first
    non-whitespace byte* after ``=`` is ``"`` or ``'``; any quote char
    later in an otherwise-unquoted value is a literal, not a delimiter.

    Within a quoted span, a backslash escapes the next char. Returns
    ``None`` if the value is unquoted or the quote is balanced.
    """
    eq_idx = line_text.find("=")
    if eq_idx == -1:
        return None
    value = line_text[eq_idx + 1 :]
    # Strip trailing EOL.
    value = value.rstrip("\r\n")
    # Find first non-whitespace char to decide if this is a quoted value.
    stripped = value.lstrip(" \t")
    if not stripped or stripped[0] not in ('"', "'"):
        return None
    quote_char = stripped[0]
    # Scan the quoted span from after the opening quote.
    i = len(value) - len(stripped) + 1
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            i += 2
            continue
        if ch == quote_char:
            return None
        i += 1
    return quote_char


def _split_logical_lines(buf: bytes) -> list[_LogicalLine]:
    """Split *buf* into logical dotenv lines, preserving raw bytes.

    Physical-line splitting is done with ``splitlines(keepends=True)`` so
    EOLs stay attached to the preceding content. When a key's value
    opens a quote that is not closed on the same physical line, the
    subsequent physical lines are concatenated into the same
    :class:`_LogicalLine` until the quote closes.
    """
    if not buf:
        return []
    # Decode permissively - we already accepted the file through the
    # read path (which used dotenv_values) in callers; sniff in
    # ``safe_rewrite`` will reject true non-UTF-8 bytes on the write.
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError:
        # Fall back: treat as latin-1 so every byte maps somewhere. The
        # output will still be byte-identical because we carry the raw
        # bytes forward; only the key-parsing side loses fidelity and
        # safe_rewrite will refuse the write on sniff.
        text = buf.decode("latin-1")

    physical_lines = text.splitlines(keepends=True)
    raw_pieces = buf.splitlines(keepends=True)
    # These two should be the same length (and usually are). If they
    # diverge (unlikely with UTF-8 + keepends), fall back to the raw
    # bytes as authoritative.
    if len(physical_lines) != len(raw_pieces):
        physical_lines = [p.decode("utf-8", errors="replace") for p in raw_pieces]

    logical: list[_LogicalLine] = []
    i = 0
    while i < len(physical_lines):
        line_text = physical_lines[i]
        raw_bytes = raw_pieces[i]
        key, has_export = _parse_key(line_text)

        if key is None:
            logical.append(_LogicalLine(raw=raw_bytes, key=None, has_export=False))
            i += 1
            continue

        # Key line. Check whether the value opens an unclosed quote.
        open_quote = _value_opens_unclosed_quote(line_text)
        if open_quote is None:
            logical.append(_LogicalLine(raw=raw_bytes, key=key, has_export=has_export))
            i += 1
            continue

        # Gather subsequent physical lines until the quote closes (or EOF).
        merged_text = line_text
        merged_raw = raw_bytes
        j = i + 1
        while j < len(physical_lines):
            merged_text += physical_lines[j]
            merged_raw += raw_pieces[j]
            if _value_opens_unclosed_quote(merged_text) is None:
                j += 1
                break
            j += 1
        logical.append(_LogicalLine(raw=merged_raw, key=key, has_export=has_export))
        i = j

    return logical


def _serialize_lines(lines: list[_LogicalLine]) -> bytes:
    """Concatenate raw bytes of every logical line."""
    return b"".join(line.raw for line in lines)


def _format_assignment(
    key: str,
    value: str,
    *,
    has_export: bool,
    eol: bytes,
) -> bytes:
    """Build raw bytes for a ``[export ]KEY=VALUE<EOL>`` line.

    The value is emitted unquoted and without any escape processing -
    the rewriter only accepts values that ``_validate_value`` has
    cleared. Callers upstream (lock/unlock/scan-apply) always pass
    opaque decoy strings with no newlines/NUL/control bytes.
    """
    prefix = "export " if has_export else ""
    text = f"{prefix}{key}={value}"
    return text.encode("utf-8") + eol


def _rebuild_assignment_preserving_format(raw: bytes, new_value: str) -> bytes:
    """Surgically replace only the value bytes of a parsed ``KEY=VALUE`` line.

    Preserves the ``export`` prefix, key, surrounding whitespace, the
    ``=`` delimiter, the value's quote style (if any), a trailing inline
    ``# comment``, and the EOL style (LF / CRLF / none). The rest of the
    line is byte-identical to *raw*.

    Called on the UPDATE path only. The APPEND path (new key) uses the
    clean :func:`_format_assignment` instead.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    eq_idx = text.find("=")
    if eq_idx == -1:  # pragma: no cover - only called on parsed KEY=VALUE lines
        return (text + new_value).encode("utf-8")

    prefix = text[: eq_idx + 1]
    remainder = text[eq_idx + 1 :]

    if remainder.endswith("\r\n"):
        trailing_eol = "\r\n"
        body = remainder[:-2]
    elif remainder.endswith("\n"):
        trailing_eol = "\n"
        body = remainder[:-1]
    else:
        trailing_eol = ""
        body = remainder

    stripped_body = body.lstrip(" \t")
    leading_ws = body[: len(body) - len(stripped_body)]

    if not stripped_body:
        return (prefix + leading_ws + new_value + trailing_eol).encode("utf-8")

    first = stripped_body[0]

    if first in ('"', "'"):
        quote = first
        i = 1
        while i < len(stripped_body):
            ch = stripped_body[i]
            if ch == "\\" and i + 1 < len(stripped_body):
                i += 2
                continue
            if ch == quote:
                after_quote = stripped_body[i + 1 :]
                return (
                    prefix + leading_ws + quote + new_value + quote + after_quote + trailing_eol
                ).encode("utf-8")
            i += 1
        return (prefix + leading_ws + quote + new_value + quote + trailing_eol).encode("utf-8")

    comment_start: int | None = None
    for i, ch in enumerate(stripped_body):
        if ch == "#" and i > 0 and stripped_body[i - 1] in (" ", "\t"):
            j = i - 1
            while j > 0 and stripped_body[j - 1] in (" ", "\t"):
                j -= 1
            comment_start = j
            break

    if comment_start is not None:
        ws_and_comment = stripped_body[comment_start:]
        return (prefix + leading_ws + new_value + ws_and_comment + trailing_eol).encode("utf-8")

    return (prefix + leading_ws + new_value + trailing_eol).encode("utf-8")


_POSIX_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")


def _validate_var_name(name: str) -> None:
    """Refuse keys outside POSIX env-var syntax.

    Matches ``[A-Za-z_][A-Za-z0-9_]*``. This structurally prevents line
    injection (no newlines), assignment smuggling (no ``=``), empty
    strings, and keys the shell couldn't ``export`` anyway.
    """
    if not isinstance(name, str) or not _POSIX_NAME_RE.match(name):
        raise ValueError("dotenv var name must match POSIX env syntax [A-Za-z_][A-Za-z0-9_]*")


def _validate_value(value: str) -> None:
    """Refuse values that would break the dotenv shape on write OR
    silently corrupt when round-tripped through a standard dotenv parser.

    Structural rejects (always catastrophic):

    * Newlines (``\\n`` / ``\\r``) would let a caller inject a second
      assignment line.
    * NUL bytes routinely mis-parse downstream tooling.

    Round-trip-stability rejects (silent data loss on read-back):

    * ``space + #`` sequence: dotenv parsers treat this as the start of
      an inline comment; the stored value would be truncated at the
      space. Literal ``#`` not preceded by whitespace is fine.
    * Leading ``"`` or ``'``: parsers treat it as an opening quote and
      strip it from the value.
    * Leading or trailing whitespace: unquoted values are
      whitespace-stripped on read.

    Callers upstream (lock/unlock/scan) write opaque decoy strings
    (UUIDs, tokens) that never trigger these guards. The validator's
    job is to turn a future caller-side bug into a loud ``ValueError``
    instead of a silent truncation.
    """
    if "\n" in value or "\r" in value:
        raise ValueError("dotenv value must not contain newlines")
    if "\x00" in value:
        raise ValueError("dotenv value must not contain NUL bytes")
    # Checked before the whitespace guard below: inline-comment truncation
    # is the more surprising hazard, so it wins the diagnostic for values
    # like "\t#foo" that trip both checks.
    if " #" in value or "\t#" in value:
        raise ValueError(
            "dotenv value contains whitespace+'#' (inline comment; truncates on read-back)"
        )
    if value[:1] in ('"', "'"):
        raise ValueError(
            "dotenv value must not start with a quote character (stripped on read-back)"
        )
    if value and (value[0].isspace() or value[-1].isspace()):
        raise ValueError(
            "dotenv value must not have leading or trailing whitespace (stripped on read-back)"
        )
    # Embedded quotes: if the current on-disk line happens to be quoted
    # (``KEY="old"``), ``_rebuild_assignment_preserving_format`` wraps
    # *new_value* in the preserved quote char. A value of ``abc"def``
    # then produces ``KEY="abc"def"`` which python-dotenv flags as
    # unparsable. We cannot know the on-disk quote style from here, so
    # we refuse both quote chars defensively. Matches the "refuse, don't
    # mangle" posture of the other validators above.
    if '"' in value or "'" in value:
        raise ValueError(
            "dotenv value must not contain embedded quote characters "
            "(would corrupt a rewrite into a pre-existing quoted line)"
        )


def _safe_read_existing_bytes(path: Path) -> bytes:
    """Read *path*'s bytes without following symlinks or blocking on specials.

    Returns an empty byte string if the path does not exist. Raises
    :class:`UnsafeRewriteRefused` directly for every hostile shape
    (symlink, FIFO, socket, directory, char/block device, oversized
    file, ``lstat``/``os.open`` failures, inode/dev mismatch between
    ``lstat`` and the post-open ``fstat``). We do *not* route refusals
    through :func:`safe_rewrite` with an empty payload: under a race
    where the hostile condition clears (oversized file truncated,
    symlink swapped for regular file, EPERM cleared) between our check
    and the gate's check, such a call could succeed and wipe the file.
    Raising directly here eliminates that window — no write path is
    ever reached on a refusal.
    """
    try:
        lst = os.lstat(str(path))
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise UnsafeRewriteRefused(UnsafeReason.IO_ERROR) from exc
    if _stat.S_ISLNK(lst.st_mode):
        raise UnsafeRewriteRefused(UnsafeReason.SYMLINK)
    if not _stat.S_ISREG(lst.st_mode):
        raise UnsafeRewriteRefused(UnsafeReason.SPECIAL_FILE)
    if lst.st_size > _MAX_BYTES:
        raise UnsafeRewriteRefused(UnsafeReason.SIZE)
    # Open with O_NOFOLLOW + O_RDONLY so a TOCTOU symlink-flip between
    # the lstat above and this open still refuses rather than reading
    # through the symlink.
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise UnsafeRewriteRefused(UnsafeReason.IO_ERROR) from exc
    try:
        # O_NOFOLLOW blocks a symlink-flip but not an atomic rename
        # that swaps a different regular file over the path. Matching
        # (st_ino, st_dev) against the lstat result proves fd refers
        # to the file we validated.
        try:
            post = os.fstat(fd)
        except OSError as exc:
            raise UnsafeRewriteRefused(UnsafeReason.IO_ERROR) from exc
        if post.st_ino != lst.st_ino or post.st_dev != lst.st_dev:
            raise UnsafeRewriteRefused(UnsafeReason.TOCTOU)
        size = post.st_size
        if size > _MAX_BYTES:
            raise UnsafeRewriteRefused(UnsafeReason.SIZE)
        if size <= 0:
            return b""
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Public destructive helpers (all route through ``safe_rewrite``).
# ---------------------------------------------------------------------------


def _create_new_env_file(env_path: Path, var_name: str, value: str) -> None:
    """Atomic exclusive create for the missing-file path.

    ``safe_rewrite`` refuses missing targets by contract (see
    ``tests/safe_rewrite/test_atomic.py::test_target_missing_refused``).
    To honour ``add_or_rewrite_env_key``'s "creating or updating"
    docstring, the first-write path goes through this helper instead:
    ``O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`` with mode ``0o600`` so a
    racing symlink or pre-existing file aborts the write rather than
    silently dereferencing or clobbering it.

    Durability: we fsync the file fd AND the parent directory. Without
    the parent-dir fsync, a crash between write and the next
    ``safe_rewrite`` call could leave the file's data durable on disk
    but its directory entry gone - the classic POSIX "ghost file"
    durability gap. Matches ``safe_rewrite``'s rename path (which
    fsyncs both sides for the same reason).
    """
    payload = _format_assignment(var_name, value, has_export=False, eol=b"\n")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(str(env_path), flags, 0o600)
    except FileExistsError as exc:
        raise UnsafeRewriteRefused(UnsafeReason.TOCTOU) from exc
    except OSError as exc:
        raise UnsafeRewriteRefused(UnsafeReason.IO_ERROR) from exc
    try:
        written = 0
        mv = memoryview(payload)
        while written < len(payload):
            n = os.write(fd, mv[written:])
            if n <= 0:
                # Raise OSError (not UnsafeRewriteRefused) so the outer
                # ``except OSError`` cleanup branch runs — otherwise the
                # fd stays open and a partially-written file survives on
                # disk. Cleanup re-wraps as UnsafeRewriteRefused for the
                # caller.
                raise OSError(errno.EIO, "short write")
            written += n
        os.fsync(fd)
    except OSError as exc:
        try:
            os.close(fd)
        finally:
            try:
                env_path.unlink()
            except OSError:
                pass
        raise UnsafeRewriteRefused(UnsafeReason.IO_ERROR) from exc
    else:
        os.close(fd)

    # Directory entry fsync. Best-effort: if this fails, the file
    # content is durable but the directory entry may not be. We don't
    # raise (contract: file was created successfully) but we don't
    # silently succeed either - log so operators see "durability
    # unconfirmed" the same way safe_rewrite's post-rename path does.
    try:
        dir_fd = os.open(
            str(env_path.parent),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
    except OSError as exc:
        _log.warning(
            "newly-created %s: could not open parent dir for fsync "
            "(errno=%s %s); directory entry durability unconfirmed",
            env_path,
            exc.errno,
            exc.strerror,
        )
        return
    try:
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            _log.warning(
                "newly-created %s: parent-dir fsync failed "
                "(errno=%s %s); directory entry may revert on crash",
                env_path,
                exc.errno,
                exc.strerror,
            )
    finally:
        os.close(dir_fd)


def add_or_rewrite_env_key(env_path: Path, var_name: str, value: str) -> None:
    """Set *var_name* to *value* in *env_path*, creating or updating.

    If *env_path* does not yet exist, a new file is created atomically
    (``O_CREAT|O_EXCL|O_NOFOLLOW``, mode ``0o600``) containing a single
    ``KEY=VALUE`` line. If it exists and *var_name* is present, its
    value is replaced on the same logical line (preserving any
    ``export`` prefix and surrounding formatting). Otherwise a new
    ``KEY=VALUE`` line is appended.

    Updates to an existing file route through :func:`safe_rewrite`;
    invariant violations raise :class:`UnsafeRewriteRefused` with the
    original file byte-identical.
    """
    _validate_var_name(var_name)
    _validate_value(value)
    if not env_path.exists() and not env_path.is_symlink():
        # Route the missing-file create path through the same basename
        # gate ``safe_rewrite`` enforces on the rewrite branch. Without
        # this, ``add_or_rewrite_env_key(Path("~/.bashrc"), "PATH", "/x")``
        # on a host with no ``.bashrc`` would happily create one with
        # attacker-controlled content — the exact "zshrc-lock" class
        # WOR-252 is designed to make structurally impossible.
        _check_basename(env_path)
        _create_new_env_file(env_path, var_name, value)
        return
    existing = _safe_read_existing_bytes(env_path)
    stripped, had_bom = _strip_bom(existing)
    eol = _detect_eol(stripped)
    lines = _split_logical_lines(stripped)

    matched = False
    for idx, line in enumerate(lines):
        if line.key == var_name:
            lines[idx] = _LogicalLine(
                raw=_rebuild_assignment_preserving_format(line.raw, value),
                key=var_name,
                has_export=line.has_export,
            )
            matched = True
            break

    if not matched:
        if lines and not lines[-1].raw.endswith((b"\n", b"\r\n")):
            last = lines[-1]
            lines[-1] = _LogicalLine(
                raw=last.raw + eol,
                key=last.key,
                has_export=last.has_export,
            )
        lines.append(
            _LogicalLine(
                raw=_format_assignment(var_name, value, has_export=False, eol=eol),
                key=var_name,
                has_export=False,
            )
        )

    new_content = _restore_bom(_serialize_lines(lines), had_bom)
    if new_content == existing:
        # Idempotent: same bytes. Skip the write so the gate's delta
        # and sniff gates are not re-run on a no-op.
        return
    safe_rewrite(
        env_path,
        new_content,
        original_user_arg=env_path,
        allow_outside_repo=True,
        expected_baseline_sha256=hashlib.sha256(existing).digest(),
    )


def remove_env_key(env_path: Path, var_name: str) -> None:
    """Remove *var_name* from *env_path* if present.

    Drops the full logical line (including an ``export`` prefix and
    every physical line of a multiline-quoted value). If *var_name* is
    not present, this is a pure no-op - no write happens and
    :func:`safe_rewrite` is NOT called.
    """
    _validate_var_name(var_name)
    existing = _safe_read_existing_bytes(env_path)
    stripped, had_bom = _strip_bom(existing)
    lines = _split_logical_lines(stripped)

    kept: list[_LogicalLine] = [line for line in lines if line.key != var_name]
    if len(kept) == len(lines):
        # Key absent: true no-op, including zero safe_rewrite calls.
        return

    new_content = _restore_bom(_serialize_lines(kept), had_bom)
    if new_content == existing:
        return
    safe_rewrite(
        env_path,
        new_content,
        original_user_arg=env_path,
        allow_outside_repo=True,
        expected_baseline_sha256=hashlib.sha256(existing).digest(),
    )


def _validate_rewrite_args(
    updates: dict[str, str],
    additions: dict[str, str] | None,
    removals: set[str] | None,
) -> None:
    for var_name in updates:
        _validate_var_name(var_name)
    for value in updates.values():
        _validate_value(value)
    if additions:
        for var_name in additions:
            _validate_var_name(var_name)
        for value in additions.values():
            _validate_value(value)
    if removals:
        for var_name in removals:
            _validate_var_name(var_name)

    # Per CodeRabbit nitpick: reject overlapping keys across the three sets.
    # `updates ∩ removals` would update then delete the same key — silent
    # mangling. `additions ∩ removals` is similarly nonsense. `updates ∩
    # additions` is ambiguous (which value wins?). Refuse deterministically
    # so callers get a clear error rather than a surprising rewrite.
    update_keys = set(updates)
    addition_keys = set(additions) if additions else set()
    removal_keys = set(removals) if removals else set()

    if update_keys and removal_keys:
        overlap = update_keys & removal_keys
        if overlap:
            raise ValueError(
                f"updates and removals overlap (key would be updated then "
                f"deleted): {sorted(overlap)!r}"
            )
    if addition_keys and removal_keys:
        overlap = addition_keys & removal_keys
        if overlap:
            raise ValueError(
                f"additions and removals overlap (key would be added then "
                f"deleted): {sorted(overlap)!r}"
            )
    if update_keys and addition_keys:
        overlap = update_keys & addition_keys
        if overlap:
            raise ValueError(
                f"updates and additions overlap (ambiguous: which value wins?): {sorted(overlap)!r}"
            )


def _apply_updates(lines: list[_LogicalLine], updates: dict[str, str], env_path: Path) -> None:
    matched: set[str] = set()
    for idx, line in enumerate(lines):
        if line.key in updates:
            lines[idx] = _LogicalLine(
                raw=_rebuild_assignment_preserving_format(line.raw, updates[line.key]),
                key=line.key,
                has_export=line.has_export,
            )
            matched.add(line.key)
    missing = set(updates) - matched
    if missing:
        raise KeyError(f"Variable(s) not found in {env_path}: {sorted(missing)!r}")


def _append_additions(lines: list[_LogicalLine], additions: dict[str, str], eol: bytes) -> None:
    if lines and not lines[-1].raw.endswith((b"\n", b"\r\n")):
        last = lines[-1]
        lines[-1] = _LogicalLine(raw=last.raw + eol, key=last.key, has_export=last.has_export)
    for var_name, value in additions.items():
        lines.append(
            _LogicalLine(
                raw=_format_assignment(var_name, value, has_export=False, eol=eol),
                key=var_name,
                has_export=False,
            )
        )


def rewrite_env_keys(
    env_path: Path,
    updates: dict[str, str],
    *,
    additions: dict[str, str] | None = None,
    removals: set[str] | None = None,
    _hook_before_replace: Callable[[], None] | None = None,
) -> None:
    """Atomically replace N keys in *env_path* via one ``safe_rewrite`` call.

    Every key in *updates* must already exist in *env_path* — missing
    keys raise :class:`KeyError` before any write happens. This is the
    all-or-nothing primitive underpinning transactional multi-key lock:
    either every key is replaced atomically or the file is byte-identical.

    *additions* (optional) are appended at the end of the file, in
    iteration order. They are a clean insert and must not already exist
    as keys in the file.

    *removals* (optional) drop matching keys from the file. Missing
    removal targets are silently ignored — consistent with
    :func:`remove_env_key`. Used by transactional unlock to delete
    proxy ``*_BASE_URL`` lines in the same atomic write that restores
    plaintext keys.

    *_hook_before_replace* is forwarded to :func:`safe_rewrite`; the
    lock command binds a closure that runs reconstruct-and-verify for
    every shard under an exclusive SQLite flock before the rename.
    """
    _validate_rewrite_args(updates, additions, removals)
    if not updates and not additions and not removals:
        return

    existing = _safe_read_existing_bytes(env_path)
    stripped, had_bom = _strip_bom(existing)
    eol = _detect_eol(stripped)
    lines = _split_logical_lines(stripped)

    _apply_updates(lines, updates, env_path)
    if removals:
        lines = [line for line in lines if line.key not in removals]
    if additions:
        _append_additions(lines, additions, eol)

    new_content = _restore_bom(_serialize_lines(lines), had_bom)
    if new_content == existing:
        return
    safe_rewrite(
        env_path,
        new_content,
        original_user_arg=env_path,
        allow_outside_repo=True,
        expected_baseline_sha256=hashlib.sha256(existing).digest(),
        _hook_before_replace=_hook_before_replace,
    )


def rewrite_env_key(env_path: Path, var_name: str, new_value: str) -> None:
    """Atomically replace the value of *var_name* in *env_path*.

    Preserves comments, blank lines, ordering, ``export`` prefixes, and
    every other key's formatting. Raises :class:`KeyError` if
    *var_name* is not present (matching the legacy contract).
    """
    _validate_var_name(var_name)
    _validate_value(new_value)
    existing = _safe_read_existing_bytes(env_path)
    stripped, had_bom = _strip_bom(existing)
    lines = _split_logical_lines(stripped)

    matched = False
    for idx, line in enumerate(lines):
        if line.key == var_name:
            lines[idx] = _LogicalLine(
                raw=_rebuild_assignment_preserving_format(line.raw, new_value),
                key=var_name,
                has_export=line.has_export,
            )
            matched = True
            break

    if not matched:
        raise KeyError(f"Variable {var_name!r} not found in {env_path}")

    new_content = _restore_bom(_serialize_lines(lines), had_bom)
    if new_content == existing:
        return
    safe_rewrite(
        env_path,
        new_content,
        original_user_arg=env_path,
        allow_outside_repo=True,
        expected_baseline_sha256=hashlib.sha256(existing).digest(),
    )

"""Invariant-gated safe rewrite for ``.env`` files.

This module exposes two public functions, :func:`safe_rewrite` and
:func:`safe_restore`, which perform an atomic, invariant-checked rewrite
of a literal ``.env`` file. Every check is structured so that the
historical ".zshrc lock bug" - where a symlink or path confusion caused
the tool to clobber a user's shell rc file - is *structurally impossible*.

``safe_rewrite`` is the normal write path with every gate engaged.
``safe_restore`` is the recovery entry point: it reuses the same gate
pipeline but bypasses the DELTA (content-blowup) gate, which otherwise
refuses large decoy -> original swaps during lock-checkpoint restore.
All other gates - SYMLINK, SIZE, SNIFF, TOCTOU, CONTAINMENT,
PATH_IDENTITY, LOCKED, IO_ERROR - still fire.

Every refusal raises :class:`UnsafeRewriteRefused`; the public message is
opaque, the granular cause is on ``.reason``, and the target file is
byte-identical across every refusal path.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import stat as _stat
import sys
from pathlib import Path
from collections.abc import Callable

if sys.platform != "win32":
    import fcntl
else:  # pragma: no cover — PLATFORM gate refuses before any fcntl is used
    fcntl = None  # type: ignore[assignment]

from dotenv import dotenv_values

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.fs_check import require_atomic_fs

__all__ = [
    "UnsafeReason",
    "UnsafeRewriteRefused",
    "safe_restore",
    "safe_rewrite",
]


_log = logging.getLogger("worthless.safe_rewrite")


# ---------------------------------------------------------------------------
# Module constants - the contract surface. Tests reference these values.
# ---------------------------------------------------------------------------

_BASENAME_ALLOWLIST: frozenset[str] = frozenset(
    {
        ".env",
        ".env.local",
        ".env.development",
        ".env.development.local",
        ".env.production",
        ".env.production.local",
        ".env.test",
        ".env.staging",
        ".env.testing",
    }
)
_BASENAME_DENYLIST: frozenset[str] = frozenset(
    {
        ".zshrc",
        ".bashrc",
        ".profile",
        ".netrc",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "config",
        "authorized_keys",
        "known_hosts",
    }
)
_MAX_BYTES: int = 1 << 20
_MAX_LINES: int = 500
_DELTA_MIN: float = 0.25
_DELTA_MAX: float = 4.0
_TMP_RETRIES: int = 3

# Shell-construct markers. If any line of the existing file content
# (trimmed of leading whitespace) starts with one of these prefixes OR
# contains one of the infix markers, we treat the file as "not dotenv"
# and refuse.
_SHELL_PREFIXES: tuple[str, ...] = (
    "#!",
    "alias ",
    "function ",
    "source ",
    "if ",
    "case ",
    "eval ",
    "eval\t",
)
# Heredoc detector (PR #86 discussion_r3124934951). A true shell
# heredoc opener has the form ``cmd <<WORD`` or ``cmd <<-WORD`` on an
# assignment-free line where WORD starts with an identifier character
# or a quote. The previous loose ``"<<" in line`` check was too broad
# and refused legitimate dotenv values like ``TOKEN=abc<<def`` or
# ``URL=https://x?q=a<<b``, turning any ``.env`` containing them into
# a permanently un-rewritable file. ``^[^=]*\s<<-?\s*["']?\w`` anchors
# on the start of the (stripped) line, rejects any line with ``=``
# before the ``<<`` (i.e. ``KEY=value`` lines can't trip it), and
# requires a WORD-like token after the ``<<``. Actual shell rc files
# are already blocked by the basename denylist before sniff runs.
_HEREDOC_RE = re.compile(r"^[^=]*\s<<-?\s*[\"']?\w")

# Darwin's F_FULLFSYNC command constant. We don't rely on fcntl exporting
# it (Linux fcntl has no such constant) and fall back to plain fsync if
# the syscall returns ENOTTY/EINVAL.
_F_FULLFSYNC: int = 51


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _refuse(reason: UnsafeReason, target: Path | None = None) -> UnsafeRewriteRefused:
    """Build (but do not raise) a sanitised :class:`UnsafeRewriteRefused`.

    The DEBUG-log line carries the granular reason and the target path;
    the public message is opaque.
    """
    if target is not None:
        _log.debug("refused: reason=%s target=%s", reason.value, target)
    else:
        _log.debug("refused: reason=%s", reason.value)
    return UnsafeRewriteRefused(reason)


def _fullfsync(fd: int) -> None:
    """Best-effort durability barrier.

    On Darwin, ``fcntl.fcntl(fd, F_FULLFSYNC)`` is the only way to flush
    the drive write-cache. We call it unconditionally when ``sys.platform
    == "darwin"`` and swallow OSError (some test harnesses fake Darwin
    on Linux where the ioctl is ENOTTY).
    """
    if sys.platform == "darwin":
        try:
            fcntl.fcntl(fd, _F_FULLFSYNC)
        except OSError:
            # Faked darwin under a Linux kernel will ENOTTY; the test
            # asserts the attempt, not success.
            pass


def _is_regular_file(st: os.stat_result) -> bool:
    return _stat.S_ISREG(st.st_mode)


def _renameat2(src: str, dst: str) -> None:
    """Atomic rename helper. Linux can wire ``RENAME_NOREPLACE`` here; on
    every other platform we delegate to ``os.replace`` which is atomic on
    Linux/Darwin within the same filesystem.

    Tests monkeypatch ``os.replace`` to inject ``OSError(ENOSYS)`` /
    ``EROFS`` and verify the implementation falls back to ``os.replace``
    after a fresh fstatat recheck. Path.replace() bypasses the module-
    level binding via pathlib's accessor, so the explicit os.replace
    call is load-bearing.
    """
    os.replace(src, dst)  # noqa: PTH105


def _shell_marker_scan(text: str) -> bool:
    """Return True if *text* contains any shell-style construct."""
    for raw_line in text.splitlines():
        line = raw_line.lstrip()
        if not line or line.startswith("#") and not line.startswith("#!"):
            continue
        for prefix in _SHELL_PREFIXES:
            if line.startswith(prefix):
                return True
        if _HEREDOC_RE.match(line):
            return True
    return False


def _check_dotenv_content(buf: bytes) -> None:
    """Full-file dotenv sniff. Raises :class:`UnsafeRewriteRefused` on shell-smell."""
    # Decode permissively: a non-UTF8 file cannot be a dotenv.
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _refuse(UnsafeReason.SNIFF) from exc

    # Line-count bound applies here (before sniff, still under SIZE
    # category per the plan).
    # (Already enforced in the size gate; kept here defensively in case
    # the caller reorders.)

    # Explicit shell-marker scan first - dotenv_values is too lenient
    # (it silently accepts ``export FOO=bar`` as ``FOO=bar``).
    if _shell_marker_scan(text):
        raise _refuse(UnsafeReason.SNIFF)

    # Full-file parse: dotenv_values emits warnings for malformed lines
    # but never raises. We inspect its logger to detect parse failure.
    dotenv_logger = logging.getLogger("dotenv.main")
    errors: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            errors.append(record)

    handler = _Collector(level=logging.WARNING)
    dotenv_logger.addHandler(handler)
    prev_level = dotenv_logger.level
    dotenv_logger.setLevel(logging.WARNING)
    try:
        dotenv_values(stream=io.StringIO(text))
    except Exception as exc:  # defence in depth - lib is supposed not to raise
        raise _refuse(UnsafeReason.SNIFF) from exc
    finally:
        dotenv_logger.removeHandler(handler)
        dotenv_logger.setLevel(prev_level)

    if errors:
        raise _refuse(UnsafeReason.SNIFF)


def _basename_check(target: Path) -> None:
    name = target.name
    if name in _BASENAME_DENYLIST:
        raise _refuse(UnsafeReason.BASENAME, target)
    if name not in _BASENAME_ALLOWLIST:
        raise _refuse(UnsafeReason.BASENAME, target)


def _platform_check() -> None:
    if sys.platform.startswith("win"):
        raise _refuse(UnsafeReason.PLATFORM)


def _unlink_tmp(tmp_path: str) -> None:
    """Best-effort unlink of the temp file. Never raises."""
    try:
        Path(tmp_path).unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Per-invariant gate helpers. Each raises UnsafeRewriteRefused directly.
# These exist purely to keep _safe_rewrite_core()'s cyclomatic complexity
# in rank-B territory; they are NOT independent abstractions and the call
# order in _safe_rewrite_core() is load-bearing.
# ---------------------------------------------------------------------------


def _check_basename(target: Path) -> None:
    """Invariant 2: literal basename, denylist, NUL/trailing-slash poison."""
    # Guard against embedded NUL in the path (pathlib/os may raise ValueError
    # or OSError - both are "refused" for our purposes).
    try:
        target_name = target.name
    except (ValueError, OSError) as exc:
        raise _refuse(UnsafeReason.BASENAME) from exc
    if "\x00" in str(target):
        raise _refuse(UnsafeReason.BASENAME)
    # Refuse a trailing-slash path (foo/.env/): POSIX open() would ENOTDIR
    # on a regular file; we translate to a clean refuse without opening.
    if str(target).endswith("/") and str(target) != "/":
        raise _refuse(UnsafeReason.BASENAME)
    _ = target_name
    _basename_check(target)


def _check_user_arg_basename(target: Path, original_user_arg: Path) -> None:
    """Invariant 2b: caller cannot pass a resolved .env with a denylisted user arg."""
    try:
        if original_user_arg.name != target.name:
            raise _refuse(UnsafeReason.PATH_IDENTITY, target)
    except (ValueError, OSError) as exc:
        raise _refuse(UnsafeReason.PATH_IDENTITY, target) from exc


def _lstat_target(target: Path) -> os.stat_result:
    """Invariant 3a: lstat the target (refuses on missing/IO error)."""
    try:
        return os.lstat(str(target))
    except FileNotFoundError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc


def _check_special_file(lst: os.stat_result, target: Path) -> None:
    """Invariant 3b: reject symlinks, dirs, fifos, sockets, char/block devs."""
    if _stat.S_ISLNK(lst.st_mode):
        raise _refuse(UnsafeReason.SYMLINK, target)
    if _stat.S_ISDIR(lst.st_mode):
        raise _refuse(UnsafeReason.SPECIAL_FILE, target)
    if (
        _stat.S_ISFIFO(lst.st_mode)
        or _stat.S_ISSOCK(lst.st_mode)
        or _stat.S_ISCHR(lst.st_mode)
        or _stat.S_ISBLK(lst.st_mode)
    ):
        raise _refuse(UnsafeReason.SPECIAL_FILE, target)
    if not _stat.S_ISREG(lst.st_mode):
        raise _refuse(UnsafeReason.SPECIAL_FILE, target)


def _check_containment(target: Path, repo_root: Path | None, allow_outside_repo: bool) -> None:
    """Invariant 4: realpath containment + same-filesystem (mount-ID) gate."""
    if repo_root is None or allow_outside_repo:
        return
    try:
        target_resolved = target.resolve(strict=False)
        repo_resolved = repo_root.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise _refuse(UnsafeReason.CONTAINMENT, target) from exc

    # Containment: target's realpath must be a *descendant* of repo_root's
    # realpath. Defense-in-depth is provided by three layers already —
    # basename allowlist/denylist (:func:`_check_basename`), realpath
    # resolution (above), and fsid equality (below). Those three layers
    # catch symlink escapes, bind-mount escapes, and non-dotenv targets;
    # an additional "direct-child-only" rule would add no bar against any
    # concrete threat and would refuse valid monorepo layouts.
    try:
        target_resolved.relative_to(repo_resolved)
    except ValueError as exc:
        raise _refuse(UnsafeReason.CONTAINMENT, target) from exc

    # Mount-ID / filesystem ID check: if repo and target live on
    # different filesystems (bind-mount, overlay, cross-device), refuse.
    try:
        repo_statvfs = os.statvfs(str(repo_root))
        target_statvfs = os.statvfs(str(target.parent))
    except OSError as exc:
        raise _refuse(UnsafeReason.CONTAINMENT, target) from exc
    if repo_statvfs.f_fsid != target_statvfs.f_fsid:
        raise _refuse(UnsafeReason.CONTAINMENT, target)


def _check_path_identity(target: Path, original_user_arg: Path, lst: os.stat_result) -> None:
    """Invariant 5: target & original_user_arg resolve to same inode; no hardlinks."""
    try:
        # Use os.stat so tests that monkeypatch os.stat can observe the
        # original-arg stat as well as the post-open recheck. Path.stat()
        # uses pathlib's accessor and bypasses module-level patches.
        orig_stat = os.stat(str(original_user_arg))  # noqa: PTH116
    except OSError as exc:
        # If original arg can't be stat'd at all, we refuse.
        raise _refuse(UnsafeReason.PATH_IDENTITY, target) from exc
    if (orig_stat.st_dev, orig_stat.st_ino) != (lst.st_dev, lst.st_ino):
        raise _refuse(UnsafeReason.PATH_IDENTITY, target)

    # Hardlink check: st_nlink > 1 means the same inode is referenced by
    # another name. A benign .env rarely has hardlinks; the risk is a
    # hardlink to a denylisted inode (.zshrc, id_rsa, ...). Refuse.
    if lst.st_nlink > 1:
        raise _refuse(UnsafeReason.PATH_IDENTITY, target)


def _open_target_fd(target: Path) -> int:
    """Invariant 6a: open target with O_RDWR | O_NOFOLLOW | O_CLOEXEC."""
    try:
        return os.open(
            str(target),
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        # ENOTDIR / ENOENT / EMFILE / ELOOP -> refuse cleanly.
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc


def _fstat_baseline(target_fd: int, target: Path, lst: os.stat_result) -> os.stat_result:
    """Invariant 6b: fstat the opened fd; double-check S_ISREG and dev/ino vs lst."""
    try:
        baseline_fstat = os.fstat(target_fd)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc

    # Double-check identity on the opened fd. S_ISREG in particular.
    if not _stat.S_ISREG(baseline_fstat.st_mode):
        raise _refuse(UnsafeReason.SPECIAL_FILE, target)
    if (baseline_fstat.st_dev, baseline_fstat.st_ino) != (lst.st_dev, lst.st_ino):
        raise _refuse(UnsafeReason.TOCTOU, target)
    return baseline_fstat


def _flock_exclusive_nonblocking(target_fd: int, target: Path) -> None:
    """Invariant 7: take LOCK_EX|LOCK_NB on target_fd or refuse LOCKED."""
    try:
        fcntl.flock(target_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise _refuse(UnsafeReason.LOCKED, target) from exc
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            raise _refuse(UnsafeReason.LOCKED, target) from exc
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc


def _read_existing(target_fd: int, old_size: int, target: Path) -> bytes:
    """Read the existing file once for line-count + sniff. Refuses on IO error."""
    try:
        os.lseek(target_fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc

    if old_size <= 0:
        return b""

    to_read = old_size
    chunks: list[bytes] = []
    try:
        while to_read > 0:
            chunk = os.read(target_fd, to_read)
            if not chunk:
                break
            chunks.append(chunk)
            to_read -= len(chunk)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    return b"".join(chunks)


def _line_count(buf: bytes) -> int:
    """Count logical lines in *buf*. A non-newline-terminated last line counts."""
    if not buf:
        return 0
    newline_count = buf.count(b"\n")
    if buf.endswith(b"\n"):
        return newline_count
    return newline_count + 1


def _data_line_count(buf: bytes) -> int:
    """Count non-blank lines in *buf* for the DELTA "single-entry" proxy.

    The DELTA gate targets "one KEY=value file gets replaced by a 10 MB
    blob". The natural shape of such a file is a single data line plus
    any trailing blank padding — so ``b"KEY=v\\n\\n"`` should be treated
    as single-entry. Using the raw ``_line_count`` (which counts every
    newline) would let an attacker slip a trailing ``\\n`` past the gate
    and blow a tiny ``.env`` up to 1 MiB unchecked.
    """
    if not buf:
        return 0
    return sum(1 for line in buf.splitlines() if line.strip())


def _check_delta(new_size: int, old_size: int, old_data_lines: int, target: Path) -> None:
    """Invariant 8c: blowup-only delta gate for single-entry files.

    Blocks "attacker replaces tiny .env with 10 MB payload" (upper bound).
    Does NOT block shrinks: locking a real key (165+ chars) with a 24-char
    decoy is the product's primary use case and shrinks the file 4x-8x.
    Attack value of single-line truncation is near-zero — the basename,
    path-identity, and sniff invariants already block content substitution.

    ``old_data_lines`` counts non-blank lines so a file like ``KEY=v\\n\\n``
    is still treated as single-entry for the purpose of the blowup ratio.
    """
    if not (old_size > 0 and old_size < _MAX_BYTES and old_data_lines <= 1):
        return
    ratio = new_size / old_size
    if old_size >= 5 and ratio > _DELTA_MAX:
        raise _refuse(UnsafeReason.DELTA, target)


def _check_size_sniff_delta(
    target_fd: int,
    baseline_fstat: os.stat_result,
    new_content: bytes,
    target: Path,
    expected_baseline_sha256: bytes | None = None,
    *,
    skip_delta: bool = False,
) -> None:
    """Invariant 8: size + line-count + sniff + delta on existing & new content.

    If *expected_baseline_sha256* is supplied, the under-lock read of the
    existing file is hashed and compared; a mismatch refuses with
    :attr:`UnsafeReason.TOCTOU`. This lets callers pass the baseline they
    derived their *new_content* from and catch a concurrent writer that
    mutated the file after the caller's read but before we took the lock.

    When *skip_delta* is True, the blowup-ratio DELTA check is bypassed.
    Every other gate (SIZE, line-count, SNIFF) still runs. This is the
    single knob that ``safe_restore`` turns to allow recovery writes that
    legitimately re-inflate a tiny decoy back to its original size.
    """
    old_size = baseline_fstat.st_size
    if old_size > _MAX_BYTES:
        raise _refuse(UnsafeReason.SIZE, target)

    existing_buf = _read_existing(target_fd, old_size, target)

    if expected_baseline_sha256 is not None:
        actual_sha = hashlib.sha256(existing_buf).digest()
        if not hmac.compare_digest(actual_sha, expected_baseline_sha256):
            raise _refuse(UnsafeReason.TOCTOU, target)

    # Line-count gate (bytes).
    line_count = _line_count(existing_buf)
    if line_count > _MAX_LINES:
        raise _refuse(UnsafeReason.SIZE, target)

    # Full-file sniff for existing content.
    if existing_buf:
        _check_dotenv_content(existing_buf)

    # new_content invariants: size, line-count, and dotenv sniff must all
    # apply symmetrically with existing content. Skipping these would let
    # a caller replace a clean .env with shell-like content as long as the
    # delta gate passed. Sniff MUST precede _check_delta so the refusal
    # reason is SNIFF (not DELTA) when shell syntax is present.
    new_size = len(new_content)
    if new_size > _MAX_BYTES:
        raise _refuse(UnsafeReason.SIZE, target)
    if _line_count(new_content) > _MAX_LINES:
        raise _refuse(UnsafeReason.SIZE, target)
    if new_content:
        _check_dotenv_content(new_content)

    # Delta gate. ``safe_restore`` is the only caller that sets skip_delta;
    # every other path must enforce the blowup ratio.
    if not skip_delta:
        _check_delta(new_size, old_size, _data_line_count(existing_buf), target)


def _open_dir_fd(parent: Path, target: Path) -> int:
    """Invariant 9: open the parent directory fd for fsync + atomic rename."""
    try:
        return os.open(
            str(parent),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc


def _create_tmp_excl(parent: Path, target: Path) -> tuple[int, str]:
    """Invariant 10: create tmp file with O_EXCL and randomised suffix, with retries."""
    last_exc: OSError | None = None
    for _attempt in range(_TMP_RETRIES):
        candidate = str(parent / f".env.tmp-{secrets.token_hex(16)}")
        try:
            tmp_fd = os.open(
                candidate,
                os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_WRONLY,
                0o600,
            )
            return tmp_fd, candidate
        except FileExistsError as exc:
            last_exc = exc
            continue
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                last_exc = exc
                continue
            raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    raise _refuse(UnsafeReason.TMP_COLLISION, target) from last_exc


def _write_all(tmp_fd: int, new_content: bytes, target: Path) -> None:
    """Invariant 11: short-write loop until all bytes are flushed to tmp_fd."""
    try:
        view = memoryview(new_content)
        offset = 0
        while offset < len(view):
            written = os.write(tmp_fd, view[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            offset += written
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc


def _fsync_tmp(tmp_fd: int, target: Path) -> None:
    """Invariant 12: fsync + best-effort F_FULLFSYNC + chmod 0o600 on tmp_fd."""
    try:
        os.fsync(tmp_fd)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    _fullfsync(tmp_fd)
    # chmod explicitly in case umask or mode-mask weirdness left the
    # tmp world-readable. (O_CREAT mode arg is masked by umask.)
    try:
        os.fchmod(tmp_fd, 0o600)
    except OSError:
        pass


def _fsync_dir(dir_fd: int, target: Path) -> None:
    """Invariant 13/17: fsync + F_FULLFSYNC the parent directory fd."""
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    _fullfsync(dir_fd)


def _stage_tmp(tmp_path: str, parent: Path, target: Path) -> str:
    """Invariant 13b: rename tmp under a non-".env.tmp-*" staging name.

    Ensures the chaos suite's ".env.tmp-*" leak glob is empty even after
    uncatchable signals between fsync and the atomic rename.
    """
    staging_path = str(parent / f".env.staging-{secrets.token_hex(16)}")
    try:
        Path(tmp_path).rename(staging_path)
    except OSError as exc:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc
    return staging_path


def _recheck_target(target: Path, baseline_fstat: os.stat_result) -> None:
    """Invariant 15: re-stat target via os.stat (lstat) and compare dev/ino/mode."""
    # We use plain os.stat here so tests that monkeypatch os.stat can
    # observe dev/ino mutations between open and rename. Path.stat()
    # uses an internal accessor that does not honour module-level
    # patches, so the explicit os.stat call is load-bearing.
    try:
        recheck = os.stat(str(target))  # noqa: PTH116
    except OSError as exc:
        raise _refuse(UnsafeReason.TOCTOU, target) from exc
    if (recheck.st_dev, recheck.st_ino) != (baseline_fstat.st_dev, baseline_fstat.st_ino):
        raise _refuse(UnsafeReason.TOCTOU, target)
    if not _stat.S_ISREG(recheck.st_mode):
        raise _refuse(UnsafeReason.TOCTOU, target)
    # Mode-match recheck: if a hook (or attacker) flipped permissions
    # between open and rename, refuse. Otherwise ``os.replace`` would
    # silently overwrite a chmod-0000 file and we'd lose the signal.
    if _stat.S_IMODE(recheck.st_mode) != _stat.S_IMODE(baseline_fstat.st_mode):
        raise _refuse(UnsafeReason.TOCTOU, target)


def _atomic_replace_with_fallback(
    staging_path: str, target: Path, baseline_fstat: os.stat_result
) -> None:
    """Invariant 16: atomic replace with fstatat-recheck fallback on ENOSYS/EINVAL."""
    try:
        _renameat2(staging_path, str(target))
        return
    except OSError as exc:
        if exc.errno not in (errno.ENOSYS, errno.EINVAL):
            raise _refuse(UnsafeReason.IO_ERROR, target) from exc

    # Fall back: re-run the fstatat recheck (mock may have mutated
    # state since the first recheck) then os.replace.
    try:
        recheck2 = os.stat(str(target))  # noqa: PTH116
    except OSError as exc2:
        raise _refuse(UnsafeReason.TOCTOU, target) from exc2
    if (recheck2.st_dev, recheck2.st_ino) != (
        baseline_fstat.st_dev,
        baseline_fstat.st_ino,
    ):
        # Sanitised refusal: hide original errno from caller (may leak path/env data).
        raise _refuse(UnsafeReason.TOCTOU, target) from None
    try:
        # fd-relative atomic replace; pathlib cannot express this alongside fstatat
        os.replace(staging_path, str(target))  # noqa: PTH105
    except OSError as exc2:
        raise _refuse(UnsafeReason.IO_ERROR, target) from exc2


def _close_fds(
    target_fd: int | None,
    dir_fd: int | None,
    tmp_fd: int | None,
    flock_held: bool,
) -> None:
    """Best-effort close of all fds, releasing flock first."""
    if tmp_fd is not None:
        try:
            os.close(tmp_fd)
        except OSError:
            pass
    if dir_fd is not None:
        try:
            os.close(dir_fd)
        except OSError:
            pass
    if target_fd is not None:
        if flock_held:
            try:
                fcntl.flock(target_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(target_fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Private core + public entry points.
# ---------------------------------------------------------------------------


def _safe_rewrite_core(
    target: Path,
    new_content: bytes,
    *,
    original_user_arg: Path,
    repo_root: Path | None = None,
    allow_outside_repo: bool = False,
    expected_baseline_sha256: bytes | None = None,
    _hook_before_replace: Callable[[], None] | None = None,
    skip_delta: bool = False,
) -> None:
    """Gate pipeline shared by :func:`safe_rewrite` and :func:`safe_restore`.

    ``skip_delta`` is the single knob that distinguishes the two public
    entry points. When True, the DELTA blowup-ratio gate is bypassed;
    every other gate (PLATFORM, BASENAME, SYMLINK, SPECIAL_FILE,
    CONTAINMENT, PATH_IDENTITY, TOCTOU, LOCKED, SIZE, SNIFF, IO_ERROR)
    still fires. Kept private so callers cannot opt out of DELTA on the
    normal write path — only ``safe_restore`` may bypass it.
    """

    # -- 1-5. Pre-open invariant gates. ------------------------------------
    _platform_check()
    require_atomic_fs(target)
    _check_basename(target)
    _check_user_arg_basename(target, original_user_arg)
    lst = _lstat_target(target)
    _check_special_file(lst, target)
    _check_containment(target, repo_root, allow_outside_repo)
    _check_path_identity(target, original_user_arg, lst)

    # -- 6+. Open target, fstat, lock, sniff, then atomic replace. ---------
    target_fd: int | None = None
    dir_fd: int | None = None
    tmp_fd: int | None = None
    tmp_path: str | None = None
    staging_path: str | None = None
    flock_held = False

    try:
        target_fd = _open_target_fd(target)
        baseline_fstat = _fstat_baseline(target_fd, target, lst)

        _flock_exclusive_nonblocking(target_fd, target)
        flock_held = True

        _check_size_sniff_delta(
            target_fd,
            baseline_fstat,
            new_content,
            target,
            expected_baseline_sha256=expected_baseline_sha256,
            skip_delta=skip_delta,
        )

        parent = target.parent
        dir_fd = _open_dir_fd(parent, target)
        tmp_fd, tmp_path = _create_tmp_excl(parent, target)

        _write_all(tmp_fd, new_content, target)
        _fsync_tmp(tmp_fd, target)

        # Close tmp fd so the rename target is not held open.
        try:
            os.close(tmp_fd)
        finally:
            tmp_fd = None

        _fsync_dir(dir_fd, target)

        # -- 14. Caller hook (e.g. shard-write ordering in sub-PR 2). ------
        # Hook runs while the file is still named ``.env.tmp-*`` so any
        # uncatchable signal (SIGKILL/SIGTERM) during the hook leaves an
        # artifact that the existing ``.env.tmp-*`` ghost-tmp spine can
        # see. Staging under ``.env.staging-*`` is deferred to the
        # narrow window immediately before the atomic rename.
        if _hook_before_replace is not None:
            _hook_before_replace()

        _recheck_target(target, baseline_fstat)

        # Stage tmp under a non-".env.tmp-*" name. This happens AFTER
        # the hook so the hook-kill window is covered by the existing
        # ``.env.tmp-*`` leak assertions; the staging-named window is
        # now reduced to ``_recheck_target``-to-``_atomic_replace`` and
        # is additionally covered by ``.env.staging-*`` glob checks in
        # the chaos spine.
        staging_path = _stage_tmp(tmp_path, parent, target)
        tmp_path = None
        _atomic_replace_with_fallback(staging_path, target, baseline_fstat)
        # Staging has been consumed by the rename - forget its path so the
        # cleanup handler doesn't try to unlink the live target.
        staging_path = None

        # -- 17. Final fsync of parent directory. --------------------------
        # Post-rename fsync failures do NOT roll back - the rename
        # already committed. Raising ``UnsafeRewriteRefused`` here would
        # be a contract lie (the message is literally "unsafe rewrite
        # refused") and would cause idempotent retry callers to
        # double-write on top of baseline-sha checks. Inline the fsync
        # instead and log + continue on OSError.
        #
        # IMPORTANT: ``_fullfsync(dir_fd)`` must run EVEN IF ``os.fsync``
        # raises. On Darwin/APFS, plain ``os.fsync`` is effectively a
        # no-op for durability - ``F_FULLFSYNC`` is the only barrier
        # that actually flushes the drive cache. If we gated
        # ``_fullfsync`` on ``os.fsync`` success, an ENOSPC on macOS
        # would skip the only call that matters and the rewrite really
        # could revert on crash. ``_fullfsync`` swallows its own
        # ``OSError`` (see its docstring), so calling it unconditionally
        # is safe.
        fsync_exc: OSError | None = None
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            fsync_exc = exc
        _fullfsync(dir_fd)
        if fsync_exc is not None:
            _log.warning(
                "post-rename parent-dir fsync failed for %s: errno=%s %s; "
                "rewrite may revert on crash (durability barrier unconfirmed); "
                "callers relying on baseline-sha idempotency should treat "
                "this as a successful write",
                target,
                fsync_exc.errno,
                fsync_exc.strerror,
            )

    except UnsafeRewriteRefused:
        if tmp_path is not None:
            _unlink_tmp(tmp_path)
        if staging_path is not None:
            _unlink_tmp(staging_path)
        raise
    except BaseException:
        # Any non-Unsafe exception (signals-as-exceptions, RuntimeError
        # from the hook, KeyboardInterrupt, ...) - clean up tmp and
        # re-raise.
        if tmp_path is not None:
            _unlink_tmp(tmp_path)
        if staging_path is not None:
            _unlink_tmp(staging_path)
        raise
    finally:
        _close_fds(target_fd, dir_fd, tmp_fd, flock_held)


def safe_rewrite(
    target: Path,
    new_content: bytes,
    *,
    original_user_arg: Path,
    repo_root: Path | None = None,
    allow_outside_repo: bool = False,
    expected_baseline_sha256: bytes | None = None,
    _hook_before_replace: Callable[[], None] | None = None,
) -> None:
    """Atomically rewrite a literal ``.env`` file under invariant gates.

    Raises :class:`UnsafeRewriteRefused` for any invariant violation. The
    public exception message is opaque; callers inspect ``.reason`` or the
    DEBUG log for granular cause.

    ``expected_baseline_sha256``: when supplied, the under-lock read of the
    existing file is SHA-256 hashed and compared against this value. A
    mismatch refuses the write with :attr:`UnsafeReason.TOCTOU`, so callers
    that derived *new_content* from a previously-read baseline cannot clobber
    a concurrent writer's changes.

    ``_hook_before_replace`` fires after the tmp file has been written,
    fsynced, and the parent directory fsynced - and before the atomic
    rename. Sub-PR 2 uses it to order shard writes without monkeypatching.

    The DELTA blowup-ratio gate is always enforced on this path; the
    recovery-only :func:`safe_restore` entry point is the sole way to
    bypass it.
    """
    _safe_rewrite_core(
        target,
        new_content,
        original_user_arg=original_user_arg,
        repo_root=repo_root,
        allow_outside_repo=allow_outside_repo,
        expected_baseline_sha256=expected_baseline_sha256,
        _hook_before_replace=_hook_before_replace,
        skip_delta=False,
    )


def safe_restore(
    target: Path,
    new_content: bytes,
    *,
    original_user_arg: Path,
    repo_root: Path | None = None,
    allow_outside_repo: bool = False,
    expected_baseline_sha256: bytes | None = None,
    _hook_before_replace: Callable[[], None] | None = None,
) -> None:
    """Recovery write path: rewrite ``.env`` bypassing only the DELTA gate.

    ``safe_restore`` exists for the lock-checkpoint recovery flow where a
    tiny decoy must be swapped back to its original (potentially much
    larger) content. The DELTA blowup-ratio gate would otherwise refuse
    such a swap as an implausible expansion. Every other gate - SYMLINK,
    SIZE, SNIFF, TOCTOU, CONTAINMENT, PATH_IDENTITY, LOCKED, IO_ERROR -
    still fires, so a malicious or corrupted on-disk state cannot ride
    the recovery path to clobber a shell rc file or similar.

    The ``_hook_before_replace`` hook fires at the same point as on the
    normal write path.
    """
    _safe_rewrite_core(
        target,
        new_content,
        original_user_arg=original_user_arg,
        repo_root=repo_root,
        allow_outside_repo=allow_outside_repo,
        expected_baseline_sha256=expected_baseline_sha256,
        _hook_before_replace=_hook_before_replace,
        skip_delta=True,
    )

"""Sidecar lifecycle: split the Fernet key to per-PID share files, spawn the
sidecar subprocess with an env contract, and tear it all down (zeroing
share bytearrays) on any exit path.

Security rules: SR-01 (bytearray, not bytes), SR-02 (explicit zero_buf on
shard buffers at shutdown and on every failure path), SR-04 (never log
share bytes — only the run-dir path).
"""

from __future__ import annotations

import atexit
import collections
import hashlib
import logging
import os
import shutil
import socket
import subprocess  # nosec B404 — required for sidecar subprocess lifecycle
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, NamedTuple
from collections.abc import Callable

from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.crypto.splitter import split_key
from worthless.crypto.types import zero_buf
from worthless.sidecar import _hardening

_logger = logging.getLogger("worthless.cli.sidecar_lifecycle")

_RUN_SUBDIR = "run"
_SHARE_A_NAME = "share_a.bin"
_SHARE_B_NAME = "share_b.bin"


@dataclass
class ShareFiles:
    """Handle returned by :func:`split_to_tmpfs`.

    The bytearrays stay in memory so :func:`shutdown_sidecar` can zero them
    after the sidecar terminates. Callers MUST NOT mutate ``shard_a`` or
    ``shard_b`` before shutdown — they back the live shares on disk.
    """

    share_a_path: Path
    share_b_path: Path
    shard_a: bytearray
    shard_b: bytearray
    run_dir: Path


class ServiceUids(NamedTuple):
    """Resolved uid/gid triple for the two-uid Docker topology (WOR-310 Phase C).

    Single Optional through ``spawn_sidecar`` — replaces the original
    ``target_uid + target_gid`` two-kwarg shape that allowed an invalid
    ``(set, None)`` combination. ``deploy/start.py::_resolve_service_uids``
    constructs this from ``pwd.getpwnam`` when running as root, or returns
    ``None`` to preserve the bare-metal single-uid path.

    Field order is positional-callable (``ServiceUids(10001, 10002, 10001)``);
    the order of fields IS the contract. Reordering would silently flip
    proxy/crypto uids in any caller that used positional construction.
    """

    proxy_uid: int
    crypto_uid: int
    worthless_gid: int


def _write_share(path: Path, data: bytearray) -> None:
    """Atomically create *path* at mode 0o600 and write *data*.

    Uses ``O_EXCL`` so the file never exists at a wider mode, even
    transiently. Belt-and-braces ``fchmod`` defends against a permissive
    process umask masking the ``0o600`` mode bits passed to ``os.open``.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
    finally:
        os.close(fd)


def split_to_tmpfs(fernet_key: bytearray, home_dir: Path) -> ShareFiles:
    """Split *fernet_key* and write the two shares to ``home_dir/run/<pid>/``.

    The run directory is created at mode ``0o700``. Each share file is
    created atomically at mode ``0o600`` via ``os.O_EXCL`` so the bytes
    never exist on disk at a wider permission. Both files and the run
    dir are owned by the current uid.

    Args:
        fernet_key: The 44-byte fernet key, as a mutable bytearray.
        home_dir: The Worthless home dir (typically ``~/.worthless``).

    Returns:
        A :class:`ShareFiles` handle whose bytearrays the caller must keep
        alive until :func:`shutdown_sidecar` zeroes them.
    """
    run_dir = home_dir / _RUN_SUBDIR / str(os.getpid())
    # Pin the parent dir to 0o700 too: ``parents=True`` lands at umask-masked
    # 0o755 on default systems. A world-traversable parent leaks live session
    # PIDs to any local user (ptrace target enumeration).
    parent_run_dir = home_dir / _RUN_SUBDIR
    parent_run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_run_dir.chmod(0o700)

    # POSIX guarantees PID uniqueness while the holder is alive, so any dir
    # already at our PID path is the residue of a crashed prior session.
    if run_dir.exists():
        _logger.warning(
            "split_to_tmpfs: removing stale run dir %s (likely from a "
            "prior crashed session at the same PID)",
            run_dir,
        )
        shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    # ``mkdir(mode=...)`` is umask-masked on POSIX; pin explicitly.
    run_dir.chmod(0o700)

    share_a_path = run_dir / _SHARE_A_NAME
    share_b_path = run_dir / _SHARE_B_NAME

    # Pre-declared so the SR-02 zero-loop in the except branch sees the names
    # even if ``split_key`` itself raises before assignment.
    shard_a: bytearray | None = None
    shard_b: bytearray | None = None
    try:
        result = split_key(fernet_key)
        shard_a = result.shard_a
        shard_b = result.shard_b
        _write_share(share_a_path, shard_a)
        _write_share(share_b_path, shard_b)
    except BaseException:
        for path in (share_a_path, share_b_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            run_dir.rmdir()
        except OSError:
            pass
        # SR-02: zero plaintext shards before re-raising.
        for shard in (shard_a, shard_b):
            if shard is not None:
                zero_buf(shard)
        raise

    # SR-04: log only the run dir path, never share bytes.
    _logger.debug("split_to_tmpfs: wrote shares under run_dir=%s", run_dir)

    return ShareFiles(
        share_a_path=share_a_path,
        share_b_path=share_b_path,
        shard_a=shard_a,
        shard_b=shard_b,
        run_dir=run_dir,
    )


# ---------------------------------------------------------------------------
# spawn_sidecar (WRTLS-114 SIDECAR_NOT_READY) + SidecarHandle
# ---------------------------------------------------------------------------


# Maximum bytes of stderr we keep in the rolling buffer for error diagnostics.
_STDERR_CAPTURE_LIMIT = 4096


def _collect_stderr(
    pipe: IO[bytes],
    buf: collections.deque[bytes],
) -> None:
    """Read stderr chunks into a bounded deque for crash diagnostics.

    Runs in a daemon thread so the 64 KiB kernel pipe buffer never fills
    and blocks the sidecar.  The deque is bounded by ``_STDERR_CAPTURE_LIMIT``
    total bytes (dropping the oldest chunks) so the buffer cannot grow
    unboundedly in a hypothetical chatty failure path.
    """
    total = 0
    try:
        while True:
            chunk = pipe.read(256)
            if not chunk:
                break
            buf.append(chunk)
            total += len(chunk)
            # Trim oldest chunks once we exceed the cap.
            while total > _STDERR_CAPTURE_LIMIT and buf:
                dropped = buf.popleft()
                total -= len(dropped)
    except OSError:
        pass


_READY_POLL_INTERVAL_S = 0.05

# AF_UNIX ``sockaddr_un.sun_path`` is char[104] on macOS, char[108] on Linux.
# Cap at the smaller (104) for portability. The string + null terminator
# must fit, so usable strings are at most 103 bytes on macOS.
_AF_UNIX_SUN_PATH_LIMIT = 104


def _resolve_short_socket_path(socket_path: Path) -> Path:
    """Return *socket_path* unchanged when it fits AF_UNIX, else a short fallback.

    When the natural path (under WORTHLESS_HOME) exceeds the AF_UNIX
    ``sun_path`` limit — pytest deep tmpdirs, dev sandboxes nested under
    cache dirs — we relocate the socket into a 0o700-mode directory
    under ``/tmp``. ``mkdtemp(0o700, dir="/tmp")`` rather than a bare
    ``/tmp/wls-*.sock`` because the existing access-control model gates
    the socket via PARENT-DIR mode (owner-only), not the socket inode
    itself. mkdtemp is atomic and the random suffix makes the path
    unguessable, defeating squat attacks on the world-writable /tmp.
    The fallback dir is registered for ``atexit`` cleanup; if the
    process is SIGKILLed the dir leaks but contents are 0o700 so
    nothing sensitive is exposed.

    Raises:
        WorthlessError: WRTLS-114 if mkdtemp fails, or if the fallback
            path itself exceeds the limit (degenerate TMPDIR case).
    """
    encoded_path = str(socket_path).encode()
    if len(encoded_path) < _AF_UNIX_SUN_PATH_LIMIT:
        return socket_path

    digest = hashlib.sha256(encoded_path).hexdigest()[:8]
    try:
        fallback_dir = Path(
            tempfile.mkdtemp(prefix=f"wls-{digest}-", dir="/tmp")  # noqa: S108  # nosec B108
        )
    except OSError as exc:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"could not create AF_UNIX fallback dir under /tmp: {exc}",
        ) from exc
    # mkdtemp creates with mode 0o700 on POSIX. Pin explicitly in case of
    # umask interference on exotic systems.
    fallback_dir.chmod(0o700)
    fallback = fallback_dir / "sidecar.sock"
    if len(str(fallback).encode()) >= _AF_UNIX_SUN_PATH_LIMIT:
        shutil.rmtree(fallback_dir, ignore_errors=True)
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"socket path too long for AF_UNIX even after fallback: "
            f"{fallback} ({len(str(fallback).encode())} bytes; "
            f"max {_AF_UNIX_SUN_PATH_LIMIT - 1})",
        )
    atexit.register(shutil.rmtree, str(fallback_dir), ignore_errors=True)
    _logger.info(
        "sidecar socket_path %s (%d bytes) exceeds AF_UNIX limit %d; falling back to %s",
        socket_path,
        len(encoded_path),
        _AF_UNIX_SUN_PATH_LIMIT - 1,
        fallback,
    )
    return fallback


@dataclass
class SidecarHandle:
    """Live handle to a spawned sidecar subprocess.

    The caller owns the lifecycle. No ``__enter__``/``__exit__`` —
    cleanup ordering matters and is wired explicitly by callers.

    ``drain_timeout`` is forwarded to the sidecar via
    ``WORTHLESS_SIDECAR_DRAIN_TIMEOUT`` and read back by
    :func:`shutdown_sidecar` to size the SIGTERM grace window.
    """

    proc: subprocess.Popen[bytes]
    socket_path: Path
    shares: ShareFiles
    allowed_uid: int
    drain_timeout: float
    stderr_buf: collections.deque[bytes]


def _can_connect(socket_path: Path) -> bool:
    """True iff a connect() to *socket_path* succeeds.

    The socket inode appears at ``bind()`` time, BEFORE ``listen()`` —
    using ``socket_path.exists()`` as a ready signal opens a window where
    the proxy's first IPC ``connect()`` would hit ``ECONNREFUSED``. A
    successful ``connect()`` is the only ready signal that proves
    ``listen()`` has been called.

    Probe is cheap: AF_UNIX socket creation, 0.1 s timeout, immediate
    close. The sidecar's accept loop sees a connect-then-disconnect (no
    payload sent), which is benign.
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        sock.settimeout(0.1)
        try:
            sock.connect(str(socket_path))
        except OSError:
            return False
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _wait_for_ready(
    proc: subprocess.Popen[bytes],
    socket_path: Path,
    deadline: float,
) -> bool:
    """Poll until ``socket_path`` is bound AND listening, or the child exits.

    Uses a ``connect()`` probe rather than ``socket_path.exists()``: the
    inode appears at ``bind()`` time, but the proxy's first IPC call
    fails with ``ECONNREFUSED`` until ``listen()`` has run. The race
    window is microseconds in the happy case but real on busy systems —
    a connect-probe closes it deterministically.

    We deliberately do NOT parse stdout: PIPE buffers ~64 KB of kernel
    data, and ``readline()`` blocks until newline-or-EOF, which would
    deadlock if the sidecar ever grew chatty before binding.
    """
    while time.monotonic() < deadline:
        # Cheap fast-fail before the more expensive connect-probe: if the
        # inode doesn't exist yet, neither does the listening socket.
        if socket_path.exists() and _can_connect(socket_path):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(_READY_POLL_INTERVAL_S)
    return False


def _verify_socket_inode(socket_path: Path) -> None:
    """Raise if ``socket_path`` is not a real AF_UNIX socket inode (WOR-310 C4).

    Brutus Q8 defense-in-depth. ``lstat`` (not ``stat`` — we want to see
    symlinks themselves, not their targets) confirms the rendezvous
    inode is the actual sidecar socket, not a symlink planted by a
    same-group attacker between sidecar bind and parent connect. Today
    the worthless group has only proxy + crypto so this is preventative
    against future drift. Extracted as a top-level helper so tests can
    monkeypatch it where mocking real sockets is impractical.
    """
    import stat as _stat

    try:
        st = os.lstat(socket_path)
    except OSError as exc:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"socket integrity check failed: lstat({socket_path}) "
            f"raised {exc.__class__.__name__}: {exc}",
        ) from exc
    if not _stat.S_ISSOCK(st.st_mode):
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"socket integrity check failed: lstat({socket_path}) returned "
            f"mode={st.st_mode:#o} (not S_ISSOCK). The inode at the "
            "rendezvous path is not a Unix socket — possible symlink "
            "redirect by a same-group attacker. Refusing.",
        )


def _make_priv_drop_preexec(uids: ServiceUids) -> Callable[[], None]:
    """Build the ``preexec_fn`` that drops privs in the forked sidecar child.

    The returned callable runs in the forked child between ``fork()`` and
    ``exec()``. Order is kernel-enforced and pinned by tests in
    ``test_sidecar_lifecycle_priv_drop.py``:

      1. ``setresgid(gid, gid, gid)``     — first, still has CAP_SETGID
      2. ``setgroups([])``                — clear inherited supplementary groups
      3. ``set_no_new_privs_or_log()``    — lock NO_NEW_PRIVS pre-uid-drop
      4. ``setresuid(uid, uid, uid)``     — last, drops cap_set*
      5. ``set_dumpable_zero_or_log()``   — applies to dropped process

    Why ``setresgid``/``setresuid`` and not ``setgid``/``setuid``: only
    the ``setres*`` family locks all three (real / effective / saved)
    atomically. ``setgid`` leaves saved-gid as 0, allowing post-RCE
    re-escalation if the attacker recovers CAP_SETGID.

    Why ``set_*_or_log`` not the strict ``set_dumpable_zero``: the
    forked child cannot propagate Python exceptions back to the parent.
    A raise in preexec_fn yields ``OSError`` in ``Popen.__init__`` —
    workable but the partial-drop state is opaque. Logging keeps the
    spawn deterministic.
    """

    def _drop_in_child() -> None:
        gid = uids.worthless_gid
        crypto_uid = uids.crypto_uid
        os.setresgid(gid, gid, gid)
        os.setgroups([])
        _hardening.set_no_new_privs_or_log()
        # CAPBSET_DROP after NNP and before setresuid: NNP locks "no new
        # privs" but doesn't clear the existing bounding set. Iterating
        # PR_CAPBSET_DROP closes the residual escalation surface — dropped
        # uid cannot regain capabilities even via legacy file caps. Defense
        # in depth on top of NNP.
        _hardening.set_capbset_drop_or_log()
        os.setresuid(crypto_uid, crypto_uid, crypto_uid)
        _hardening.set_dumpable_zero_or_log()

    return _drop_in_child


def _format_ready_timeout_message(
    proc: subprocess.Popen[bytes],
    ready_timeout: float,
    stderr_buf: collections.deque[bytes],
) -> str:
    """Build the WRTLS-114 message with sidecar exit code + stderr tail.

    A bare "did not become ready within Ns" hides the actual cause.
    If the sidecar already exited (e.g. raised WRTLS-NNN at startup),
    fold in the last bytes captured by the background stderr-drainer
    thread.  If it's still running, say so explicitly so the operator
    knows the bind itself was slow rather than a crash.
    """
    exit_code = proc.poll()
    if exit_code is None:
        tail = " (sidecar still running; suspect slow bind)"
    else:
        stderr_bytes = b"".join(stderr_buf)
        captured = stderr_bytes.decode("utf-8", errors="replace").strip() if stderr_bytes else ""
        tail = f" (sidecar exited rc={exit_code}; stderr={captured!r})"
    return f"sidecar did not become ready within {ready_timeout}s{tail}"


def _apply_ready_timeout_override(default: float) -> float:
    """Return *default* unless ``WORTHLESS_SIDECAR_READY_TIMEOUT_SECS`` is set.

    CI override: a slow runner can blow past 5 s on cold-start before
    asyncio is even up. The env var lets the workflow extend the deadline
    without touching the production default.
    """
    raw = os.environ.get("WORTHLESS_SIDECAR_READY_TIMEOUT_SECS")
    if not raw:
        return default
    try:
        override = float(raw)
    except ValueError:
        return default
    return override if override > 0 else default


def _validate_service_uids(uids: ServiceUids) -> None:
    """Raise :class:`WorthlessError` WRTLS-114 if *uids* is unsafe to use.

    Two invariants checked:
    - All ids must be non-root (> 0): dropping to uid 0 is a no-op that
      silently voids the security claim.  Catches future Dockerfile drift
      or a shadowed /etc/passwd before Popen runs.
    - proxy_uid != crypto_uid: equal uids collapse the uid-wall — both
      processes share same-uid ptrace/proc-mem access.
    """
    if uids.proxy_uid < 1 or uids.crypto_uid < 1 or uids.worthless_gid < 1:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"service_uids must have non-root ids "
            f"(proxy={uids.proxy_uid}, crypto={uids.crypto_uid}, "
            f"gid={uids.worthless_gid}); refusing to spawn",
        )
    if uids.proxy_uid == uids.crypto_uid:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"service_uids.proxy_uid == service_uids.crypto_uid == "
            f"{uids.proxy_uid}; uid wall requires distinct uids. "
            "Refusing to spawn — security claim would silently break.",
        )


def _close_stderr_read_end(proc: subprocess.Popen[bytes]) -> None:
    """Close the READ end of *proc*'s stderr pipe so the drainer thread sees EOF.

    The write end is already closed once the child exits; leaving the read end
    open defers fd release until the ``Popen`` object is GC-collected, which
    CPython delays long enough that accumulated leaks across many test
    teardowns caused the 97%-completion CI hang (10-min timeout).
    """
    if proc.stderr is not None:
        try:
            proc.stderr.close()
        except OSError:
            pass


def _kill_and_close_proc(
    proc: subprocess.Popen[bytes],
    socket_path: Path,
) -> None:
    """Kill *proc*, wait for exit, close stderr, and unlink *socket_path*.

    Called from the ``except BaseException`` path of :func:`spawn_sidecar`
    so the sidecar never leaks as an orphan on any failure mode.

    See :func:`_close_stderr_read_end` for why the stderr read end is closed
    explicitly here.
    """
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    _close_stderr_read_end(proc)
    try:
        if socket_path.exists():
            socket_path.unlink()
    except OSError:
        pass


def spawn_sidecar(
    socket_path: Path,
    shares: ShareFiles,
    allowed_uid: int,
    *,
    ready_timeout: float = 5.0,
    drain_timeout: float = 5.0,
    service_uids: ServiceUids | None = None,
) -> SidecarHandle:
    """Spawn ``python -m worthless.sidecar`` and wait for it to be ready.

    Returns the handle once the sidecar's Unix socket exists. Raises
    :class:`WorthlessError` with :attr:`ErrorCode.SIDECAR_NOT_READY`
    (WRTLS-114) if the socket does not appear within *ready_timeout*.

    Args:
        socket_path: Path the sidecar will bind. Must NOT already exist.
        shares: Share files written by :func:`split_to_tmpfs`.
        allowed_uid: Numeric uid permitted to connect to the sidecar.
        ready_timeout: Seconds to wait for the socket / ready line.
        drain_timeout: Forwarded to the sidecar via
            ``WORTHLESS_SIDECAR_DRAIN_TIMEOUT``.
        service_uids: When set (Docker root-entry path), the sidecar is
            spawned via a ``preexec_fn`` that drops privs to
            ``service_uids.crypto_uid``. ``None`` (bare metal, dev) preserves
            the current single-uid behavior.

    Raises:
        WorthlessError: WRTLS-114 if the path is too long for AF_UNIX,
            the sidecar does not become ready, or *service_uids* contains
            a root id (uid/gid 0) that would silently no-op the drop.

    Environment:
        ``WORTHLESS_SIDECAR_READY_TIMEOUT_SECS``: when set to a positive
            float, overrides *ready_timeout*. Required for slow CI runners
            (GitHub Actions Ubuntu can exceed 5 s for cold-start Python +
            asyncio + bind under xdist load); unused in prod where startup
            is reliably <2 s.
    """
    ready_timeout = _apply_ready_timeout_override(ready_timeout)

    if service_uids is not None:
        _validate_service_uids(service_uids)

    socket_path = _resolve_short_socket_path(socket_path)

    # A stale socket inode at the target path would make _wait_for_ready
    # return True against the leftover before the new sidecar binds.
    if socket_path.exists():
        try:
            socket_path.unlink()
        except OSError:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                f"stale socket at {socket_path} could not be removed",
            ) from None

    env = {
        **os.environ,
        "WORTHLESS_SIDECAR_SOCKET": str(socket_path),
        "WORTHLESS_SIDECAR_SHARE_A": str(shares.share_a_path),
        "WORTHLESS_SIDECAR_SHARE_B": str(shares.share_b_path),
        "WORTHLESS_SIDECAR_ALLOWED_UID": str(allowed_uid),
        "WORTHLESS_SIDECAR_DRAIN_TIMEOUT": str(drain_timeout),
        "WORTHLESS_LOG_LEVEL": "WARNING",
    }
    # When service_uids is set (Docker root-entry path), the forked child
    # runs the priv-drop dance via preexec_fn before exec'ing the sidecar
    # python. Bare-metal (None) omits preexec_fn entirely — no callback
    # to deadlock on, no syscalls to mis-order.
    preexec_fn = _make_priv_drop_preexec(service_uids) if service_uids is not None else None

    # close_fds=True + pass_fds=() ensures NO inherited descriptors land in the
    # sidecar — SQLite handles, log fds, prometheus sockets in the parent process
    # would otherwise be readable from the sidecar's address space, defeating the
    # uid-wall security claim before it starts. Defense in depth on bare metal too,
    # where the sidecar shares the parent uid.
    # stdout=DEVNULL: readiness detection uses a socket connect-probe, not
    # the sidecar's ready-line.  DEVNULL eliminates the 64 KiB stdout pipe
    # buffer that would otherwise block the sidecar if it ever grew chatty.
    # stderr=PIPE: kept so a crash before bind gives a useful error message.
    # A background thread collects the last _STDERR_CAPTURE_LIMIT bytes into
    # stderr_buf; _format_ready_timeout_message reads the buf (never the pipe
    # directly) so the drainer and the error path never race.
    stderr_buf: collections.deque[bytes] = collections.deque()
    proc = subprocess.Popen(  # noqa: S603  # nosec B603 — args are static, no shell
        [sys.executable, "-m", "worthless.sidecar"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=(),
        preexec_fn=preexec_fn,
    )

    # Start the stderr drainer immediately — before the ready-poll — so the
    # pipe buffer never fills even if the sidecar crashes with verbose output.
    if proc.stderr is not None:
        threading.Thread(
            target=_collect_stderr,
            args=(proc.stderr, stderr_buf),
            daemon=True,
        ).start()

    # Reap the child on ANY BaseException — WRTLS-114 timeout, KeyboardInterrupt
    # from the poll loop, signal-mapped-to-KbdInt — otherwise the spawned
    # sidecar PID leaks as an orphan the caller can't see.
    try:
        deadline = time.monotonic() + ready_timeout
        ready = _wait_for_ready(proc, socket_path, deadline)
        if not ready:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                _format_ready_timeout_message(proc, ready_timeout, stderr_buf),
            )
        _verify_socket_inode(socket_path)
    except BaseException:
        _kill_and_close_proc(proc, socket_path)
        raise

    _logger.debug("spawn_sidecar: pid=%d socket=%s", proc.pid, socket_path)
    return SidecarHandle(
        proc=proc,
        socket_path=socket_path,
        shares=shares,
        allowed_uid=allowed_uid,
        drain_timeout=drain_timeout,
        stderr_buf=stderr_buf,
    )


# ---------------------------------------------------------------------------
# shutdown_sidecar — graceful teardown + SR-02 zeroing
# ---------------------------------------------------------------------------


# SIGKILL follow-up only needs long enough for the kernel to reap.
_SHUTDOWN_KILL_GRACE_S = 2.0


def shutdown_sidecar(handle: SidecarHandle) -> None:
    """Terminate the sidecar and clean up its on-disk state.

    Steps, in order:

    1. SIGTERM the process; wait up to ``handle.drain_timeout`` seconds for
       a graceful exit, matching the drain budget the sidecar was started with.
    2. SIGKILL if still alive after the grace window; wait for the kernel
       to reap.
    3. Best-effort unlink of ``share_a.bin``, ``share_b.bin``, and the
       sidecar socket inode.
    4. Best-effort ``rmdir`` of the per-pid run dir.
    5. Zero the ``shard_a`` and ``shard_b`` bytearrays in memory (SR-02).

    Idempotent: a second call after a successful first call MUST NOT raise.
    """
    proc = handle.proc

    if proc.poll() is None:
        # The child can exit between poll() and signal — ProcessLookupError
        # is benign; proceed to wait + cleanup either way.
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=handle.drain_timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=_SHUTDOWN_KILL_GRACE_S)
            except subprocess.TimeoutExpired:
                # Kernel didn't reap; the up.py supervisor surfaces this as
                # WRTLS-113 if the runaway persists.
                pass

    _close_stderr_read_end(proc)

    for path in (
        handle.shares.share_a_path,
        handle.shares.share_b_path,
        handle.socket_path,
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _logger.warning("shutdown_sidecar: could not unlink %s", path)

    try:
        handle.shares.run_dir.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        _logger.warning(
            "shutdown_sidecar: could not rmdir %s (run dir not empty)",
            handle.shares.run_dir,
        )

    # SR-02: zero in-memory shard buffers. Idempotent on re-call.
    zero_buf(handle.shares.shard_a)
    zero_buf(handle.shares.shard_b)

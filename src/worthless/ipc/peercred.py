"""Peer-uid authentication for Unix-socket IPC.

Different OSes expose peer credentials through different APIs. This module
hides that split behind a single :func:`get_peer_credentials` function
that returns a :class:`PeerCredentials` dataclass regardless of platform.

Supported:
    * **Linux**  — ``getsockopt(SO_PEERCRED)``, returns pid/uid/gid.
    * **macOS**  — ``getpeereid()`` via ``ctypes``, returns uid/gid only
      (pid requires a separate ``LOCAL_PEERPID`` call we skip for v1.1).

On any other platform, importing this module succeeds but calls to
:func:`get_peer_credentials` raise :class:`UnsupportedPlatformError`.

Why uid, not pid, is the auth primitive:
    PID is captured at ``connect()`` time and is trivially reused after
    the peer exits. UID is stable for the connection lifetime and is
    what the kernel actually enforces. See socket(7) §SO_PEERCRED for
    the documented PID-reuse race.

See ``engineering/ipc-contract.md`` §Transport (auth).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
import sys
from dataclasses import dataclass
from collections.abc import Iterable

__all__ = [
    "PeerCredentials",
    "PeerCredError",
    "UnauthorizedPeerError",
    "UnsupportedPlatformError",
    "get_peer_credentials",
    "require_peer_uid",
]


@dataclass(frozen=True)
class PeerCredentials:
    """Identity of the process on the other end of a Unix socket.

    ``pid`` is best-effort: populated on Linux, ``None`` on macOS.
    Never use pid for authentication — see module docstring.
    """

    uid: int
    gid: int
    pid: int | None


class PeerCredError(Exception):
    """Base class for peer-credential errors."""


class UnsupportedPlatformError(PeerCredError):
    """Platform does not support peer credentials on Unix sockets."""


class UnauthorizedPeerError(PeerCredError):
    """Peer uid is not in the allowlist."""


# ---------------------------------------------------------------------------
# Linux — SO_PEERCRED
# ---------------------------------------------------------------------------

# struct ucred { pid_t pid; uid_t uid; gid_t gid; }
# Linux pid_t/uid_t/gid_t are all 32-bit on every supported arch.
_UCRED_STRUCT = struct.Struct("iII")
_UCRED_SIZE = _UCRED_STRUCT.size  # 12


def _get_peer_credentials_linux(sock: socket.socket) -> PeerCredentials:
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
    except OSError as exc:
        # e.g. ENOPROTOOPT on TCP sockets, EBADF on closed sockets.
        raise PeerCredError(
            f"SO_PEERCRED failed: {exc.strerror or exc} (socket family={sock.family!r})"
        ) from exc
    pid, uid, gid = _UCRED_STRUCT.unpack(raw)
    return PeerCredentials(uid=uid, gid=gid, pid=pid)


# ---------------------------------------------------------------------------
# macOS — getpeereid() via ctypes
# ---------------------------------------------------------------------------


def _bind_getpeereid() -> ctypes.CDLL | None:
    """Load libc and bind getpeereid. Returns None if libc is unreachable.

    getpeereid itself has shipped in Darwin libc since 10.4 (2005); we
    don't guard against its absence — if it's missing, the system is
    broken and failing at import is the honest behavior.
    """
    libc_path = ctypes.util.find_library("c")
    if libc_path is None:
        return None
    libc = ctypes.CDLL(libc_path, use_errno=True)
    # int getpeereid(int s, uid_t *euid, gid_t *egid);
    libc.getpeereid.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    libc.getpeereid.restype = ctypes.c_int
    return libc


_LIBC_MACOS = _bind_getpeereid() if sys.platform == "darwin" else None


def _get_peer_credentials_macos(sock: socket.socket) -> PeerCredentials:
    if _LIBC_MACOS is None:
        raise UnsupportedPlatformError("getpeereid not found in libc on this macOS build")
    uid = ctypes.c_uint32(0)
    gid = ctypes.c_uint32(0)
    rc = _LIBC_MACOS.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid))
    if rc != 0:
        # ctypes.get_errno() reads the per-thread errno maintained by the
        # `use_errno=True` libc binding. This is safe across threads — ctypes
        # snapshots errno immediately after the call returns, before the GIL
        # can hand off. Do NOT replace with `os.strerror(ctypes.get_errno())`
        # at the call site: that would cross another libc call and clobber it.
        errno = ctypes.get_errno()
        raise PeerCredError(
            f"getpeereid failed: errno={errno} ({os.strerror(errno)}) "
            f"(socket family={sock.family!r})"
        )
    return PeerCredentials(uid=uid.value, gid=gid.value, pid=None)


# ---------------------------------------------------------------------------
# Platform dispatch
# ---------------------------------------------------------------------------


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Return credentials of the process on the other end of ``sock``.

    Args:
        sock: A connected ``AF_UNIX`` stream socket.

    Raises:
        PeerCredError: socket is not ``AF_UNIX``, or the kernel refused
            the query (e.g. socket closed).
        UnsupportedPlatformError: this OS doesn't support peer creds
            over Unix sockets in a way we understand.

    Security note:
        Darwin's ``getpeereid`` returns success on non-Unix sockets,
        filling in the calling process's own uid/gid. That would let
        a bug or attack authenticate as the sidecar. We reject any
        non-AF_UNIX socket up front on every platform.
    """
    if sock.family != socket.AF_UNIX:
        raise PeerCredError(f"peer-uid auth requires AF_UNIX socket, got {sock.family!r}")
    if sys.platform == "linux":
        return _get_peer_credentials_linux(sock)
    if sys.platform == "darwin":
        return _get_peer_credentials_macos(sock)
    raise UnsupportedPlatformError(f"peer-uid auth not implemented for platform {sys.platform!r}")


def require_peer_uid(sock: socket.socket, allowed_uids: Iterable[int]) -> PeerCredentials:
    """Assert the peer is running as one of ``allowed_uids``.

    Args:
        sock: A connected ``AF_UNIX`` stream socket.
        allowed_uids: Iterable of uids permitted to connect. Empty
            allowlist always rejects.

    Returns:
        The peer credentials (useful for logging / per-peer decisions).

    Raises:
        UnauthorizedPeerError: peer uid not in ``allowed_uids``.
        PeerCredError, UnsupportedPlatformError: see
            :func:`get_peer_credentials`.
    """
    allowed_set = frozenset(allowed_uids)
    creds = get_peer_credentials(sock)
    if creds.uid not in allowed_set:
        raise UnauthorizedPeerError(
            f"peer uid {creds.uid} not in allowed set {sorted(allowed_set)} (peer pid={creds.pid})"
        )
    return creds

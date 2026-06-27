"""Atomic-rename filesystem gate (WOR-276 v2).

``safe_rewrite`` relies on POSIX ``rename(2)`` being atomic: the target
either points at the old inode or the new one, never at a partial
state. A number of filesystems break this contract and must be refused
before we attempt a transactional rewrite:

- **CIFS / SMB**: rename atomicity is not guaranteed across the wire;
  the Windows server can split the operation.
- **NFSv3/v4**: silent failures on client-side caches; rename can
  succeed on the server and be retried after a hard reboot, landing
  twice.
- **FAT / exFAT**: no metadata journal; power loss during rename can
  leave a truncated directory entry.
- **9P / fuse.drvfs**: the WSL ``/mnt/c`` bridge — atomicity depends on
  the underlying NTFS driver on the Windows side, which is not a
  POSIX rename.

For v2 we refuse. Users in the ``/mnt/c`` case are told to move their
project to ``/home`` (the Microsoft- and VS-Code-recommended path);
ephemeral-backup support for these filesystems is tracked as a
fast-follow in WOR-325.

Environment variable ``WORTHLESS_FORCE_FS=1`` bypasses the gate for
CI-on-exotic-FS and for users who have verified atomicity themselves.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused

__all__ = ["require_atomic_fs"]


_NON_ATOMIC_FSTYPES: frozenset[str] = frozenset(
    {
        # SMB / CIFS family.
        "cifs",
        "smb",
        "smbfs",
        "smb2",
        "smb3",
        # NFS family.
        "nfs",
        "nfs3",
        "nfs4",
        "nfsv3",
        "nfsv4",
        # FAT family.
        "fat",
        "vfat",
        "msdos",
        "exfat",
        # Plan 9 / WSL bridge.
        "9p",
        "v9fs",
        # FUSE bridges commonly used for Windows drives.
        "fuse.drvfs",
        "drvfs",
        "fuseblk",
    }
)


def _read_mountinfo() -> str:
    with open("/proc/self/mountinfo") as f:  # noqa: PTH123
        return f.read()


def _fstype_for(path: Path, mountinfo: str) -> str | None:
    """Return the filesystem type for the longest-prefix mount of ``path``.

    ``/proc/self/mountinfo`` rows look like:

        41 30 0:35 / / rw,relatime shared:1 - ext4 /dev/root rw

    Everything after ``- `` is fstype, source, and options. We care
    about column index 4 (mountpoint) and the token after ``-``.
    """
    best_prefix_len = -1
    best_fstype: str | None = None
    for row in mountinfo.splitlines():
        parts = row.split(" - ", maxsplit=1)
        if len(parts) != 2:
            continue
        left, right = parts
        left_fields = left.split()
        if len(left_fields) < 5:
            continue
        mountpoint = left_fields[4]
        right_fields = right.split()
        if not right_fields:
            continue
        fstype = right_fields[0]
        # Match only at mount boundaries to avoid ``/mnt/c`` matching
        # ``/mnt/combo``.
        if mountpoint == str(path) or str(path).startswith(
            mountpoint if mountpoint.endswith("/") else mountpoint + "/"
        ):
            if len(mountpoint) > best_prefix_len:
                best_prefix_len = len(mountpoint)
                best_fstype = fstype
    return best_fstype


def _is_wsl_mnt_drive(path: Path) -> bool:
    """Catch the WSL ``/mnt/<letter>/`` bridge even if mountinfo says ext4."""
    parts = path.parts
    if len(parts) < 3:
        return False
    if parts[0] != "/" or parts[1] != "mnt":
        return False
    drive = parts[2]
    return len(drive) == 1 and drive.isalpha()


def require_atomic_fs(path: Path) -> None:
    """Refuse non-atomic filesystems. No-op on Darwin; gated on Linux.

    Raises ``UnsafeRewriteRefused(UnsafeReason.FILESYSTEM)`` when
    ``path`` is on a filesystem where ``rename(2)`` cannot be trusted
    to be atomic. Set ``WORTHLESS_FORCE_FS=1`` to bypass.
    """
    if os.environ.get("WORTHLESS_FORCE_FS") == "1":
        return
    if sys.platform == "darwin":
        return
    if not sys.platform.startswith("linux"):
        return
    if _is_wsl_mnt_drive(path):
        raise UnsafeRewriteRefused(UnsafeReason.FILESYSTEM)
    try:
        mountinfo = _read_mountinfo()
    except OSError:
        # Fail open: containers/sandboxes may hide /proc. We do not want
        # the gate to brick worthless on environments where atomicity
        # is probably fine but unobservable.
        return
    fstype = _fstype_for(path, mountinfo)
    if fstype is None:
        return
    if fstype.lower() in _NON_ATOMIC_FSTYPES:
        raise UnsafeRewriteRefused(UnsafeReason.FILESYSTEM)

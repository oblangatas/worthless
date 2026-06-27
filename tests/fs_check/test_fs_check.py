"""Tests for ``worthless.cli.fs_check.require_atomic_fs``.

WOR-276 v2 regression tests 17-20. The fs_check gate sits between
``_platform_check`` and the rest of ``_safe_rewrite_core``, refusing
rewrites on filesystems that do not provide atomic ``rename(2)``:

- CIFS/SMB, NFS, FAT/exFAT, 9P (WSL ``/mnt/c`` bridge), FUSE bridges
  to Windows drives.

The module is Linux-centric (parses ``/proc/self/mountinfo``); on
Darwin it accepts everything because APFS+HFS+ both provide atomic
rename. On Windows, ``_platform_check`` already refuses, so fs_check
is never reached.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli import fs_check
from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused


# Synthetic ``/proc/self/mountinfo`` rows. Real format has 11+ fields;
# the shape after ``- <fstype>`` is what fs_check parses.
_MI_EXT4 = (
    "41 30 0:35 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
    "60 41 0:50 / /home rw,relatime shared:2 - ext4 /dev/sda1 rw\n"
)
_MI_WITH_CIFS = _MI_EXT4 + "82 41 0:77 / /mnt/share rw,relatime shared:3 - cifs //x/y rw\n"
_MI_WITH_NFS = _MI_EXT4 + "83 41 0:78 / /mnt/nfs rw,relatime shared:4 - nfs4 server:/ rw\n"
_MI_WITH_VFAT = _MI_EXT4 + "84 41 0:79 / /mnt/usb rw,relatime shared:5 - vfat /dev/sdb1 rw\n"
_MI_WSL_DRVFS = (
    _MI_EXT4
    + "90 41 0:88 / /mnt/c rw,relatime shared:6 - 9p drvfs rw,trans=virtio\n"
    + "91 41 0:89 / /mnt/d rw,relatime shared:7 - fuse.drvfs drvfs rw\n"
)


@pytest.fixture
def linux_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the Linux code path regardless of host platform."""
    monkeypatch.setattr(fs_check.sys, "platform", "linux")
    monkeypatch.delenv("WORTHLESS_FORCE_FS", raising=False)


# ---------------------------------------------------------------------------
# Test 17: non-atomic fstypes are refused.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mountinfo", "path"),
    [
        (_MI_WITH_CIFS, "/mnt/share/foo/.env"),
        (_MI_WITH_NFS, "/mnt/nfs/project/.env"),
        (_MI_WITH_VFAT, "/mnt/usb/.env"),
    ],
    ids=["cifs", "nfs", "vfat"],
)
def test_non_atomic_fstype_refused(
    linux_env: None, monkeypatch: pytest.MonkeyPatch, mountinfo: str, path: str
) -> None:
    monkeypatch.setattr(fs_check, "_read_mountinfo", lambda: mountinfo)
    with pytest.raises(UnsafeRewriteRefused) as exc:
        fs_check.require_atomic_fs(Path(path))
    assert exc.value.reason == UnsafeReason.FILESYSTEM


# ---------------------------------------------------------------------------
# Test 18: WSL ``/mnt/c`` (9p / fuse.drvfs) is refused. This is the
# "Windows dev in /mnt/c" case the project target-users memory flags —
# we fast-follow in WOR-325; for v2 we refuse.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/mnt/c/Users/alice/project/.env", "/mnt/d/work/.env"],
    ids=["mnt-c", "mnt-d"],
)
def test_wsl_mnt_prefix_refused(
    linux_env: None, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setattr(fs_check, "_read_mountinfo", lambda: _MI_WSL_DRVFS)
    with pytest.raises(UnsafeRewriteRefused) as exc:
        fs_check.require_atomic_fs(Path(path))
    assert exc.value.reason == UnsafeReason.FILESYSTEM


# ---------------------------------------------------------------------------
# Test 19: atomic fstypes are accepted.
# ---------------------------------------------------------------------------


def test_ext4_accepted(linux_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs_check, "_read_mountinfo", lambda: _MI_EXT4)
    fs_check.require_atomic_fs(Path("/home/alice/project/.env"))
    fs_check.require_atomic_fs(Path("/root.env"))  # falls on / mount


def test_darwin_always_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs_check.sys, "platform", "darwin")
    monkeypatch.delenv("WORTHLESS_FORCE_FS", raising=False)
    fs_check.require_atomic_fs(Path("/Users/alice/project/.env"))


# ---------------------------------------------------------------------------
# Test 20: ``WORTHLESS_FORCE_FS=1`` escape hatch bypasses the gate —
# documented for CI-on-exotic-FS and for the fast-follow in WOR-325.
# ---------------------------------------------------------------------------


def test_force_fs_escape_hatch_bypasses_refusal(
    linux_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WORTHLESS_FORCE_FS", "1")
    monkeypatch.setattr(fs_check, "_read_mountinfo", lambda: _MI_WITH_CIFS)
    fs_check.require_atomic_fs(Path("/mnt/share/foo/.env"))


def test_force_fs_set_to_other_value_does_not_bypass(
    linux_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WORTHLESS_FORCE_FS", "0")
    monkeypatch.setattr(fs_check, "_read_mountinfo", lambda: _MI_WITH_CIFS)
    with pytest.raises(UnsafeRewriteRefused):
        fs_check.require_atomic_fs(Path("/mnt/share/foo/.env"))


# ---------------------------------------------------------------------------
# Robustness: missing/unreadable mountinfo fails open (we do not want the
# gate to brick systems where /proc is unavailable, e.g. containers).
# ---------------------------------------------------------------------------


def test_mountinfo_read_error_fails_open(linux_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> str:
        raise OSError("no /proc")

    monkeypatch.setattr(fs_check, "_read_mountinfo", _raise)
    fs_check.require_atomic_fs(Path("/home/alice/.env"))

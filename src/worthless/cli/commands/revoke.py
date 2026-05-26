"""Revoke command -- wipe an enrolled key (shard_a + DB records)."""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import typer

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import acquire_lock, get_home
from worthless.cli.console import get_console
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.keystore import delete_fernet_key
from worthless.storage.repository import ShardRepository

_ALIAS_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


async def _revoke_async(alias: str, repo: ShardRepository, shard_a_dir: Path) -> tuple[bool, bool]:
    """Delete all DB records and wipe shard_a file for *alias*.

    Returns (revoked, was_last) where was_last is True when zero enrollments
    remain after this revoke.

    Note: zeroing shard_a is best-effort on CoW filesystems (APFS, btrfs).
    Full-disk encryption is the real mitigation for data-at-rest.
    """
    shard_a_path = shard_a_dir / alias

    # Atomic DB cleanup: spend_log + enrollment_config + shard (CASCADE) in one txn
    db_deleted = await repo.revoke_all(alias)

    # Check remaining count before touching shard_a so the count is stable.
    remaining = await repo.count_aliases()

    # Best-effort wipe of shard_a: zero contents, then unlink.
    # O_NOFOLLOW prevents TOCTOU symlink race.
    shard_a_exists = shard_a_path.exists() and not shard_a_path.is_symlink()
    if shard_a_exists:
        try:
            fd = os.open(str(shard_a_path), os.O_WRONLY | os.O_NOFOLLOW)
        except OSError:
            # Symlink appeared between check and open, or permission error — skip wipe
            shard_a_path.unlink(missing_ok=True)
            return True, remaining == 0
        try:
            size = os.fstat(fd).st_size
            if size > 0:
                os.write(fd, b"\x00" * size)
                os.fsync(fd)
        finally:
            os.close(fd)
        shard_a_path.unlink()
        return True, remaining == 0

    return db_deleted, remaining == 0


def _revoke_key(alias: str) -> None:
    """Core revoke logic."""
    if not _ALIAS_RE.match(alias):
        raise WorthlessError(ErrorCode.SCAN_ERROR, f"Invalid alias: {alias!r}")

    console = get_console()
    home = get_home()

    with acquire_lock(home):

        async def _run() -> tuple[bool, bool]:
            async with open_repo(home) as repo:
                await repo.initialize()
                return await _revoke_async(alias, repo, home.shard_a_dir)

        revoked, was_last = asyncio.run(_run())

        if revoked and was_last:
            # Still inside the lock — prevents a concurrent enroll from slipping
            # in between the count check and the keychain delete.
            delete_fernet_key(home.base_dir)
            # Remove the bootstrap sentinel so the next enroll treats this as a
            # fresh install and generates a new Fernet key rather than failing
            # with WRTLS-102 (key gone but sentinel says "already set up").
            home.bootstrapped_marker.unlink(missing_ok=True)

    if revoked:
        console.print_success(
            f"Key '{alias}' revoked. Shard and enrollments removed.\n"
            "Note: CoW filesystems (APFS, btrfs) may retain copies of zeroed data. "
            "Use full-disk encryption for complete erasure."
        )
    else:
        console.print_warning(f"Alias '{alias}' not found. Nothing to revoke.")


def register_revoke_commands(app: typer.Typer) -> None:
    """Register the revoke command on the Typer app."""

    @app.command()
    @error_boundary
    def revoke(
        alias: str = typer.Option(..., "--alias", "-a", help="Alias of the key to revoke"),
    ) -> None:
        """Permanently revoke an enrolled API key."""
        _revoke_key(alias)

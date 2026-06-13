"""`worthless uninstall` (WOR-435) — restore every locked .env, then wipe.

Assembles existing primitives rather than duplicating crypto:
- enumerate locked .env files via ``ShardRepository.list_enrollments`` (each
  carries the ``original_mode`` captured by ``lock`` per WOR-715);
- reconstruct + restore each key reusing ``unlock``'s ``_unlock_batch``;
- restore the original file mode, clamped to owner-only (``secure_restore_mode``),
  informing the user when a loose mode was tightened (human gets asked);
- wipe keychain + ``~/.worthless`` — but ONLY after every restore succeeds
  (the restore-ALL-then-wipe key-shredder guard: a wipe that runs after a
  failed restore would delete shard-B while the real key was never put back).
"""

from __future__ import annotations

import asyncio
import os
import shutil
from collections import defaultdict
from pathlib import Path

import typer

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import acquire_lock, get_home
from worthless.cli.commands.unlock import (
    _apply_openclaw_unlock,
    _build_oc_restores,
    _unlock_batch,
)
from worthless.cli.console import get_console
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.keystore import delete_fernet_key

# ``0o700`` keeps only the owner's bits; ANDing with it strips every group and
# other bit (and setuid/setgid/sticky), so a restored .env that holds the real
# reconstructed key can never be read by another local user.
_OWNER_ONLY_MASK = 0o700


def secure_restore_mode(original_mode: int | None) -> int | None:
    """The safe POSIX mode to restore for a .env that now holds the real key.

    Restore the user's original permission, but NEVER looser than owner-only:
    all group/other bits are stripped so the restored .env (holding the
    reconstructed plaintext key) is not readable by other local users.
    ``None`` = "mode was never captured (pre-715 install) — leave the file
    mode as-is".

    Rationale (brutus /merge-ready gate-6 P1): ``original_mode`` may be an
    accidental or attacker-influenced ``0o666`` captured at lock time; a blind
    ``chmod`` back would re-expose the key — the precise ``.env``-at-rest leak
    ``lock`` exists to close. Owner-only is the security floor.
    """
    if original_mode is None:
        return None
    return original_mode & _OWNER_ONLY_MASK


def _decide_mode(
    env_path: str, original_mode: int | None, *, assume_yes: bool, console
) -> int | None:
    """Choose the mode to restore for one .env, informing/asking the user.

    - ``None`` (never captured) → ``None`` (leave file as-is).
    - already owner-only (incl. tighter ``0o400``) → restore it exactly, silently.
    - looser than owner-only → clamp to the safe mode. A human (no ``--yes``)
      is asked whether to keep their original instead; an agent (``--yes`` /
      piped EOF) gets the safe default plus a plain notice. Non-judgmental.
    """
    safe = secure_restore_mode(original_mode)
    if original_mode is None or safe == original_mode:
        return original_mode  # nothing to clamp

    if not assume_yes:
        # Human at the keyboard — let them decide, plainly. typer.confirm
        # returns the default on EOF (piped/closed stdin), so the safe path
        # is the no-input fallback too.
        keep_safe = typer.confirm(
            f"{env_path} was 0o{original_mode:o} — other users on this machine could read "
            f"this file, which now holds your real key. Set minimal-safe 0o{safe:o}?",
            default=True,
        )
        if not keep_safe:
            console.print_warning(
                f"{env_path}: kept original 0o{original_mode:o} at your request "
                f"(other local users can read this key)."
            )
            return original_mode
        return safe

    # Agent / --yes: clamp to safe, tell them plainly how to revert.
    console.print_warning(
        f"{env_path}: original 0o{original_mode:o} was readable by other users; "
        f"set to minimal-safe 0o{safe:o}. Run 'chmod {original_mode:o} {env_path}' to revert."
    )
    return safe


async def _restore_all(
    home, repo, *, assume_yes: bool, console
) -> tuple[
    list[tuple[str, int | None]],
    list[tuple[str, str]],
    list,
    list[str],
]:
    """Reconstruct + restore every locked .env, applying the mode policy.

    Returns ``(restored, failed, unlocked, enroll_only)``:
    - ``restored`` — ``(env_path, applied_mode)`` per file put back.
    - ``failed`` — ``(env_path, reason)`` per file that could NOT be restored
      (triggers the no-wipe key-shredder guard in the caller).
    - ``unlocked`` — ``OcRestore`` objects for OpenClaw symmetric undo.
    - ``enroll_only`` — aliases with no ``.env`` (from ``worthless enroll``);
      nothing to restore, so they DON'T block the wipe — surfaced as a warning.

    Each restore reuses ``unlock``'s transactional ``_unlock_batch`` (rewrites
    the .env with the real key, deletes that file's shard rows), then applies
    :func:`_decide_mode`.
    """
    await repo.initialize()
    enrollments = await repo.list_enrollments()

    by_path: dict[str, dict] = defaultdict(lambda: {"aliases": [], "mode": None})
    enroll_only: list[str] = []
    for e in enrollments:
        if e.env_path is None:
            # No .env to restore (enroll-only key). Removing it on wipe is the
            # only option — warn, but never block the whole uninstall on it.
            enroll_only.append(e.key_alias)
            continue
        slot = by_path[e.env_path]
        slot["aliases"].append(e.key_alias)
        if slot["mode"] is None:
            slot["mode"] = e.original_mode

    restored: list[tuple[str, int | None]] = []
    failed: list[tuple[str, str]] = []
    # OcRestore objects for the OpenClaw symmetric undo — built by unlock's own
    # _build_oc_restores so uninstall feeds _apply_openclaw_unlock exactly what
    # it expects (WOR-621 changed the contract from (provider, alias) tuples).
    unlocked: list = []
    for env_path, slot in by_path.items():
        try:
            planned = await _unlock_batch(slot["aliases"], home, repo, Path(env_path))
            unlocked.extend(await _build_oc_restores(planned, repo, console))
            target = _decide_mode(env_path, slot["mode"], assume_yes=assume_yes, console=console)
            if target is not None:
                os.chmod(env_path, target)  # noqa: PTH101
            restored.append((env_path, target))
        except Exception as exc:  # noqa: BLE001 — collect every failure, never abort mid-loop
            failed.append((env_path, str(exc)))

    return restored, failed, unlocked, enroll_only


def _run_uninstall(*, assume_yes: bool) -> None:
    """Restore every locked .env, then (only if all succeeded) wipe Worthless."""
    console = get_console()
    home = get_home()

    with acquire_lock(home):

        async def _run():
            async with open_repo(home) as repo:
                return await _restore_all(home, repo, assume_yes=assume_yes, console=console)

        restored, failed, unlocked, enroll_only = asyncio.run(_run())

        for env_path, mode in restored:
            shown = f"0o{mode:o}" if mode is not None else "unchanged"
            console.print_success(f"restored {env_path}  (mode {shown})")

        for alias in enroll_only:
            console.print_warning(
                f"enroll-only key {alias!r} has no .env to restore — it will be removed. "
                "Rotate it at your provider if you still need it."
            )

        if failed:
            # Key-shredder guard: a restore failed → DO NOT wipe. shard-B for the
            # failed files is still in the DB for a retry.
            for env_path, why in failed:
                console.print_warning(f"could NOT restore {env_path}: {why}")
            console.print_failure(
                f"Aborting uninstall — {len(failed)} file(s) could not be restored. "
                "Nothing was wiped; fix the above and re-run, or unlock those files manually."
            )
            raise WorthlessError(
                ErrorCode.SHARD_STORAGE_FAILED,
                "uninstall aborted: not all .env files restored",
            )

        # OpenClaw symmetric undo — best-effort, NEVER blocks the wipe (L1).
        # Removes worthless-* providers from openclaw.json so an OpenClaw-primary
        # user isn't left pointing at the now-deleted proxy.
        _apply_openclaw_unlock(unlocked, console, home)

        delete_fernet_key(home.base_dir)
        home.bootstrapped_marker.unlink(missing_ok=True)

    # Remove the home dir last (outside the lock — we're deleting its dir).
    shutil.rmtree(home.base_dir, ignore_errors=True)

    n = len(restored)
    if home.base_dir.exists():
        # Partial wipe (e.g. an immutable/locked file survived rmtree). Tell the
        # truth — do NOT claim "~/.worthless removed" right after warning it wasn't.
        console.print_warning(
            f"~/.worthless could not be fully removed ({home.base_dir}); delete it manually."
        )
        console.print_success(
            f"Worthless uninstalled. {n} .env file(s) restored to their real keys; "
            "keychain entry removed (some ~/.worthless files remain — see the warning above)."
        )
    else:
        console.print_success(
            f"Worthless uninstalled. {n} .env file(s) restored to their real keys; "
            "keychain entry and ~/.worthless removed."
        )


def register_uninstall_commands(app: typer.Typer) -> None:
    """Register the ``uninstall`` command on *app*."""

    @app.command()
    @error_boundary
    def uninstall(
        yes: bool = typer.Option(
            False, "--yes", "-y", help="Skip the permission prompt (for agents / scripts)."
        ),
    ) -> None:
        """Restore every locked .env to its real key, then remove Worthless.

        Permissions are restored owner-only by default (never re-exposing a key
        to other local users). If any .env can't be restored, nothing is wiped.
        """
        _run_uninstall(assume_yes=yes)

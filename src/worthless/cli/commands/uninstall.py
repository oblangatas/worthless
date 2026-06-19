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
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

import typer

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import WorthlessHome, acquire_lock
from worthless.cli.commands.down import _stop_daemon
from worthless.cli.commands.unlock import (
    _apply_openclaw_unlock,
    _build_oc_restores,
    _unlock_batch,
)
from worthless.cli.console import get_console
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.keystore import delete_fernet_key
from worthless.crypto.types import zero_buf

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


def _zero_restore_keys(restores: list) -> None:
    """Zero every reconstructed plaintext key held by built ``OcRestore``s.

    On the happy path ``_apply_openclaw_unlock`` zeros these in its ``finally``.
    But on the restore-failure path the wipe is aborted BEFORE that call, so the
    reconstructed keys would otherwise linger in heap until GC. Zero them here so
    a failed uninstall never leaves real key material in memory (SR-02).
    ``zero_buf`` is idempotent, so re-zeroing an already-cleared buffer is safe.
    """
    for r in restores:
        key = getattr(r, "plaintext_key", None)
        if key is not None:
            zero_buf(key)


async def _restore_all(
    home, repo, *, assume_yes: bool, console
) -> tuple[
    list[tuple[str, int | None]],
    list[tuple[str, str]],
    list[str],
    list,
    list[str],
]:
    """Reconstruct + restore every locked .env, applying the mode policy.

    Returns ``(restored, failed, missing, unlocked, enroll_only)``:
    - ``restored`` — ``(env_path, applied_mode)`` per file put back.
    - ``failed`` — ``(env_path, reason)`` per file that EXISTS but could NOT be
      restored (triggers the no-wipe key-shredder guard in the caller).
    - ``missing`` — ``env_path`` whose file was deleted (project removed): no key
      to brick, so a skip+warn, NOT a block (BUG-2).
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
    missing: list[str] = []
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
            # Route by the ACTUAL state, only AFTER attempting the restore — never
            # pre-classify via exists() (CodeRabbit): a .env confirmed GONE
            # (deleted project) is a skip+warn, nothing to brick (BUG-2); a file
            # that's present but unrestorable (transient EACCES, tamper) falls to
            # `failed` and still trips the key-shredder guard.
            if not Path(env_path).exists():
                missing.append(env_path)
            else:
                failed.append((env_path, str(exc)))

    return restored, failed, missing, unlocked, enroll_only


def _resolve_home_no_bootstrap() -> WorthlessHome:
    """The WorthlessHome for the configured path WITHOUT bootstrapping.

    uninstall must NOT re-create or re-init a home it's about to delete, and a
    corrupt DB must surface as "broken install" (handled in _run_uninstall),
    not crash get_home()/ensure_home()'s DB-init. So build the dataclass
    directly — the same object get_home would, minus the bootstrap side effects.
    """
    env_home = os.environ.get("WORTHLESS_HOME")
    return WorthlessHome(base_dir=Path(env_home)) if env_home else WorthlessHome()


def _stdin_is_tty() -> bool:
    """Whether stdin is an interactive terminal (extracted for testability)."""
    return sys.stdin.isatty()


def _confirm_uninstall(console, *, assume_yes: bool) -> bool:  # noqa: ANN001
    """Return True to proceed. A human at a TTY is asked; a non-interactive caller
    without --yes is refused (raise) rather than prompted (typer.confirm on closed
    stdin raises Abort → a confusing internal error). Returns False on an
    interactive decline.
    """
    if assume_yes:
        return True
    if not _stdin_is_tty():
        console.print_failure(
            "Refusing to uninstall without confirmation in a non-interactive "
            "shell. Re-run with --yes to confirm (this restores your real keys "
            "to every locked .env, then removes Worthless)."
        )
        raise typer.Exit(code=1)
    if not typer.confirm(
        "This restores your real API keys into every locked .env and removes "
        "Worthless from this machine. Continue?",
        default=True,
    ):
        console.print_hint("Uninstall cancelled — nothing was changed.")
        return False
    return True


def _handle_broken_repo(console, exc, *, force: bool):  # noqa: ANN001, ANN201
    """BUG-1: the install can't be read (no fernet key / corrupt DB). Without
    --force refuse cleanly; with --force warn and return empty buckets to wipe.
    """
    if not force:
        console.print_failure(
            f"Can't read this Worthless install ({exc}). It looks broken, so "
            "keys can't be restored. Re-run with --force to wipe the remains "
            "anyway — your real keys are unrecoverable from here; rotate them "
            "at your provider."
        )
        raise typer.Exit(code=1) from exc
    console.print_warning(
        f"--force: could not restore keys (broken install: {exc}); wiping the "
        "remains anyway. Rotate your keys at the provider."
    )
    return [], [], [], [], []


def _report_outcomes(console, restored, missing, enroll_only) -> None:  # noqa: ANN001
    """Print per-file results: restored, skipped-because-gone, enroll-only."""
    for env_path, mode in restored:
        shown = f"0o{mode:o}" if mode is not None else "unchanged"
        console.print_success(f"restored {env_path}  (mode {shown})")
    for env_path in missing:
        # BUG-2: project deleted — nothing to restore, never a block.
        console.print_warning(
            f"skipping {env_path}: the project file is gone — nothing to restore "
            "(removing the dead record)."
        )
    for alias in enroll_only:
        console.print_warning(
            f"enroll-only key {alias!r} has no .env to restore — it will be removed. "
            "Rotate it at your provider if you still need it."
        )


def _guard_failed_restores(console, failed, unlocked, *, force: bool) -> None:  # noqa: ANN001
    """Key-shredder guard: a .env EXISTS but its key couldn't be reconstructed.
    Zero any built keys (SR-02), then block (no --force) or warn and continue
    (--force).
    """
    if not failed:
        return
    _zero_restore_keys(unlocked)
    for env_path, why in failed:
        console.print_warning(f"could NOT restore {env_path}: {why}")
    if not force:
        console.print_failure(
            f"Aborting uninstall — {len(failed)} file(s) could not be restored. "
            "Nothing was wiped; fix the above and re-run, or pass --force to wipe "
            "anyway (those keys become unrecoverable)."
        )
        raise WorthlessError(
            ErrorCode.SHARD_STORAGE_FAILED,
            "uninstall aborted: not all .env files restored",
        )
    console.print_warning(
        f"--force: wiping despite {len(failed)} file(s) whose keys could not be "
        "restored. Rotate those keys at your provider."
    )


def _finalize_wipe(console, home, n_restored: int) -> None:  # noqa: ANN001
    """Remove ~/.worthless (outside the lock) and report honestly on partial wipes."""
    shutil.rmtree(home.base_dir, ignore_errors=True)
    if home.base_dir.exists():
        # Partial wipe (e.g. an immutable/locked file survived rmtree). Tell the
        # truth — do NOT claim "~/.worthless removed" right after warning it wasn't.
        console.print_warning(
            f"~/.worthless could not be fully removed ({home.base_dir}); delete it manually."
        )
        console.print_success(
            f"Worthless uninstalled. {n_restored} .env file(s) restored to their real keys; "
            "keychain entry removed (some ~/.worthless files remain — see the warning above)."
        )
    else:
        console.print_success(
            f"Worthless uninstalled. {n_restored} .env file(s) restored to their real keys; "
            "keychain entry and ~/.worthless removed."
        )


def _run_uninstall(*, assume_yes: bool, force: bool = False) -> None:
    """Restore every locked .env, then (only when it's safe) wipe Worthless.

    ``force`` is the escape hatch for broken states: it wipes even when keys
    can't be restored — a broken repo (no fernet key / corrupt DB) or a
    present-but-unrestorable ``.env``. Without it, an unrestorable REAL key
    blocks the wipe (key-shredder guard); a MISSING ``.env`` never blocks.
    """
    console = get_console()
    # Don't bootstrap a home we're about to delete: resolve it directly so a
    # corrupt DB surfaces as "broken install" (handled below), not a get_home crash.
    home = _resolve_home_no_bootstrap()

    if not home.base_dir.exists():
        console.print_success("Nothing to uninstall — Worthless is not installed here.")
        return

    if not _confirm_uninstall(console, assume_yes=assume_yes):
        return

    oc_partial = False
    with acquire_lock(home):

        async def _run():
            async with open_repo(home) as repo:
                return await _restore_all(home, repo, assume_yes=assume_yes, console=console)

        try:
            restored, failed, missing, unlocked, enroll_only = asyncio.run(_run())
        except (WorthlessError, sqlite3.Error, OSError) as exc:
            restored, failed, missing, unlocked, enroll_only = _handle_broken_repo(
                console, exc, force=force
            )

        _report_outcomes(console, restored, missing, enroll_only)
        _guard_failed_restores(console, failed, unlocked, force=force)

        # fzbi: stop a running proxy daemon before wiping its home. Best-effort —
        # a daemon we can't stop must never block the teardown.
        try:
            _stop_daemon(home, console)
        except Exception as exc:  # noqa: BLE001 — best-effort; never block the wipe
            console.print_warning(f"could not stop the proxy daemon ({exc}); continuing.")

        # OpenClaw symmetric undo — best-effort; a partial failure → exit 73 AFTER
        # the wipe (jl13), mirroring unlock.
        oc_partial = _apply_openclaw_unlock(unlocked, console, home)

        # Cleanup is best-effort so a broken install (key already gone) still wipes.
        try:
            delete_fernet_key(home.base_dir)
        except Exception as exc:  # noqa: BLE001 — best-effort cleanup
            console.print_warning(f"could not remove the keychain entry ({exc}); continuing.")
        home.bootstrapped_marker.unlink(missing_ok=True)

    _finalize_wipe(console, home, len(restored))

    if oc_partial:
        raise typer.Exit(code=73)


def register_uninstall_commands(app: typer.Typer) -> None:
    """Register the ``uninstall`` command on *app*."""

    @app.command()
    @error_boundary
    def uninstall(
        yes: bool = typer.Option(
            False,
            "--yes",
            "-y",
            help="Skip all confirmation prompts (for agents / scripts).",
        ),
        force: bool = typer.Option(
            False,
            "--force",
            help="Wipe even when keys can't be restored — a broken install "
            "(missing fernet key / corrupt DB) or an unrestorable .env. Those "
            "keys become unrecoverable; rotate them at your provider.",
        ),
    ) -> None:
        """Restore every locked .env to its real key, then remove Worthless.

        Permissions are restored owner-only by default (never re-exposing a key
        to other local users). A deleted project's .env is skipped; an
        unrestorable real key blocks the wipe unless you pass --force.
        """
        _run_uninstall(assume_yes=yes, force=force)

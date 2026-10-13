"""Embedded ``SKILL.md`` install/uninstall for OpenClaw.

We own ``~/.openclaw/workspace/skills/worthless/`` (locked decision L3)
and overwrite stale content. Installs are stage-then-rename so a crash
mid-copy leaves the user with either the old folder or no folder — never
half-written state.

Symlinks are refused on both install and uninstall (F34): an attacker
who can plant a link could redirect a privileged write or sweep an
unrelated directory on unlock.

Spec: ``.claude/plans/graceful-dreaming-reef.md`` §"Public API contracts
for Phase 2.a" / ``worthless.openclaw.skill`` and failure-mode rows
F30, F31, F33, F34, F35.
"""

from __future__ import annotations

import contextlib
import errno as _errno_mod
import functools
import os
import re
import shutil
import tempfile
from pathlib import Path

from worthless.openclaw.errors import (
    OpenclawErrorCode,
    OpenclawIntegrationError,
)

_SKILL_ASSETS_DIR = (Path(__file__).resolve().parent / "skill_assets").resolve()
_SKILL_FILE = "SKILL.md"
_SKILL_DIR_NAME = "worthless"
_VERSION_LINE = re.compile(r"^Version:\s*(\S+)\s*$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Asset access
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _read_skill_asset() -> str:
    """Return the embedded ``SKILL.md`` body as a UTF-8 string.

    Reads from ``skill_assets/`` next to this module via ``Path(__file__)``
    rather than ``importlib.resources``. Both work for source + wheel
    installs; ``Path(__file__)`` is simpler, has zero false-positive
    Python-3.7-compatibility lint hits, and works for our setuptools
    package-data layout. The cache is process-lifetime (the asset is
    embedded and immutable). Tests that monkeypatch this function should
    call ``_read_skill_asset.cache_clear()``.
    """
    return (_SKILL_ASSETS_DIR / _SKILL_FILE).read_text(encoding="utf-8")


def current_version() -> str:
    """Return the version string declared in the embedded ``SKILL.md``.

    Parses the first ``Version: <token>`` line. Phase 3 will replace the
    body with the real skill content; the parsing contract stays.
    """
    try:
        body = _read_skill_asset()
    except OSError as exc:
        raise OpenclawIntegrationError(
            OpenclawErrorCode.SKILL_INSTALL_FAILED,
            f"embedded SKILL.md unreadable: {exc}",
        ) from exc
    match = _VERSION_LINE.search(body)
    if not match:
        # Defensive: a future SKILL.md without a Version line is a bug we
        # want to catch loudly rather than silently fall back.
        raise OpenclawIntegrationError(
            OpenclawErrorCode.SKILL_INSTALL_FAILED,
            "embedded SKILL.md is missing a Version: line",
        )
    return match.group(1)


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------


def _refuse_if_symlink(path: Path) -> None:
    """Raise SYMLINK_REFUSED if ``path`` is a symlink.

    Uses ``lstat`` semantics via ``Path.is_symlink`` so a dangling link
    is still caught. Canonicalize via ``Path.resolve`` (F35) for the
    final on-disk identity check elsewhere.
    """
    if path.is_symlink():
        raise OpenclawIntegrationError(
            OpenclawErrorCode.SYMLINK_REFUSED,
            f"refusing to follow symlink at {path}",
        )


def _cleanup_install(staging: Path | None, final: Path, retired: Path | None) -> None:
    """Remove the staging dir; put the previous install back if the new one is missing.

    On success *final* exists, so this only drops the moved-aside previous
    install. On a failure or Ctrl-C it restores it (worthless-1jfr).
    """
    if staging is not None:
        shutil.rmtree(staging, ignore_errors=True)
    if retired is None:
        return
    if not final.exists():
        with contextlib.suppress(OSError):
            os.rename(retired, final)  # noqa: PTH104 — put the previous install back
    shutil.rmtree(retired, ignore_errors=True)


def install(target_dir: Path) -> Path:
    """Install the embedded skill folder at ``target_dir/worthless/``.

    Stage into ``target_dir/.worthless.tmp.<pid>/``, then atomic-rename
    over any existing folder. Cleans up the staging dir on any failure.

    Returns the resolved final path. Raises :class:`OpenclawIntegrationError`
    on hard refusals (e.g. symlink at the destination or parent, missing version).
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    # F34: refuse symlinks on BOTH the parent skills/ dir AND the final
    # worthless/ entry. A symlinked parent would redirect the entire install
    # tree outside the OpenClaw workspace just as effectively as a symlinked
    # destination — the single-level check was insufficient.
    _refuse_if_symlink(target_dir)
    final = target_dir / _SKILL_DIR_NAME
    _refuse_if_symlink(final)

    # ``staging`` is bound INSIDE the try so a mkdtemp failure
    # (target_dir not writable, ENOSPC) wraps cleanly as
    # SKILL_INSTALL_FAILED instead of leaking a raw OSError to callers.
    staging: Path | None = None
    retired: Path | None = None  # the previous install, moved aside until the new one is in
    try:
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".worthless.tmp.{os.getpid()}.",
                dir=str(target_dir),
            )
        )
        # Copy every embedded asset file into the staging dir. Reading
        # the directory next to the module keeps this content-agnostic
        # (R10) — Phase 3 can add files without us touching this code.
        for entry in _SKILL_ASSETS_DIR.iterdir():
            name = entry.name
            # Skip Python package noise (__init__.py, __pycache__/),
            # dotfiles (.DS_Store, .gitkeep), and bytecode. The asset
            # dir is now a real on-disk directory (not a Traversable),
            # so this filter is load-bearing — without it we'd ship
            # whatever is sitting next to SKILL.md.
            if name == "__init__.py" or name.startswith((".", "__")):
                continue
            if entry.suffix in {".py", ".pyc"}:
                continue
            if not entry.is_file():
                continue
            (staging / name).write_text(entry.read_text(encoding="utf-8"), encoding="utf-8")

        # Move the previous install aside (never delete it first): a Ctrl-C or
        # a failed rename between delete and rename left no skill at all
        # (worthless-1jfr). If the process is killed outright in between, the
        # aside copy is a dot-folder OpenClaw ignores, and the next install
        # puts the skill back.
        retired = staging.with_name(staging.name + ".old")
        try:
            os.rename(final, retired)  # noqa: PTH104
        except FileNotFoundError:
            retired = None  # first install

        # ``os.replace`` (not ``Path.replace``) is patchable at the module
        # level so failure-injection tests can simulate disk-full / EACCES.
        try:
            os.replace(staging, final)  # noqa: PTH105
        except OSError as _exc:
            # ENOTEMPTY (macOS errno 66, Linux errno 39): rename(2) refuses
            # to replace a non-empty directory.  This is a benign race when
            # two concurrent processes (e.g. xdist workers) both run
            # install() at the same time — the winner already placed a valid
            # skill directory at ``final``.  Accept the result and discard
            # our staging copy — but only after verifying the winner wrote
            # the SAME asset content we would have written.  If final is
            # missing SKILL.md or contains stale content (e.g. rmtree silently
            # failed to delete an old version), re-raise so the caller sees a
            # real failure rather than silently keeping wrong content.
            _installed = final / _SKILL_FILE
            if (
                _exc.errno == _errno_mod.ENOTEMPTY
                and _installed.is_file()
                and _installed.read_text(encoding="utf-8") == _read_skill_asset()
            ):
                shutil.rmtree(staging, ignore_errors=True)
                staging = None
            else:
                raise
        staging = None  # replace consumed it (or we cleaned it above)
        _cleanup_install(None, final, retired)  # drops the previous install
        retired = None
    except BaseException as exc:
        # Any failure (mkdtemp failure, EACCES, ENOSPC, simulated rename
        # failures) is wrapped as SKILL_INSTALL_FAILED so callers in
        # apply_lock() can surface it as a structured event without
        # leaking raw OSError types into --json output. Always clean up
        # the staging dir (F33) — guarded since mkdtemp may not have run.
        _cleanup_install(staging, final, retired)
        if not isinstance(exc, Exception) or isinstance(exc, OpenclawIntegrationError):
            raise  # a Ctrl-C stays a Ctrl-C
        raise OpenclawIntegrationError(
            OpenclawErrorCode.SKILL_INSTALL_FAILED,
            f"failed to install skill into {final}: {exc}",
        ) from exc

    return final.resolve()


def uninstall(target_dir: Path) -> bool:
    """Remove ``target_dir/worthless/`` if present. Returns True on removal.

    Tolerant: a missing target_dir or worthless/ subfolder returns False
    without error — supports doctor/unlock retries on partially-installed
    hosts (F-XS-44).

    Refuses to follow a symlink at the destination (F34).
    """
    final = target_dir / _SKILL_DIR_NAME
    # One ``lstat`` decides the whole branch: symlink → refuse;
    # missing → no-op; real dir → remove. Saves three pre-stats.
    try:
        st_mode = final.lstat().st_mode
    except FileNotFoundError:
        return False

    import stat as _stat

    if _stat.S_ISLNK(st_mode):
        raise OpenclawIntegrationError(
            OpenclawErrorCode.SYMLINK_REFUSED,
            f"refusing to follow symlink at {final}",
        )

    shutil.rmtree(final)
    return True

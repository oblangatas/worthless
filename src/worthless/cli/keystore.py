"""OS keyring-backed Fernet key storage with file fallback."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import sys
from pathlib import Path

import keyring

from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.platform import IS_WINDOWS
from worthless.crypto.types import zero_buf

# WOR-456: on macOS, route writes through our own ctypes wrapper that
# explicitly pins ``kSecAttrSynchronizable=kCFBooleanFalse`` so Fernet keys
# never leak into iCloud Keychain. The upstream ``keyring`` library omits
# the attribute, leaving items eligible for sync. ``keystore_macos`` raises
# ImportError on non-darwin (module-level platform guard), which is why
# the import is gated. Reads stay on ``keyring.get_password`` because the
# default ``SecItemCopyMatching`` scope already excludes synced entries.
if sys.platform == "darwin":
    from worthless.cli import keystore_macos
else:
    keystore_macos = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_SERVICE = "worthless"
_USERNAME = "fernet-key"


def _keyring_username(home_dir: Path | None = None) -> str:
    """Derive a per-install keyring username to avoid collisions.

    Two worthless installs on the same machine (e.g. staging vs prod) get
    unique keyring entries based on the resolved home directory path.
    """
    if home_dir is None:
        home_dir = Path.home() / ".worthless"
    digest = hashlib.sha256(str(home_dir.resolve()).encode()).hexdigest()[:12]
    return f"fernet-key-{digest}"


# Fully-qualified backend names that are not real credential stores.
# Matched against module.qualname (e.g. "keyring.backends.fail.Keyring").
_REJECTED_BACKENDS = frozenset(
    {
        "keyring.backends.fail.Keyring",
        "keyring.backends.null.Keyring",
        "keyrings.alt.file.PlaintextKeyring",
    }
)


def _is_macos_keyring() -> bool:
    """True iff macOS AND the active keyring backend is the OS keychain.

    Routes WOR-456's synchronizable-False writes only when the upstream
    ``keyring`` library would have actually used the macOS Keychain. On
    Linux/Windows, on null/file fallback, or in pytest with the null
    backend installed (WOR-469), this returns False and writes go through
    the upstream library unchanged.
    """
    if sys.platform != "darwin" or keystore_macos is None:
        return False
    try:
        backend = keyring.get_keyring()
    except Exception:
        return False
    return type(backend).__module__.startswith("keyring.backends.macOS")


def keyring_available() -> bool:
    """Return True if the OS keyring backend is a real credential store.

    Honors the ``WORTHLESS_KEYRING_BACKEND`` env-var escape hatch: when set
    to ``"null"``, force file-only Fernet storage without touching the OS
    keyring backend at all. Two audiences:

    1. **Tests that subprocess-spawn ``worthless``** — ``tests/conftest.py``
       sets this var via ``os.environ.setdefault`` so the parent pytest's
       ``keyring.backends.null`` convention propagates across the process
       boundary. Pre-WOR-463 the convention was lost, leaving real
       ``fernet-key-*`` entries in the user's macOS keychain on every
       e2e test run (128 orphans found in dogfood discovery).
    2. **Production users** who don't trust their OS keyring (shared dev
       machine, audit-locked environment) — opt out by exporting the var.
       Sibling override to ``WORTHLESS_FERNET_KEY_PATH`` and
       ``WORTHLESS_FERNET_KEY``. The ``logger.info`` makes the choice
       visible in support logs.
    """
    if os.environ.get("WORTHLESS_KEYRING_BACKEND") == "null":
        logger.info("Keyring backend forced to null via WORTHLESS_KEYRING_BACKEND")
        return False
    try:
        backend = keyring.get_keyring()
        fqn = f"{type(backend).__module__}.{type(backend).__qualname__}"
        if fqn in _REJECTED_BACKENDS:
            logger.debug("Keyring backend rejected: %s", fqn)
            return False
        logger.debug("Keyring backend accepted: %s", fqn)
        return True
    except Exception:
        return False


def store_fernet_key(key: bytes, home_dir: Path | None = None) -> None:
    """Store Fernet key in OS keyring, falling back to file.

    Args:
        key: Raw Fernet key bytes (from ``Fernet.generate_key()``).
        home_dir: Directory for file fallback (default ``~/.worthless``).
    """
    if keyring_available():
        try:
            username = _keyring_username(home_dir)
            if _is_macos_keyring() and keystore_macos is not None:
                # WOR-456: explicit synchronizable=False, no iCloud sync.
                keystore_macos.set_password_local(_SERVICE, username, key.decode())
            else:
                keyring.set_password(_SERVICE, username, key.decode())
            logger.info("Fernet key stored in OS keyring")
            # Clean up stale fernet.key file left from pre-keyring installs
            try:
                stale = _fernet_file_path(home_dir)
                if stale.exists():
                    stale.unlink()
                    logger.info("Removed stale fernet.key file")
            except OSError:
                logger.warning("Could not remove stale fernet.key file; remove it manually")
            return
        except Exception:
            logger.warning("Keyring write failed, falling back to file")

    _write_key_file(key, home_dir)


def migrate_file_to_keyring(home_dir: Path | None = None) -> bool:
    """Opportunistically promote a file-based Fernet key to the OS keyring.

    Returns True if migration succeeded, False if skipped or failed.
    Never raises — all failures are swallowed to debug log.
    """
    try:
        if not keyring_available():
            logger.debug("migrate_file_to_keyring: keyring unavailable, skip")
            return False
        # File-existence check FIRST so we don't fire keyring.get_password on
        # every CLI invocation just to confirm "no migration needed". When
        # there is no fernet.key file (the common case post-migration), we
        # return immediately without touching the keyring — preserves the
        # HF2 1-keyring-read-per-CLI promise on the existing-key path.
        fernet_path = _fernet_file_path(home_dir)
        if not fernet_path.exists():
            logger.debug("migrate_file_to_keyring: no file at %s, skip", fernet_path)
            return False
        # File exists. Now check keyring — worth a get_password only when a
        # file is present and migration is actually possible.
        username = _keyring_username(home_dir)
        if keyring.get_password(_SERVICE, username) is not None:
            logger.debug("migrate_file_to_keyring: keyring already has key, skip")
            return False
        # Read from file and store to keyring (which also cleans up the file).
        # store_fernet_key deletes the file on keyring success and re-creates
        # it on fallback. If the file still exists afterward, keyring write
        # failed and the migration did not actually happen.
        key_bytes = fernet_path.read_bytes().strip()
        store_fernet_key(key_bytes, home_dir)
        if fernet_path.exists():
            logger.debug("Keyring write fell back to file; migration not successful")
            return False
        logger.info("Migrated Fernet key from file to OS keyring")
        return True
    except Exception:
        logger.debug("File-to-keyring migration skipped", exc_info=True)
        return False


# HF3 (worthless-cmpf): valid-shape Fernet key for code paths that need
# to instantiate Fernet/ShardRepository but never actually call decrypt
# (e.g. ``commands/scan.py:_build_enrollment_checker_async`` reads only
# plaintext metadata via ``list_enrollments``). Co-located here next to
# ``read_fernet_key`` so any future "decrypt-free" path finds it without
# importing from a CLI command module.
PLACEHOLDER_FERNET_KEY: bytes = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def read_fernet_key_from_file(home_dir: Path | None = None) -> bytearray:
    """Read the Fernet key directly from the on-disk file fallback.

    HF3 (worthless-cmpf): companion to ``read_fernet_key`` for callers
    that know the file is the authoritative source and want to bypass
    the keyring step in the cascade. ``read_fernet_key``'s order is
    env → keyring → file, so calling it on a file-only system still
    invokes the keyring backend (silent on macOS when no entry exists,
    but still an API touch — and prompts on backends that authenticate
    the lookup itself). Use this helper from bootstrap when
    ``_fernet_key_present`` is True via file alone.

    Returns ``bytearray`` per SR-01.

    Raises ``WorthlessError(KEY_NOT_FOUND)`` if the file does not exist.
    """
    fernet_path = _fernet_file_path(home_dir)
    try:
        return _read_fernet_file(fernet_path, validate=True)
    except FileNotFoundError as exc:
        # Skip the upfront ``exists()`` stat: ``read_bytes`` already
        # raises on a missing file, and the TOCTOU race is harmless
        # (we'd just fail with the same error a microsecond later).
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"Fernet key file not found at {fernet_path}.",
        ) from exc


def _fernet_file_path(home_dir: Path | None) -> Path:
    """Resolve fernet key file path, respecting WORTHLESS_FERNET_KEY_PATH."""
    env_path = os.environ.get("WORTHLESS_FERNET_KEY_PATH")
    if env_path:
        return Path(env_path)
    if home_dir is None:
        home_dir = Path.home() / ".worthless"
    return home_dir / "fernet.key"


def _validate_fernet_file(path: Path) -> None:
    """Reject world-readable or foreign-owned fernet.key before read (worthless-l3qj)."""
    if IS_WINDOWS:
        # NTFS ACLs — POSIX mode/uid checks are not meaningful on Windows.
        return
    try:
        st = path.lstat()
    except OSError as exc:
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"Cannot read Fernet key file at {path}.",
        ) from exc
    if not stat.S_ISREG(st.st_mode):
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            "fernet.key is not a regular file — refusing to read.",
        )
    mode = stat.S_IMODE(st.st_mode)
    if fernet_ipc_only_enabled():
        if mode != 0o400:
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                f"fernet.key must be mode 0o400 under WORTHLESS_FERNET_IPC_ONLY "
                f"(found {mode:#o}) — refusing to read.",
            )
        return
    if st.st_uid != os.geteuid():
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            "fernet.key is not owned by the current user — refusing to read.",
        )
    if mode != 0o600:
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"fernet.key must be mode 0o600 (found {mode:#o}) — refusing to read.",
        )


def _read_fernet_file(path: Path, *, validate: bool) -> bytearray:
    if validate:
        _validate_fernet_file(path)
    return bytearray(path.read_bytes().strip())


def _write_key_file(key: bytes | bytearray, home_dir: Path | None) -> None:
    """Write key to file with 0o600 permissions."""
    fernet_path = _fernet_file_path(home_dir)
    fd = os.open(str(fernet_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("Fernet key stored in file")


def _fernet_file_bytes(path: Path) -> bytes | None:
    """Return on-disk Fernet bytes when readable; ``None`` if absent or unreadable."""
    try:
        return path.read_bytes().strip()
    except FileNotFoundError:
        return None
    except OSError:
        return None


def sync_fernet_for_launchd(
    home_dir: Path | None = None,
    *,
    key: bytes | bytearray | None = None,
) -> None:
    """Write the canonical Fernet key to ``fernet.key`` for service-managed startup.

    LaunchAgents and systemd user units read the on-disk file under
    ``WORTHLESS_SERVICE_MANAGED=1``. Interactive sessions store the canonical
    key in the OS keyring after enroll/lock; this sync copies keyring → file
    so headless restarts decrypt with the same bytes (WOR-748).

    When *key* is supplied (e.g. from ``WorthlessHome.fernet_key`` cache after
    ``lock``), no second keystore read occurs — preserving the HF2 one-read
    contract.

    Reads via the **interactive** cascade (keyring before file), even when
    ``WORTHLESS_SERVICE_MANAGED`` is set in the caller's environment, so a
    stale ``fernet.key`` never wins over the keyring during sync.
    """
    owned_buf: bytearray | None = None
    saved_managed = os.environ.get("WORTHLESS_SERVICE_MANAGED")
    saved_env_key = os.environ.get("WORTHLESS_FERNET_KEY")
    try:
        if key is None:
            if saved_managed is not None:
                os.environ.pop("WORTHLESS_SERVICE_MANAGED", None)
            # Sync must copy keyring → file, not inherit a poison shell env.
            if saved_env_key is not None:
                os.environ.pop("WORTHLESS_FERNET_KEY", None)
            owned_buf = read_fernet_key(home_dir)
            key_bytes = owned_buf
        else:
            key_bytes = key

        fernet_path = _fernet_file_path(home_dir)
        existing = _fernet_file_bytes(fernet_path)
        if existing is not None and existing == key_bytes:
            return

        _write_key_file(key_bytes, home_dir)
    finally:
        if owned_buf is not None:
            zero_buf(owned_buf)
        if saved_managed is not None:
            os.environ["WORTHLESS_SERVICE_MANAGED"] = saved_managed
        if saved_env_key is not None:
            os.environ["WORTHLESS_FERNET_KEY"] = saved_env_key


def _service_managed() -> bool:
    return os.environ.get("WORTHLESS_SERVICE_MANAGED", "").strip() == "1"


def read_fernet_key(home_dir: Path | None = None) -> bytearray:
    """Read Fernet key from storage backends.

    Order (interactive): env var -> keyring -> file -> error.
    Order (``WORTHLESS_SERVICE_MANAGED=1``): env var -> file -> keyring -> error.

    LaunchAgents cannot reliably use Keychain on every restart; the live
    pack syncs Keychain → ``fernet.key`` before ``service install``. Prefer
    the file under service-managed so decrypt matches what ``lock`` wrote.

    Returns bytearray per SR-01 (mutable, can be zeroed).

    Note: pipe fd transport (WORTHLESS_FERNET_FD) is handled by
    proxy/config.py, not here. Fd is a transport mechanism, not storage.
    """
    # 1. Environment variable
    env_val = os.environ.get("WORTHLESS_FERNET_KEY")
    if env_val:
        return bytearray(env_val.encode())

    fernet_path = _fernet_file_path(home_dir)

    # 2. File first under launchd/systemd (WOR-748)
    if _service_managed() and fernet_path.exists():
        return _read_fernet_file(fernet_path, validate=True)

    # 3. Keyring (namespaced username only — no legacy fallback)
    keyring_read_failed = False
    if keyring_available():
        try:
            value = keyring.get_password(_SERVICE, _keyring_username(home_dir))
            if value is not None:
                return bytearray(value.encode())
        except Exception:
            keyring_read_failed = True
            logger.debug("Keyring read failed", exc_info=True)

    # 4. File (interactive fallback, or service-managed when sync not run yet)
    if fernet_path.exists():
        if keyring_read_failed and not _service_managed():
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                "Keyring read failed and a fernet.key file also exists — refusing "
                "silent file fallback in an interactive session (stale file causes "
                "401 under launchd). Run `worthless doctor` and resolve fernet_drift, "
                "or sync Keychain to fernet.key before `worthless service install`.",
            )
        return _read_fernet_file(fernet_path, validate=True)
    raise WorthlessError(
        ErrorCode.KEY_NOT_FOUND,
        "No Fernet key found. Run 'worthless enroll' or set WORTHLESS_FERNET_KEY.",
    )


def delete_fernet_key(home_dir: Path | None = None) -> None:
    """Remove Fernet key from keyring and file. Never raises on missing."""
    if keyring_available():
        try:
            keyring.delete_password(_SERVICE, _keyring_username(home_dir))
        except Exception:
            logger.debug("Keyring delete failed (may not exist)")

    fernet_path = _fernet_file_path(home_dir)
    fernet_path.unlink(missing_ok=True)

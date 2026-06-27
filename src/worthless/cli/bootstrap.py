"""First-run ~/.worthless/ initialization and lock management."""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from worthless._async import run_sync
from worthless._flags import (
    WORTHLESS_SIDECAR_SOCKET_ENV,
    ipc_mode_active,
)
from worthless.cli.errors import ErrorCode, WorthlessError, sanitize_exception
from worthless.cli.keystore import (
    _SERVICE,
    _keyring_username,
    keyring_available,
    migrate_file_to_keyring,
    read_fernet_key,
    read_fernet_key_from_file,
    store_fernet_key,
)
from worthless.cli.platform import IS_WINDOWS
from worthless.crypto.types import zero_buf
from worthless.ipc.client import IPCClient, IPCError
from worthless.proxy.config import DEFAULT_SIDECAR_SOCKET_PATH

logger = logging.getLogger(__name__)

_DEFAULT_BASE = Path.home() / ".worthless"
_STALE_LOCK_SECONDS = 300  # 5 minutes

_BOOTSTRAP_ATTEST_PURPOSE = "bootstrap-validate"


def _validate_via_sidecar(socket_path: Path) -> None:
    """Round-trip an ``attest`` call to confirm a sidecar is running and
    returns structurally valid evidence. Raises :class:`WorthlessError(SIDECAR_NOT_READY)` on
    any failure — never falls back to reading ``home.fernet_key``.

    Structural validation (bytes type, exact HMAC-SHA256 length) is the
    minimum bar; the CLI uid cannot verify the MAC because it has no
    access to the key on the flag-on proxy-container path. A stub
    sidecar returning empty bytes or wrong length is refused here.
    """
    from worthless.sidecar.backends.base import HMAC_SHA256_LEN

    nonce = secrets.token_bytes(32)

    async def _go() -> bytes:
        async with IPCClient(socket_path) as client:
            return await client.attest(nonce, purpose=_BOOTSTRAP_ATTEST_PURPOSE)

    def _fail(generic: str, cause: BaseException) -> WorthlessError:
        return WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            sanitize_exception(cause, generic=generic)
            if isinstance(cause, OSError | ValueError)
            else generic,
        )

    try:
        evidence = run_sync(_go())
    except IPCError as exc:
        raise _fail(
            f"Sidecar is not reachable for bootstrap attestation ({socket_path}). "
            "Start the sidecar before invoking the CLI inside the proxy "
            "container, or unset WORTHLESS_FERNET_IPC_ONLY for bare-metal use.",
            exc,
        ) from exc
    except OSError as exc:
        raise _fail("sidecar attestation failed", exc) from exc
    except ValueError as exc:
        # ``os.fspath`` rejects embedded NUL bytes (abstract-namespace
        # AF_UNIX paths) BEFORE asyncio.open_unix_connection ever runs.
        raise _fail("sidecar socket path is invalid", exc) from exc
    except asyncio.CancelledError as exc:
        # SIGINT during bootstrap surfaces as CancelledError under the
        # asyncio.run scope.
        raise _fail("Bootstrap attestation cancelled before completion.", exc) from exc

    bad_type = not isinstance(evidence, bytes | bytearray)
    if bad_type or len(evidence) != HMAC_SHA256_LEN:
        observed = "non-bytes" if bad_type else str(len(evidence))
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"Sidecar returned malformed attestation evidence "
            f"(expected {HMAC_SHA256_LEN} bytes, got {observed}).",
        )


@dataclass
class WorthlessHome:
    """Paths within the ``~/.worthless/`` directory tree."""

    base_dir: Path = field(default_factory=lambda: _DEFAULT_BASE)
    # HF2 / worthless-mnlp: per-instance cache for the Fernet key so a single
    # CLI invocation triggers exactly one keychain probe (one macOS Keychain
    # prompt on first run). Excluded from init/repr/compare so it doesn't
    # leak into reprs or break dataclass equality across cached/uncached
    # instances.
    _cached_fernet_key: bytearray | None = field(
        default=None, init=False, repr=False, compare=False
    )
    # Per-instance lock guarding the lazy-populate path. The check-then-set
    # in ``fernet_key`` is two operations; without this lock, two threads
    # accessing the property concurrently on the same instance can both
    # observe ``None`` and both call ``read_fernet_key`` — firing duplicate
    # macOS Keychain prompts and discarding one bytearray without
    # ``zero_buf``. Real call site: ``src/worthless/mcp/server.py`` runs
    # FastMCP's asyncio loop on the main thread but dispatches blocking
    # work (``_do_lock``) via ``loop.run_in_executor`` to the default
    # thread pool — main + executor can both touch ``home.fernet_key``.
    _cache_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    @property
    def db_path(self) -> Path:
        return self.base_dir / "worthless.db"

    @property
    def fernet_key_path(self) -> Path:
        env_path = os.environ.get("WORTHLESS_FERNET_KEY_PATH")
        if env_path:
            return Path(env_path)
        return self.base_dir / "fernet.key"

    @property
    def shard_a_dir(self) -> Path:
        return self.base_dir / "shard_a"

    @property
    def recovery_dir(self) -> Path:
        """Directory holding ``<account>.recover`` files for sibling-Mac
        recovery (WOR-456). Only populated when ``worthless doctor --fix``
        migrates a synced keychain entry — the value is exported here so
        a user with a second Mac can copy the file across before iCloud's
        tombstone propagates and removes the local copy on the sibling.
        """
        return self.base_dir / "recovery"

    @property
    def lock_file(self) -> Path:
        return self.base_dir / ".lock-in-progress"

    @property
    def bootstrapped_marker(self) -> Path:
        """Marker file written at the end of a successful ensure_home().

        HF3 (worthless-cmpf): used to distinguish "first-run /
        previously-failed bootstrap" (probe must run, key must be
        generated) from "bootstrap completed at least once" (probe
        gated). Stronger than ``base_dir.exists()`` because a failed
        prior run leaves the dir present but the keystore empty; the
        marker is only created at the END of a successful ensure_home,
        so its presence is a positive signal of completed bootstrap.
        """
        return self.base_dir / ".bootstrapped"

    @property
    def warranty_notice_marker(self) -> Path:
        """Marker that the one-time AS-IS notice has been shown (WOR-488).

        Deliberately separate from ``.bootstrapped`` (keystore init) so the
        legal notice and the keystore lifecycle never couple.
        """
        return self.base_dir / ".warranty-ack"

    @property
    def fernet_key(self) -> bytearray:
        """Read the Fernet key via keystore cascade (SR-01: mutable bytearray).

        Memoized per-instance with double-checked locking. macOS Keychain
        re-evaluates the per-call ACL, so without this cache one
        ``worthless lock`` triggers 3+ Keychain prompts.

        Returns a fresh bytearray copy on each access so callers can
        ``zero_buf()`` per SR-01 without poisoning the cache.
        """
        if self._cached_fernet_key is None:
            with self._cache_lock:
                if self._cached_fernet_key is None:
                    logger.debug("WorthlessHome.fernet_key cache MISS — reading from keystore")
                    self._cached_fernet_key = read_fernet_key(self.base_dir)
        else:
            logger.debug("WorthlessHome.fernet_key cache HIT")
        return bytearray(self._cached_fernet_key)

    def _seed_cached_fernet_key(self, key: bytes | bytearray) -> None:
        """Install *key* into the cache under ``_cache_lock``.

        HF3 (worthless-cmpf): single entry point for any code that
        wants to populate the cache from a known source (env var,
        on-disk file, freshly generated key). Mirrors the locking
        discipline of the property's read path so a concurrent
        ``home.fernet_key`` call cannot race the assignment.
        """
        with self._cache_lock:
            self._cached_fernet_key = bytearray(key)


def _fernet_key_present(home: WorthlessHome) -> bool:
    """True if a Fernet key is provisioned WITHOUT touching the keyring.

    HF3 (worthless-cmpf): cheap probe that lets read-only commands
    (``worthless scan`` in particular) bypass the keystore entirely.
    Sources, in priority order:

    1. ``WORTHLESS_FERNET_KEY`` env var — used by IPC fd transport
       and CI environments.
    2. The on-disk fernet key file — pre-keyring fallback that still
       exists on legacy installs.

    The keyring is intentionally NOT consulted here — its access on
    macOS triggers a per-call keychain prompt, which is the very UX
    bug HF3 is closing. For users with only a keyring entry (no env
    var, no file), this returns False and the caller falls through
    to the keyring probe — that's correct: first-run detection has
    to happen somewhere.
    """
    if os.environ.get("WORTHLESS_FERNET_KEY"):
        return True
    if home.fernet_key_path.exists():
        return True
    return False


def _provision_keystore_path(home: WorthlessHome) -> bool:
    """Run the bare-metal keystore cascade for ``ensure_home``.

    Split out so ``ensure_home`` itself stays under xenon's rank-C
    cyclomatic ceiling. Handles three states discriminated by the
    ``.bootstrapped`` marker: first-run probe-and-generate, post-
    bootstrap env-or-file pre-populate, and keyring-only fallthrough.

    Returns ``True`` on first run (marker not yet written) so the
    caller can write the marker after ``_init_db()`` succeeds.
    """
    # Validate custom fernet key path if set via env var
    fernet_path = home.fernet_key_path
    fernet_parent = fernet_path.parent
    if os.environ.get("WORTHLESS_FERNET_KEY_PATH") and not fernet_parent.is_dir():
        raise WorthlessError(
            ErrorCode.BOOTSTRAP_FAILED,
            f"WORTHLESS_FERNET_KEY_PATH directory does not exist: {fernet_parent}\n"
            "Create it or mount a volume at that path.",
        )

    if not home.bootstrapped_marker.exists():
        _first_run_keystore(home)
        # Do NOT write .bootstrapped here — _init_db() runs in the caller
        # (ensure_home) after we return.  Writing the marker before _init_db
        # succeeds means a failed DB init leaves the marker in place, causing
        # every subsequent boot to skip bootstrap entirely.  The caller writes
        # the marker only after _init_db() returns without raising.
        return True
    if _fernet_key_present(home):
        _seed_cache_from_advisory_source(home)
    # else: keyring-only post-bootstrap → skip; lazy fetch later.
    return False


def _first_run_keystore(home: WorthlessHome) -> None:
    """Probe the keystore; generate a fresh key if absent."""
    try:
        _ = home.fernet_key
    except WorthlessError as exc:
        if exc.code != ErrorCode.KEY_NOT_FOUND:
            raise
        logger.info("ensure_home: no Fernet key found, generating new one")
        # Equivalent to ``Fernet.generate_key()`` — inlined so the proxy
        # import path never loads ``cryptography.fernet``.
        key = base64.urlsafe_b64encode(os.urandom(32))
        store_fernet_key(key, home_dir=home.base_dir)
        home._seed_cached_fernet_key(key)
    else:
        migrate_file_to_keyring(home.base_dir)


def _seed_cache_from_advisory_source(home: WorthlessHome) -> None:
    """Pre-populate the key cache from env or file when present.

    When both keyring and ``fernet.key`` exist, seed from the keyring if they
    differ. A stale file left from a prior ``service install`` sync must not
    poison ``worthless lock`` while launchd reads the synced file (WOR-748).

    Under ``WORTHLESS_SERVICE_MANAGED=1``, seed via :func:`read_fernet_key`
    so ``split_to_tmpfs`` uses the same file-first key launchd will read
    (WOR-749).
    """
    if os.environ.get("WORTHLESS_SERVICE_MANAGED", "").strip() == "1":
        try:
            home._seed_cached_fernet_key(read_fernet_key(home.base_dir))
        except WorthlessError:
            logger.debug(
                "ensure_home: service-managed fernet cache seed deferred to lazy fetch",
                exc_info=True,
            )
        return

    if os.environ.get("WORTHLESS_FERNET_KEY"):
        try:
            _ = home.fernet_key
        except WorthlessError as exc:
            if exc.code != ErrorCode.KEY_NOT_FOUND:
                raise
            logger.debug(
                "ensure_home: WORTHLESS_FERNET_KEY env var unset or "
                "malformed between _fernet_key_present and read; "
                "deferring to lazy keyring fetch"
            )
        return

    if keyring_available() and home.fernet_key_path.exists():
        try:
            import keyring

            kr_val = keyring.get_password(_SERVICE, _keyring_username(home.base_dir))
            if kr_val is not None:
                file_key = read_fernet_key_from_file(home.base_dir)
                kr_buf = bytearray(kr_val.encode())
                try:
                    if not hmac.compare_digest(file_key, kr_buf):
                        logger.warning(
                            "fernet.key differs from keyring; using keyring for this session"
                        )
                        home._seed_cached_fernet_key(kr_buf)
                        return
                finally:
                    zero_buf(file_key)
                    zero_buf(kr_buf)
        except Exception:
            logger.debug(
                "ensure_home: keyring/file compare failed during cache seed",
                exc_info=True,
            )

    try:
        key = read_fernet_key_from_file(home.base_dir)
    except WorthlessError as exc:
        if exc.code != ErrorCode.KEY_NOT_FOUND:
            raise
        logger.debug(
            "ensure_home: fernet key file disappeared between "
            "_fernet_key_present and read; deferring to lazy keyring fetch"
        )
    else:
        home._seed_cached_fernet_key(key)


def ensure_home(base_dir: Path | None = None) -> WorthlessHome:
    """Create ``~/.worthless/`` structure on first run (idempotent).

    Creates directories with 0700 permissions, generates a Fernet key
    if missing, initialises the SQLite database, and writes a
    ``.bootstrapped`` marker on completion. The marker gates future
    keystore probes so post-bootstrap CLI invocations skip the
    keyring entirely when scan/status/other read-only paths run.
    """
    home = WorthlessHome(base_dir=base_dir or _DEFAULT_BASE)

    try:
        # Create directories
        home.base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        home.shard_a_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        if not IS_WINDOWS:
            home.base_dir.chmod(0o700)
            home.shard_a_dir.chmod(0o700)

        # WOR-465 A3b / A4: under the proxy uid, bypass the keystore cascade
        # and attest via IPC — fernet.key is unreadable. See ipc_mode_active()
        # for the predicate; failure mode is hard SIDECAR_NOT_READY, never a
        # silent fallback.
        #
        # Socket-existence guard: entrypoint.sh calls get_home() before
        # start.py spawns the sidecar, so the socket does not yet exist on
        # first boot. When absent, fall through to _provision_keystore_path so
        # the key is generated as root; start.py reads it (also as root, before
        # priv-drop) to split_to_tmpfs. The entrypoint chmod then locks the
        # file to worthless-crypto:worthless-crypto 0400. WOR-309 hard-fail.
        if ipc_mode_active():
            socket_path = Path(
                os.environ.get(WORTHLESS_SIDECAR_SOCKET_ENV, DEFAULT_SIDECAR_SOCKET_PATH)
            )
            if socket_path.exists():
                _validate_via_sidecar(socket_path)
                _init_db(home)
                return home
            if home.bootstrapped_marker.exists():
                # Post-bootstrap: sidecar should be running — missing socket means it
                # crashed. Fail hard rather than falling through to key generation,
                # which would silently attempt to read a fernet.key the proxy uid
                # cannot access (locked 0400 worthless-crypto by entrypoint.sh).
                raise WorthlessError(
                    ErrorCode.SIDECAR_NOT_READY,
                    f"Sidecar socket not found at {socket_path}. "
                    "The sidecar has stopped or crashed. "
                    "Run: docker exec --user root <container> worthless doctor",
                )
            # First boot: entrypoint.sh calls ensure_home() before start.py spawns
            # the sidecar, so the socket does not yet exist.  Fall through to key
            # generation below (as root, before priv-drop).

        first_run = _provision_keystore_path(home)
    except WorthlessError:
        raise
    except OSError as exc:
        fernet_env = os.environ.get("WORTHLESS_FERNET_KEY_PATH")
        if fernet_env:
            raise WorthlessError(
                ErrorCode.BOOTSTRAP_FAILED,
                f"Cannot write fernet key to {fernet_env}: "
                f"{sanitize_exception(exc, generic='permission denied or path invalid')}\n"
                "Check that the directory exists and is writable.",
            ) from exc
        raise WorthlessError(
            ErrorCode.BOOTSTRAP_FAILED,
            sanitize_exception(exc, generic="failed to initialise home directory"),
        ) from exc

    # Initialise database (idempotent — CREATE TABLE IF NOT EXISTS)
    try:
        _init_db(home)
    except (OSError, sqlite3.DatabaseError) as exc:
        raise WorthlessError(
            ErrorCode.SHARD_STORAGE_FAILED,
            sanitize_exception(exc, generic="failed to initialise database"),
        ) from exc

    # Write .bootstrapped AFTER _init_db() succeeds.  Writing it before
    # risks a scenario where _init_db() fails and the marker is already
    # present, causing every subsequent boot to skip bootstrap entirely.
    if first_run:
        home.bootstrapped_marker.touch(mode=0o600, exist_ok=True)
    return home


def _init_db(home: WorthlessHome) -> None:
    """Create the SQLite database using the canonical schema and run migrations."""
    from worthless.storage.schema import SCHEMA, migrate_db

    conn = sqlite3.connect(str(home.db_path))
    try:
        conn.execute("PRAGMA foreign_keys = ON")

        # Run forward-only migrations BEFORE the full schema so that
        # upgraded installs whose enrollments table pre-dates the
        # decoy_hash column get it added before CREATE INDEX touches it.
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "enrollments" in tables:
            cursor = conn.execute("PRAGMA table_info(enrollments)")
            columns = {row[1] for row in cursor.fetchall()}
            if "decoy_hash" not in columns:
                try:
                    conn.execute("ALTER TABLE enrollments ADD COLUMN decoy_hash TEXT")
                    conn.commit()
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).lower():
                        raise

        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()
    finally:
        conn.close()

    # Run async migrations (WOR-183: rules engine columns, spend_log cleanup)
    try:
        asyncio.get_running_loop()
        # Already in async context — schedule as a task won't work from sync.
        # Use a new thread's event loop instead.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(asyncio.run, migrate_db(str(home.db_path))).result()
    except RuntimeError:
        # No running loop — safe to use asyncio.run()
        # Snapshot threads BEFORE the call so we only join the aiosqlite
        # cleanup thread that migrate_db spawns, not the pre-existing xdist
        # worker / pytest-asyncio threads that would each block 2 s (WOR-582).
        _threads_before = set(threading.enumerate())
        asyncio.run(migrate_db(str(home.db_path)))
        # aiosqlite starts a daemon thread per connection and signals it to
        # stop before close() returns, but never calls thread.join().  The
        # thread breaks out of its loop and calls _delete() a few
        # microseconds after the future resolves — which is after
        # asyncio.run() returns.  deploy/start.py checks threading.active_count()
        # immediately after ensure_home(); join here to guarantee the aiosqlite
        # thread has fully exited before we return (WRTLS-114).
        _main = threading.main_thread()
        for _t in list(threading.enumerate()):
            if _t is not _main and _t not in _threads_before:
                _t.join(timeout=2.0)

    # Restrict DB file permissions (no-op on Windows — NTFS ACLs are different)
    if not IS_WINDOWS:
        home.db_path.chmod(0o600)


@contextmanager
def acquire_lock(home: WorthlessHome) -> Generator[None, None, None]:
    """Acquire an exclusive lock file using O_CREAT|O_EXCL."""
    check_stale_lock(home)
    try:
        fd = os.open(
            str(home.lock_file),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.close(fd)
    except FileExistsError:
        raise WorthlessError(
            ErrorCode.LOCK_IN_PROGRESS,
            "Another worthless operation is in progress. "
            "Remove ~/.worthless/.lock-in-progress if stale.",
        ) from None  # FileExistsError context is not useful to callers
    try:
        yield
    finally:
        try:
            home.lock_file.unlink()
        except FileNotFoundError:
            pass


def get_home() -> WorthlessHome:
    """Resolve WorthlessHome from WORTHLESS_HOME env var or default."""
    env_home = os.environ.get("WORTHLESS_HOME")
    if env_home:
        return ensure_home(Path(env_home))
    return ensure_home()


def resolve_home() -> WorthlessHome | None:
    """Try to load WorthlessHome; return None if not initialized."""
    try:
        env_home = os.environ.get("WORTHLESS_HOME")
        if env_home:
            base = Path(env_home)
            if base.exists():
                return ensure_home(base)
            return None
        default = Path.home() / ".worthless"
        if default.exists():
            return ensure_home(default)
        return None
    except Exception:
        return None


def check_stale_lock(home: WorthlessHome) -> None:
    """Remove stale lock files (> 5 min old), raise on fresh locks."""
    if not home.lock_file.exists():
        return
    age = time.time() - home.lock_file.stat().st_mtime
    if age > _STALE_LOCK_SECONDS:
        home.lock_file.unlink(missing_ok=True)
    else:
        raise WorthlessError(
            ErrorCode.LOCK_IN_PROGRESS,
            f"Lock file is {int(age)}s old (< {_STALE_LOCK_SECONDS}s). "
            "Another operation may be running.",
        )

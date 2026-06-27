"""HF3 (worthless-cmpf): `worthless scan` must not touch the keystore.

`worthless scan` is documented as a read-only command. Triggering a
macOS Keychain dialog from a scan call is a UX regression — it makes
the command look like it's doing more than reading. These tests pin
the contract that scan completes without any keyring access.

Two paths previously triggered the prompt:

1. ``commands/scan.py:_build_enrollment_checker_async`` instantiating
   ``ShardRepository(home.db_path, home.fernet_key)``. The Fernet key
   is unused because ``list_enrollments()`` only reads non-encrypted
   metadata (var_name, env_path). Pin: pass a placeholder bytearray
   and assert ``list_enrollments`` does not decrypt.

2. ``bootstrap.ensure_home`` running the keyring probe (``_ =
   home.fernet_key``) on every CLI invocation. Pin: ``ensure_home``
   skips the probe when ``_fernet_key_present(home)`` is True (env
   var or on-disk file).
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import WorthlessHome, _fernet_key_present, ensure_home
from worthless.cli.commands import scan as scan_module
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.keystore import PLACEHOLDER_FERNET_KEY
from worthless.storage.repository import ShardRepository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_file_fernet_key(home_dir: Path) -> Path:
    """Drop a valid Fernet placeholder key on disk.

    Uses ``PLACEHOLDER_FERNET_KEY`` (urlsafe-b64 of 32 zero bytes) so
    these fixtures stay correct even if a future hardening teaches
    ``read_fernet_key_from_file`` / ``home.fernet_key`` to validate
    Fernet shape. Per CodeRabbit FINDING on PR #126: a non-shape-valid
    sentinel would fail those tests for the wrong reason.
    """
    home_dir.mkdir(parents=True, exist_ok=True)
    key_path = home_dir / "fernet.key"
    key_path.write_bytes(PLACEHOLDER_FERNET_KEY)
    key_path.chmod(0o600)
    return key_path


def _mark_bootstrapped(home_dir: Path) -> None:
    """Drop the ``.bootstrapped`` marker so ``ensure_home`` treats this as
    a post-bootstrap invocation (see HF3's gate)."""
    home_dir.mkdir(parents=True, exist_ok=True)
    (home_dir / ".bootstrapped").touch(mode=0o600, exist_ok=True)


# ---------------------------------------------------------------------------
# (1) scan.py:192 — placeholder Fernet bytearray, no keyring touch
# ---------------------------------------------------------------------------


class TestScanBuildsEnrollmentCheckerWithoutKeystore:
    """scan must not call home.fernet_key when building the enrollment checker."""

    def test_build_enrollment_checker_does_not_access_fernet_key(self, tmp_path: Path) -> None:
        """``_load_db_state_async`` must NOT read ``home.fernet_key``.

        list_enrollments() only reads var_name + env_path (non-encrypted
        metadata). The Fernet key is dead weight for this code path —
        instantiating it just to satisfy ShardRepository's constructor
        triggers a keychain prompt for nothing.

        HF5 renamed ``_build_enrollment_checker_async`` → ``_load_db_state_async``
        (now returns ``(enrolled, orphans)``). Same contract: no fernet read.
        """
        # Set up a usable home with a DB but no enrollments — scan should
        # short-circuit at the empty-enrollments check, but on the way
        # through must not call ``home.fernet_key``.
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        # Mark bootstrapped so ``ensure_home`` takes the post-bootstrap
        # file-only path (no keyring touch). Without this the fixture
        # setup itself would trigger the bootstrap probe — on macOS
        # that's exactly the keychain access this test is supposed to
        # pin AGAINST. Per CodeRabbit FINDING on PR #126.
        _mark_bootstrapped(home_base)

        # Build a real home and assert ``home.fernet_key`` is never read.
        home = ensure_home(base_dir=home_base)

        # Spy on the property: replace it with one that fails the test.
        accessed = {"value": False}

        def _spy(self_unused) -> bytearray:
            accessed["value"] = True
            raise AssertionError("scan touched home.fernet_key (HF3 regression)")

        with patch.object(WorthlessHome, "fernet_key", new=property(_spy)):
            # Patch get_home so scan's helper sees our prepared home.
            with patch("worthless.cli.commands.scan.get_home", return_value=home):
                # Run the async helper directly so we don't pull in CliRunner.
                enrolled, orphans = asyncio.run(scan_module._load_db_state_async())

        assert not accessed["value"], "home.fernet_key must not be touched on scan path"
        # No enrollments — checker is None, orphans empty (graceful degrade).
        assert enrolled is None
        assert orphans == []

    def test_shard_repository_list_enrollments_does_not_decrypt(self, tmp_path: Path) -> None:
        """Pin the contract that ShardRepository.list_enrollments() does NOT
        decrypt anything — it reads plaintext columns only.

        Two layers of pin:
        1. Row layer: seed a real enrollment (encrypted with a real key),
           then list with a *different* repository whose Fernet key would
           NOT decrypt that row. ``list_enrollments`` must succeed —
           proving it never reaches the encrypted columns. Per CodeRabbit
           FINDING on PR #126: empty-table fast path alone is insufficient.
        2. Spy layer: also mock the ``Fernet.decrypt`` call on the listing
           repository so ANY decrypt attempt fails loudly. Belt-and-braces.

        If a future refactor encrypts ``var_name`` or ``env_path`` (or
        starts decrypting metadata while iterating real rows), this test
        fails loudly so HF3's placeholder-Fernet-key trick stays safe.
        """
        from cryptography.fernet import Fernet

        from worthless.crypto.splitter import split_key
        from worthless.storage.repository import StoredShard

        db_path = tmp_path / "test.db"

        # Step 1 — seed an enrollment row using a REAL Fernet key.
        real_key = Fernet.generate_key()
        seed_repo = ShardRepository(str(db_path), bytearray(real_key))
        asyncio.run(seed_repo.initialize())

        # Generate a real shard from a fake API key so store_enrolled has
        # something to encrypt. The actual key bytes don't matter — only
        # that ``list_enrollments`` later doesn't try to decrypt them.
        sr = split_key(b"sk-proj-" + b"x" * 40)
        try:
            stored = StoredShard(
                shard_b=bytearray(sr.shard_b),
                commitment=bytearray(sr.commitment),
                nonce=bytearray(sr.nonce),
                provider="openai",
            )
            asyncio.run(
                seed_repo.store_enrolled(
                    "openai-row-test",
                    stored,
                    var_name="OPENAI_API_KEY",
                    env_path=str(tmp_path / ".env"),
                )
            )
        finally:
            sr.zero()

        # Step 2 — open the SAME db with a DIFFERENT Fernet key.
        # Any decrypt attempt would fail with InvalidToken because the
        # placeholder key cannot decrypt rows encrypted with real_key.
        list_repo = ShardRepository(str(db_path), bytearray(PLACEHOLDER_FERNET_KEY))
        asyncio.run(list_repo.initialize())

        # Belt: also fail-loud on any decrypt attempt against this repo.
        original_decrypt = list_repo._fernet.decrypt  # type: ignore[union-attr]

        def _fail_decrypt(*_a, **_kw):
            raise AssertionError("list_enrollments tried to decrypt; HF3 contract broken")

        list_repo._fernet.decrypt = _fail_decrypt  # type: ignore[union-attr]
        try:
            enrollments = asyncio.run(list_repo.list_enrollments())
        finally:
            list_repo._fernet.decrypt = original_decrypt  # type: ignore[union-attr]

        # Row IS visible — proves the SELECT touched plaintext columns
        # (key_alias, var_name, env_path) and never the ciphertext.
        assert len(enrollments) == 1, f"expected 1 row, got {enrollments}"
        assert enrollments[0].key_alias == "openai-row-test"
        assert enrollments[0].var_name == "OPENAI_API_KEY"


# ---------------------------------------------------------------------------
# (2) bootstrap.py — _fernet_key_present gate around the keyring probe
# ---------------------------------------------------------------------------


class TestFernetKeyPresent:
    """_fernet_key_present checks env var + on-disk file. NEVER the keyring."""

    def test_returns_true_when_env_var_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Use a Fernet-valid placeholder so a future shape-validation
        # hardening doesn't fail this test for the wrong reason.
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", PLACEHOLDER_FERNET_KEY.decode())
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        assert _fernet_key_present(home) is True

    def test_returns_true_when_file_exists(self, tmp_path: Path) -> None:
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        home = WorthlessHome(base_dir=home_base)
        assert _fernet_key_present(home) is True

    def test_returns_false_when_neither_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        assert _fernet_key_present(home) is False

    def test_does_not_touch_keyring(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The whole point — `_fernet_key_present` must be cheap.

        If a future refactor adds a keyring fall-through, this test
        catches it: we patch keyring.get_password to fail the test.
        """
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        home = WorthlessHome(base_dir=home_base)

        with patch(
            "worthless.cli.keystore.keyring.get_password",
            side_effect=AssertionError("_fernet_key_present must not call keyring"),
        ):
            assert _fernet_key_present(home) is True


class TestEnsureHomeProbeGate:
    """ensure_home gates the keystore probe on a ``.bootstrapped`` marker.

    Marker absent → first-run (or previous bootstrap crashed); probe runs
                    regardless of signal so a clean / partially-bootstrapped
                    machine ends up with a usable Fernet key.
    Marker present + env var → call ``home.fernet_key`` (cascade returns at
                    env step, no keyring touch; populates HF2 cache).
    Marker present + file only → read file directly via
                    ``read_fernet_key_from_file`` (bypasses keyring API).
    Marker present + keyring only → skip; lazy fetch via ``home.fernet_key``.

    The marker is the post-completion signal flagged by CodeRabbit: stronger
    than ``base_dir.exists()`` because a failed prior bootstrap leaves the
    dir present but the keystore empty, and we still want to re-run.
    """

    def test_first_run_probes_and_generates(self, tmp_path: Path) -> None:
        """No marker → probe runs and key is generated. This is the magic-
        moment first-run-on-clean-macOS path."""
        home_base = tmp_path / ".worthless"
        probe_called = {"value": False}

        def _probe(*args, **kwargs):
            probe_called["value"] = True
            raise WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key")

        with (
            patch("worthless.cli.bootstrap.read_fernet_key", side_effect=_probe),
            patch("worthless.cli.bootstrap.store_fernet_key"),
        ):
            home = ensure_home(base_dir=home_base)
            assert probe_called["value"], "first-run must probe the keystore"
            assert home.bootstrapped_marker.exists(), (
                "marker must be written on successful first-run completion"
            )

    def test_docker_volume_mount_first_run_probes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pre-existing empty home dir (no marker, no key) → probe MUST run.

        Regression pin for the docker-e2e failure on commit ``3675b14``:
        Docker mounts ``/data`` as a volume before the entrypoint runs,
        which pre-creates the mount-point directory empty. The earlier
        gate ``if not home.base_dir.exists() or _fernet_key_present(home):``
        treated the pre-existing-empty-dir case as "subsequent run" and
        SKIPPED the probe, so no Fernet key was ever generated. The
        container's entrypoint then died on ``exec 3< $FERNET_PATH``
        because the file did not exist; ``set -e`` propagated the failure
        and uvicorn never started — explaining why all 25 docker-e2e
        tests reported ``Container did not become healthy`` (the State
        was ``exited``, not ``starting``).

        The marker-file gate fixes this: marker absent ⇒ probe runs,
        regardless of whether the dir was pre-created by a volume
        mount, a manually-created WORTHLESS_HOME, or a failed prior
        bootstrap. CodeRabbit's FINDING 1 caught the class of bug;
        this test pins the specific manifestation.
        """
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home_base = tmp_path / ".worthless"
        # Simulate Docker volume-mount: pre-create the dir empty, no
        # marker, no fernet.key. (A real volume mount would also have
        # ``home.shard_a_dir`` ready to be created; ensure_home handles
        # that idempotently.)
        home_base.mkdir(parents=True, exist_ok=True)

        probe_called = {"value": False}

        def _probe(*args, **kwargs):
            probe_called["value"] = True
            raise WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key")

        with (
            patch("worthless.cli.bootstrap.read_fernet_key", side_effect=_probe),
            patch("worthless.cli.bootstrap.store_fernet_key"),
        ):
            home = ensure_home(base_dir=home_base)
            assert probe_called["value"], (
                "pre-existing empty home (Docker volume mount) MUST trigger "
                "the probe-and-generate path; otherwise the container "
                "starts without a Fernet key and the entrypoint crashes "
                "on the FD-based key transport"
            )
            assert home.bootstrapped_marker.exists(), (
                "marker must be written so subsequent invocations can skip the probe"
            )

    def test_failed_prior_bootstrap_re_runs_probe(self, tmp_path: Path) -> None:
        """Pre-existing home dir WITHOUT marker → treated as failed bootstrap.

        Closes CodeRabbit's FINDING 1: ``base_dir.exists()`` is too weak as
        a first-run signal because a prior crashed run leaves the dir but
        no key. The marker is the only positive completion signal.
        """
        home_base = tmp_path / ".worthless"
        # Pre-create the dir but DO NOT touch the marker — simulates a
        # crashed prior bootstrap that did mkdir but never reached
        # store_fernet_key.
        home_base.mkdir(parents=True, exist_ok=True)
        probe_called = {"value": False}

        def _probe(*args, **kwargs):
            probe_called["value"] = True
            raise WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key")

        with (
            patch("worthless.cli.bootstrap.read_fernet_key", side_effect=_probe),
            patch("worthless.cli.bootstrap.store_fernet_key"),
        ):
            ensure_home(base_dir=home_base)
            assert probe_called["value"], (
                "missing marker means previous bootstrap was incomplete; "
                "probe MUST re-run to recover"
            )

    def test_keyring_not_reached_for_env_var_subsequent_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Marker present + env var → cascade returns at env step, no
        keyring API touch."""
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", PLACEHOLDER_FERNET_KEY.decode())
        home_base = tmp_path / ".worthless"
        _mark_bootstrapped(home_base)

        with patch(
            "worthless.cli.keystore.keyring.get_password",
            side_effect=AssertionError(
                "ensure_home reached keyring despite WORTHLESS_FERNET_KEY env var"
            ),
        ):
            ensure_home(base_dir=home_base)

    def test_file_only_branch_bypasses_read_fernet_key(self, tmp_path: Path) -> None:
        """Marker present + file only → read file directly. Critical fix
        for CodeRabbit FINDING 2: ``read_fernet_key``'s cascade is
        env → KEYRING → file, so going through it for a file-only state
        still touches the keyring API. The bypass uses
        ``read_fernet_key_from_file`` to skip the keyring step entirely.
        """
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        _mark_bootstrapped(home_base)

        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=AssertionError(
                    "file-only branch must NOT call read_fernet_key (it touches keyring)"
                ),
            ),
            patch(
                "worthless.cli.keystore.keyring.get_password",
                side_effect=AssertionError("file-only branch must NOT touch keyring API at all"),
            ),
        ):
            home = ensure_home(base_dir=home_base)
            # Cache should be populated from file so a later
            # ``home.fernet_key`` access is also keyring-free.
            assert home._cached_fernet_key is not None, (
                "file-only branch must populate the cache from disk"
            )

    def test_file_disappears_between_check_and_read_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """File-only signal is advisory, not fatal. If the fernet.key
        file vanishes between ``_fernet_key_present`` and
        ``read_fernet_key_from_file`` (TOCTOU race, e.g. user deletes
        it concurrently with a CLI invocation), ``ensure_home`` MUST
        defer to the lazy keyring fetch instead of crashing the
        whole CLI invocation on what may be a read-only command.

        Per CodeRabbit FINDING on PR #126: turning a TOCTOU race into
        a hard ensure_home failure was the wrong tradeoff.
        """
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        _mark_bootstrapped(home_base)

        # Simulate the file disappearing between check and read.
        with patch(
            "worthless.cli.bootstrap.read_fernet_key_from_file",
            side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "vanished"),
        ):
            # Must NOT raise — degrades gracefully to the lazy path.
            home = ensure_home(base_dir=home_base)
            # Cache should remain unpopulated; next ``home.fernet_key``
            # access will go through the full cascade and succeed via
            # keyring (or fail loudly there with a clear KEY_NOT_FOUND).
            assert home._cached_fernet_key is None

    def test_non_key_not_found_errors_propagate_from_file_branch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The TOCTOU defer in the file-only branch ONLY suppresses
        ``KEY_NOT_FOUND``. Any other ``WorthlessError`` (e.g.
        ``BOOTSTRAP_FAILED`` from a permission error, or a future
        ``CORRUPTED_KEY``) must propagate so the operator sees the
        real failure instead of silently falling through to keyring.

        This pins the ``if exc.code != ErrorCode.KEY_NOT_FOUND: raise``
        guard against accidental loosening.
        """
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home_base = tmp_path / ".worthless"
        _set_file_fernet_key(home_base)
        _mark_bootstrapped(home_base)

        sentinel = WorthlessError(ErrorCode.BOOTSTRAP_FAILED, "disk on fire — not a TOCTOU")
        with patch(
            "worthless.cli.bootstrap.read_fernet_key_from_file",
            side_effect=sentinel,
        ):
            with pytest.raises(WorthlessError) as exc_info:
                ensure_home(base_dir=home_base)
            assert exc_info.value.code == ErrorCode.BOOTSTRAP_FAILED, (
                "non-KEY_NOT_FOUND errors from read_fernet_key_from_file "
                "must propagate to the operator, not be silently swallowed"
            )

    def test_probe_skipped_for_keyring_only_subsequent_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Marker present + no env var + no file (keyring-only) → probe
        SKIPPED. The HF3 magic-moment state for read-only commands."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        home_base = tmp_path / ".worthless"
        _mark_bootstrapped(home_base)

        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=AssertionError(
                "ensure_home probed the keystore on a keyring-only subsequent run"
            ),
        ):
            ensure_home(base_dir=home_base)


class TestSeedCachedFernetKeyHoldsLock:
    """``WorthlessHome._seed_cached_fernet_key`` is the single entry
    point ``ensure_home`` uses to populate the cache. It must hold
    ``_cache_lock`` for the duration of the assignment — same
    discipline as the property body's read path (HF2's double-checked
    locking).

    Pinning the helper directly is much simpler than instrumenting
    every assignment site: as long as ``ensure_home`` calls only
    ``_seed_cached_fernet_key`` (verified by the regression tests in
    ``TestEnsureHomeProbeGate``), this contract covers both the
    first-run generate path and the file-only subsequent-run path.
    """

    def test_seed_holds_cache_lock_during_assignment(self, tmp_path: Path) -> None:
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        # Replace the C-level lock with a Python-level RLock so we can
        # observe ``locked()`` mid-callback (the C lock works for the
        # ``with`` block but the boolean ``locked()`` is racy on it).
        home._cache_lock = threading.RLock()

        held_during_assignment: list[bool] = []
        original_setattr = WorthlessHome.__setattr__

        def spy(self, name, value):
            if name == "_cached_fernet_key" and value is not None:
                # ``locked()`` returns True iff the current thread holds
                # this RLock — exactly the question we want answered.
                held_during_assignment.append(self._cache_lock._is_owned())
            original_setattr(self, name, value)

        with patch.object(WorthlessHome, "__setattr__", spy):
            home._seed_cached_fernet_key(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

        assert held_during_assignment == [True], (
            f"_seed_cached_fernet_key wrote _cached_fernet_key without holding "
            f"_cache_lock; observed: {held_during_assignment}"
        )

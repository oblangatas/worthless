"""Tests for bootstrap.py keystore integration (WOR-187).

These tests verify that bootstrap delegates Fernet key storage and
retrieval to the keystore module instead of doing direct file I/O.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.cli.errors import ErrorCode, WorthlessError


class TestEnsureHomeUsesKeystore:
    """ensure_home() must delegate to store_fernet_key for new keys."""

    def test_calls_store_fernet_key_when_key_missing(self, tmp_path: Path):
        """When no fernet key exists, ensure_home calls store_fernet_key."""
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
            ),
            patch("worthless.cli.bootstrap.store_fernet_key") as mock_store,
        ):
            ensure_home(base_dir=tmp_path / ".worthless")
            mock_store.assert_called_once()
            key_arg = mock_store.call_args[0][0]
            assert isinstance(key_arg, bytes)
            assert len(key_arg) == 44  # Fernet keys are 44 bytes base64

    def test_store_receives_home_base_dir(self, tmp_path: Path):
        """store_fernet_key is called with the home base_dir."""
        base = tmp_path / ".worthless"
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
            ),
            patch("worthless.cli.bootstrap.store_fernet_key") as mock_store,
        ):
            ensure_home(base_dir=base)
            call_args = mock_store.call_args
            if len(call_args[0]) > 1:
                assert call_args[0][1] == base
            else:
                assert call_args[1].get("home_dir") == base

    def test_does_not_call_store_when_key_exists(self, tmp_path: Path):
        """When fernet key already exists, store_fernet_key is NOT called.

        ``migrate_file_to_keyring`` is patched out: it can call
        ``store_fernet_key`` when promoting a file-backed key. That's a
        separate path. Patching keeps the assertion strict and
        backend-independent.
        """
        base = tmp_path / ".worthless"
        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            ensure_home(base_dir=base)

        with (
            patch("worthless.cli.bootstrap.store_fernet_key") as mock_store,
            patch("worthless.cli.bootstrap.migrate_file_to_keyring"),
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                return_value=bytearray(b"x" * 44),
            ),
        ):
            ensure_home(base_dir=base)
        mock_store.assert_not_called()

    def test_idempotent_no_error_on_second_call(self, tmp_path: Path):
        """Calling ensure_home twice does not raise."""
        base = tmp_path / ".worthless"
        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            ensure_home(base_dir=base)
            ensure_home(base_dir=base)

    def test_store_fernet_key_error_wrapped_in_worthless_error(self, tmp_path: Path):
        """If store_fernet_key raises, ensure_home wraps it in WorthlessError."""
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
            ),
            patch(
                "worthless.cli.bootstrap.store_fernet_key",
                side_effect=OSError("keyring exploded"),
            ),
        ):
            with pytest.raises(WorthlessError) as exc_info:
                ensure_home(base_dir=tmp_path / ".worthless")
            assert exc_info.value.code.value == 100  # BOOTSTRAP_FAILED

    def test_no_direct_os_open_for_fernet_key(self, tmp_path: Path):
        """ensure_home must NOT use os.open to write the fernet key directly."""
        import os

        original_os_open = os.open
        fernet_opens: list[str] = []

        def tracking_open(path, flags, mode=0o777, *args, **kwargs):
            if "fernet" in str(path):
                fernet_opens.append(str(path))
            return original_os_open(path, flags, mode, *args, **kwargs)

        with (
            patch("os.open", side_effect=tracking_open),
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
            ),
            patch("worthless.cli.bootstrap.store_fernet_key") as mock_store,
        ):
            ensure_home(base_dir=tmp_path / ".worthless")

        if mock_store.called:
            assert fernet_opens == [], (
                f"ensure_home called os.open for fernet key directly: {fernet_opens}"
            )


class TestFernetKeyPropertyUsesKeystore:
    """WorthlessHome.fernet_key must delegate to read_fernet_key."""

    def test_calls_read_fernet_key(self, tmp_path: Path):
        """fernet_key property calls read_fernet_key with base_dir."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")

        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            return_value=bytearray(b"test-key-value-padded-to-44-bytes-12345678901"),
        ) as mock_read:
            _ = home.fernet_key
            mock_read.assert_called_once_with(home.base_dir)

    def test_returns_bytearray(self, tmp_path: Path):
        """fernet_key property returns bytearray per SR-01."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        fake_key = bytearray(b"fake-fernet-key-44-chars-padded-to-44-bytes")

        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            return_value=fake_key,
        ):
            result = home.fernet_key
            assert isinstance(result, bytearray), f"Expected bytearray, got {type(result).__name__}"
            assert result == bytes(fake_key)

    def test_propagates_key_not_found_error(self, tmp_path: Path):
        """When read_fernet_key raises KEY_NOT_FOUND, property propagates it."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")

        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
        ):
            with pytest.raises(WorthlessError) as exc_info:
                _ = home.fernet_key
            assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND


class TestFernetKeyMemoization:
    """HF2 / worthless-mnlp: ``WorthlessHome.fernet_key`` is memoized
    per-instance to collapse 3+ keychain calls per ``worthless lock`` to 1.

    THIS IS process-scoped caching at the dataclass instance level. THIS IS
    NOT keychain permission permanence — macOS re-evaluates the
    ``SecKeychainItemCopyContent`` ACL on every call, so 'Always Allow' on
    the dialog only sticks to the exact call that triggered the dialog;
    subsequent reads in the same process re-prompt unless served from an
    in-memory cache. New CLI invocations still re-fetch (cache is per-process,
    not per-session) — that is acceptable per the bead spec.
    """

    def test_property_memoizes_first_read(self, tmp_path: Path):
        """Accessing ``.fernet_key`` 5x must call ``read_fernet_key`` exactly once.

        Bug repro: today the property re-reads on every access, firing a fresh
        keychain ACL probe each time. After memoization the first access
        populates a private cache and subsequent accesses return the cached
        bytearray.
        """
        home = WorthlessHome(base_dir=tmp_path / ".worthless")

        # ``side_effect=lambda *_: bytearray(...)`` returns a NEW bytearray on
        # every underlying call so the cache cannot inadvertently alias a
        # test-owned reference; ``call_count`` becomes the only honest proof
        # of memoization (CodeRabbit nit #2 on PR #125).
        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(b"memoized-key-padded-to-44-bytes-12345678901"),
        ) as mock_read:
            for _ in range(5):
                _ = home.fernet_key
            assert mock_read.call_count == 1, (
                f"fernet_key not memoized — read_fernet_key called "
                f"{mock_read.call_count} times for 5 accesses on the same instance"
            )

    def test_memoization_is_per_instance(self, tmp_path: Path):
        """Two ``WorthlessHome`` instances must each trigger one read.

        Memoization is per-dataclass-instance, not module-level. Multi-tenant
        test fixtures (or pytest-xdist workers sharing a process) must NOT
        share a fernet cache; each ``WorthlessHome`` object owns its own.
        """
        home_a = WorthlessHome(base_dir=tmp_path / "a" / ".worthless")
        home_b = WorthlessHome(base_dir=tmp_path / "b" / ".worthless")

        # Fresh bytearray per underlying call, same rationale as
        # test_property_memoizes_first_read — see CodeRabbit nit #2 on PR #125.
        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(b"shared-fake-key-padded-to-44-bytes-1234567"),
        ) as mock_read:
            _ = home_a.fernet_key
            _ = home_a.fernet_key
            _ = home_b.fernet_key
            _ = home_b.fernet_key
            assert mock_read.call_count == 2, (
                f"each WorthlessHome should trigger one read, got {mock_read.call_count}"
            )

    def test_caller_mutation_does_not_poison_cache(self, tmp_path: Path) -> None:
        """Consumer ``zero_buf`` on the returned bytearray must NOT poison the cache.

        Production callers (``unlock.py``, ``proxy/app.py``) zero their
        bytearray after using the key, per SR-01. The OLD design (return the
        cached object directly) would have meant their ``zero_buf`` zeroed
        the cache itself, so the next reader on the same ``WorthlessHome``
        would silently get all-zero bytes — decryption would corrupt without
        raising. This test simulates that exact flow: read, zero the returned
        copy, read again, assert clean key bytes are returned.

        A future regression to "return self._cached_fernet_key" (no copy)
        would fail this test loudly.
        """
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        clean_key = b"poison-test-padded-to-44-bytes-1234567890123"
        # Mock returns a NEW bytearray each call so the cache stores its own
        # bytearray (not a reference the test holds onto).
        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(clean_key),
        ):
            first = home.fernet_key
            # Caller zeros their copy — simulates SR-01 ``zero_buf()`` after use.
            for i in range(len(first)):
                first[i] = 0
            assert all(b == 0 for b in first), "precondition: caller's copy is fully zeroed"

            # Subsequent reader must get the original clean key bytes from cache,
            # not whatever residue the caller left in their now-zeroed copy.
            second = home.fernet_key
            assert bytes(second) == clean_key, (
                f"cache was poisoned by caller mutation: returned "
                f"{bytes(second)!r}, expected {clean_key!r}"
            )
            assert any(b != 0 for b in second), (
                "second read returned all-zero bytes — cache was poisoned"
            )

    def test_property_returns_fresh_bytearray_copies_with_same_content(
        self, tmp_path: Path
    ) -> None:
        """Each property access returns an INDEPENDENT bytearray copy.

        After memoization, the cache is the canonical source but the property
        returns a fresh copy on each access so callers can ``zero_buf()`` their
        own copy (per SR-01) without poisoning the cache. This test pins:

        * SR-01 type contract — cached and returned values are ``bytearray``,
          not immutable ``bytes``.
        * True memoization — proven by ``call_count == 1`` over two accesses.
          The earlier version of this test asserted ``first is second``, which
          would have passed even without a cache because ``mock.return_value``
          is the same object on every call. Using ``side_effect=lambda *_:
          bytearray(...)`` returns a NEW object on each underlying read, so
          ``call_count`` is the only honest way to prove the cache is engaged.
        * Fresh-copy contract — ``first is not second`` confirms callers each
          get their own bytearray. A future regression to "return the cached
          object directly" would re-introduce the consumer-zeroing-poisons-
          cache bug; this assertion catches that.
        """
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        # Mock returns a NEW bytearray each underlying call so identity-only
        # checks cannot false-pass.
        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(b"sr01-check-padded-to-44-bytes-1234567890123"),
        ) as mock_read:
            first = home.fernet_key
            second = home.fernet_key
            assert mock_read.call_count == 1, (
                f"fernet_key not memoized — read_fernet_key called "
                f"{mock_read.call_count} times for 2 accesses on the same instance"
            )
            assert isinstance(first, bytearray), "first read must be bytearray (SR-01)"
            assert isinstance(second, bytearray), "second read must be bytearray (SR-01)"
            assert first == second, "both reads must derive from the same cached source"
            assert first is not second, (
                "property must return a FRESH bytearray copy on each access so "
                "callers can zero_buf() their copy without poisoning the cache"
            )

    def test_concurrent_first_read_triggers_one_keychain_call(self, tmp_path: Path) -> None:
        """Concurrent first-readers on one ``WorthlessHome`` must collapse to
        exactly one ``read_fernet_key`` call (one Keychain prompt).

        Without a lock, the lazy-init check-then-set is two operations: two
        threads can both observe ``_cached_fernet_key is None`` and both
        call ``read_fernet_key``, firing duplicate macOS Keychain prompts
        and discarding one bytearray without ``zero_buf``. Real call site:
        ``src/worthless/mcp/server.py`` runs FastMCP's asyncio loop on the
        main thread but dispatches blocking work (``_do_lock``) via
        ``loop.run_in_executor`` to the default thread pool — main +
        executor can both touch ``home.fernet_key``.

        A ``threading.Barrier(4)`` synchronises all 4 worker threads so they
        reach the outer ``_cached_fernet_key is None`` check simultaneously,
        deterministically maximising the race window without any timing
        dependence. With the per-instance ``threading.Lock`` and
        double-checked init, ``call_count == 1`` regardless of the number
        of concurrent first-readers.
        """
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        # Barrier serialises the 4 worker threads: they all block at
        # ``barrier.wait()`` until the last one arrives, then all release
        # simultaneously. This deterministically maximises the race window —
        # without the lock, all 4 would reach the outer ``is None`` check
        # together and all call ``read_fernet_key``. With the lock, exactly
        # one enters the populate branch. No timing dependence (replaces an
        # earlier ``time.sleep`` per CodeRabbit's nit on PR #125).
        barrier = threading.Barrier(4)

        def access_fernet_key(_: object) -> bytearray:
            barrier.wait()
            return home.fernet_key

        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(b"thread-safe-padded-to-44-bytes-12345678901a"),
        ) as mock_read:
            with ThreadPoolExecutor(max_workers=4) as ex:
                results = list(ex.map(access_fernet_key, range(4)))

            assert mock_read.call_count == 1, (
                f"thread-safe lock failed: read_fernet_key called "
                f"{mock_read.call_count} times across 4 concurrent first-readers"
            )
            # All readers should derive from the single cached source.
            first_content = bytes(results[0])
            assert all(bytes(r) == first_content for r in results), (
                "concurrent reads returned divergent content — cache populate raced"
            )
            # And each result is its own bytearray copy (fresh-copy contract).
            for i, r in enumerate(results):
                for j in range(i + 1, len(results)):
                    assert r is not results[j], (
                        f"results[{i}] and results[{j}] are the SAME object — "
                        "fresh-copy contract violated"
                    )


class TestKeyringCallCountInvariants:
    """One ``keyring.get_password`` per CLI invocation — both paths.

    Background: HF2 PR #125 review surfaced via real-keyring spy that the
    existing-key path was hitting the keyring TWICE per CLI invocation,
    not once as the bead claimed. Root cause: ``migrate_file_to_keyring``
    (called by ``ensure_home`` after a successful probe) was calling
    ``keyring.get_password`` directly to ask "is the key already in
    keyring?", bypassing the property cache. First-ever-boot path also
    counted 2 because the probe raised KEY_NOT_FOUND before assigning the
    cache, so the first consumer re-read.

    These tests pin both paths at 1 keyring read.
    """

    def test_migrate_skips_keyring_when_no_fernet_file_exists(self, tmp_path: Path):
        """``migrate_file_to_keyring`` MUST check file existence first.

        If no ``fernet.key`` file is on disk (the common case post-migration),
        no migration is possible — the function must return immediately
        without calling ``keyring.get_password``. Anything else inflates the
        keyring read count on every CLI invocation.
        """
        from worthless.cli import keystore

        with (
            patch.object(keystore, "keyring_available", return_value=True),
            patch.object(keystore.keyring, "get_password") as mock_get,
        ):
            result = keystore.migrate_file_to_keyring(home_dir=tmp_path / ".worthless")

        assert result is False, "no file → migration cannot succeed"
        # Real assertion (NOT a tuple) — assert_not_called raises directly if
        # the mock was called. Prior code wrapped this in a tuple expression
        # that silently discarded the failure message.
        assert mock_get.call_count == 0, (
            "migrate_file_to_keyring called keyring.get_password despite no "
            "fernet.key file present — this is the HF2 bypass that re-read the "
            f"keyring on every existing-key CLI invocation. Calls: {mock_get.call_count}"
        )

    def test_ensure_home_seeds_cache_after_generating_key_on_missing_key_path(
        self, tmp_path: Path
    ) -> None:
        """First-ever-boot path: cache MUST be populated after key generation.

        When ``read_fernet_key`` raises ``KEY_NOT_FOUND`` during the bootstrap
        probe, the property body re-raises before assigning ``_cached_fernet_key``.
        ``ensure_home``'s ``except`` branch generates and stores a fresh key —
        but unless it ALSO seeds the cache directly from that key, the next
        ``home.fernet_key`` consumer (e.g., ``ShardRepository`` init) would
        re-read the freshly stored key from keyring. This test pins the
        cache-seeding contract.
        """
        from cryptography.fernet import Fernet

        generated = Fernet.generate_key()
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "no key"),
            ),
            patch("worthless.cli.bootstrap.store_fernet_key"),
            patch(
                "worthless.cli.bootstrap.base64.urlsafe_b64encode",
                return_value=generated,
            ),
            patch(
                "worthless.cli.bootstrap.os.urandom",
                return_value=b"\x00" * 32,
            ),
        ):
            home = ensure_home(base_dir=tmp_path / ".worthless")

        assert home._cached_fernet_key is not None, (
            "cache was not seeded after generate_key — first-ever-boot path "
            "still costs an extra keyring.get_password on the next consumer"
        )
        assert isinstance(home._cached_fernet_key, bytearray), (
            f"cache must be bytearray (SR-01); got {type(home._cached_fernet_key).__name__}"
        )
        assert bytes(home._cached_fernet_key) == generated, (
            "cache value does not match the freshly generated key"
        )


class TestObservabilityAndCascadePaths:
    """Coverage for the small gaps surfaced in the HF2 final pass:
    logger statements + WORTHLESS_FERNET_KEY env-var cascade path.
    """

    def test_logger_fires_on_cache_miss_then_hit(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Cache-miss + cache-hit log lines fire from the property body.

        Future debugging via ``WORTHLESS_LOG_LEVEL=DEBUG`` (or pytest
        ``--log-cli-level=DEBUG``) needs these two messages to surface the
        exact path each access took. If someone removes them, no functional
        test catches it; this one does.
        """
        import logging

        caplog.set_level(logging.DEBUG, logger="worthless.cli.bootstrap")
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        with patch(
            "worthless.cli.bootstrap.read_fernet_key",
            side_effect=lambda *_: bytearray(b"log-test-padded-to-44-bytes-1234567890123"),
        ):
            _ = home.fernet_key  # cache MISS
            _ = home.fernet_key  # cache HIT (warm path)

        miss_logs = [r for r in caplog.records if "cache MISS" in r.message]
        hit_logs = [r for r in caplog.records if "cache HIT" in r.message]
        assert len(miss_logs) == 1, (
            f"expected one 'cache MISS' log on first access, got {len(miss_logs)}"
        )
        assert len(hit_logs) == 1, (
            f"expected one 'cache HIT' log on second access, got {len(hit_logs)}"
        )

    def test_env_var_path_populates_cache_without_keyring_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``WORTHLESS_FERNET_KEY`` env var beats keyring in ``read_fernet_key``
        and the value still flows through the HF2 cache.

        Three invariants:
        1. The cached value matches the env var (proves the cascade is intact).
        2. ``keyring.get_password`` is NOT called (env path short-circuits).
        3. Repeated property access stays at zero ``keyring.get_password`` calls
           (cache works the same regardless of which read_fernet_key branch
           returned the bytes).
        """
        import keyring

        env_key = "env-var-fernet-padded-to-44-bytes-12345678901"
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", env_key)
        home = WorthlessHome(base_dir=tmp_path / ".worthless")

        original_get_password = keyring.get_password
        keyring_calls = [0]

        def _spy(*args: object, **kwargs: object) -> object:
            keyring_calls[0] += 1
            return original_get_password(*args, **kwargs)

        monkeypatch.setattr(keyring, "get_password", _spy)

        first = home.fernet_key
        for _ in range(4):
            _ = home.fernet_key

        assert bytes(first) == env_key.encode(), (
            f"env var value did not flow through cache: got {bytes(first)!r}"
        )
        assert keyring_calls[0] == 0, (
            f"env var path leaked into keyring: keyring.get_password called "
            f"{keyring_calls[0]} times despite WORTHLESS_FERNET_KEY being set"
        )
        assert home._cached_fernet_key is not None
        assert bytes(home._cached_fernet_key) == env_key.encode()

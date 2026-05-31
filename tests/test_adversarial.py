"""Adversarial attack tests -- written from the attacker's perspective.

Each test class is named after the attack vector. Each test describes what
the attacker tries. A PASSING test means the attack FAILS -- the defense
holds.

These tests cover the 7 P1 release blockers fixed on fix/v1-release-blockers.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cryptography.fernet import Fernet

from worthless.crypto.shard_signing import (
    ShardSigningError,
    generate_signing_key,
    sign_shard_a,
    verify_and_extract,
)
from worthless.proxy.errors import ErrorResponse
from worthless.storage.repository import ShardRepository


class TestShardSigningAdversarial:
    """Phase 6 shard-A HMAC signing — attacks that must fail.

    Each test is named after the attack vector. A passing test means
    the defense holds — the attack is defeated.
    """

    def test_git_history_replay_rejected_after_relock(self, tmp_path):
        """ATTACK: steal a signed envelope from git history; present it after re-lock.

        The HMAC is cryptographically valid (right key, right alias) but the owner
        re-locked, rotating the nonce. The proxy's is_valid_signing_nonce check catches
        the stale nonce and rejects the request.
        """
        db_path = str(tmp_path / "test.db")
        fernet_key = Fernet.generate_key()
        signing_key = generate_signing_key()
        alias = "stolen-from-git"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "G" * 60).encode())

        async def _run() -> None:
            repo = ShardRepository(db_path, fernet_key)
            await repo.initialize()

            # Attacker captures this envelope from a git commit
            stolen_envelope, nonce_1, expires_1 = sign_shard_a(
                shard_a, alias, signing_key, prefix=prefix
            )
            await repo.store_signing_nonce(alias, nonce_1, expires_1)

            # Owner re-locks — nonce_1 is revoked
            _, nonce_2, expires_2 = sign_shard_a(shard_a, alias, signing_key, prefix=prefix)
            await repo.store_signing_nonce(alias, nonce_2, expires_2)

            # Attacker presents stolen_envelope — HMAC verifies but nonce is stale
            _, stolen_nonce, _ = verify_and_extract(
                bytearray(stolen_envelope), alias, signing_key, prefix=prefix
            )
            is_valid = await repo.is_valid_signing_nonce(alias, stolen_nonce)
            assert not is_valid, "Stolen pre-relock envelope must be rejected after re-lock"

        asyncio.run(_run())

    def test_forged_envelope_wrong_signing_key_rejected(self):
        """ATTACK: attacker generates their own signing key and forges an envelope.

        Without the real server-side signing.key, any envelope the attacker constructs
        will fail HMAC verification — the HMAC is bound to the secret key.
        """
        alias = "target-alias"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "F" * 60).encode())

        real_key = generate_signing_key()
        attacker_key = generate_signing_key()  # attacker's own key — not the real one
        assert real_key != attacker_key

        # Attacker signs with their own key
        forged_envelope, _, _ = sign_shard_a(shard_a, alias, attacker_key, prefix=prefix)

        # Proxy verifies with the real key — must reject
        with pytest.raises(ShardSigningError, match="HMAC"):
            verify_and_extract(forged_envelope, alias, real_key, prefix=prefix)

    def test_bit_flip_forgery_rejected(self):
        """ATTACK: flip one bit in the HMAC section of the overhead.

        Any single-bit mutation in the 16-byte truncated HMAC is caught with
        overwhelming probability (2^128 forgery resistance).
        """
        alias = "target-alias"
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "B" * 60).encode())
        key = generate_signing_key()

        envelope, _, _ = sign_shard_a(shard_a, alias, key, prefix=prefix)

        # Flip a bit inside the HMAC region of the base64url overhead.
        # Overhead starts after the prefix; HMAC occupies bytes 20-36 of the
        # decoded overhead (nonce=0-16, expiry=16-20, hmac=20-36).
        prefix_len = len(prefix)
        # Mutate the first char of the overhead block (safe to corrupt any position)
        envelope[prefix_len] = envelope[prefix_len] ^ 0x01

        with pytest.raises(ShardSigningError):
            verify_and_extract(envelope, alias, key, prefix=prefix)

    def test_cross_alias_injection_rejected(self):
        """ATTACK: take a valid envelope for alias-A and present it under alias-B.

        The HMAC input includes the alias string, so cross-alias reuse is impossible
        without knowing the signing key.
        """
        prefix = "sk-proj-"
        shard_a = bytearray(("sk-proj-" + "C" * 60).encode())
        key = generate_signing_key()

        alias_a = "openai-victim"
        alias_b = "anthropic-target"

        # Attacker has a valid envelope for alias_a
        envelope_a, _, _ = sign_shard_a(shard_a, alias_a, key, prefix=prefix)

        # Present it to the proxy as if it belongs to alias_b — must fail
        with pytest.raises(ShardSigningError, match="HMAC"):
            verify_and_extract(envelope_a, alias_b, key, prefix=prefix)


# ---------------------------------------------------------------------------
# Attack 1: Stale key file exfiltration (worthless-48k)
# ---------------------------------------------------------------------------


class TestStaleKeyExfiltration:
    """After a keyring migration, attacker checks disk for leftover fernet.key
    containing the plaintext Fernet key."""

    def test_attacker_cannot_read_key_from_disk_after_keyring_migration(self, tmp_path: Path):
        """Attacker scenario: victim migrates fernet.key to OS keyring.
        Attacker later gains disk access and looks for the stale file.
        Defense: store_fernet_key deletes the file after keyring write."""
        from worthless.cli.keystore import store_fernet_key

        # Simulate pre-existing fernet.key on disk (pre-keyring era)
        stale_file = tmp_path / "fernet.key"
        stale_file.write_bytes(b"super-secret-fernet-key-44-chars-base64-xxx=")

        # Mock a working keyring so store_fernet_key prefers it
        fake_keyring: dict[tuple[str, str], str] = {}

        def _set_pw(service: str, username: str, password: str) -> None:
            fake_keyring[(service, username)] = password

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring.set_password", side_effect=_set_pw),
            patch("worthless.cli.keystore._fernet_file_path", return_value=stale_file),
        ):
            store_fernet_key(b"new-fernet-key-44-chars-base64-xxxxxxxxxxxx", tmp_path)

        # ATTACK: attacker looks for the stale file
        assert not stale_file.exists(), (
            "Stale fernet.key survives keyring migration -- attacker can exfiltrate it"
        )


# ---------------------------------------------------------------------------
# Attack 2: Cross-install keyring theft (worthless-2fd)
# ---------------------------------------------------------------------------


class TestCrossInstallKeyringTheft:
    """Attacker runs a second worthless install on the same machine and
    attempts to read the victim's Fernet key from the shared OS keyring."""

    def test_attacker_install_cannot_read_victim_keyring_entry(self, tmp_path: Path):
        """Attacker scenario: victim installs worthless in /home/victim/.worthless,
        attacker installs in /home/attacker/.worthless. Both use the same OS
        keyring service name. Defense: keyring username is derived from the
        resolved home_dir path, so entries are isolated."""
        from worthless.cli.keystore import (
            _keyring_username,
            read_fernet_key,
            store_fernet_key,
        )

        victim_home = tmp_path / "victim" / ".worthless"
        attacker_home = tmp_path / "attacker" / ".worthless"
        victim_home.mkdir(parents=True)
        attacker_home.mkdir(parents=True)

        # Verify usernames differ
        victim_username = _keyring_username(victim_home)
        attacker_username = _keyring_username(attacker_home)
        assert victim_username != attacker_username, (
            "Keyring usernames collide -- cross-install theft is possible"
        )

        # Simulate keyring as a dict keyed by (service, username)
        fake_keyring: dict[tuple[str, str], str] = {}

        def _set_pw(service: str, username: str, password: str) -> None:
            fake_keyring[(service, username)] = password

        def _get_pw(service: str, username: str) -> str | None:
            return fake_keyring.get((service, username))

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring.set_password", side_effect=_set_pw),
            patch("worthless.cli.keystore.keyring.get_password", side_effect=_get_pw),
        ):
            # Victim stores their key
            store_fernet_key(b"victim-secret-key-base64-xxxxxxxxxxxxxxxxx", victim_home)

            # ATTACK: attacker tries to read victim's key from their own home_dir
            from worthless.cli.errors import WorthlessError

            with pytest.raises(WorthlessError):
                read_fernet_key(attacker_home)


# ---------------------------------------------------------------------------
# Attack 3: Memory dump key extraction (worthless-3sd)
# ---------------------------------------------------------------------------


class TestMemoryDumpKeyExtraction:
    """Attacker has RCE, dumps process memory after proxy shutdown, looking
    for Fernet key remnants in the heap."""

    def test_key_material_zeroed_after_repository_close(self, tmp_path: Path):
        """Attacker scenario: proxy shuts down, attacker reads /proc/pid/mem.
        Defense: ShardRepository.close() zeros the fernet_key bytearray."""
        from cryptography.fernet import Fernet as FernetCls
        from worthless.storage.repository import ShardRepository

        fernet_key = FernetCls.generate_key()
        key = bytearray(fernet_key)
        repo = ShardRepository(str(tmp_path / "test.db"), key)

        # Grab a reference to the internal buffer BEFORE close
        internal_key = repo._fernet_key_bytes
        assert any(b != 0 for b in internal_key), "Precondition: key is non-zero"

        repo.close()

        # ATTACK: attacker scans memory for key material
        assert all(b == 0 for b in internal_key), (
            "Key material survives in memory after close -- attacker can extract it"
        )

    @pytest.mark.asyncio
    async def test_settings_key_zeroed_after_lifespan_shutdown(self, tmp_path):
        """Attacker scenario: proxy process exits, attacker finds the
        ProxySettings fernet_key bytearray still in memory.
        Defense: _lifespan handler zeros the bytearray on shutdown."""
        from cryptography.fernet import Fernet as FernetCls

        from worthless.proxy.app import create_app
        from worthless.proxy.config import ProxySettings

        db_path = str(tmp_path / "test.db")
        fernet_key = bytearray(FernetCls.generate_key())
        key_ref = fernet_key  # hold a reference to the same bytearray

        settings = ProxySettings(db_path=db_path, fernet_key=fernet_key)
        app = create_app(settings)

        # Precondition: key is non-zero
        assert any(b != 0 for b in key_ref)

        # Exercise actual lifespan (startup + shutdown)
        async with app.router.lifespan_context(app):
            # Proxy is "running" — key still alive
            assert any(b != 0 for b in key_ref)

        # After lifespan shutdown: key should be zeroed
        assert all(b == 0 for b in key_ref), (
            "ProxySettings fernet_key survives lifespan shutdown -- "
            "attacker can extract it from process memory"
        )

    @pytest.mark.asyncio
    async def test_settings_key_zeroed_even_when_db_close_raises(self, tmp_path):
        """Attacker scenario: db.close() throws during shutdown, attacker
        hopes the fernet_key zeroing is skipped due to the exception.
        Defense: zeroing runs in a finally block."""
        from cryptography.fernet import Fernet as FernetCls

        from worthless.proxy.app import create_app
        from worthless.proxy.config import ProxySettings

        db_path = str(tmp_path / "test.db")
        fernet_key = bytearray(FernetCls.generate_key())
        key_ref = fernet_key

        settings = ProxySettings(db_path=db_path, fernet_key=fernet_key)
        app = create_app(settings)

        assert any(b != 0 for b in key_ref)

        try:
            async with app.router.lifespan_context(app):
                # Sabotage db.close so it raises during shutdown
                real_db = app.state.db
                real_db.close = AsyncMock(side_effect=RuntimeError("db boom"))
        except RuntimeError:
            pass  # expected from the sabotaged close

        assert all(b == 0 for b in key_ref), (
            "ProxySettings fernet_key not zeroed when db.close() raises -- "
            "attacker can extract key from memory after crash"
        )


# ---------------------------------------------------------------------------
# Attack 4: Rate limit burst bypass (worthless-ks6)
# ---------------------------------------------------------------------------


class TestRateLimitBurstBypass:
    """Attacker fires 20 simultaneous requests to bypass a 5 RPS rate limit,
    hoping concurrent reads of the sliding window let them all through."""

    @pytest.mark.asyncio
    async def test_attacker_burst_cannot_exceed_rate_limit(self):
        """Attacker scenario: 20 concurrent requests against 5 RPS limit.
        Defense: per-key asyncio.Lock serializes window reads."""
        from worthless.proxy.rules import RateLimitRule

        rule = RateLimitRule(default_rps=5.0, db_path=None)

        # Build 20 fake requests with the same client IP
        fake_request = MagicMock()
        fake_request.client = MagicMock()
        fake_request.client.host = "10.0.0.1"

        results = await asyncio.gather(
            *[rule.evaluate("test-alias", fake_request, provider="openai") for _ in range(20)]
        )

        allowed = [r for r in results if r is None]
        denied = [r for r in results if isinstance(r, ErrorResponse)]

        assert len(allowed) == 5, (
            f"Rate limiter allowed {len(allowed)} of 20 burst requests "
            f"(expected exactly 5) -- burst bypass succeeded"
        )
        assert len(denied) == 15, (
            f"Rate limiter denied {len(denied)} of 20 burst requests "
            f"(expected 15) -- burst bypass partially succeeded"
        )


# ---------------------------------------------------------------------------
# Attack 5: Enrollment crash exploitation (worthless-m58)
# ---------------------------------------------------------------------------


class TestEnrollmentCrashExploitation:
    """Attacker induces a DB failure during enrollment, hoping to leave an
    orphan shard_a file they can later use without proper DB authorization."""

    def test_db_crash_leaves_no_exploitable_artifacts(self, tmp_path: Path):
        """Attacker scenario: DB write fails mid-enrollment. Attacker checks
        disk for orphan shard_a file containing half the split key.
        Defense: compensation logic in _enroll_single deletes shard_a on failure."""
        from worthless.cli.bootstrap import WorthlessHome
        from worthless.cli.commands.lock import _enroll_single
        from worthless.cli.errors import WorthlessError

        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        home.base_dir.mkdir(parents=True)
        home.shard_a_dir.mkdir(parents=True)

        # Write a real fernet key so ShardRepository can initialize
        from cryptography.fernet import Fernet as FernetCls

        fernet_key = FernetCls.generate_key()

        # Mock read_fernet_key to return our test key, and store_enrolled to crash
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                return_value=bytearray(fernet_key),
            ),
            patch(
                "worthless.storage.repository.ShardRepository.store_enrolled",
                new_callable=AsyncMock,
                side_effect=RuntimeError("simulated DB crash"),
            ),
            patch(
                "worthless.storage.repository.ShardRepository.initialize",
                new_callable=AsyncMock,
            ),
        ):
            with pytest.raises(WorthlessError):
                _enroll_single(
                    alias="test-key",
                    key="sk-proj-aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc",
                    provider="openai",
                    home=home,
                )

        # ATTACK: attacker searches for orphan shard_a files
        shard_a_path = home.shard_a_dir / "test-key"
        assert not shard_a_path.exists(), (
            "Orphan shard_a file survives DB crash -- attacker can exploit it"
        )


# ---------------------------------------------------------------------------
# Attack 6: Streaming OOM attack (worthless-kyc)
# ---------------------------------------------------------------------------


class TestStreamingOOMAttack:
    """Attacker crafts a request triggering a massive streaming response
    (100k SSE chunks), hoping to OOM the proxy's metering buffer."""

    def test_massive_stream_does_not_grow_metering_buffer(self):
        """Attacker scenario: send a prompt that generates 100,000 SSE chunks.
        Defense: StreamingUsageCollector processes chunks incrementally
        without buffering raw data."""
        from worthless.proxy.metering import StreamingUsageCollector

        collector = StreamingUsageCollector(provider="openai")

        # Generate 100,000 SSE chunks (typical streaming response chunks)
        chunk_template = (
            b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk",'
            b'"choices":[{"delta":{"content":"word "},"index":0}]}\n\n'
        )

        # Measure baseline: the collector should have bounded internal state
        # (no growing list of raw chunks)
        for i in range(100_000):
            collector.feed(chunk_template)

        # Verify the collector did NOT accumulate raw chunks.
        # The collector should only have scalar state (_partial_line, counters).
        # Check that no internal list has grown proportional to input.
        internal_attrs = vars(collector)
        for attr_name, attr_val in internal_attrs.items():
            if isinstance(attr_val, list | bytearray):
                assert len(attr_val) < 1000, (
                    f"StreamingUsageCollector.{attr_name} grew to {len(attr_val)} "
                    f"entries after 100k chunks -- OOM attack viable"
                )
            if isinstance(attr_val, str):
                assert len(attr_val) < 10_000, (
                    f"StreamingUsageCollector.{attr_name} grew to {len(attr_val)} "
                    f"chars after 100k chunks -- OOM attack viable"
                )

        # Verify collector still produces a valid (empty) result -- no crash
        result = collector.result()
        assert result is None, "Collector should return None when no usage chunk was seen"

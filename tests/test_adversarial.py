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

from worthless.proxy.errors import ErrorResponse


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
    async def test_settings_key_never_held_by_proxy(self, tmp_path):
        """WOR-309: the proxy MUST never hold the Fernet key in memory.

        Pre-WOR-309 the proxy reconstructed shard-B in-process and zeroed
        ``ProxySettings.fernet_key`` on lifespan shutdown. Post-WOR-309 the
        sidecar owns the key and the proxy only sees ciphertext-at-rest, so
        there is no key in proxy memory for an attacker to extract — even
        if the caller hands one to ``ProxySettings``, the proxy never reads
        it. The strongest assertion we can make is that ``proxy.app`` does
        not reference ``fernet_key`` at all.
        """
        import inspect

        from worthless.proxy import app as proxy_app_module

        src = inspect.getsource(proxy_app_module)
        assert "fernet_key" not in src, (
            "proxy.app references fernet_key — WOR-309 invariant broken: "
            "the sidecar owns the key, the proxy must never see it"
        )

    @pytest.mark.asyncio
    async def test_proxy_never_imports_fernet(self, tmp_path):
        """WOR-309: the proxy import chain must be Fernet-free.

        Pre-WOR-309 the proxy zeroed the fernet_key in a finally block to
        survive db.close() raising. Post-WOR-309 the proxy doesn't import
        ``cryptography.fernet`` at all — there's no Fernet object to clean
        up because the sidecar owns crypto. This test asserts the absence
        of the import to lock the invariant from a different angle than
        ``test_settings_key_never_held_by_proxy``.
        """
        import inspect

        from worthless.proxy import app as proxy_app_module

        src = inspect.getsource(proxy_app_module)
        assert "from cryptography" not in src, (
            "proxy.app imports cryptography — WOR-309 invariant broken: "
            "the proxy must delegate all crypto to the sidecar over IPC"
        )
        assert "import cryptography" not in src, (
            "proxy.app imports cryptography — WOR-309 invariant broken"
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

"""Live attack tests -- prove split shards are useless against real APIs.

No Docker, no mocks. Splits real API keys using format-preserving split,
then fires each attack vector at the real OpenAI and Anthropic endpoints.

Requires OPENAI_API_KEY and/or ANTHROPIC_API_KEY in environment.
Costs ~$0.002 per full run (9 tests, ~5 API calls per provider max).

Run with:
    uv run pytest tests/test_openclaw_live.py -x -v -m live -o "addopts="
"""

from __future__ import annotations

import os

import httpx
import pytest

from worthless.cli.key_patterns import detect_prefix
from worthless.crypto.splitter import reconstruct_key_fp, split_key_fp

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.timeout(120),
]

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

OPENAI_BODY = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
    "max_tokens": 5,
}

ANTHROPIC_BODY = {
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 5,
    "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
}


def _post_openai(key: str) -> httpx.Response:
    """POST to OpenAI chat completions with the given key."""
    return httpx.post(
        OPENAI_URL,
        json=OPENAI_BODY,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        timeout=15.0,
    )


def _post_anthropic(key: str) -> httpx.Response:
    """POST to Anthropic messages with the given key."""
    return httpx.post(
        ANTHROPIC_URL,
        json=ANTHROPIC_BODY,
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        timeout=15.0,
    )


def _split_openai():
    """Split the real OpenAI key, return the FormatPreservingSplitResult."""
    prefix = detect_prefix(OPENAI_KEY, "openai")
    return split_key_fp(OPENAI_KEY, prefix, "openai")


def _split_anthropic():
    """Split the real Anthropic key, return the FormatPreservingSplitResult."""
    prefix = detect_prefix(ANTHROPIC_KEY, "anthropic")
    return split_key_fp(ANTHROPIC_KEY, prefix, "anthropic")


# ---------------------------------------------------------------------------
# TestLiveReconstruction -- positive path (original tests)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
class TestLiveReconstruction:
    """Prove format-preserving split/reconstruct against real OpenAI API."""

    def test_live_full_flow(self):
        """The money test: split -> shard-A fails -> reconstruct -> success."""
        print()

        # 1. Format-preserving split
        prefix = detect_prefix(OPENAI_KEY, "openai")
        sr = split_key_fp(OPENAI_KEY, prefix, "openai")
        shard_a = sr.shard_a.decode("utf-8")
        print(
            f"1. Split: key ({len(OPENAI_KEY)} chars)"
            f" -> shard_a ({len(shard_a)} chars) + shard_b ({len(sr.shard_b)} bytes)"
        )
        print()

        # 2. Try shard-A against OpenAI -> 401
        resp_shard = _post_openai(shard_a)
        print(f"2. shard-A alone -> OpenAI: {resp_shard.status_code}")
        assert resp_shard.status_code == 401, f"Expected 401, got {resp_shard.status_code}"

        # 3. Try a random decoy -> 401
        fake_decoy = f"sk-proj-{'x' * 40}"
        resp_decoy = _post_openai(fake_decoy)
        print(f"3. decoy -> OpenAI: {resp_decoy.status_code}")
        assert resp_decoy.status_code == 401, f"Expected 401, got {resp_decoy.status_code}"

        # 4. Reconstruct and call OpenAI -> 200
        key_buf = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            sr.prefix,
            sr.charset,
        )
        reconstructed = key_buf.decode()
        assert reconstructed == OPENAI_KEY, "Reconstruction mismatch"

        resp_real = _post_openai(reconstructed)
        print(f"4. reconstructed -> OpenAI: {resp_real.status_code}")
        # 200 = success, 429 = key recognized but quota exhausted
        assert resp_real.status_code in (200, 429), (
            f"Expected 200/429, got {resp_real.status_code}: {resp_real.text}"
        )

        # 5. Zero key material
        key_buf[:] = b"\x00" * len(key_buf)
        sr.zero()

        print("5. key material zeroed")
        print()
        print(f"   shard-A alone:  {resp_shard.status_code}")
        print(f"   decoy:          {resp_decoy.status_code}")
        print(f"   reconstructed:  {resp_real.status_code}")
        print()
        print("   PASS")


# ---------------------------------------------------------------------------
# TestLiveAttacks -- adversarial attack vectors
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not OPENAI_KEY and not ANTHROPIC_KEY,
    reason="Neither OPENAI_API_KEY nor ANTHROPIC_API_KEY set",
)
class TestLiveAttacks:
    """Prove that stolen or tampered shards are useless against real APIs.

    Each test method is one attack vector. All tests are independent.
    We accept 401 (and sometimes 400) as proof the key was rejected.
    We accept 200 or 429 as proof the key was accepted.
    """

    # -- Attack 1: shard-A alone -> OpenAI (401) --------------------------

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_shard_a_alone_openai(self):
        """Attack: attacker steals shard-A (looks like a real key) and tries OpenAI.

        shard-A has the correct prefix (sk-proj-...) and character set,
        making it indistinguishable from a real key by format alone.
        But it is the modular complement -- not the actual secret.
        """
        sr = _split_openai()
        shard_a = sr.shard_a.decode("utf-8")

        resp = _post_openai(shard_a)

        print(f"\n  shard-A alone -> OpenAI: {resp.status_code}")
        assert resp.status_code == 401, f"shard-A should be rejected, got {resp.status_code}"

        sr.zero()

    # -- Attack 2: shard-A alone -> Anthropic (401) -----------------------

    @pytest.mark.skipif(not ANTHROPIC_KEY, reason="ANTHROPIC_API_KEY not set")
    def test_shard_a_alone_anthropic(self):
        """Attack: attacker steals shard-A and tries Anthropic.

        Even though shard-A preserves the sk-ant-api03- prefix format,
        it contains none of the real key material.
        """
        sr = _split_anthropic()
        shard_a = sr.shard_a.decode("utf-8")

        resp = _post_anthropic(shard_a)

        print(f"\n  shard-A alone -> Anthropic: {resp.status_code}")
        assert resp.status_code == 401, f"shard-A should be rejected, got {resp.status_code}"

        sr.zero()

    # -- Attack 3: shard-B alone -> OpenAI (401) --------------------------

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_shard_b_alone_openai(self):
        """Attack: attacker steals shard-B (charset body, no prefix) and tries OpenAI.

        shard-B has no API key prefix -- it is raw charset characters.
        Even if prefixed manually, it is the wrong value.
        """
        sr = _split_openai()
        shard_b = sr.shard_b.decode("utf-8")

        resp = _post_openai(shard_b)

        print(f"\n  shard-B alone -> OpenAI: {resp.status_code}")
        assert resp.status_code == 401, f"shard-B should be rejected, got {resp.status_code}"

        sr.zero()

    # -- Attack 4: shard-B alone -> Anthropic (401) -----------------------

    @pytest.mark.skipif(not ANTHROPIC_KEY, reason="ANTHROPIC_API_KEY not set")
    def test_shard_b_alone_anthropic(self):
        """Attack: attacker steals shard-B and tries Anthropic.

        shard-B is the modular complement body without any provider prefix.
        Anthropic rejects it immediately.
        """
        sr = _split_anthropic()
        shard_b = sr.shard_b.decode("utf-8")

        resp = _post_anthropic(shard_b)

        print(f"\n  shard-B alone -> Anthropic: {resp.status_code}")
        assert resp.status_code == 401, f"shard-B should be rejected, got {resp.status_code}"

        sr.zero()

    # -- Attack 5: shard-A with one char bit-flipped -> OpenAI (401) ------

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_shard_a_bitflip_openai(self):
        """Attack: attacker has shard-A but flips one character (brute-force attempt).

        Even a single character change in the body produces a completely
        different key after reconstruction. Without the exact shard-A,
        reconstruction yields garbage.
        """
        sr = _split_openai()
        shard_a = sr.shard_a.decode("utf-8")

        # Flip one char in the body (past the prefix)
        prefix = detect_prefix(OPENAI_KEY, "openai")
        prefix_len = len(prefix)
        body = list(shard_a)
        # Pick a character in the body and shift it
        flip_idx = prefix_len + 5
        original_char = body[flip_idx]
        body[flip_idx] = "A" if original_char != "A" else "B"
        tampered = "".join(body)

        resp = _post_openai(tampered)

        print(f"\n  shard-A bitflip (idx {flip_idx}) -> OpenAI: {resp.status_code}")
        assert resp.status_code == 401, (
            f"Tampered shard-A should be rejected, got {resp.status_code}"
        )

        sr.zero()

    # -- Attack 6: shard-A truncated -> OpenAI (401) ----------------------

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_shard_a_truncated_openai(self):
        """Attack: attacker captures partial shard-A (truncated in transit).

        A truncated key cannot authenticate. Even if the prefix is correct,
        the body is incomplete and does not match any valid key.
        """
        sr = _split_openai()
        shard_a = sr.shard_a.decode("utf-8")

        # Truncate to 70% of original length
        truncated = shard_a[: int(len(shard_a) * 0.7)]

        resp = _post_openai(truncated)

        print(
            f"\n  shard-A truncated ({len(shard_a)} -> {len(truncated)} chars)"
            f" -> OpenAI: {resp.status_code}"
        )
        assert resp.status_code == 401, (
            f"Truncated shard-A should be rejected, got {resp.status_code}"
        )

        sr.zero()

    # -- Attack 7: cross-contamination -> reconstruct -> garbage (401) ----

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_cross_contamination_openai(self):
        """Attack: attacker has shard-A from key-1 and shard-B from key-2.

        Splits the same key twice (different random nonces produce different
        shards). Mixes shard-A from split-1 with shard-B from split-2.
        Reconstruction produces garbage that authenticates nowhere.

        Note: reconstruct_key_fp verifies the commitment hash, so this
        should raise ShardTamperedError. We catch that and verify the
        mismatched shards cannot produce a working key.
        """
        from worthless.exceptions import ShardTamperedError

        sr1 = _split_openai()
        sr2 = _split_openai()

        print("\n  cross-contamination (split-1 shard-A + split-2 shard-B):")

        # Attempt reconstruction with mismatched shards
        try:
            key_buf = reconstruct_key_fp(
                sr1.shard_a,
                sr2.shard_b,
                sr1.commitment,  # commitment from split-1
                sr1.nonce,
                sr1.prefix,
                sr1.charset,
            )
            # If reconstruction did not raise (commitment check passed by luck),
            # the result is still garbage -- verify it fails auth
            garbage_key = key_buf.decode("utf-8", errors="replace")
            resp = _post_openai(garbage_key)

            print(f"  reconstructed garbage -> OpenAI: {resp.status_code}")
            assert resp.status_code == 401, (
                f"Cross-contaminated key should be rejected, got {resp.status_code}"
            )

            key_buf[:] = b"\x00" * len(key_buf)

        except ShardTamperedError:
            print("  ShardTamperedError raised (commitment check caught mismatch)")

        sr1.zero()
        sr2.zero()

    # -- Attack 8: correct reconstruction -> OpenAI (200/429) -------------

    @pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
    def test_correct_reconstruction_openai(self):
        """Control: correct reconstruction produces a working key for OpenAI.

        This is the positive control -- proves the split/reconstruct cycle
        preserves the real key and OpenAI accepts it.
        """
        sr = _split_openai()

        key_buf = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            sr.prefix,
            sr.charset,
        )
        reconstructed = key_buf.decode("utf-8")

        assert reconstructed == OPENAI_KEY, "Reconstruction mismatch -- crypto bug"

        resp = _post_openai(reconstructed)

        print(f"\n  reconstructed -> OpenAI: {resp.status_code}")
        assert resp.status_code in (200, 429), (
            f"Reconstructed key should be accepted, got {resp.status_code}: {resp.text}"
        )

        key_buf[:] = b"\x00" * len(key_buf)
        sr.zero()

    # -- Attack 9: correct reconstruction -> Anthropic (200/429) ----------

    @pytest.mark.skipif(not ANTHROPIC_KEY, reason="ANTHROPIC_API_KEY not set")
    def test_correct_reconstruction_anthropic(self):
        """Control: correct reconstruction produces a working key for Anthropic.

        Same positive control as test 8, but against the Anthropic API
        to prove format-preserving split works across providers.
        """
        sr = _split_anthropic()

        key_buf = reconstruct_key_fp(
            sr.shard_a,
            sr.shard_b,
            sr.commitment,
            sr.nonce,
            sr.prefix,
            sr.charset,
        )
        reconstructed = key_buf.decode("utf-8")

        assert reconstructed == ANTHROPIC_KEY, "Reconstruction mismatch -- crypto bug"

        resp = _post_anthropic(reconstructed)

        print(f"\n  reconstructed -> Anthropic: {resp.status_code}")
        # A valid reconstructed key is "accepted" if Anthropic authenticated it
        # and took the (fixed, valid) request: 200, 429/529 (throttled/overloaded),
        # or 400 "credit balance too low" (billing). A bad key returns 401, and the
        # body here is hard-coded valid, so a 400 can only be billing -- which still
        # proves the key + wire format are good. Matches the convention already used
        # by test_e2e_live.py's Anthropic round-trip and SDK tests.
        assert resp.status_code in (200, 400, 429, 529), (
            f"Reconstructed key should be accepted (200/400-billing/429/529), "
            f"got {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            content = resp.json()["content"][0]["text"]
            print(f'  Completion: "{content.strip()}"')
        else:
            print("  Key recognized (429 quota exhausted)")
        print("  RESULT: accepted -- reconstruction works")

        key_buf[:] = b"\x00" * len(key_buf)
        sr.zero()

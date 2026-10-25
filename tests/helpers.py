"""Shared test helpers for the worthless test suite."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from worthless.storage.repository import ShardRepository, StoredShard


# ---------------------------------------------------------------------------
# Root runners (Docker, some CI) — worthless-x9z1
# ---------------------------------------------------------------------------
# Root bypasses POSIX permission checks, so a test that provokes EACCES via
# chmod can't observe it as root. Skip those there; non-root CI still runs them.
# ---------------------------------------------------------------------------

RUNNING_AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

skip_if_root = pytest.mark.skipif(
    RUNNING_AS_ROOT,
    reason="root bypasses POSIX permission checks; covered on non-root CI",
)


# ---------------------------------------------------------------------------
# Scanner-safe fake key generators
# ---------------------------------------------------------------------------
# Generate deterministic high-entropy keys at runtime so literal API-key
# patterns never appear in source — avoids tripping ``worthless scan``,
# GitHub secret scanning, or any other regex-based secret detector.
# ---------------------------------------------------------------------------


def fake_key(prefix: str, seed: str = "test-fixture-seed") -> str:
    """Generate a deterministic high-entropy fake key at runtime."""
    raw = hashlib.sha256(seed.encode()).digest()
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")[:48]
    return prefix + body


def fake_openai_key() -> str:
    return fake_key("sk-" + "proj-")


def fake_anthropic_key() -> str:
    return fake_key("sk-" + "ant-" + "api03-", seed="anthropic-fixture-seed")


def fake_openrouter_key() -> str:
    """A vendor whose wire protocol is ``openai`` but whose name is not.

    Needed by worthless-v4n2: the gateway-lookup bug only shows when the key's
    vendor differs from its protocol, and five bundled providers declare
    ``protocol = "openai"``. Must be high-entropy — ``scan_env_keys`` drops
    low-entropy values as placeholders, so a repetitive literal is silently
    invisible to the scanner and any test built on one proves nothing.
    """
    return fake_key("sk-" + "or-" + "v1-", seed="openrouter-fixture-seed")


def seed_enrollment(db_path: Path, alias: str, var_name: str, env_path: str | None) -> None:
    """Insert one shard and its enrollment straight into the DB.

    The shard bytes are placeholders, so use it only for rows nothing
    reconstructs: an enroll-only key (``env_path=None``) or a .env that is gone.
    """
    con = sqlite3.connect(str(db_path))
    try:
        con.execute(
            "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
            "VALUES (?, ?, ?, ?, ?)",
            (alias, b"x", b"c", b"n", "openai"),
        )
        con.execute(
            "INSERT INTO enrollments (key_alias, var_name, env_path) VALUES (?, ?, ?)",
            (alias, var_name, env_path),
        )
        con.commit()
    finally:
        con.close()


def assert_not_shown(output: str, *secrets: str) -> None:
    """Fail if any of *secrets* is in *output*, without echoing it.

    Rich folds a long word across lines, so line breaks are dropped first.
    """
    unwrapped = output.replace("\n", "")
    if any(secret in unwrapped for secret in secrets):
        pytest.fail("the output shows a value it must never print")


class MockAsyncByteStream(httpx.AsyncByteStream):
    """Mock async byte stream that yields chunks one at a time."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def verify_upstream_response_openai(data: dict) -> None:
    """Assert 200/429 from an OpenAI-protocol upstream and 'choices' on 200."""
    status = data["status"]
    body = data.get("body", {})
    assert status in (200, 429), (
        f"Expected 200 or 429 from OpenAI-protocol upstream, got {status}. body: {body}"
    )
    if status == 200:
        assert "choices" in body, f"Missing 'choices' in 200 response: {body}"


def verify_upstream_response_anthropic(data: dict) -> None:
    """Assert 200/429/529 from an Anthropic-protocol upstream and 'content' on 200."""
    status = data["status"]
    body = data.get("body", {})
    assert status in (200, 429, 529), (
        f"Expected 200/429/529 from Anthropic upstream, got {status}. body: {body}"
    )
    if status == 200:
        assert "content" in body, f"Missing 'content' in 200 response: {body}"


def make_streaming_response(
    chunks: list[bytes],
    status_code: int = 200,
    headers: dict[str, Any] | None = None,
) -> httpx.Response:
    """Create a mock httpx.Response that streams SSE chunks."""
    _headers = {"content-type": "text/event-stream"}
    if headers:
        _headers.update(headers)
    stream = MockAsyncByteStream(chunks)
    return httpx.Response(
        status_code=status_code,
        headers=_headers,
        stream=stream,
    )


# ---------------------------------------------------------------------------
# Enrolled shards sealed with a chosen Fernet key — worthless-saaz
# ---------------------------------------------------------------------------


def seal_enrolled(db_path: Path, key: bytes, *aliases: str) -> None:
    """Enroll *aliases* in *db_path* with shard B sealed under *key*.

    Real Fernet tokens, so "this key can't open that shard" is genuine. Call it
    twice with different keys to build the mixed database a stray
    ``WORTHLESS_FERNET_KEY`` lock creates.
    """

    async def go() -> None:
        repo = ShardRepository(str(db_path), key)
        try:
            await repo.initialize()
            for alias in aliases:
                shard = StoredShard(
                    shard_b=bytearray(b"b" * 32),
                    commitment=bytearray(b"c" * 32),
                    nonce=bytearray(b"n" * 32),
                    provider="openai",
                )
                await repo.store_enrolled(
                    alias, shard, var_name="OPENAI_API_KEY", prefix="sk-", charset="x"
                )
        finally:
            repo.close()

    asyncio.run(go())

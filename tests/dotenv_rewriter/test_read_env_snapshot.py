"""Unit tests for ``read_env_snapshot``: one read of a ``.env`` (WOR-1013).

Lock saves a user's own ``*_BASE_URL`` value from the snapshot's ``raw`` before
overwriting the line, and unlock writes that value back through
``rewrite_env_keys``. The round trip must give back the line byte for byte, and
a rewrite given the snapshot's hash must refuse a file that changed since.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from worthless.cli.dotenv_rewriter import read_env_snapshot, rewrite_env_keys
from worthless.cli.errors import UnsafeRewriteRefused


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"GW_BASE_URL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        (b'GW_BASE_URL="https://openrouter.ai/api/v1"\n', "https://openrouter.ai/api/v1"),
        (b"GW_BASE_URL='https://openrouter.ai/api/v1'\n", "https://openrouter.ai/api/v1"),
        (b"export GW_BASE_URL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        (b"GW_BASE_URL=https://openrouter.ai/api/v1  # mine\n", "https://openrouter.ai/api/v1"),
        (b'GW_BASE_URL = "https://openrouter.ai/api/v1" # mine\n', "https://openrouter.ai/api/v1"),
        (b"GW_BASE_URL=https://openrouter.ai/api/v1\r\n", "https://openrouter.ai/api/v1"),
        (b"GW_BASE_URL=https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        (b"\xef\xbb\xbfGW_BASE_URL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        # Not expanded, unlike dotenv_values.
        (b"GW=https://gw.example.com\nGW_BASE_URL=${GW}/v1\n", "${GW}/v1"),
        (b'GW_BASE_URL="${GW}/v1"\n', "${GW}/v1"),
        # A second line keeps the proxy URL under safe_rewrite's growth limit.
        (b"GW_BASE_URL=\nAPP_NAME=a-reasonably-long-application-name\n", ""),
        (b'GW_BASE_URL=""\nAPP_NAME=a-reasonably-long-application-name\n', ""),
    ],
    ids=[
        "plain",
        "double-quoted",
        "single-quoted",
        "export",
        "inline-comment",
        "spaced-quoted-comment",
        "crlf",
        "no-eol",
        "bom",
        "interpolated",
        "interpolated-quoted",
        "empty",
        "empty-quoted",
    ],
)
def test_writing_the_value_back_gives_back_the_file(
    tmp_path: Path, make_env_file, content: bytes, expected: str
) -> None:
    env = make_env_file(tmp_path / ".env", content)
    original = env.read_bytes()

    value = read_env_snapshot(env).raw["GW_BASE_URL"]
    assert value == expected

    rewrite_env_keys(env, {"GW_BASE_URL": "http://127.0.0.1:8787/openai-0123abcd/v1"})
    assert env.read_bytes() != original
    rewrite_env_keys(env, {"GW_BASE_URL": value})
    assert env.read_bytes() == original


def test_unquoted_trailing_whitespace_is_dropped(tmp_path: Path, make_env_file) -> None:
    """dotenv ignores it, and rewrite_env_keys refuses a value that ends in it."""
    env = make_env_file(tmp_path / ".env", b"GW_BASE_URL=https://openrouter.ai/api/v1  \t\n")

    assert read_env_snapshot(env).raw == {"GW_BASE_URL": "https://openrouter.ai/api/v1"}


def test_raw_holds_only_base_url_values_that_can_be_written_back(
    tmp_path: Path, make_env_file
) -> None:
    """Key lines are never copied; refused values are left out; the last line decides."""
    env = make_env_file(
        tmp_path / ".env",
        b'A_BASE_URL=https://a.example/v1\nQUOTED_BASE_URL="it\'s"\n'
        b"SPACED_BASE_URL=' x'\nOPENAI_API_KEY=sk-proj-not-copied\n"
        b"DUP_BASE_URL=https://first.example/v1\nDUP_BASE_URL=' x'\n",
    )

    snapshot = read_env_snapshot(env)
    assert snapshot.raw == {"A_BASE_URL": "https://a.example/v1"}
    assert snapshot.parsed["OPENAI_API_KEY"] == "sk-proj-not-copied"


def test_parse_drops_the_bom_and_hash_covers_the_bytes(tmp_path: Path, make_env_file) -> None:
    content = b"\xef\xbb\xbfOPENAI_BASE_URL=https://api.openai.com/v1\n"
    env = make_env_file(tmp_path / ".env", content)

    snapshot = read_env_snapshot(env)
    assert list(snapshot.parsed) == ["OPENAI_BASE_URL"]
    assert snapshot.sha256 == hashlib.sha256(content).digest()


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path, make_env_file) -> None:
    env = make_env_file(tmp_path / ".env", b"OPENAI_API_KEY=sk-\xe9\xe9\xe9\n")

    with pytest.raises(UnsafeRewriteRefused):
        read_env_snapshot(env)


def test_missing_file_reads_as_empty(tmp_path: Path) -> None:
    snapshot = read_env_snapshot(tmp_path / ".env")
    assert (snapshot.parsed, snapshot.raw) == ({}, {})


def test_a_rewrite_given_the_snapshot_hash_refuses_a_changed_file(
    tmp_path: Path, make_env_file
) -> None:
    env = make_env_file(tmp_path / ".env", b"A_BASE_URL=https://a.example/v1\nB=b\n")
    snapshot = read_env_snapshot(env)
    env.write_bytes(b"A_BASE_URL=https://edited.example/v1\nB=b\n")

    with pytest.raises(UnsafeRewriteRefused):
        rewrite_env_keys(env, {"B": "c"}, expected_baseline_sha256=snapshot.sha256)
    assert env.read_bytes() == b"A_BASE_URL=https://edited.example/v1\nB=b\n"

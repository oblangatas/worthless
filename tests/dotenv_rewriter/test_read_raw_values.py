"""Unit tests for ``read_raw_values``: the value as written, for writing back (WOR-1013).

Lock reads a user's own ``*_BASE_URL`` value with it before overwriting the
line, and unlock writes that value back through ``rewrite_env_keys``. The
round trip must give back the line byte for byte.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli.dotenv_rewriter import read_raw_values, rewrite_env_keys


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"URL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        (b'URL="https://openrouter.ai/api/v1"\n', "https://openrouter.ai/api/v1"),
        (b"URL='https://openrouter.ai/api/v1'\n", "https://openrouter.ai/api/v1"),
        (b"export URL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        (b"URL=https://openrouter.ai/api/v1  # mine\n", "https://openrouter.ai/api/v1"),
        (b'URL = "https://openrouter.ai/api/v1" # mine\n', "https://openrouter.ai/api/v1"),
        (b"URL=https://openrouter.ai/api/v1\r\n", "https://openrouter.ai/api/v1"),
        (b"URL=https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        (b"\xef\xbb\xbfURL=https://openrouter.ai/api/v1\n", "https://openrouter.ai/api/v1"),
        # Not expanded, unlike dotenv_values.
        (b"GW=https://gw.example.com\nURL=${GW}/v1\n", "${GW}/v1"),
        (b'URL="${GW}/v1"\n', "${GW}/v1"),
        # A second line keeps the proxy URL under safe_rewrite's growth limit.
        (b"URL=\nAPP_NAME=a-reasonably-long-application-name\n", ""),
        (b'URL=""\nAPP_NAME=a-reasonably-long-application-name\n', ""),
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

    value = read_raw_values(env, ["URL"])["URL"]
    assert value == expected

    rewrite_env_keys(env, {"URL": "http://127.0.0.1:8787/openai-0123abcd/v1"})
    assert env.read_bytes() != original
    rewrite_env_keys(env, {"URL": value})
    assert env.read_bytes() == original


def test_unquoted_trailing_whitespace_is_dropped(tmp_path: Path, make_env_file) -> None:
    """dotenv ignores it, and rewrite_env_keys refuses a value that ends in it."""
    env = make_env_file(tmp_path / ".env", b"URL=https://openrouter.ai/api/v1  \t\n")

    assert read_raw_values(env, ["URL"]) == {"URL": "https://openrouter.ai/api/v1"}


def test_only_named_keys_that_can_be_written_back_are_returned(
    tmp_path: Path, make_env_file
) -> None:
    env = make_env_file(
        tmp_path / ".env",
        b"A=https://a.example/v1\nQUOTED=\"it's\"\nSPACED=' x'\nB=b\n",
    )

    assert read_raw_values(env, ["A", "QUOTED", "SPACED", "MISSING"]) == {
        "A": "https://a.example/v1"
    }
    assert read_raw_values(env, []) == {}


def test_missing_file_reads_as_empty(tmp_path: Path) -> None:
    assert read_raw_values(tmp_path / ".env", ["URL"]) == {}

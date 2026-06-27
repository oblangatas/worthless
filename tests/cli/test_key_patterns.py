"""Provider classification regressions for OpenRouter keys (HF1 / worthless-lj0z).

THIS IS provider-classification testing, NOT proxy-routing testing. These tests
pin that ``detect_provider`` returns the correct *label* for OpenRouter API
keys (``sk-or-v1-...`` and ``sk-or-...``). Routing — actually proxying
OpenRouter calls through ``src/worthless/proxy/`` adapters — is post-v0.3.3
backlog work; no proxy adapter yet recognises ``provider == "openrouter"``.

Discovered 2026-04-30 dogfood: ``worthless scan`` mislabelled
``OPENROUTER_API_KEY=sk-or-v1-...`` as provider ``openai`` because the
generic ``sk-`` prefix won the longest-first match. Linear: WOR-381 (full
first-class OpenRouter support — HF1 lands the detection slice only).
"""

from __future__ import annotations

from worthless.cli.key_patterns import detect_provider


def test_detect_provider_openrouter_v1() -> None:
    """``sk-or-v1-`` must classify as ``openrouter`` (was ``openai``)."""
    assert detect_provider("sk-or-v1-" + "a" * 40) == "openrouter"


def test_detect_provider_openrouter_short() -> None:
    """``sk-or-`` (without ``v1-``) must also classify as ``openrouter``.

    OpenRouter has historically issued both ``sk-or-v1-`` and ``sk-or-``
    shapes; both must be detected.
    """
    assert detect_provider("sk-or-" + "b" * 40) == "openrouter"


def test_detect_provider_openai_regression() -> None:
    """``sk-proj-`` (OpenAI project keys) must continue to classify as
    ``openai``. Adding the OpenRouter prefixes must not steal this match."""
    assert detect_provider("sk-proj-" + "c" * 40) == "openai"


def test_detect_provider_openai_plain_regression() -> None:
    """Bare ``sk-`` (legacy OpenAI keys) must continue to classify as
    ``openai`` when the key shape does not match a longer prefix
    (``sk-or-v1-``, ``sk-or-``, ``sk-ant-``, ``sk-proj-``).

    This is the most-likely-to-break case: longest-first sort must keep
    ``sk-`` as the catch-all *after* the new OpenRouter prefixes have had
    their chance.
    """
    assert detect_provider("sk-" + "d" * 40) == "openai"

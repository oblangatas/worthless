"""Provider prefix patterns and auto-detection for API keys."""

from __future__ import annotations

import re

# Ordered longest-first per provider for greedy matching.
PROVIDER_PREFIXES: dict[str, list[str]] = {
    "openai": ["sk-proj-", "sk-"],
    "openrouter": ["sk-or-v1-", "sk-or-"],
    "anthropic": ["sk-ant-api03-", "sk-ant-", "anthropic-"],
    "google": ["AIza"],
    "xai": ["xai-"],
}

# Build a combined regex: any known prefix followed by 10+ word/dash chars.
_all_prefixes = sorted(
    (prefix for prefixes in PROVIDER_PREFIXES.values() for prefix in prefixes),
    key=len,
    reverse=True,
)
_prefix_pattern = "|".join(re.escape(p) for p in _all_prefixes)
KEY_PATTERN: re.Pattern[str] = re.compile(rf"(?:{_prefix_pattern})[\w\-]{{10,}}")


# Flat lookup sorted longest-first so "sk-ant-" beats "sk-".
_PREFIX_TO_PROVIDER: list[tuple[str, str]] = sorted(
    ((prefix, provider) for provider, prefixes in PROVIDER_PREFIXES.items() for prefix in prefixes),
    key=lambda t: len(t[0]),
    reverse=True,
)


def detect_provider(api_key: str) -> str | None:
    """Return the provider name for *api_key*, or ``None`` if unrecognised."""
    for prefix, provider in _PREFIX_TO_PROVIDER:
        if api_key.startswith(prefix):
            return provider
    return None


ENTROPY_THRESHOLD: float = 3.9
# Lowered 4.5 → 3.9 so legitimate OpenRouter keys (entropy ~4.118) clear the
# scan, while common placeholders ("sk-your-key-here" 3.03, "sk-aaaa" 0.88,
# WRTLS-decoy 3.63, "sk-PLACEHOLDER" 3.74) remain rejected. The earlier
# 4.5 cutoff false-flagged real OpenRouter (entropy 4.118) and structured
# provider keys in the 4.0-5.0 entropy band.


# Canonical API-key env var convention: ``<PROVIDER>_API_KEY`` (with the
# underscores between PROVIDER, API, and KEY individually optional). Used
# by ``lock`` to warn users whose ``.env`` uses non-canonical names like
# ``MY_OPENAI_KEY`` — apps that read such vars directly (without passing
# ``base_url=`` to the SDK client) bypass the proxy and send shard-A
# upstream. The end anchor ``$`` is critical: it prevents accidental
# matches like ``OPENAI_API_KEY_OLD``. ``worthless-v5sy`` (P3 follow-up)
# upgrades the warning to a refusal under ``worthless lock --strict``.
CANONICAL_KEY_VAR_RE: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9]*_?API_?KEY$")


def detect_prefix(api_key: str, provider: str) -> str:
    """Return the matching prefix string for *api_key* given *provider*."""
    prefixes = PROVIDER_PREFIXES.get(provider, [])
    for prefix in prefixes:
        if api_key.startswith(prefix):
            return prefix
    raise ValueError(f"No matching prefix for provider {provider!r}")

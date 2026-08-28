"""WOR-650 — DB-backed recognition of existing OpenClaw provider entries.

``worthless lock`` rewrites ``models.providers.<provider>``. Before WOR-650 it
overwrote whatever was there, silently. Now it classifies the existing entry
against the set of aliases Worthless created (``managed_aliases``):

* real key (non-proxy baseUrl) or recognized re-lock (alias in the set) →
  overwrite silently, byte-identical to before.
* unrecognized proxy-shaped entry → adopt-with-notice (consented) or skip
  (unconsented).

The parsed alias is attacker-controllable (anyone who writes openclaw.json),
so the security tests pin sanitization + SR-04 redaction.

Provider shapes are grounded against the real OpenClaw container (FAFO probe
2026-06-20): ``api`` = ``openai-completions`` / ``anthropic-messages``,
baseUrl keeps ``/v1``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from worthless.openclaw import integration
from worthless.openclaw.errors import OpenclawErrorCode
from worthless.openclaw.integration import AdoptionPolicy

PROXY = "http://127.0.0.1:8787"
_API = {"openai": "openai-completions", "anthropic": "anthropic-messages"}


def _seed_entry(config_path: Path, provider: str, base_url: str, api_key: str = "sk-old") -> None:
    """Write a single existing provider entry (grounded valid shape)."""
    config_path.write_text(
        json.dumps(
            {
                "models": {
                    "providers": {
                        provider: {
                            "baseUrl": base_url,
                            "apiKey": api_key,
                            "api": _API[provider],
                            "models": [{"id": "m", "name": "m"}],
                        }
                    }
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _lock(config_path, provider, new_alias, policy):  # noqa: ANN001
    return integration.apply_lock(
        planned_updates=[(provider, new_alias, f"sk-shard-{provider}")],
        proxy_base_url=PROXY,
        adoption_policy=policy,
    )


def _adoption_events(result) -> list:  # noqa: ANN001
    codes = {
        OpenclawErrorCode.PROVIDER_ADOPTED_UNRECOGNIZED,
        OpenclawErrorCode.PROVIDER_ADOPTION_SKIPPED,
        OpenclawErrorCode.PROVIDER_RECOGNITION_UNAVAILABLE,
    }
    return [e for e in result.events if e.code in codes]


def _entry(config_path: Path, provider: str) -> dict | None:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    return data["models"]["providers"].get(provider)


# ---------------------------------------------------------------------------
# Behavior matrix × {openai, anthropic}
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_real_key_no_event(openclaw_present, monkeypatch, provider) -> None:
    """Non-proxy baseUrl = the user's real key → overwrite silently."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    real = "https://api.openai.com/v1" if provider == "openai" else "https://api.anthropic.com"
    _seed_entry(cp, provider, real)

    result = _lock(cp, provider, f"{provider}-new1111", AdoptionPolicy(managed_aliases=set()))

    assert _adoption_events(result) == []
    assert _entry(cp, provider)["baseUrl"].endswith(f"/{provider}-new1111/v1")


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_recognized_relock_no_event(openclaw_present, monkeypatch, provider) -> None:
    """Existing proxy entry whose alias IS in the managed set → silent re-lock."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, provider, f"{PROXY}/{provider}-known999/v1")

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases={f"{provider}-known999"}),
    )

    assert _adoption_events(result) == []
    assert _entry(cp, provider)["baseUrl"].endswith(f"/{provider}-new1111/v1")


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_unrecognized_adopt_emits_info_and_overwrites(
    openclaw_present, monkeypatch, provider
) -> None:
    """Unrecognized proxy entry + consent → PROVIDER_ADOPTED_UNRECOGNIZED, overwrite."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, provider, f"{PROXY}/{provider}-foreign/v1")

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases=set(), adopt_unrecognized=True),
    )

    evts = _adoption_events(result)
    assert [e.code for e in evts] == [OpenclawErrorCode.PROVIDER_ADOPTED_UNRECOGNIZED]
    assert evts[0].level == "info"
    assert _entry(cp, provider)["baseUrl"].endswith(f"/{provider}-new1111/v1")


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_unrecognized_declined_skips_and_leaves_entry(
    openclaw_present, monkeypatch, provider
) -> None:
    """Unrecognized proxy entry + NO consent → SKIP, entry untouched."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, provider, f"{PROXY}/{provider}-foreign/v1")

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases=set(), adopt_unrecognized=False),
    )

    evts = _adoption_events(result)
    assert [e.code for e in evts] == [OpenclawErrorCode.PROVIDER_ADOPTION_SKIPPED]
    # Entry NOT overwritten — still the foreign alias.
    assert _entry(cp, provider)["baseUrl"].endswith(f"/{provider}-foreign/v1")
    assert (provider, "unrecognized_not_adopted") in result.providers_skipped


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_unparseable_alias_no_event_still_overwrites(
    openclaw_present, monkeypatch, provider
) -> None:
    """Proxy-shaped but the path segment isn't a valid alias → can't name it,
    overwrite silently (no event, no junk echoed)."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    # No '/<alias>/v1' segment → _alias_from_base_url returns None.
    _seed_entry(cp, provider, f"{PROXY}/nope")

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases=set(), adopt_unrecognized=False),
    )

    assert _adoption_events(result) == []
    assert _entry(cp, provider)["baseUrl"].endswith(f"/{provider}-new1111/v1")


def test_none_managed_aliases_is_recognition_unavailable(openclaw_present, monkeypatch) -> None:
    """managed_aliases=None (DB unreadable) → recognition_unavailable, fail-safe
    SKIP when unconsented; adopt when consented. Never silently 'recognized'."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, "openai", f"{PROXY}/openai-foreign/v1")

    # Unconsented → unavailable event + skip.
    r1 = _lock(cp, "openai", "openai-new1111", AdoptionPolicy(managed_aliases=None))
    assert [e.code for e in _adoption_events(r1)] == [
        OpenclawErrorCode.PROVIDER_RECOGNITION_UNAVAILABLE
    ]
    assert _entry(cp, "openai")["baseUrl"].endswith("/openai-foreign/v1")  # skipped

    # Re-seed, consented → unavailable event + overwrite.
    _seed_entry(cp, "openai", f"{PROXY}/openai-foreign/v1")
    r2 = _lock(
        cp,
        "openai",
        "openai-new2222",
        AdoptionPolicy(managed_aliases=None, adopt_unrecognized=True),
    )
    assert [e.code for e in _adoption_events(r2)] == [
        OpenclawErrorCode.PROVIDER_RECOGNITION_UNAVAILABLE
    ]
    assert _entry(cp, "openai")["baseUrl"].endswith("/openai-new2222/v1")  # adopted


def test_no_policy_is_backcompat_no_event(openclaw_present, monkeypatch) -> None:
    """adoption_policy=None (existing callers) → recognition disabled, no event,
    overwrite as today."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, "openai", f"{PROXY}/openai-foreign/v1")

    result = integration.apply_lock(
        planned_updates=[("openai", "openai-new1111", "sk-shard")],
        proxy_base_url=PROXY,
    )
    assert _adoption_events(result) == []
    assert _entry(cp, "openai")["baseUrl"].endswith("/openai-new1111/v1")


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_alias_sanitized_controlchars_ansi_crlf(openclaw_present, monkeypatch) -> None:
    """A malicious baseUrl can't inject ANSI/CRLF/control chars into the event.
    The tightened regex restricts to [A-Za-z0-9_-]; this is belt-and-suspenders
    for the sanitizer itself."""
    # Direct unit test of the sanitizer (the parser already drops junk).
    dirty = "ok\x1b[31m\r\n\x00name"
    cleaned = integration._sanitize_alias_for_log(dirty)
    assert "\x1b" not in cleaned and "\r" not in cleaned and "\n" not in cleaned
    assert "\x00" not in cleaned

    # And a baseUrl whose 'alias' contains control chars yields None (no echo).
    assert integration._alias_from_base_url("http://127.0.0.1:8787/ev\x1bil/v1") is None


def test_alias_length_capped(openclaw_present, monkeypatch) -> None:
    """A 5000-char alias is capped before it can bloat the sentinel/terminal."""
    capped = integration._sanitize_alias_for_log("a" * 5000)
    assert len(capped) <= integration._MAX_ALIAS_LOG_LEN + 1  # +1 for the ellipsis marker


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_adoption_event_redacts_keys_sr04(openclaw_present, monkeypatch, provider) -> None:
    """SR-04: the existing entry's apiKey never appears in the adoption event."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    secret = "sk-ant-SUPERSECRET-9f8e7d6c5b4a"  # noqa: S105 — test fixture key, not a real secret
    _seed_entry(cp, provider, f"{PROXY}/{provider}-foreign/v1", api_key=secret)

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases=set(), adopt_unrecognized=True),
    )
    blob = json.dumps([e.to_dict() for e in result.events]) + str([e.extra for e in result.events])
    assert secret not in blob, "SR-04: existing apiKey leaked into an event"
    assert "SUPERSECRET" not in blob


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_recognition_is_not_a_security_gate(openclaw_present, monkeypatch, provider) -> None:
    """Recognition only chooses inform-vs-silent; with consent, an unrecognized
    entry is ALWAYS overwritten (the attacker-plant case is neutralized by the
    overwrite, never gated)."""
    monkeypatch.chdir(openclaw_present["home"])
    cp = openclaw_present["config_path"]
    _seed_entry(cp, provider, f"{PROXY}/attacker-controlled/v1")

    result = _lock(
        cp,
        provider,
        f"{provider}-new1111",
        AdoptionPolicy(managed_aliases=set(), adopt_unrecognized=True),
    )
    # Foreign baseUrl is GONE — replaced by Worthless's own proxy URL.
    assert _entry(cp, provider)["baseUrl"] == f"{PROXY}/{provider}-new1111/v1"
    assert provider in result.providers_set

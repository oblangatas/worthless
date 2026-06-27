"""Tests for the provider URL → protocol registry (worthless-8rqs Phase 1).

The registry is the source of truth for known LLM-provider upstream URLs
and their wire protocol. ``worthless lock`` looks up the URL it reads from
``.env`` against this registry to auto-detect protocol; users can extend
the registry locally via ``~/.worthless/providers.toml`` without a PR.

Contract pinned by these tests:
- Bundled file ``src/worthless/providers.toml`` ships with 6 providers.
- User override at ``~/.worthless/providers.toml`` is optional.
- Merge: user entries take precedence on URL conflict.
- Malformed user TOML is logged + skipped (bundled still loads).
- Lookup is by URL (the unique key).
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Imports that don't yet exist — these MUST fail until Phase 1 GREEN lands.
from worthless.cli.providers import (
    ProviderEntry,
    load_registry,
    lookup_by_url,
)


class TestBundledRegistry:
    """The bundled providers.toml is the source of truth for known providers."""

    def test_bundled_registry_loads(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Loading with no user override returns the bundled entries."""
        # Point user-override path at a non-existent file so only bundled loads.
        monkeypatch.setenv("HOME", str(tmp_path))
        registry = load_registry()
        assert len(registry) >= 1, "bundled registry must not be empty"

    def test_bundled_registry_has_six_providers(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Bundled file ships with exactly 6 entries (the practical-set decision).

        If this fails because someone added a 7th provider: that's a deliberate
        decision; update this assertion AND document the new provider in the
        same PR. If it fails because someone REMOVED a provider: that's a
        breaking change for users locked against that URL — block the PR.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        registry = load_registry()
        assert len(registry) == 6, (
            f"bundled registry has {len(registry)} entries, expected 6 "
            f"(openai, anthropic, openrouter, groq, together, ollama)"
        )

    def test_bundled_includes_openai(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        entry = lookup_by_url("https://api.openai.com/v1")
        assert entry is not None, "OpenAI must be in the bundled registry"
        assert entry.name == "openai"
        assert entry.protocol == "openai"

    def test_bundled_includes_anthropic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        entry = lookup_by_url("https://api.anthropic.com/v1")
        assert entry is not None
        assert entry.name == "anthropic"
        assert entry.protocol == "anthropic"

    def test_bundled_includes_openrouter(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        entry = lookup_by_url("https://openrouter.ai/api/v1")
        assert entry is not None
        assert entry.protocol == "openai", "OpenRouter speaks the OpenAI wire protocol"

    def test_bundled_includes_ollama_local(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Ollama uses http:// (not https://) — registry must accept that."""
        monkeypatch.setenv("HOME", str(tmp_path))
        entry = lookup_by_url("http://localhost:11434/v1")
        assert entry is not None
        assert entry.name == "ollama"

    def test_unknown_url_returns_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        assert lookup_by_url("https://not-a-known-provider.example.com/v1") is None


class TestUserOverride:
    """Users can extend the registry via ~/.worthless/providers.toml."""

    def _write_user_registry(self, home: Path, content: str) -> None:
        """Helper: create ~/.worthless/providers.toml with given content."""
        worthless_dir = home / ".worthless"
        worthless_dir.mkdir(parents=True, exist_ok=True)
        (worthless_dir / "providers.toml").write_text(content)

    def test_user_override_adds_new_provider(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """User entry for a NEW URL appears in lookups."""
        monkeypatch.setenv("HOME", str(tmp_path))
        self._write_user_registry(
            tmp_path,
            """
[provider.fireworks]
url = "https://api.fireworks.ai/inference/v1"
protocol = "openai"
""",
        )
        entry = lookup_by_url("https://api.fireworks.ai/inference/v1")
        assert entry is not None, "user override entry must be discoverable"
        assert entry.name == "fireworks"
        assert entry.protocol == "openai"

    def test_user_override_wins_on_url_conflict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """If user redefines a bundled URL, user entry wins (e.g., to rename)."""
        monkeypatch.setenv("HOME", str(tmp_path))
        self._write_user_registry(
            tmp_path,
            """
[provider.my-openai-staging]
url = "https://api.openai.com/v1"
protocol = "openai"
""",
        )
        entry = lookup_by_url("https://api.openai.com/v1")
        assert entry is not None
        assert entry.name == "my-openai-staging", (
            f"user entry should override bundled, got name={entry.name!r}"
        )

    def test_missing_user_file_is_fine(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No ~/.worthless/providers.toml → bundled-only registry still loads."""
        monkeypatch.setenv("HOME", str(tmp_path))
        # Do NOT create the user file.
        registry = load_registry()
        assert len(registry) == 6, "bundled-only when user file absent"

    def test_malformed_user_toml_is_skipped_with_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A broken user TOML must NOT break lock — log warning, fall back to bundled."""
        import logging

        monkeypatch.setenv("HOME", str(tmp_path))
        self._write_user_registry(tmp_path, "this is not [valid TOML")

        with caplog.at_level(logging.WARNING):
            registry = load_registry()

        assert len(registry) == 6, "malformed user file must not break bundled load"
        assert any(
            "providers.toml" in r.message.lower() or "registry" in r.message.lower()
            for r in caplog.records
        ), (
            "expected a warning log about the malformed file, got: "
            f"{[r.message for r in caplog.records]}"
        )


class TestProviderEntry:
    """ProviderEntry is the typed return value — pin its shape."""

    def test_provider_entry_has_name_url_protocol(self) -> None:
        entry = ProviderEntry(name="x", url="https://x.example/v1", protocol="openai")
        assert entry.name == "x"
        assert entry.url == "https://x.example/v1"
        assert entry.protocol == "openai"

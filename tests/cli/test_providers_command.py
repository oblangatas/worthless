"""Tests for ``worthless providers`` subcommands (worthless-8rqs Phase 2).

The ``providers`` command group lets users:

- ``worthless providers list`` — see the merged registry (bundled + user override)
- ``worthless providers register`` — append a custom provider to ~/.worthless/providers.toml

Contract pinned by these tests:
- ``list`` prints all 6 bundled entries plus any user-registered ones.
- ``list --json`` emits machine-readable output with name/url/protocol/source.
- ``register`` writes to the user file (creating ~/.worthless/ if absent).
- ``register`` refuses bundled-name conflicts (suggests a different name).
- ``register`` refuses bundled-URL conflicts (unless ``--force``).
- ``register`` rejects malformed URLs (scheme must be http/https, netloc non-empty).
- ``register`` rejects malformed protocols (must be openai or anthropic).
- ``register`` appends to existing user file (does not clobber).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app

runner = CliRunner()


class TestProvidersList:
    """`worthless providers list` shows the merged registry."""

    def test_list_shows_bundled_six(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(app, ["providers", "list"])
        assert result.exit_code == 0, result.output
        # All six bundled provider names must appear.
        for name in ("openai", "anthropic", "openrouter", "groq", "together", "ollama"):
            assert name in result.output, f"{name!r} missing from list output"

    def test_list_includes_protocol_column(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(app, ["providers", "list"])
        assert result.exit_code == 0
        assert "openai" in result.output and "anthropic" in result.output

    def test_list_json_output(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """--json emits a parseable list of {name, url, protocol, source} objects."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(app, ["--json", "providers", "list"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert isinstance(payload, list)
        assert len(payload) == 6
        for entry in payload:
            assert set(entry.keys()) >= {"name", "url", "protocol", "source"}
            assert entry["source"] == "bundled"

    def test_list_includes_user_override(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        worthless_dir = tmp_path / ".worthless"
        worthless_dir.mkdir(parents=True)
        (worthless_dir / "providers.toml").write_text(
            "[provider.fireworks]\n"
            'url = "https://api.fireworks.ai/inference/v1"\n'
            'protocol = "openai"\n'
        )
        result = runner.invoke(app, ["--json", "providers", "list"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        names = {e["name"] for e in payload}
        assert "fireworks" in names, f"user-registered provider not in list: {names}"
        # User entry should be marked as such.
        fireworks = next(e for e in payload if e["name"] == "fireworks")
        assert fireworks["source"] == "user"


class TestProvidersRegister:
    """`worthless providers register` appends to ~/.worthless/providers.toml."""

    def test_register_writes_user_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "fireworks",
                "--url",
                "https://api.fireworks.ai/inference/v1",
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code == 0, result.output
        user_file = tmp_path / ".worthless" / "providers.toml"
        assert user_file.exists()
        content = user_file.read_text()
        assert "fireworks" in content
        assert "https://api.fireworks.ai/inference/v1" in content

    def test_register_refuses_bundled_name_conflict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Cannot reuse a bundled name (openai, anthropic, ...) for a user entry."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "openai",  # bundled
                "--url",
                "https://staging.openai.example/v1",
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code != 0
        # Error message should explain why and suggest a fix.
        assert "openai" in result.output.lower()
        # User file should not have been written.
        assert not (tmp_path / ".worthless" / "providers.toml").exists()

    def test_register_refuses_bundled_url_conflict_without_force(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "my-openai",
                "--url",
                "https://api.openai.com/v1",  # bundled URL
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code != 0
        # User file should not have been written.
        assert not (tmp_path / ".worthless" / "providers.toml").exists()

    def test_register_accepts_bundled_url_with_force(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "my-openai",
                "--url",
                "https://api.openai.com/v1",
                "--protocol",
                "openai",
                "--force",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_register_rejects_malformed_url(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "bad",
                "--url",
                "not-a-url",
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code != 0

    def test_register_rejects_javascript_url(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """javascript: URLs must be rejected — only http/https allowed."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "bad",
                "--url",
                "javascript:alert(1)",
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code != 0

    def test_register_accepts_localhost_http(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """http://localhost is valid (Ollama's default)."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "my-ollama",
                "--url",
                "http://localhost:1234/v1",
                "--protocol",
                "openai",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_register_rejects_unknown_protocol(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            app,
            [
                "providers",
                "register",
                "--name",
                "alien",
                "--url",
                "https://x.example/v1",
                "--protocol",
                "telepathy",  # not openai or anthropic
            ],
        )
        assert result.exit_code != 0

    def test_register_appends_does_not_clobber(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A second register call must keep the first entry."""
        monkeypatch.setenv("HOME", str(tmp_path))
        for name, url in [
            ("first", "https://a.example/v1"),
            ("second", "https://b.example/v1"),
        ]:
            result = runner.invoke(
                app,
                [
                    "providers",
                    "register",
                    "--name",
                    name,
                    "--url",
                    url,
                    "--protocol",
                    "openai",
                ],
            )
            assert result.exit_code == 0, result.output

        content = (tmp_path / ".worthless" / "providers.toml").read_text()
        assert "first" in content and "second" in content

    def test_register_refuses_existing_user_name(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Re-registering an already-user-registered name must fail before
        writing. Otherwise the second call appends a duplicate
        ``[provider.<name>]`` table to ``providers.toml``; the next
        ``load_user()`` raises ``TOMLDecodeError`` (TOML forbids
        duplicate tables) — breaking every other ``providers``/``lock``
        flow until the user hand-edits the file.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        common_args = [
            "providers",
            "register",
            "--name",
            "duplicate-me",
            "--url",
            "https://first.example/v1",
            "--protocol",
            "openai",
        ]
        first = runner.invoke(app, common_args)
        assert first.exit_code == 0, first.output

        # Second call with the same name must refuse.
        second_args = list(common_args)
        second_args[5] = "https://second.example/v1"  # different URL, same name
        second = runner.invoke(app, second_args)
        assert second.exit_code != 0, (
            f"second register with same name should fail; output={second.output[:300]}"
        )
        assert "duplicate-me" in second.output, (
            f"error should name the colliding provider; got: {second.output[:300]}"
        )

        # File must still be parseable (no duplicate table written).
        from worthless.cli.providers import load_user

        loaded = load_user()
        assert any(e.name == "duplicate-me" for e in loaded.values()), (
            "first registration should still be present"
        )
        assert all(e.url != "https://second.example/v1" for e in loaded.values()), (
            "second registration must not have been written"
        )

    def test_load_user_returns_empty_on_non_utf8_bytes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``load_user()`` docstring promises ``{}`` on any failure mode.
        ``UnicodeDecodeError`` was missing from the except tuple in M6 —
        a file with non-UTF-8 bytes (Latin-1 user, copy-pasted bytes
        from a Windows tool, corrupted file) would crash the CLI on
        any ``providers``/``lock``/``unlock`` invocation.

        Test writes a TOML containing a Latin-1-only byte (0xc3 alone is
        invalid UTF-8 — it's the lead byte of a 2-byte sequence with no
        continuation), monkey-patches HOME, asserts ``load_user`` returns
        ``{}`` instead of raising.
        """
        from worthless.cli.providers import load_user

        user_dir = tmp_path / ".worthless"
        user_dir.mkdir()
        # Non-UTF-8 byte sequence (lone 0xc3 + ASCII).
        (user_dir / "providers.toml").write_bytes(
            b'[provider.test]\nurl = "https://x.com/v1"\nname = "\xc3\x28"\nprotocol = "openai"\n'
        )
        monkeypatch.setenv("HOME", str(tmp_path))

        # Must not raise. Falls back to empty.
        loaded = load_user()
        assert loaded == {}, f"expected {{}} on non-UTF-8 input, got: {loaded}"

    def test_load_user_returns_empty_on_provider_not_a_table(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """If a user types ``provider = "openrouter"`` at file root instead
        of ``[provider.openrouter]`` (common config-file confusion), the
        ``raw.get("provider", {}).items()`` call used to raise
        ``AttributeError`` (strings don't have ``.items()``). The fix
        guards with ``isinstance(providers, dict)`` and falls back to
        empty.
        """
        from worthless.cli.providers import load_user

        user_dir = tmp_path / ".worthless"
        user_dir.mkdir()
        (user_dir / "providers.toml").write_text('provider = "openrouter"\n')
        monkeypatch.setenv("HOME", str(tmp_path))

        loaded = load_user()
        assert loaded == {}, f"expected {{}} when provider is a string not a table, got: {loaded}"

    def test_load_user_decodes_non_ascii_as_utf8(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """User TOML must decode as UTF-8 regardless of platform locale.

        Without ``encoding="utf-8"`` on ``read_text()`` the call falls
        back to ``locale.getencoding()`` — cp1252 on a fresh Windows
        install — which corrupts any non-ASCII byte. Bundled
        ``providers.toml`` is pure ASCII today so the bug is latent on
        Linux/macOS CI; this test pins the contract so a future drift
        back to the platform default would fail loudly.

        Setup writes a TOML containing a Cyrillic provider name and an
        em-dash in a comment — both invalid in cp1252.
        """
        from worthless.cli.providers import load_user

        user_dir = tmp_path / ".worthless"
        user_dir.mkdir()
        # TOML bare keys are ASCII; non-ASCII goes in a quoted key OR in
        # values. Cover both: an em-dash in a comment + a Cyrillic name
        # via quoted-key syntax + a non-ASCII URL fragment.
        (user_dir / "providers.toml").write_bytes(
            (
                "# i18n provider — registered locally\n"
                '[provider."staging-провайдер"]\n'
                'url = "https://staging.example/v1?région=eu"\n'
                'protocol = "openai"\n'
            ).encode()
        )
        monkeypatch.setenv("HOME", str(tmp_path))

        loaded = load_user()
        names = [e.name for e in loaded.values()]
        urls = [e.url for e in loaded.values()]
        assert any("провайдер" in n for n in names), (
            f"Cyrillic provider name not parsed correctly — likely a "
            f"non-UTF-8 decode happened. Got names: {names}"
        )
        assert any("région" in u for u in urls), (
            f"Non-ASCII URL fragment lost — likely a non-UTF-8 decode happened. Got URLs: {urls}"
        )

    def test_lookup_normalizes_trailing_slash(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Registry lookup must treat trailing slash as equivalent.
        ``https://api.openai.com/v1`` (bundled) and
        ``https://api.openai.com/v1/`` (user with extra slash in .env)
        must resolve to the same entry — otherwise lock-time URL
        validation refuses a perfectly valid OpenAI URL just because the
        user added a slash.
        """
        from worthless.cli.providers import lookup_by_url

        monkeypatch.setenv("HOME", str(tmp_path))
        without = lookup_by_url("https://api.openai.com/v1")
        with_slash = lookup_by_url("https://api.openai.com/v1/")
        assert without is not None, "bundled URL without trailing slash must resolve"
        assert with_slash is not None, (
            "bundled URL WITH trailing slash must resolve to the same entry "
            "(otherwise lock refuses users whose .env has the extra slash)"
        )
        assert without.name == with_slash.name == "openai"

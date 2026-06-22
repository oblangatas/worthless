"""WOR-650 — CLI wiring for DB-backed recognition.

Covers the two new seams between ``worthless lock`` and the recognition engine:

* :func:`integration.preview_unrecognized` — the read-only preview the CLI uses
  to decide whether to prompt at all.
* :func:`lock._resolve_adoption_policy` — the consent decision: ``--adopt`` /
  non-TTY adopt silently; interactive prompts once over the previewed entries;
  ``managed_aliases=None`` threads straight through.

The full lock→openclaw pipeline is proven in the docker e2e; these stay at the
seam so they're fast and deterministic.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from worthless.cli.commands import lock as lock_cmd
from worthless.openclaw import integration

PROXY = "http://127.0.0.1:8787"
_API = {"openai": "openai-completions", "anthropic": "anthropic-messages"}


def _seed(config_path, provider, base_url, api_key="sk-old"):  # noqa: ANN001
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


def _planned(provider, alias):  # noqa: ANN001
    return SimpleNamespace(provider=provider, alias=alias)


class _FakeConsole:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def print_warning(self, msg: str) -> None:
        self.warnings.append(msg)


def _tty(monkeypatch, value: bool) -> None:
    monkeypatch.setattr(lock_cmd.sys, "stdin", SimpleNamespace(isatty=lambda: value))


def _no_prompt(monkeypatch) -> None:
    monkeypatch.setattr(
        lock_cmd.typer, "confirm", lambda *a, **k: pytest.fail("prompted unexpectedly")
    )


# ---------------------------------------------------------------------------
# preview_unrecognized
# ---------------------------------------------------------------------------


def test_preview_flags_foreign_proxy_entry(openclaw_present, monkeypatch) -> None:
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", f"{PROXY}/openai-foreign/v1")
    out = integration.preview_unrecognized(
        [("openai", "openai-new", "")], proxy_base_url=PROXY, managed_aliases=set()
    )
    assert out == ["openai"]


def test_preview_silent_for_recognized_alias(openclaw_present, monkeypatch) -> None:
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", f"{PROXY}/openai-known/v1")
    out = integration.preview_unrecognized(
        [("openai", "openai-new", "")],
        proxy_base_url=PROXY,
        managed_aliases={"openai-known"},
    )
    assert out == []


def test_preview_silent_for_real_key(openclaw_present, monkeypatch) -> None:
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", "https://api.openai.com/v1")
    out = integration.preview_unrecognized(
        [("openai", "openai-new", "")], proxy_base_url=PROXY, managed_aliases=set()
    )
    assert out == []


# ---------------------------------------------------------------------------
# _resolve_adoption_policy
# ---------------------------------------------------------------------------


def test_policy_adopt_flag_skips_prompt(monkeypatch) -> None:
    """--adopt adopts even on a TTY, without prompting."""
    _tty(monkeypatch, True)
    _no_prompt(monkeypatch)
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "a")],
        managed_aliases=set(),
        adopt=True,
        console=_FakeConsole(),
        quiet=False,
    )
    assert pol.adopt_unrecognized is True


def test_policy_non_tty_adopts_without_prompt(monkeypatch) -> None:
    """Non-interactive shell (agent/CI) adopts-with-notice, never blocks."""
    _tty(monkeypatch, False)
    _no_prompt(monkeypatch)
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "a")],
        managed_aliases=set(),
        adopt=False,
        console=_FakeConsole(),
        quiet=False,
    )
    assert pol.adopt_unrecognized is True


def test_policy_interactive_prompt_yes_adopts(openclaw_present, monkeypatch) -> None:
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", f"{PROXY}/openai-foreign/v1")
    _tty(monkeypatch, True)
    monkeypatch.setattr(lock_cmd, "_openclaw_proxy_base_url", lambda: ("127.0.0.1", PROXY))
    monkeypatch.setattr(lock_cmd.typer, "confirm", lambda *a, **k: True)
    console = _FakeConsole()
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "openai-new")],
        managed_aliases=set(),
        adopt=False,
        console=console,
        quiet=False,
    )
    assert pol.adopt_unrecognized is True
    assert any("openai" in w for w in console.warnings)  # named the provider


def test_policy_interactive_prompt_no_skips(openclaw_present, monkeypatch) -> None:
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", f"{PROXY}/openai-foreign/v1")
    _tty(monkeypatch, True)
    monkeypatch.setattr(lock_cmd, "_openclaw_proxy_base_url", lambda: ("127.0.0.1", PROXY))
    monkeypatch.setattr(lock_cmd.typer, "confirm", lambda *a, **k: False)
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "openai-new")],
        managed_aliases=set(),
        adopt=False,
        console=_FakeConsole(),
        quiet=False,
    )
    assert pol.adopt_unrecognized is False


def test_policy_no_foreign_entry_does_not_prompt(openclaw_present, monkeypatch) -> None:
    """A recognized/real-key config never reaches the prompt."""
    monkeypatch.chdir(openclaw_present["home"])
    _seed(openclaw_present["config_path"], "openai", "https://api.openai.com/v1")
    _tty(monkeypatch, True)
    monkeypatch.setattr(lock_cmd, "_openclaw_proxy_base_url", lambda: ("127.0.0.1", PROXY))
    _no_prompt(monkeypatch)
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "openai-new")],
        managed_aliases=set(),
        adopt=False,
        console=_FakeConsole(),
        quiet=False,
    )
    assert pol.adopt_unrecognized is False


def test_policy_threads_none_managed(monkeypatch) -> None:
    """A failed DB snapshot (None) reaches the policy verbatim — never coerced
    to an empty set, so downstream renders recognition_unavailable."""
    _tty(monkeypatch, False)
    pol = lock_cmd._resolve_adoption_policy(
        [_planned("openai", "a")],
        managed_aliases=None,
        adopt=True,
        console=_FakeConsole(),
        quiet=False,
    )
    assert pol.managed_aliases is None

"""Tests for the canonical openclaw.json config reader/writer.

Covers WOR-431 Phase 1 acceptance criteria. These tests drive the public API
exposed by ``worthless.openclaw.config`` (used by both WOR-431 and WOR-321).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from worthless.openclaw import config as ocfg
from worthless.openclaw.config import (
    OpenclawConfigError,
    get_provider,
    locate_config_path,
    read_config,
    set_provider,
    unset_provider,
)


# ---------------------------------------------------------------------------
# locate_config_path
# ---------------------------------------------------------------------------


def test_locate_config_project_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Project-local ./openclaw.json wins over global config."""
    monkeypatch.chdir(tmp_path)
    local = tmp_path / "openclaw.json"
    local.write_text("{}")

    found = locate_config_path()

    assert found is not None
    assert found.resolve() == local.resolve()


def test_locate_config_global_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``~/.openclaw/openclaw.json`` is the canonical global path (verified live).

    OpenClaw daemon container uses ``/home/node/.openclaw/openclaw.json``;
    host platforms mirror this (~/.openclaw/) on both macOS and Linux.
    """
    home = tmp_path / "home"
    home.mkdir()
    global_path = home / ".openclaw" / "openclaw.json"
    global_path.parent.mkdir(parents=True)
    global_path.write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)  # cwd has no project-local openclaw.json

    found = locate_config_path()

    assert found is not None
    assert found.resolve() == global_path.resolve()


def test_locate_config_xdg_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``~/.config/openclaw/openclaw.json`` is the XDG fallback when ~/.openclaw is absent."""
    home = tmp_path / "home"
    home.mkdir()
    xdg_path = home / ".config" / "openclaw" / "openclaw.json"
    xdg_path.parent.mkdir(parents=True)
    xdg_path.write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    found = locate_config_path()

    assert found is not None
    assert found.resolve() == xdg_path.resolve()


def test_locate_config_canonical_wins_over_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``~/.openclaw/`` takes priority over ``~/.config/openclaw/`` when both exist."""
    home = tmp_path / "home"
    canonical = home / ".openclaw" / "openclaw.json"
    canonical.parent.mkdir(parents=True)
    canonical.write_text("{}")
    xdg = home / ".config" / "openclaw" / "openclaw.json"
    xdg.parent.mkdir(parents=True)
    xdg.write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    found = locate_config_path()
    assert found is not None
    assert found.resolve() == canonical.resolve()


def test_locate_config_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when no config exists locally or globally."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    assert locate_config_path() is None


# ---------------------------------------------------------------------------
# read_config
# ---------------------------------------------------------------------------


def test_read_empty_file(tmp_path: Path) -> None:
    """Non-existent file returns ``{}``."""
    missing = tmp_path / "openclaw.json"

    assert read_config(missing) == {}


def test_read_malformed_json(tmp_path: Path) -> None:
    """Malformed JSON raises OpenclawConfigError."""
    bad = tmp_path / "openclaw.json"
    bad.write_text("{this is not json")

    with pytest.raises(OpenclawConfigError):
        read_config(bad)


# ---------------------------------------------------------------------------
# set_provider
# ---------------------------------------------------------------------------


def test_set_provider_creates_file(tmp_path: Path) -> None:
    """When the file (and its parents) do not exist, set_provider creates them."""
    target = tmp_path / "nested" / "dir" / "openclaw.json"

    set_provider(
        target,
        provider="worthless-openai",
        base_url="http://localhost:8787/v1",
    )

    assert target.exists()
    data = json.loads(target.read_text())
    assert data["models"]["providers"]["worthless-openai"]["baseUrl"] == "http://localhost:8787/v1"


def test_set_provider_round_trip(tmp_path: Path) -> None:
    """Write then read returns the same data."""
    target = tmp_path / "openclaw.json"

    set_provider(target, provider="worthless-openai", base_url="http://x/v1", api_key="k")

    data = read_config(target)
    assert data["models"]["providers"]["worthless-openai"]["baseUrl"] == "http://x/v1"
    assert data["models"]["providers"]["worthless-openai"]["apiKey"] == "k"


def test_set_provider_idempotent(tmp_path: Path) -> None:
    """Calling set_provider twice with same args produces the same file."""
    target = tmp_path / "openclaw.json"

    set_provider(target, provider="worthless-openai", base_url="http://x/v1")
    first = target.read_text()

    set_provider(target, provider="worthless-openai", base_url="http://x/v1")
    second = target.read_text()

    assert json.loads(first) == json.loads(second)


def test_set_provider_preserves_other_providers(tmp_path: Path) -> None:
    """Adding a provider does not touch unrelated providers."""
    target = tmp_path / "openclaw.json"
    target.write_text(
        json.dumps(
            {
                "models": {
                    "providers": {
                        "existing": {
                            "baseUrl": "http://existing/v1",
                            "apiKey": "keep-me",
                            "api": "openai-completions",
                            "models": [{"id": "m", "name": "M"}],
                        }
                    }
                }
            }
        )
    )

    set_provider(target, provider="worthless-openai", base_url="http://new/v1")

    data = read_config(target)
    assert data["models"]["providers"]["existing"]["apiKey"] == "keep-me"
    assert data["models"]["providers"]["worthless-openai"]["baseUrl"] == "http://new/v1"


def test_set_provider_atomic_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed write must not corrupt the existing file (atomic via os.replace)."""
    target = tmp_path / "openclaw.json"
    original_payload = {
        "models": {
            "providers": {
                "existing": {"baseUrl": "http://existing/v1"},
            }
        }
    }
    target.write_text(json.dumps(original_payload))

    real_replace = os.replace

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("simulated disk full during replace")

    with mock.patch.object(ocfg.os, "replace", side_effect=boom):
        with pytest.raises(OSError):
            set_provider(target, provider="worthless-openai", base_url="http://new/v1")

    # Restore for subsequent tests just in case (mock.patch already does this).
    assert os.replace is real_replace

    # Original file content must be untouched.
    assert json.loads(target.read_text()) == original_payload

    # No leftover .tmp files in the same dir. The .openclaw.json.lock sentinel
    # is expected and persists across writers — it's the inter-process lock.
    tmp_leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert tmp_leftovers == [], f"temp files leaked: {tmp_leftovers}"


def test_set_provider_with_api_key(tmp_path: Path) -> None:
    """apiKey is set when provided."""
    target = tmp_path / "openclaw.json"

    set_provider(
        target,
        provider="worthless-openai",
        base_url="http://x/v1",
        api_key="PLACEHOLDER_SHARD_A",
    )

    data = read_config(target)
    assert data["models"]["providers"]["worthless-openai"]["apiKey"] == "PLACEHOLDER_SHARD_A"


# ---------------------------------------------------------------------------
# unset_provider
# ---------------------------------------------------------------------------


def test_unset_provider_removes_entry(tmp_path: Path) -> None:
    """Removing a provider deletes its entry but keeps siblings."""
    target = tmp_path / "openclaw.json"
    set_provider(target, provider="a", base_url="http://a/v1")
    set_provider(target, provider="b", base_url="http://b/v1")

    removed = unset_provider(target, provider="a")

    assert removed.get("baseUrl") == "http://a/v1"
    data = read_config(target)
    assert "a" not in data["models"]["providers"]
    assert "b" in data["models"]["providers"]


def test_unset_provider_missing(tmp_path: Path) -> None:
    """Removing a non-existent provider is a no-op and returns ``{}``."""
    target = tmp_path / "openclaw.json"
    set_provider(target, provider="b", base_url="http://b/v1")

    removed = unset_provider(target, provider="does-not-exist")

    assert removed == {}
    data = read_config(target)
    assert "b" in data["models"]["providers"]


# ---------------------------------------------------------------------------
# get_provider
# ---------------------------------------------------------------------------


def test_get_provider_returns_dict(tmp_path: Path) -> None:
    """Existing provider returns its dict."""
    target = tmp_path / "openclaw.json"
    set_provider(target, provider="worthless-openai", base_url="http://x/v1", api_key="k")

    got = get_provider(target, provider="worthless-openai")

    assert got is not None
    assert got["baseUrl"] == "http://x/v1"
    assert got["apiKey"] == "k"


def test_get_provider_missing_returns_none(tmp_path: Path) -> None:
    """Missing provider returns None."""
    target = tmp_path / "openclaw.json"
    set_provider(target, provider="worthless-openai", base_url="http://x/v1")

    assert get_provider(target, provider="nope") is None
    assert get_provider(tmp_path / "no-file.json", provider="anything") is None


# ---------------------------------------------------------------------------
# Edge cases for branch coverage
# ---------------------------------------------------------------------------


def test_locate_config_project_wins_over_global(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Project-local config takes precedence over the global path."""
    home = tmp_path / "home"
    (home / ".openclaw").mkdir(parents=True)
    global_path = home / ".openclaw" / "openclaw.json"
    global_path.write_text("{}")

    project = tmp_path / "project"
    project.mkdir()
    local = project / "openclaw.json"
    local.write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)

    found = locate_config_path()
    assert found is not None
    assert found.resolve() == local.resolve()


def test_read_blank_file_returns_empty(tmp_path: Path) -> None:
    """A file containing only whitespace parses as empty dict, not error."""
    target = tmp_path / "openclaw.json"
    target.write_text("   \n  \t\n")

    assert read_config(target) == {}


def test_read_non_object_top_level(tmp_path: Path) -> None:
    """Top-level JSON array (not an object) raises OpenclawConfigError."""
    target = tmp_path / "openclaw.json"
    target.write_text("[1, 2, 3]")

    with pytest.raises(OpenclawConfigError):
        read_config(target)


def test_set_provider_rejects_non_object_models(tmp_path: Path) -> None:
    """If 'models' exists as a non-object, set_provider raises."""
    target = tmp_path / "openclaw.json"
    target.write_text(json.dumps({"models": "not-an-object"}))

    with pytest.raises(OpenclawConfigError):
        set_provider(target, provider="x", base_url="http://x")


def test_set_provider_rejects_non_object_providers(tmp_path: Path) -> None:
    """If 'models.providers' exists as a non-object, set_provider raises."""
    target = tmp_path / "openclaw.json"
    target.write_text(json.dumps({"models": {"providers": []}}))

    with pytest.raises(OpenclawConfigError):
        set_provider(target, provider="x", base_url="http://x")


def test_unset_provider_on_missing_file(tmp_path: Path) -> None:
    """unset_provider on a missing file returns {} (no-op)."""
    target = tmp_path / "openclaw.json"
    assert unset_provider(target, provider="anything") == {}


def test_unset_provider_with_malformed_models(tmp_path: Path) -> None:
    """unset_provider tolerates malformed 'models' / 'providers' entries."""
    target = tmp_path / "openclaw.json"
    target.write_text(json.dumps({"models": "wrong"}))
    assert unset_provider(target, provider="x") == {}

    target.write_text(json.dumps({"models": {"providers": "wrong"}}))
    assert unset_provider(target, provider="x") == {}


def test_get_provider_with_malformed_models(tmp_path: Path) -> None:
    """get_provider returns None when 'models' or 'providers' is malformed."""
    target = tmp_path / "openclaw.json"

    target.write_text(json.dumps({"models": "wrong"}))
    assert get_provider(target, provider="x") is None

    target.write_text(json.dumps({"models": {"providers": "wrong"}}))
    assert get_provider(target, provider="x") is None


def test_get_provider_non_dict_entry_raises(tmp_path: Path) -> None:
    """A provider entry that is not a JSON object raises OpenclawConfigError."""
    target = tmp_path / "openclaw.json"
    target.write_text(json.dumps({"models": {"providers": {"x": "not-an-object"}}}))

    with pytest.raises(OpenclawConfigError):
        get_provider(target, provider="x")


# ---------------------------------------------------------------------------
# Concurrency — flock prevents lost updates between concurrent writers.
# Without this, atomic-replace prevents torn files but two read-modify-write
# transactions could interleave and silently drop one of the providers.
# Verified live by the WOR-431 dynamic-verify pass: 8 parallel writers without
# the lock landed only 7 providers; with the lock all N must land.
# ---------------------------------------------------------------------------


def _set_provider_in_subprocess(args: tuple[str, str, str]) -> None:
    """Module-level helper for multiprocessing; must be top-level picklable."""
    target_str, provider, base_url = args
    # Re-import inside the subprocess (sys.path inheritance suffices via uv run).
    from worthless.openclaw.config import set_provider as _set

    _set(Path(target_str), provider=provider, base_url=base_url)


def test_set_provider_concurrent_writers_no_lost_updates(tmp_path: Path) -> None:
    """N parallel processes each adding a unique provider — all N must land."""
    import multiprocessing

    target = tmp_path / "openclaw.json"
    n_writers = 8
    work = [(str(target), f"prov-{i:02d}", f"http://host-{i}/v1") for i in range(n_writers)]

    # spawn (not fork) — safer cross-platform, matches CI behavior.
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=n_writers) as pool:
        pool.map(_set_provider_in_subprocess, work)

    data = read_config(target)
    landed = set(data["models"]["providers"].keys())
    expected = {f"prov-{i:02d}" for i in range(n_writers)}
    missing = expected - landed
    assert not missing, f"lost-update race: {missing} dropped from concurrent writes"

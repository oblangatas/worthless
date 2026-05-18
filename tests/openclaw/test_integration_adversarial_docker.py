"""Adversarial tests for openclaw integration: Docker shared-volume permissions.

Simulates permission constraints that arise when openclaw and the worthless
proxy share a Docker named volume:

  DV-01 — Config dir locked to 0700 by openclaw daemon on startup.
      ``detect()`` must return ``present=True`` (not ``False``) so
      ``apply_lock`` can surface a ``WRITE_FAILED`` diagnostic event
      instead of silently returning ``detected=False``.

  DV-02 — Config file unreadable (0600 by foreign uid, dir still 0777).
      ``read_config`` must return ``{}``; ``set_provider`` must write a
      fresh entry via atomic replace.  Existing non-worthless config keys
      are lost (documented in ``read_config`` docstring — openclaw
      regenerates them on restart).

  DV-03 — Atomic write mode with ``WORTHLESS_OPENCLAW_CONFIG_SHARED=1``.
      Written file must be ``0o644`` so the openclaw container (different
      uid) can read it.

  DV-04 — Atomic write mode without the env var.
      ``tempfile.mkstemp`` produces ``0o600``; the written file must stay
      restrictive (no world-read).

  SR-04 equiv — ``shard_a`` never appears in event ``detail`` or ``extra``
      strings, and never appears in the ``OpenclawApplyResult`` repr.
      Guards against the same class of secret-in-log leaks covered by
      SR-04 in the key-split path.

Tests that manipulate filesystem permissions use ``chmod(0o000)`` on paths
the test *owns* — the owner bit is stripped so the test process cannot
traverse the dir, faithfully replicating the "foreign 0700 dir" scenario
without requiring two uids.  All such tests are skipped when running as
root (root bypasses permission checks and the simulation would be invalid).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME at a tmp_path-rooted sandbox."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _needs_nonroot() -> None:
    """Skip when running as root — chmod tests are meaningless under root."""
    if os.getuid() == 0:
        pytest.skip("chmod permission tests are meaningless when running as root")


# ---------------------------------------------------------------------------
# DV-01 — Config dir locked (simulates openclaw chmod 700 on startup)
# ---------------------------------------------------------------------------


def test_dv01_detect_present_when_config_dir_locked(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DV-01a: detect() returns present=True when the config dir is inaccessible.

    OpenClaw sets its config dir to 0700 on startup (security policy).  The
    worthless proxy (different uid) can no longer traverse the dir, so
    ``Path.exists()`` returns False for the config file.  Before the fix,
    ``detect()`` silently returned ``present=False``, which caused
    ``apply_lock`` to return ``detected=False`` with no diagnostic — the
    operator had no way to know openclaw was detected but unreachable.

    After the fix ``_probe_config()`` tries ``p.stat()`` when ``p.exists()``
    returns False: a ``PermissionError`` from ``stat()`` means "dir exists but
    is locked" rather than "dir absent".  ``detect()`` must:

    - return ``present=True``
    - populate ``config_path`` with the locked path
    - include a note mentioning the lock
    """
    _needs_nonroot()

    from worthless.openclaw import integration

    openclaw_dir = fake_home / ".openclaw"
    openclaw_dir.mkdir()
    config_file = openclaw_dir / "openclaw.json"
    config_file.write_text("{}", encoding="utf-8")

    # Simulate openclaw locking the dir (strip all permissions so even the
    # owner cannot traverse — same effect as 700 by a foreign uid from the
    # perspective of stat() on children).
    openclaw_dir.chmod(0o000)
    try:
        state = integration.detect()
    finally:
        openclaw_dir.chmod(0o755)  # restore before pytest teardown

    assert state.present, (
        "detect() must return present=True when config dir is locked — "
        "openclaw IS installed, it just locked its own dir"
    )
    assert state.config_path is not None
    assert any("locked" in n.lower() or "permissionerror" in n.lower() for n in state.notes), (
        f"expected a diagnostic note about the locked dir, got: {state.notes}"
    )


def test_dv01_apply_lock_emits_write_failed_not_detected_false_when_dir_locked(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DV-01b: apply_lock surfaces WRITE_FAILED event, not silent detected=False.

    With the dir locked (0700 by openclaw), ``apply_lock`` cannot write to
    ``openclaw.json``.  The correct result is:

    - ``result.detected = True`` (we know openclaw is there)
    - providers_set is empty (nothing could be written)
    - providers_skipped contains the provider with reason "write_failed"
    - At least one WRITE_FAILED event is present in ``result.events``
    - ``apply_lock`` does NOT raise (per L1: openclaw failures never roll back
      lock-core)

    Before the fix the function returned ``detected=False`` with no events,
    leaving the operator with no indication of what went wrong.
    """
    _needs_nonroot()

    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode

    openclaw_dir = fake_home / ".openclaw"
    openclaw_dir.mkdir()
    (openclaw_dir / "openclaw.json").write_text("{}", encoding="utf-8")

    openclaw_dir.chmod(0o000)
    try:
        result = integration.apply_lock(
            planned_updates=[("openai", "openai", "sk-shard-a-value")],
            proxy_base_url="http://proxy:8787",
        )
    finally:
        openclaw_dir.chmod(0o755)

    assert result.detected, (
        "apply_lock must return detected=True when openclaw dir is locked — "
        "openclaw is present, the write just failed"
    )
    assert len(result.providers_set) == 0, "no providers can be written when dir is locked"
    assert len(result.providers_skipped) == 1
    provider_name, reason = result.providers_skipped[0]
    assert "write_failed" in reason.lower(), f"unexpected skip reason: {reason!r}"
    assert any(e.code == OpenclawErrorCode.WRITE_FAILED for e in result.events), (
        f"expected WRITE_FAILED event, got: {[e.code for e in result.events]}"
    )


def test_dv01_notes_contain_actionable_guidance_when_dir_locked(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DV-01c: the diagnostic note for a locked dir mentions stopping openclaw.

    The note is the operator's first (and only) signal.  It must be
    actionable — "stop openclaw to re-lock" is the correct workaround.
    """
    _needs_nonroot()

    from worthless.openclaw import integration

    openclaw_dir = fake_home / ".openclaw"
    openclaw_dir.mkdir()
    (openclaw_dir / "openclaw.json").write_text("{}", encoding="utf-8")

    openclaw_dir.chmod(0o000)
    try:
        state = integration.detect()
    finally:
        openclaw_dir.chmod(0o755)

    note_text = " ".join(state.notes).lower()
    assert "stop" in note_text or "re-lock" in note_text or "0700" in note_text, (
        "diagnostic note must guide the operator; got: " + repr(state.notes)
    )


# ---------------------------------------------------------------------------
# DV-02 — Config file unreadable (0600 foreign-owned), dir still writable
# ---------------------------------------------------------------------------


def test_dv02_read_config_strict_raises_on_permission_denied(tmp_path: Path) -> None:
    """DV-02a: read_config raises OpenclawConfigError in strict mode (default).

    By default, a PermissionError is surfaced so callers like get_provider
    and unset_provider can distinguish "file absent" from "file unreadable" —
    the latter is an error, not a no-op.
    """
    _needs_nonroot()

    from worthless.openclaw.config import OpenclawConfigError, read_config

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps({"models": {"providers": {"existing": {"baseUrl": "http://x"}}}}),
        encoding="utf-8",
    )
    cfg.chmod(0o000)
    try:
        with pytest.raises(OpenclawConfigError, match="could not read"):
            read_config(cfg)
    finally:
        cfg.chmod(0o644)


def test_dv02_read_config_permission_as_missing_returns_empty(tmp_path: Path) -> None:
    """DV-02a-opt: read_config(permission_as_missing=True) returns {} on PermissionError.

    set_provider opts into this mode so it can write fresh entries via atomic
    replace even when the existing file is foreign-owned (0600 node:node in
    the Docker shared-volume setup).
    """
    _needs_nonroot()

    from worthless.openclaw.config import read_config

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        json.dumps({"models": {"providers": {"existing": {"baseUrl": "http://x"}}}}),
        encoding="utf-8",
    )
    cfg.chmod(0o000)
    try:
        result = read_config(cfg, permission_as_missing=True)
    finally:
        cfg.chmod(0o644)

    assert result == {}, (
        "read_config(permission_as_missing=True) must return {} on PermissionError — "
        "treating unreadable file as 'no existing config' for the atomic write path"
    )


def test_dv02_set_provider_succeeds_when_dir_writable_file_locked(tmp_path: Path) -> None:
    """DV-02b: set_provider writes via atomic replace even if the existing file
    is unreadable.

    ``os.replace`` (rename) only needs write permission on the containing
    directory — not on the target file inode being replaced.  When the dir is
    0o777 but the file is 0o000 (simulating foreign 0o600), the atomic write
    must succeed.  The existing config content is lost (read_config returns {}),
    which is the documented behaviour for the Docker shared-volume case.
    """
    _needs_nonroot()

    from worthless.openclaw.config import read_config, set_provider

    cfg = tmp_path / "openclaw.json"
    # Seed with a "foreign" provider entry that should survive vs. be lost.
    cfg.write_text(
        json.dumps({"models": {"providers": {"gateway-token": {"baseUrl": "http://gw"}}}}),
        encoding="utf-8",
    )
    # Lock the file — simulates openclaw rewriting it as 0600 foreign-owned.
    cfg.chmod(0o000)
    try:
        set_provider(
            cfg,
            provider="worthless-openai",
            base_url="http://proxy:8787/openai/v1",
            api_key="sk-shard-a",
        )
    finally:
        cfg.chmod(0o644)  # restore for read / teardown

    data = read_config(cfg)
    providers = data["models"]["providers"]
    assert "worthless-openai" in providers, "our provider must be written"
    assert providers["worthless-openai"]["baseUrl"] == "http://proxy:8787/openai/v1"
    # "gateway-token" is lost — read_config returned {} (PermissionError) so
    # set_provider had no knowledge of the existing entry.  This is documented.
    assert "gateway-token" not in providers, (
        "non-worthless config keys are intentionally lost when the file was "
        "unreadable — openclaw regenerates them on restart"
    )


# ---------------------------------------------------------------------------
# DV-03 / DV-04 — Written file permissions (shared-volume vs default)
# ---------------------------------------------------------------------------


def test_dv03_shared_volume_mode_writes_0o644(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DV-03: WORTHLESS_OPENCLAW_CONFIG_SHARED=1 → written file is 0o644.

    The openclaw container runs as a different uid.  The file must be
    world-readable (0o644) so openclaw can read the provider entry that the
    proxy just wrote.  Without this chmod, openclaw sees an unreadable config
    and ignores the provider — the proxy is never registered.
    """
    from worthless.openclaw.config import set_provider

    monkeypatch.setenv("WORTHLESS_OPENCLAW_CONFIG_SHARED", "1")

    cfg = tmp_path / "openclaw.json"
    set_provider(cfg, provider="worthless-openai", base_url="http://proxy:8787/openai/v1")

    mode = cfg.stat().st_mode & 0o777
    assert mode == 0o644, (
        f"with WORTHLESS_OPENCLAW_CONFIG_SHARED=1 the written file must be "
        f"0o644 (world-readable) so the openclaw container can read it; "
        f"got 0o{mode:o}"
    )


def test_dv04_default_mode_is_restrictive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """DV-04: without WORTHLESS_OPENCLAW_CONFIG_SHARED the file stays 0o600.

    ``tempfile.mkstemp`` always creates files as 0o600.  After
    ``os.replace`` the destination inherits that mode.  No chmod is applied
    in the non-shared case, so the file must remain 0o600 — readable only by
    the proxy user.
    """
    from worthless.openclaw.config import set_provider

    monkeypatch.delenv("WORTHLESS_OPENCLAW_CONFIG_SHARED", raising=False)

    cfg = tmp_path / "openclaw.json"
    set_provider(cfg, provider="worthless-openai", base_url="http://proxy:8787/openai/v1")

    mode = cfg.stat().st_mode & 0o777
    assert mode == 0o600, (
        f"without WORTHLESS_OPENCLAW_CONFIG_SHARED the written file must be "
        f"0o600 (restrictive default from mkstemp); got 0o{mode:o}"
    )


# ---------------------------------------------------------------------------
# SR-04 equiv — shard_a must not appear in events or result repr
# ---------------------------------------------------------------------------


def test_sr04_shard_a_not_in_event_detail_strings(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-04 equiv: shard_a never leaks into event detail or extra values.

    ``shard_a`` is written to ``openclaw.json`` as ``apiKey`` (half of the
    split key).  It must never appear in structured event output — if it did,
    any log aggregator or ``--json`` consumer would receive half the key in
    plaintext, undermining the split-key security model.

    Verifies all event ``detail`` strings and all ``extra`` dict values.
    """
    from worthless.openclaw import integration

    # Stage a minimal openclaw presence.
    openclaw_dir = fake_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    (openclaw_dir / "openclaw.json").write_text("{}", encoding="utf-8")

    shard_a = "sk-shard-a-SENTINEL-must-not-leak-into-events"

    result = integration.apply_lock(
        planned_updates=[("openai", "openai", shard_a)],
        proxy_base_url="http://proxy:8787",
    )

    for event in result.events:
        assert shard_a not in event.detail, f"shard_a leaked in event.detail: {event.detail!r}"
        for k, v in (event.extra or {}).items():
            assert shard_a not in str(v), f"shard_a leaked in event.extra[{k!r}]: {v!r}"


def test_sr04_shard_a_not_in_apply_result_repr(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-04 equiv: shard_a must not appear in OpenclawApplyResult repr.

    ``OpenclawApplyResult`` is a frozen dataclass.  Its ``__repr__`` includes
    all field values.  ``shard_a`` must not be stored in any field — it is
    consumed during the write to ``openclaw.json`` and must not be retained in
    the return value.
    """
    from worthless.openclaw import integration

    openclaw_dir = fake_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    (openclaw_dir / "openclaw.json").write_text("{}", encoding="utf-8")

    shard_a = "sk-shard-a-SENTINEL-must-not-appear-in-repr"

    result = integration.apply_lock(
        planned_updates=[("openai", "openai", shard_a)],
        proxy_base_url="http://proxy:8787",
    )

    assert shard_a not in repr(result), (
        f"shard_a leaked in OpenclawApplyResult repr: {repr(result)!r}"
    )

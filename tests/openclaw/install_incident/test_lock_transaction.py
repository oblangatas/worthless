"""Tests for WOR-516: worthless lock transactional rollback, UID-mismatch gate, .bak cleanup,
and doctor type safety.  Implementation is complete; all tests must pass.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from worthless.openclaw import config as _config
from worthless.openclaw import integration as _integration
from worthless.openclaw.integration import IntegrationState

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = {
    "models": {
        "providers": {
            "existing-provider": {
                "api": "openai-completions",
                "apiKey": "sk-existing-key",
                "baseUrl": "https://api.example.com/v1",
                "models": [],
            }
        }
    }
}

PLANNED = [("openai", "openai-abc123", "auth-token-xyz")]
PROXY_URL = "http://127.0.0.1:8787"


@pytest.fixture()
def oc_dir(tmp_path):
    d = tmp_path / ".openclaw"
    d.mkdir()
    return d


@pytest.fixture()
def openclaw_config(oc_dir):
    cfg = oc_dir / "openclaw.json"
    cfg.write_text(json.dumps(MINIMAL_CONFIG))
    return cfg


@pytest.fixture()
def mock_state(openclaw_config):
    return IntegrationState(
        present=True,
        config_path=openclaw_config,
        workspace_path=None,
        skill_path=None,
        home_dir=openclaw_config.parent.parent,
        notes=(),
    )


# ---------------------------------------------------------------------------
# AC1  clean config + clean audit → exits 0, providers written, existing preserved
# ---------------------------------------------------------------------------


def test_ac1_clean_config_providers_written_existing_preserved(openclaw_config, mock_state):
    with patch.object(_integration, "detect", return_value=mock_state):
        result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert result.detected
    assert not result.has_failure
    assert "worthless-openai" in result.providers_set

    written = _config.read_config(openclaw_config)
    providers = written["models"]["providers"]
    assert "worthless-openai" in providers, "new provider missing"
    assert "existing-provider" in providers, "existing provider must NOT be clobbered"


# ---------------------------------------------------------------------------
# AC2  config_state="unreadable" (UID mismatch) → abort, zero writes
# ---------------------------------------------------------------------------


def test_ac2_uid_mismatch_aborts_before_writes(openclaw_config, mock_state):
    from worthless.openclaw.errors import OpenclawConfigUnreadableError

    original_bytes = openclaw_config.read_bytes()

    real_st = openclaw_config.stat()
    mock_st = MagicMock()
    mock_st.st_uid = os.geteuid() + 1  # different owner
    mock_st.st_mode = real_st.st_mode

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch("os.stat", return_value=mock_st):
            with pytest.raises(OpenclawConfigUnreadableError):
                _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert openclaw_config.read_bytes() == original_bytes, "file must be untouched"


# ---------------------------------------------------------------------------
# AC3  WORTHLESS_OPENCLAW_CONFIG_SHARED=1 → abort, zero writes
# ---------------------------------------------------------------------------


def test_ac3_shared_env_set_aborts_before_writes(openclaw_config, mock_state):
    from worthless.openclaw.errors import OpenclawConfigUnreadableError

    original_bytes = openclaw_config.read_bytes()

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            with pytest.raises(OpenclawConfigUnreadableError):
                _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert openclaw_config.read_bytes() == original_bytes


# ---------------------------------------------------------------------------
# AC4  build_lock_plan on clean config → config_state="present", no writes
# ---------------------------------------------------------------------------


def test_ac4_build_lock_plan_clean_no_writes(openclaw_config, mock_state):
    from worthless.openclaw.integration import LockPlan, build_lock_plan

    original_bytes = openclaw_config.read_bytes()

    plan = build_lock_plan(mock_state, PLANNED, proxy_base_url=PROXY_URL)

    assert isinstance(plan, LockPlan)
    assert plan.config_state == "present"
    assert "worthless-openai" in plan.providers_to_add
    assert openclaw_config.read_bytes() == original_bytes, "build_lock_plan must not write"


# ---------------------------------------------------------------------------
# AC5  build_lock_plan on unreadable config → config_state="unreadable", no writes
# ---------------------------------------------------------------------------


def test_ac5_build_lock_plan_unreadable_config_state(openclaw_config, mock_state):
    from worthless.openclaw.integration import build_lock_plan

    original_bytes = openclaw_config.read_bytes()

    real_st = openclaw_config.stat()
    mock_st = MagicMock()
    mock_st.st_uid = os.geteuid() + 1
    mock_st.st_mode = real_st.st_mode

    with patch("os.stat", return_value=mock_st):
        plan = build_lock_plan(mock_state, PLANNED, proxy_base_url=PROXY_URL)

    assert plan.config_state == "unreadable"
    assert openclaw_config.read_bytes() == original_bytes


# ---------------------------------------------------------------------------
# AC6  post-flight (mid-loop) failure → original_config snapshot exposed
# ---------------------------------------------------------------------------


def test_ac6_result_exposes_original_config_snapshot(openclaw_config, mock_state):
    """apply_lock result carries original_config_snapshot for caller-side rollback."""
    original_data = json.loads(openclaw_config.read_text())

    with patch.object(_integration, "detect", return_value=mock_state):
        result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert hasattr(result, "original_config_snapshot"), (
        "OpenclawApplyResult must expose original_config_snapshot"
    )
    assert result.original_config_snapshot == original_data


# ---------------------------------------------------------------------------
# AC6b rollback_config restores byte-identical content
# ---------------------------------------------------------------------------


def test_ac6b_rollback_config_restores_exactly(openclaw_config, mock_state):
    from worthless.openclaw.integration import rollback_config

    original_data = json.loads(openclaw_config.read_text())

    with patch.object(_integration, "detect", return_value=mock_state):
        result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    # Providers were written; now rollback
    rollback_config(result.config_path, result.original_config_snapshot)

    restored = json.loads(openclaw_config.read_text())
    assert restored == original_data, "rollback must restore pre-mutation state"
    assert "worthless-openai" not in restored["models"]["providers"], (
        "new provider must be gone after rollback"
    )


# ---------------------------------------------------------------------------
# AC7  re-lock exits 0
# ---------------------------------------------------------------------------


def test_ac7_relock_is_idempotent(openclaw_config, mock_state):
    with patch.object(_integration, "detect", return_value=mock_state):
        r1 = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)
        assert not r1.has_failure
        r2 = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)
        assert not r2.has_failure


# ---------------------------------------------------------------------------
# AC8  build_lock_plan and apply_lock share same config_state classification
# ---------------------------------------------------------------------------


def test_ac8_plan_shape_same_for_dry_run_and_live(openclaw_config, mock_state):
    from worthless.openclaw.integration import LockPlan, build_lock_plan

    plan = build_lock_plan(mock_state, PLANNED, proxy_base_url=PROXY_URL)

    assert isinstance(plan, LockPlan)
    for field in (
        "config_state",
        "providers_to_add",
        "providers_to_skip",
        "skill_to_install",
        "config_path",
        "original_config",
    ):
        assert hasattr(plan, field), f"LockPlan missing field: {field}"


# ---------------------------------------------------------------------------
# AC9  worthless doctor mentions .bak / recovery
# ---------------------------------------------------------------------------


def test_ac9_doctor_mentions_bak_recovery(capsys, monkeypatch, tmp_path):
    """_check_openclaw_section surfaces .bak recovery path when issues are found.

    Tests the text-mode doctor path directly — no fernet key or daemon needed.
    Patches detect() and _check_skill so the section fires, then checks that
    the .bak recovery hint appears in stdout.
    """
    import worthless.cli.commands.doctor as _doctor_mod
    from worthless.cli.commands.doctor import _check_openclaw_section

    fake_state = IntegrationState(
        present=True,
        config_path=None,
        workspace_path=None,
        skill_path=None,
        home_dir=tmp_path,
        notes=(),
    )
    monkeypatch.setattr(_doctor_mod._oc_integration, "detect", lambda: fake_state)
    monkeypatch.setattr(
        _doctor_mod,
        "_check_skill",
        lambda state, *, fix, dry_run: (["openclaw-skill-not-installed"], []),
    )
    monkeypatch.setattr(
        _doctor_mod,
        "_check_providers",
        lambda state, healthy, *, port: [],
    )

    _check_openclaw_section([], fix=False, dry_run=False, repo=None)

    captured = capsys.readouterr()
    output = captured.out.lower()
    assert ".bak" in output or "backup" in output or "recover" in output, (
        "doctor text-mode must mention .bak recovery path when issues found"
    )


# ===========================================================================
# ADVERSARIAL TESTS
# ===========================================================================


# A1  TOCTOU: file deleted between classify and write → graceful, not crash
def test_a1_toctou_file_deleted_mid_transaction(oc_dir, mock_state):
    cfg = oc_dir / "openclaw.json"
    cfg.write_text(json.dumps(MINIMAL_CONFIG))

    state = IntegrationState(
        present=True,
        config_path=cfg,
        workspace_path=None,
        skill_path=None,
        home_dir=oc_dir.parent,
        notes=(),
    )

    call_count = [0]
    original_set_provider = _config.set_provider

    def delete_then_call(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            cfg.unlink()
        return original_set_provider(*args, **kwargs)

    with patch.object(_integration, "detect", return_value=state):
        with patch.object(_config, "set_provider", side_effect=delete_then_call):
            # Must not raise unhandled exception — either succeeds (recreate) or has_failure
            _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)
            # FileNotFoundError must not escape apply_lock


# A2  TOCTOU: symlink planted between classify and write → refused, target not overwritten
def test_a2_toctou_symlink_injected_between_classify_and_write(oc_dir, tmp_path):
    cfg = oc_dir / "openclaw.json"
    cfg.write_text(json.dumps(MINIMAL_CONFIG))
    target = tmp_path / "innocent.txt"
    target.write_text("must not be overwritten")

    state = IntegrationState(
        present=True,
        config_path=cfg,
        workspace_path=None,
        skill_path=None,
        home_dir=oc_dir.parent,
        notes=(),
    )

    from worthless.openclaw.integration import _classify_config_state

    calls = [0]
    original_classify = _classify_config_state

    def plant_symlink_then_classify(path):
        result = original_classify(path)
        calls[0] += 1
        if calls[0] == 1 and path == cfg:
            cfg.unlink()
            cfg.symlink_to(target)
        return result

    with patch.object(_integration, "detect", return_value=state):
        with patch.object(
            _integration, "_classify_config_state", side_effect=plant_symlink_then_classify
        ):
            result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert result.has_failure, "symlink injection must produce has_failure=True"
    assert target.read_text() == "must not be overwritten", "symlink target must not be overwritten"


# A3  Rollback write fails (disk full) → error surfaced, original error not swallowed
def test_a3_rollback_write_failure_surfaces_both_errors(openclaw_config, mock_state):
    from worthless.openclaw.integration import rollback_config

    with patch.object(_integration, "detect", return_value=mock_state):
        result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    with patch("os.replace", side_effect=OSError("No space left on device")):
        with pytest.raises(OSError) as exc_info:
            rollback_config(result.config_path, result.original_config_snapshot)

    err = str(exc_info.value).lower()
    assert "space" in err or "rollback" in err or "replace" in err, (
        "rollback failure message must name the cause"
    )


# A4  Existing WOR-515 TOCTOU test is present and passes as xfail (verify, don't implement)
def test_a4_wor515_toctou_test_exists():
    audit_gate_path = Path(__file__).parent / "test_lock_audit_gate.py"
    assert audit_gate_path.exists(), "WOR-515 audit gate test file must exist"
    content = audit_gate_path.read_text().lower()
    assert "toctou" in content or "post_flight" in content or "postflight" in content, (
        "WOR-515 must have a TOCTOU / post-flight test"
    )


# A5  WORTHLESS_OPENCLAW_CONFIG_SHARED="" (falsy) → falls back to UID check, not "unreadable"
def test_a5_empty_shared_env_is_falsy(openclaw_config):
    from worthless.openclaw.integration import _classify_config_state

    real_st = openclaw_config.stat()
    mock_st = MagicMock()
    mock_st.st_uid = os.geteuid()  # same UID → "present"
    mock_st.st_mode = real_st.st_mode

    with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": ""}):
        with patch("os.stat", return_value=mock_st):
            state = _classify_config_state(openclaw_config)

    assert state == "present", "empty string env var must not trigger 'unreadable'"


# A6  Gate fires at integration layer, not just CLI — direct apply_lock call
def test_a6_gate_fires_at_integration_layer_not_only_cli(openclaw_config, mock_state):
    from worthless.openclaw.errors import OpenclawConfigUnreadableError

    real_st = openclaw_config.stat()
    mock_st = MagicMock()
    mock_st.st_uid = os.geteuid() + 1  # UID mismatch
    mock_st.st_mode = real_st.st_mode

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch("os.stat", return_value=mock_st):
            with pytest.raises(OpenclawConfigUnreadableError) as exc_info:
                _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    msg = str(exc_info.value).lower()
    assert "openclaw user" in msg or "worthless_openclaw_config_shared" in msg, (
        "error message must guide the user toward the fix"
    )


# A7  Unicode provider names round-trip byte-identical through _atomic_write_json
def test_a7_unicode_provider_names_roundtrip(tmp_path):
    cfg = tmp_path / "openclaw.json"
    unicode_config = {
        "models": {
            "providers": {
                "provider-中文-é": {
                    "api": "openai-completions",
                    "apiKey": "sk-unicode-test",
                    "baseUrl": "https://api.example.com/v1",
                    "models": [],
                }
            }
        }
    }
    _config._atomic_write_json(cfg, unicode_config)
    restored = json.loads(cfg.read_bytes().decode("utf-8"))
    assert restored == unicode_config

    # Second round-trip must still be byte-identical
    _config._atomic_write_json(cfg, restored)
    assert json.loads(cfg.read_bytes().decode("utf-8")) == unicode_config


# A8  set_provider raises mid-loop → rollback restores pre-mutation state (not partial)
def test_a8_partial_write_rolled_back_to_original(openclaw_config, mock_state):
    planned_two = [
        ("openai", "openai-aaa", "tok"),
        ("anthropic", "anthropic-bbb", "tok"),
    ]
    original_data = json.loads(openclaw_config.read_text())

    call_count = [0]
    original_sp = _config.set_provider

    def fail_on_second(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] >= 2:
            raise OSError("simulated disk full on second provider")
        return original_sp(*args, **kwargs)

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.object(_config, "set_provider", side_effect=fail_on_second):
            result = _integration.apply_lock(planned_two, proxy_base_url=PROXY_URL)

    assert result.has_failure, "mid-loop failure must set has_failure"

    # Config must be rolled back — not partial state with only openai written
    current = json.loads(openclaw_config.read_text())
    assert current == original_data, "partial write must be rolled back to pre-mutation state"


# A9  build_lock_plan produces JSON-serialisable plan with required fields
def test_a9_lock_plan_to_json_has_required_fields(openclaw_config, mock_state):
    from worthless.openclaw.integration import build_lock_plan

    plan = build_lock_plan(mock_state, PLANNED, proxy_base_url=PROXY_URL)

    plan_dict = plan.to_dict()
    serialized = json.dumps(plan_dict)  # must not raise
    parsed = json.loads(serialized)

    assert "providers_to_add" in parsed
    assert "config_state" in parsed
    assert parsed["config_state"] in ("missing", "unreadable", "present")


# A10  UID mismatch detected without PermissionError (positive-signal test)
def test_a10_uid_mismatch_triggers_unreadable_without_permission_error(openclaw_config):
    from worthless.openclaw.integration import _classify_config_state

    real_st = openclaw_config.stat()

    class _FakeStat:
        st_uid = os.geteuid() + 999  # definitely different
        st_mode = real_st.st_mode

    # os.access would return True (file is readable), but UID differs → "unreadable"
    with patch("os.stat", return_value=_FakeStat()):
        with patch("os.access", return_value=True):  # readable by process!
            state = _classify_config_state(openclaw_config)

    assert state == "unreadable", (
        "UID mismatch must trigger 'unreadable' even when os.access returns True"
    )


# ---------------------------------------------------------------------------
# SP3  OpenclawConfigUnreadableError message names the root cause
# ---------------------------------------------------------------------------


def test_sp3_unreadable_error_message_names_uid_cause(openclaw_config, mock_state):
    """SP3: the error message surfaced to the user must be actionable.

    The message must reference the root cause (uid / different user / docker
    topology) so the user knows how to fix it, not just that something failed.
    Verified by probe-uid-gate.py at runtime; this test keeps it green through
    future refactors of the error string.
    """
    from worthless.openclaw.errors import OpenclawConfigUnreadableError

    real_st = openclaw_config.stat()

    class _FakeStat:
        st_uid = os.geteuid() + 999
        st_mode = real_st.st_mode

    with (
        patch("os.stat", return_value=_FakeStat()),
        patch("os.access", return_value=True),
        patch.object(_integration, "detect", return_value=mock_state),
    ):
        with pytest.raises(OpenclawConfigUnreadableError) as exc_info:
            _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    msg = str(exc_info.value).lower()
    assert any(kw in msg for kw in ("uid", "different user", "docker", "owner")), (
        f"error message must name the cause — got: {exc_info.value!r}"
    )


# ---------------------------------------------------------------------------
# SP5  rollback_config({}) — fresh-install case must not write {} to disk
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# SP-UL  apply_unlock symmetric UID guard
# ---------------------------------------------------------------------------


def test_sp_ul_apply_unlock_skips_gracefully_on_uid_mismatch(openclaw_config, mock_state):
    """apply_unlock must skip provider removal (not raise) when openclaw.json
    is owned by a different UID — symmetric with apply_lock's guard.

    apply_lock raises OpenclawConfigUnreadableError (hard abort, user-facing).
    apply_unlock must NOT raise (unlock-core contract: L1/L2 say failures here
    never cause unlock to fail) — instead it surfaces a CONFIG_UNREADABLE event
    and skips Stage A, leaving the config untouched.
    """
    from worthless.openclaw.errors import OpenclawErrorCode

    real_st = openclaw_config.stat()
    sha_before = hashlib.sha256(openclaw_config.read_bytes()).hexdigest()

    class _FakeStat:
        st_uid = os.geteuid() + 999
        st_mode = real_st.st_mode

    aliases = [("openai", "worthless-openai"), ("anthropic", "worthless-anthropic")]

    with (
        patch("os.stat", return_value=_FakeStat()),
        patch("os.access", return_value=True),
        patch.object(_integration, "detect", return_value=mock_state),
    ):
        result = _integration.apply_unlock(aliases)

    # Must not raise — unlock-core L1/L2 contract
    sha_after = hashlib.sha256(openclaw_config.read_bytes()).hexdigest()
    assert sha_before == sha_after, (
        "apply_unlock must not touch openclaw.json when config is unreadable"
    )
    assert result.has_failure, "UID mismatch must set has_failure on the result"
    event_codes = [e.code for e in result.events]
    assert OpenclawErrorCode.CONFIG_UNREADABLE in event_codes, (
        f"expected CONFIG_UNREADABLE event, got: {event_codes}"
    )
    assert all(reason == "config_unreadable" for _, reason in result.providers_skipped), (
        "all providers must be skipped with reason='config_unreadable'"
    )
    assert all(
        key == f"worthless-{p}" for (key, _), (p, _) in zip(result.providers_skipped, aliases)
    ), "providers_skipped keys must use 'worthless-<provider>' format, not the alias"


def test_sp5_rollback_noop_when_original_was_absent(tmp_path):
    """SP5 (regression): rollback_config(path, None) must NOT write {} to disk.

    None is the sentinel for 'file was absent before this lock attempt'.
    On write failure the rollback must clean up any partial file, not create
    a new {} file.

    Before the WOR-516 fix, _atomic_write_json was called unconditionally,
    leaving an empty-dict file where no config should exist — corrupting a
    fresh OpenClaw install on next daemon start.
    """
    from worthless.openclaw.integration import rollback_config

    absent_path = tmp_path / ".openclaw" / "openclaw.json"
    absent_path.parent.mkdir()

    # Case A: file was never created — rollback must not create it.
    assert not absent_path.exists()
    rollback_config(absent_path, None)
    assert not absent_path.exists(), (
        "rollback_config(None) must not create a file when original was absent"
    )

    # Case B: a partial file was written before the failure — rollback must remove it.
    absent_path.write_text('{"models": {"providers": {"partial-entry": {}}}}')
    assert absent_path.exists()
    rollback_config(absent_path, None)
    assert not absent_path.exists(), (
        "rollback_config(None) must delete any partial file created during the failed lock"
    )


# Stage C (.bak residue hygiene) tests removed — deferred to WOR-599.
# Leave .bak alone until the daemon's crash-recovery semantics are understood.


# ---------------------------------------------------------------------------
# Fix 1: rollback_config sentinel — {} vs None
# These tests MUST FAIL before the fix (RED phase).
# ---------------------------------------------------------------------------


def test_fix1_rollback_restores_empty_config_file(tmp_path):
    """rollback_config must RESTORE a file whose original content was {}.

    Bug: `if not original_config:` treats {} (real empty file) the same as
    None (file was absent) and deletes the file.  After the fix (None sentinel),
    passing {} restores the file; only None means "delete".

    RED: fails on current code because rollback_config({}) unlinks the file.
    """
    from worthless.openclaw.integration import rollback_config

    config_path = tmp_path / "openclaw.json"
    config_path.write_text("{}")  # file existed with content {}

    rollback_config(config_path, {})  # original was {}

    assert config_path.exists(), (
        "rollback_config({}) must restore the file, not delete it — "
        "{} is a valid original config, not the absent-file sentinel"
    )
    import json

    assert json.loads(config_path.read_text()) == {}, "restored content must be {}"


def test_fix1_rollback_deletes_when_original_was_none(tmp_path):
    """rollback_config(path, None) must delete any partial file.

    After the fix, None is the explicit sentinel for 'file was absent before
    this lock attempt'.  A partial file written during the failed attempt must
    be cleaned up.

    RED: fails on current code because None is not yet the sentinel — the
    function signature only accepts dict, so this documents the new contract.
    """
    from worthless.openclaw.integration import rollback_config

    config_path = tmp_path / "openclaw.json"
    config_path.write_text('{"partial": true}')  # partial write from failed lock

    rollback_config(config_path, None)  # original was absent

    assert not config_path.exists(), (
        "rollback_config(None) must delete the partial file written during the failed attempt"
    )


# ---------------------------------------------------------------------------
# Exit code 87 for CONFIG_UNREADABLE (infra block — never attempted)
# ---------------------------------------------------------------------------


def test_config_unreadable_produces_exit_87_not_73():
    """_apply_openclaw must return 87 when apply_lock emits CONFIG_UNREADABLE.

    CONFIG_UNREADABLE is the Docker UID-mismatch case: worthless cannot read
    openclaw.json because it is owned by a different UID (daemon vs proxy
    container). The integration was never attempted — this is an infra block,
    not a partial failure.

    Exit 73 = "tried, partial fail" (lock-core committed, OpenClaw failed mid-way).
    Exit 87 = "infra blocked, never attempted" (gate fired before any write).

    RED: fails on current code which returns True (bool) instead of 87 (int).
    """
    from worthless.cli.commands import lock as _lock_mod  # noqa: PLC0415
    from worthless.openclaw.errors import OpenclawErrorCode  # noqa: PLC0415

    fake_event = MagicMock()
    fake_event.code = OpenclawErrorCode.CONFIG_UNREADABLE
    fake_event.level = "error"
    fake_event.detail = "chmod 000 uid-mismatch test"

    fake_result = MagicMock()
    fake_result.detected = True
    fake_result.has_failure = True
    fake_result.providers_skipped = []
    fake_result.events = [fake_event]
    fake_result.providers_set = []
    fake_result.skill_installed = False

    console = MagicMock()
    home = MagicMock()

    with (
        patch.object(_lock_mod._openclaw_integration, "apply_lock", return_value=fake_result),
        patch.object(_lock_mod, "_write_lock_sentinel"),
    ):
        exit_code = _lock_mod._apply_openclaw([], console, quiet=True, home=home)

    assert exit_code == 87, (
        f"CONFIG_UNREADABLE is infra-blocked (never attempted) → must return 87, "
        f"got {exit_code!r}. 73 = tried/partial; 87 = infra blocked."
    )


def test_fix2_apply_lock_aborts_when_read_config_raises_oserror(openclaw_config, mock_state):
    """apply_lock must abort with CONFIG_UNREADABLE when read_config raises OSError.

    Bug: except Exception catches any read failure and silently sets
    original_config={}, allowing the lock to proceed without a valid snapshot.
    If a mid-write failure then triggers rollback_config({}, path), the entire
    config is deleted.

    After the fix: non-FileNotFoundError exceptions from read_config must surface
    a CONFIG_UNREADABLE event and abort Stage A (no writes).

    RED: fails on current code because apply_lock proceeds and writes providers.
    """
    from worthless.openclaw.errors import OpenclawErrorCode

    original_bytes = openclaw_config.read_bytes()

    with (
        patch.object(_integration, "detect", return_value=mock_state),
        patch.object(_integration._config_mod, "read_config", side_effect=OSError("NFS hiccup")),
    ):
        result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert openclaw_config.read_bytes() == original_bytes, (
        "apply_lock must not write when read_config raises OSError"
    )
    event_codes = [e.code for e in result.events]
    assert OpenclawErrorCode.CONFIG_UNREADABLE in event_codes, (
        "apply_lock must emit CONFIG_UNREADABLE when read_config raises"
    )

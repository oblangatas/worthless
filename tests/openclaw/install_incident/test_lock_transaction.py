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
    # WOR-621 F1: lock rewrites the provider's ORIGINAL id (``openai``).
    assert "openai" in result.providers_set

    written = _config.read_config(openclaw_config)
    providers = written["models"]["providers"]
    assert "openai" in providers, "new provider missing"
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
# AC3-shared  WOR-510 live run: deploy/docker-compose.yml sets
#   WORTHLESS_OPENCLAW_CONFIG_SHARED=1 and the proxy image always creates
#   openclaw.json, so refusing on the flag means the all-container
#   deployment can never lock. A READABLE shared config must be wired with
#   existing providers preserved; an UNREADABLE one must still abort.
# ---------------------------------------------------------------------------


def test_ac3_shared_env_readable_config_is_wired(openclaw_config, mock_state):
    other_uid = openclaw_config.stat().st_uid + 1

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            with patch("os.geteuid", return_value=other_uid):
                result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert not result.has_failure
    providers = _config.read_config(openclaw_config)["models"]["providers"]
    assert "openai" in providers
    assert (
        providers["existing-provider"] == MINIMAL_CONFIG["models"]["providers"]["existing-provider"]
    ), "existing provider must be preserved exactly"
    assert openclaw_config.stat().st_mode & 0o777 == 0o664, (
        "shared volume: the other container must be able to read the result"
    )


def test_ac3_shared_env_leaves_tree_group_usable(openclaw_config, mock_state):
    """WOR-510 live run: lock (run as root via `docker compose exec`) created
    root-owned 0755 dirs under the shared volume, so the openclaw container
    (node, in the volume's group) crashed with EACCES on agents/main/sessions."""
    oc_dir = openclaw_config.parent
    sub = oc_dir / "agents" / "main" / "agent"
    sub.mkdir(parents=True, mode=0o755)
    (sub / "models.json").write_text("{}")
    (sub / "models.json").chmod(0o600)

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    for p in [oc_dir / "agents", oc_dir / "agents" / "main", sub]:
        assert p.stat().st_mode & 0o070 == 0o070, f"{p} must be group rwx"
    assert (sub / "models.json").stat().st_mode & 0o060 == 0o060, "group must read+write"
    for p in [sub, sub / "models.json", openclaw_config]:
        assert p.stat().st_mode & 0o002 == 0, f"{p} must never become world-writable"


def test_ac3_shared_tree_never_follows_symlinks_out(openclaw_config, mock_state, tmp_path):
    """The openclaw container can write the shared volume; a planted symlink
    must not make lock (root in the proxy container) loosen a file outside it
    — e.g. the proxy's own /data key material."""
    secret = tmp_path / "outside-secret"
    secret.write_text("shard-b")
    secret.chmod(0o600)
    (openclaw_config.parent / "evil").symlink_to(secret)
    (openclaw_config.parent / "evil-dir").symlink_to(tmp_path)

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert secret.stat().st_mode & 0o777 == 0o600, "symlink target outside must be untouched"


def test_share_fd_as_root_reowns_to_volume_owner(tmp_path):
    """Root path (the real compose case): re-own to the volume dir's uid:gid,
    re-read the mode after chown, then add group rw."""
    f = tmp_path / "root-created.json"
    f.write_text("{}")
    f.chmod(0o600)
    st = f.stat()
    volume_owner = (st.st_uid + 1, st.st_gid + 1)

    fd = os.open(f, os.O_RDONLY)
    try:
        with patch("os.fchown") as fchown:
            _integration._share_fd(fd, volume_owner, is_root=True)
    finally:
        os.close(fd)

    fchown.assert_called_once()
    assert fchown.call_args.args[1:] == volume_owner
    assert f.stat().st_mode & 0o777 == 0o660


def test_share_tree_ignores_missing_or_non_dir_root(tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_text("x")
    f.chmod(0o600)
    with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
        _integration._share_openclaw_tree(tmp_path / "missing")
        _integration._share_openclaw_tree(f)
        _integration._share_openclaw_tree(None)
    assert f.stat().st_mode & 0o777 == 0o600


def test_integration_imports_without_posix_only_os_attrs():
    """Windows smoke regression: O_NOFOLLOW / O_NONBLOCK / fwalk don't exist
    there, so nothing in the module may touch them at import time. Runs in a
    subprocess so stripping ``os`` can't leak into other tests."""
    import subprocess
    import sys

    code = (
        "import os\n"
        "for a in ('O_NOFOLLOW', 'O_NONBLOCK', 'fwalk'):\n"
        "    if hasattr(os, a): delattr(os, a)\n"
        "os.environ['WORTHLESS_OPENCLAW_CONFIG_SHARED'] = '1'\n"
        "from pathlib import Path\n"
        "import worthless.openclaw.integration as m\n"
        "m._share_openclaw_tree(Path('.'))\n"
        "print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a 000 file")
def test_shared_unlock_never_clobbers_unreadable_config(openclaw_config, mock_state):
    """Cursor review: CONFIG_SHARED no longer gates unlock, and Stage A reads
    with permission_as_missing=True — an unreadable config must be skipped."""
    restores = [
        _integration.OcRestore(
            provider="existing-provider",
            alias="existing-provider-deadbeef",
            oc_original_api_key_json=None,
            plaintext_key=None,
        )
    ]
    openclaw_config.chmod(0o000)
    try:
        with patch.object(_integration, "detect", return_value=mock_state):
            with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
                result = _integration.apply_unlock(restores, remove_skill=False)
    finally:
        openclaw_config.chmod(0o600)

    assert json.loads(openclaw_config.read_text()) == MINIMAL_CONFIG, "file must be untouched"
    assert ("existing-provider", "config_unreadable") in result.providers_skipped


def _escaped_workspace_state(openclaw_config, tmp_path):
    """openclaw container plants workspace -> somewhere outside the volume;
    detect() resolves it (what the real detect does)."""
    outside = tmp_path / "proxy-data"
    (outside / "skills" / "worthless").mkdir(parents=True)
    (outside / "skills" / "worthless" / "keep").write_text("proxy secret")
    (openclaw_config.parent / "workspace").symlink_to(outside)
    state = IntegrationState(
        present=True,
        config_path=openclaw_config,
        workspace_path=outside.resolve(),
        skill_path=None,
        home_dir=openclaw_config.parent.parent,
        notes=(),
    )
    return state, outside


def test_shared_lock_refuses_skill_install_through_workspace_symlink(openclaw_config, tmp_path):
    state, outside = _escaped_workspace_state(openclaw_config, tmp_path)
    with patch.object(_integration, "detect", return_value=state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert not result.skill_installed
    assert (outside / "skills" / "worthless" / "keep").read_text() == "proxy secret"
    assert not (outside / "skills" / "worthless" / "SKILL.md").exists()


def test_shared_unlock_refuses_skill_removal_through_workspace_symlink(openclaw_config, tmp_path):
    state, outside = _escaped_workspace_state(openclaw_config, tmp_path)
    with patch.object(_integration, "detect", return_value=state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            _integration.apply_unlock([], remove_skill=True)

    assert (outside / "skills" / "worthless" / "keep").exists(), "rmtree must not escape"


def test_share_tree_is_best_effort(tmp_path):
    """A walk or per-entry OSError (vanished file, EPERM) must never raise."""
    (tmp_path / "f").write_text("x")
    with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
        with patch.object(_integration, "_share_fd", side_effect=PermissionError):
            _integration._share_openclaw_tree(tmp_path)
        with patch("os.fwalk", side_effect=OSError("gone")):
            _integration._share_openclaw_tree(tmp_path)


def test_share_on_exit_never_masks_the_result(openclaw_config, mock_state):
    """The tree normalisation runs in ``finally`` — its own failure must not
    replace lock's real result."""
    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            with patch.object(
                _integration, "_share_openclaw_tree", side_effect=RuntimeError("walk blew up")
            ):
                result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert not result.has_failure


def test_ac3_no_shared_env_leaves_tree_permissions_alone(openclaw_config, mock_state):
    sub = openclaw_config.parent / "agents" / "main"
    sub.mkdir(parents=True, mode=0o700)

    with patch.object(_integration, "detect", return_value=mock_state):
        _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert sub.stat().st_mode & 0o777 == 0o700, "host installs keep their own permissions"


def test_ac3_shared_unlock_leaves_tree_group_usable(openclaw_config, mock_state):
    """Unlock runs as root in the proxy container too; OpenClaw must still start after it."""
    sub = openclaw_config.parent / "agents" / "main"
    sub.mkdir(parents=True, mode=0o700)

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            _integration.apply_unlock([], remove_skill=False)

    assert sub.stat().st_mode & 0o070 == 0o070, "group must keep rwx after unlock"


def test_ac3_shared_tree_strips_setuid(openclaw_config, mock_state):
    """Security review: the walk must never leave a setuid/setgid file in a
    volume another container writes."""
    planted = openclaw_config.parent / "planted"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o6755)
    if planted.stat().st_mode & 0o6000 != 0o6000:
        pytest.skip("filesystem refuses setuid bits for this user")

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert planted.stat().st_mode & 0o6000 == 0, "setuid/setgid must be stripped"


def test_ac3_shared_tree_shared_even_when_lock_raises(openclaw_config, mock_state):
    """Security review: a lock that raises mid-way must not leave the tree
    unusable for OpenClaw (crash-loop on EACCES)."""
    sub = openclaw_config.parent / "agents" / "main"
    sub.mkdir(parents=True, mode=0o700)

    with patch.object(_integration, "detect", return_value=mock_state):
        with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": "1"}):
            with patch.object(
                _integration, "_classify_config_state", side_effect=RuntimeError("boom")
            ):
                with pytest.raises(RuntimeError):
                    _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)

    assert sub.stat().st_mode & 0o070 == 0o070, "tree must be shared on the error path too"


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a 000 file")
@pytest.mark.parametrize("shared", ["1", ""])
def test_ac3b_unreadable_config_is_never_clobbered(openclaw_config, mock_state, shared):
    """WOR-516 case (c) protection must survive the shared-flag fix: an
    unreadable config is never treated as empty and overwritten."""
    from worthless.openclaw.errors import OpenclawConfigUnreadableError

    openclaw_config.chmod(0o000)
    try:
        with patch.object(_integration, "detect", return_value=mock_state):
            with patch.dict(os.environ, {"WORTHLESS_OPENCLAW_CONFIG_SHARED": shared}):
                try:
                    result = _integration.apply_lock(PLANNED, proxy_base_url=PROXY_URL)
                except OpenclawConfigUnreadableError:
                    result = None
    finally:
        openclaw_config.chmod(0o600)

    assert result is None or result.has_failure, "lock must report the unreadable config"
    assert json.loads(openclaw_config.read_text()) == MINIMAL_CONFIG, "file must be untouched"


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

    # WOR-621 F2 contract change: apply_unlock takes list[OcRestore], not
    # a list of (provider, alias) tuples. The UID-mismatch guard fires
    # BEFORE iterating restores, so the rollback payload is never consumed
    # — what matters here is that ``apply_unlock`` accepts the new shape
    # and surfaces CONFIG_UNREADABLE for each provider's ``r.provider``.
    restores = [
        _integration.OcRestore(
            provider=p,
            alias=f"{p}-deadbeef",
            oc_original_api_key_json=None,
            plaintext_key=None,
        )
        for p in ("openai", "anthropic")
    ]

    with (
        patch("os.stat", return_value=_FakeStat()),
        patch("os.access", return_value=True),
        patch.object(_integration, "detect", return_value=mock_state),
    ):
        result = _integration.apply_unlock(restores)

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
    # F1 contract change: providers_skipped keys are bare provider names
    # (the entry F1 rewrites in place) — no longer the ``worthless-<provider>``
    # decoy alias.
    assert [key for key, _ in result.providers_skipped] == ["openai", "anthropic"], (
        f"providers_skipped keys must be bare provider names; got "
        f"{[k for k, _ in result.providers_skipped]!r}"
    )


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

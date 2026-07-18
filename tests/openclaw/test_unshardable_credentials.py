"""WOR-797 — ``lock`` is honest about credentials it cannot shard.

Worthless shards a static API key. But most credentials OpenClaw actually
caches for the CLI-based providers it wraps (Claude Code, Codex, Gemini,
MiniMax) are OAuth refresh tokens, and OpenClaw's own ``auth-profiles.json``
can hold ``oauth``/``token`` entries too — none of these are a static key,
so none can be routed through the split-the-key proxy. A refresh-token leak
fully compromises the account regardless of ``lock``.

One test per surface (8), plus two integration tests: ``lock`` prints the
honest warning, and ``doctor --fix`` clears a detected surface end to end.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.openclaw import unshardable_credentials as uc

from tests.helpers import fake_openai_key

runner = CliRunner()


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME — every surface here resolves relative to the OS home dir,
    never ``WORTHLESS_HOME`` (a different, unrelated config root).
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    return home


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _find_surface(findings: list[uc.UnshardableCredentialFinding], surface_id: str):
    matches = [f for f in findings if f.surface_id == surface_id]
    assert matches, (
        f"no finding for surface {surface_id!r} among {[f.surface_id for f in findings]}"
    )
    return matches[0]


# ---------------------------------------------------------------------------
# Surface 1 — OS keychain "Claude Code-credentials"
# ---------------------------------------------------------------------------


def test_surface1_claude_cli_keychain(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Presence/clear go through the `security` CLI via subprocess (not
    # Worthless's internal ctypes keychain bindings, which are only built
    # and exercised against Worthless's own service string) — mock at the
    # function level rather than mocking subprocess argv construction.
    monkeypatch.setattr(
        uc, "_keychain_service_present", lambda service: service == uc.CLAUDE_CLI_KEYCHAIN_SERVICE
    )
    cleared_services: list[str] = []
    monkeypatch.setattr(
        uc, "_clear_keychain_service", lambda service: cleared_services.append(service) or True
    )

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "claude_cli_keychain")
    assert finding.clear_kind == "keychain"
    assert not finding.needs_vertex_reauth_notice

    assert uc.clear_unshardable_credential(finding)
    assert cleared_services == [uc.CLAUDE_CLI_KEYCHAIN_SERVICE]


# ---------------------------------------------------------------------------
# Surface 2 — ~/.claude/.credentials.json
# ---------------------------------------------------------------------------


def test_surface2_claude_cli_credentials_file(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    creds_path = sandboxed_home / ".claude" / ".credentials.json"
    _write_json(creds_path, {"type": "oauth", "access": "fake", "refresh": "fake"})

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "claude_cli_file")
    assert finding.clear_kind == "file"
    assert finding.location == str(creds_path)

    assert uc.clear_unshardable_credential(finding)
    assert not creds_path.exists()
    # Idempotent — clearing an already-gone file is still a "success".
    assert uc.clear_unshardable_credential(finding)


# ---------------------------------------------------------------------------
# Surface 3 — codex ~/.codex/auth.json + its own keychain entry
# ---------------------------------------------------------------------------


def test_surface3_codex_cli_auth_file_and_keychain(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth_path = sandboxed_home / ".codex" / "auth.json"
    _write_json(auth_path, {"tokens": {"access_token": "fake", "refresh_token": "fake"}})

    monkeypatch.setattr(
        uc, "_keychain_service_present", lambda service: service == uc.CODEX_CLI_KEYCHAIN_SERVICE
    )
    cleared_services: list[str] = []
    monkeypatch.setattr(
        uc, "_clear_keychain_service", lambda service: cleared_services.append(service) or True
    )

    findings = uc.detect_unshardable_credentials()
    file_finding = _find_surface(findings, "codex_cli_file")
    keychain_finding = _find_surface(findings, "codex_cli_keychain")
    assert file_finding.clear_kind == "file"
    assert keychain_finding.clear_kind == "keychain"

    assert uc.clear_unshardable_credential(file_finding)
    assert uc.clear_unshardable_credential(keychain_finding)

    assert not auth_path.exists()
    assert cleared_services == [uc.CODEX_CLI_KEYCHAIN_SERVICE]


# ---------------------------------------------------------------------------
# Surface 4 — gemini ~/.gemini/oauth_creds.json
# ---------------------------------------------------------------------------


def test_surface4_gemini_cli_oauth_file(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    creds_path = sandboxed_home / ".gemini" / "oauth_creds.json"
    _write_json(creds_path, {"access_token": "fake", "refresh_token": "fake"})

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "gemini_cli_file")
    assert finding.clear_kind == "file"

    assert uc.clear_unshardable_credential(finding)
    assert not creds_path.exists()


# ---------------------------------------------------------------------------
# Surface 5 — minimax ~/.minimax/oauth_creds.json (needs-guard: pattern-
# consistent with 1-4 but not independently body-verified — test it first)
# ---------------------------------------------------------------------------


def test_surface5_minimax_cli_oauth_file(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    creds_path = sandboxed_home / ".minimax" / "oauth_creds.json"
    _write_json(creds_path, {"access_token": "fake", "refresh_token": "fake"})

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "minimax_cli_file")
    assert finding.clear_kind == "file"

    assert uc.clear_unshardable_credential(finding)
    assert not creds_path.exists()


# ---------------------------------------------------------------------------
# Surface 6/7 — OpenClaw's OWN auth-profiles.json, type: oauth / type: token.
# Companion negative: a type: api_key entry in the SAME file must never be
# flagged (only api_key is routed through the shard proxy).
# ---------------------------------------------------------------------------


def test_surface6_auth_profiles_oauth_type(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    auth_profiles_path = (
        sandboxed_home / ".openclaw" / "agents" / "main" / "agent" / "auth-profiles.json"
    )
    _write_json(
        auth_profiles_path,
        {
            "profiles": {
                "main-anthropic-oauth": {
                    "type": "oauth",
                    "provider": "anthropic",
                    "access": "fake",
                    "refresh": "fake",
                },
                "main-openai-key": {
                    "type": "api_key",
                    "provider": "openai",
                    "key": fake_openai_key(),
                },
            }
        },
    )

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "auth_profile_oauth")
    assert finding.clear_kind == "auth_profile_entries"
    assert "main-anthropic-oauth" in finding.location
    # Negative: the api_key entry must never be classified as unshardable.
    assert not any("main-openai-key" in f.location for f in findings)

    assert uc.clear_unshardable_credential(finding)
    remaining = json.loads(auth_profiles_path.read_text())["profiles"]
    assert "main-anthropic-oauth" not in remaining
    assert "main-openai-key" in remaining, "clearing one entry must not touch an unrelated one"


def test_surface7_auth_profiles_token_type(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    auth_profiles_path = (
        sandboxed_home / ".openclaw" / "agents" / "main" / "agent" / "auth-profiles.json"
    )
    _write_json(
        auth_profiles_path,
        {
            "profiles": {
                "main-anthropic-token": {
                    "type": "token",
                    "provider": "anthropic",
                    "token": "fake",
                },
            }
        },
    )

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "auth_profile_token")
    assert finding.clear_kind == "auth_profile_entries"

    assert uc.clear_unshardable_credential(finding)
    remaining = json.loads(auth_profiles_path.read_text())["profiles"]
    assert "main-anthropic-token" not in remaining


# ---------------------------------------------------------------------------
# Surface 8 — Vertex ADC. The one surface with no in-app re-login flow —
# its clear path must carry the explicit gcloud remediation.
# ---------------------------------------------------------------------------


def test_surface8_vertex_adc_needs_reauth_notice(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    adc_path = sandboxed_home / ".config" / "gcloud" / "application_default_credentials.json"
    _write_json(
        adc_path,
        {"type": "authorized_user", "client_id": "fake", "refresh_token": "fake"},
    )

    findings = uc.detect_unshardable_credentials()
    finding = _find_surface(findings, "vertex_adc")
    assert finding.clear_kind == "file"
    assert finding.needs_vertex_reauth_notice, (
        "Vertex is the one surface with no in-app re-login flow — its clear "
        "path must flag the need for an explicit gcloud remediation message"
    )

    assert uc.clear_unshardable_credential(finding)
    assert not adc_path.exists()


# ---------------------------------------------------------------------------
# Integration — lock prints the honest warning; doctor --fix clears one.
# ---------------------------------------------------------------------------


def test_lock_prints_warning_when_unshardable_credential_present(
    home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from worthless.openclaw import unshardable_credentials as uc_mod

    monkeypatch.setattr(uc_mod, "_keychain_service_present", lambda service: False)
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_json(
        tmp_path / ".gemini" / "oauth_creds.json",
        {"access_token": "fake", "refresh_token": "fake"},
    )
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    assert "cannot protect" in result.output.lower() or "cannot protect" in result.stderr.lower()
    assert "worthless doctor --fix" in result.output or "worthless doctor --fix" in result.stderr


def test_lock_warns_about_oauth_credentials_when_no_shardable_keys_exist(
    home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gap 1 (WOR-797): a pure-OAuth user with ZERO shardable API keys must
    STILL be warned about the unshardable credentials on disk. The warning used
    to be gated inside lock's has-keys branch, so this exact user — the one the
    feature exists for — heard only "No unprotected API keys found." and nothing
    about their live OAuth logins. Fails on the pre-fix code (RED).
    """
    from worthless.openclaw import unshardable_credentials as uc_mod

    monkeypatch.setattr(uc_mod, "_keychain_service_present", lambda service: False)
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_json(
        tmp_path / ".gemini" / "oauth_creds.json",
        {"access_token": "fake", "refresh_token": "fake"},
    )
    # A .env with NO API key: nothing to shard, so lock takes its
    # "No unprotected API keys found." branch — the branch that stayed silent.
    env_file = tmp_path / ".env"
    env_file.write_text("PORT=8000\n")

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == 0, result.output
    out = result.output.lower()  # CliRunner mixes stderr into output
    # The no-keys message must still appear — the fix must not break that path.
    assert "no unprotected api keys found" in out
    # THE FIX: the OAuth warning now fires on the zero-shardable-keys path too.
    assert "cannot protect" in out
    assert "worthless doctor --fix" in result.output


def test_doctor_fix_clears_unshardable_credential_via_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uc, "_keychain_service_present", lambda service: False)
    monkeypatch.setenv("HOME", str(tmp_path))
    fake_home = ensure_home(tmp_path / ".worthless")
    # Pre-ack the one-time AS-IS notice (WOR-488) — irrelevant to this test,
    # and its stderr write can otherwise land ahead of the JSON payload
    # depending on how --json/--yes resolve as global vs. doctor-local
    # flags; sidestep that entirely rather than depend on the resolution.
    fake_home.warranty_notice_marker.touch()
    creds_path = tmp_path / ".gemini" / "oauth_creds.json"
    _write_json(creds_path, {"access_token": "fake", "refresh_token": "fake"})

    from worthless.cli.commands.doctor import runner as runner_module

    monkeypatch.setattr(runner_module, "get_home", lambda: fake_home)
    result = runner.invoke(
        app,
        ["doctor", "--fix", "--yes", "--json"],
        env={"WORTHLESS_HOME": str(fake_home.base_dir)},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    check = next(c for c in payload["checks"] if c["check_id"] == "unshardable_credentials")
    assert any(f["surface_id"] == "gemini_cli_file" for f in check["fixed"])
    assert not creds_path.exists()


# ---------------------------------------------------------------------------
# Security-review follow-ups: a 0-finding scan must never read as "verified
# clean" when part of the scan genuinely couldn't run, and clearing a
# leaf credential file must refuse a symlink rather than silently declare
# victory while the real token lives on at the link's target.
# ---------------------------------------------------------------------------


def test_clear_file_refuses_symlink_instead_of_declaring_false_victory(
    sandboxed_home: Path, tmp_path: Path
) -> None:
    """If a leaf credential file (e.g. ~/.claude/.credentials.json) is
    ITSELF a symlink, unlinking it only removes the link — the real
    credential at the target survives untouched. Clearing must refuse
    (report not-cleared) rather than report success on a token that's
    still fully live.
    """
    decoy_target = tmp_path / "decoy-real-token.json"
    decoy_target.write_text('{"access_token": "still-live"}\n', encoding="utf-8")

    creds_path = sandboxed_home / ".claude" / ".credentials.json"
    creds_path.parent.mkdir(parents=True)
    creds_path.symlink_to(decoy_target)

    finding = uc.UnshardableCredentialFinding(
        surface_id="claude_cli_file",
        description="Claude Code CLI OAuth credentials file",
        location=str(creds_path),
        clear_kind="file",
    )
    cleared = uc.clear_unshardable_credential(finding)

    assert cleared is False, "clearing a symlinked credential file must not report success"
    assert creds_path.is_symlink(), "the symlink itself should be left alone, not removed"
    assert decoy_target.read_text() == '{"access_token": "still-live"}\n', (
        "the real credential at the symlink's target must be untouched"
    )


def test_detection_caveats_flags_keychain_surfaces_unverifiable_on_non_darwin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 0-finding scan on a non-macOS host must not imply the keychain
    surfaces (Claude Code, Codex) were checked and came back clean — they
    were never checked at all.
    """
    monkeypatch.setattr(uc.sys, "platform", "linux")
    caveats = uc.detection_caveats()
    assert caveats, "non-darwin must surface a caveat about unverifiable keychain surfaces"
    assert "keychain" in caveats[0].lower()
    assert "macos" in caveats[0].lower()


def test_doctor_summary_includes_caveat_note_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The doctor check's summary text carries the caveat forward — a
    clean scan must read as 'clean, with a coverage gap', never as a
    plain, unqualified 'all clear'.
    """
    from worthless.cli.commands.doctor.checks import unshardable_credentials as check_mod
    from worthless.storage.repository import ShardRepository

    monkeypatch.setattr(check_mod, "detect_unshardable_credentials", lambda: [])
    monkeypatch.setattr(check_mod, "detection_caveats", lambda: ["keychain surfaces unchecked"])

    fake_home = ensure_home(tmp_path / ".worthless")
    ctx = check_mod.CheckContext(
        home=fake_home,
        repo=ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key)),
        fix=False,
        dry_run=False,
    )
    result = check_mod.run(ctx)
    assert "keychain surfaces unchecked" in result["summary"]

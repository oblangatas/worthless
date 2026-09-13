"""WOR-797 — enumerate credential surfaces ``lock`` cannot shard.

Worthless shards a metered API key behind the local proxy. But most
credentials OpenClaw actually caches are OAuth refresh tokens: the CLI-based
providers it wraps (Claude Code, Codex, Gemini, MiniMax) each cache their own
OAuth login, and OpenClaw's own ``auth-profiles.json`` can hold
``type: "oauth"``/``type: "token"`` entries too. None of these are a static
API key — none can be routed through the split-the-key proxy. A refresh-token
leak fully compromises the account regardless of ``lock``.

This module enumerates all 8 such surfaces, classifies each as unshardable,
and clears one on request (best-effort — a missing/unreadable surface is not
an error). Source-verified against real OpenClaw v2026.5.3-1
(``src/agents/cli-credentials.ts``, ``extensions/google/vertex-adc.ts``,
2026-07-02): every CLI-credential reader already fails soft on a missing
keychain item or file (returns ``None``, no crash — OpenClaw's own
"re-authenticate this provider" messaging takes over). Vertex ADC is the one
exception: it *throws* on a missing credentials file rather than returning
``None`` (caught one level up as a normal per-request failure, not a process
crash, but with no in-app re-login flow) — so only Vertex's clear path prints
an explicit remediation command.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from worthless.openclaw import config as _config_mod
from worthless.openclaw.integration import _agent_auth_store_dirs, _openclaw_state_dir

logger = logging.getLogger(__name__)

CLAUDE_CLI_KEYCHAIN_SERVICE = "Claude Code-credentials"
CODEX_CLI_KEYCHAIN_SERVICE = "Codex Auth"

VERTEX_REAUTH_COMMAND = "gcloud auth application-default login"

# Matches real OpenClaw's own `timeout: 5000` convention for keychain reads
# (cli-credentials.ts).
_KEYCHAIN_TIMEOUT_S = 5

# Absolute path — a bare "security" would resolve via $PATH, which a
# hostile PATH entry could hijack (ruff S607).
_SECURITY_BIN = "/usr/bin/security"


@dataclass(frozen=True)
class UnshardableCredentialFinding:
    """One detected credential surface ``lock`` cannot protect.

    ``location`` is a human-readable path/keychain descriptor for display
    only — never the secret material itself. ``clear_kind`` tells
    :func:`clear_unshardable_credential` which strategy to use.
    """

    surface_id: str
    description: str
    location: str
    clear_kind: str  # "file" | "keychain" | "auth_profile_entries"
    needs_vertex_reauth_notice: bool = False


class KeychainProbe(Enum):
    """Outcome of a keychain presence check (WOR-835).

    PRESENT
        ``security`` answered: the credential is in the keychain.
    ABSENT
        ``security`` answered: it is not. Also non-macOS, where there is no
        keychain to hold it — a definite answer, not a gap.

        Measured limit: exit 44 is NOT exclusive to "no such item". A missing
        or corrupt keychain file returns 44 with byte-identical stderr, so an
        unopenable keychain is indistinguishable from an empty one and lands
        here rather than in UNKNOWN. Nothing in the exit code or stderr can
        separate them; closing that gap needs a different probe, not a
        different threshold. See WOR-835 follow-ups.
    UNKNOWN
        The question was never answered: the binary is missing, the probe
        timed out, or it exited for a reason other than "not found".

    A plain ``bool`` cannot separate ABSENT from UNKNOWN, and collapsing them
    is precisely the false all-clear this module exists to prevent. The
    members are deliberately checked with ``is``, never truthiness — every enum
    member is truthy, so ``if probe:`` would silently treat ABSENT as PRESENT.
    A plain ``Enum`` rather than ``(str, Enum)``: nothing serialises this, and
    the mixin would let ``probe == "absent"`` quietly succeed.
    """

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


# errSecItemNotFound. The only non-zero exit treated as an answer rather than
# a failure to look — mirrors the same constant in _clear_keychain_service.
# It is the sole OSStatus in -25400..-25200 truncating to 44, but `security`
# also returns it for a keychain it could not open, so 44 means "no item
# visible", NOT "no item exists". Verified by measurement, not assumed.
_ERR_SEC_ITEM_NOT_FOUND = 44


def _keychain_probe(service: str, caveats: list[str] | None) -> KeychainProbe:
    """Best-effort presence check via the ``security`` CLI binary.

    Matches real OpenClaw's own detection mechanism exactly
    (``execSync("security find-generic-password -s ... -w")`` in
    cli-credentials.ts) — shelling out to the CLI, NOT Worthless's internal
    ``ctypes`` keychain bindings (``keystore_macos``). Those bindings are
    built and exercised only against Worthless's own service string; a raw
    ctypes call against an arbitrary THIRD-PARTY service name hit an
    unexercised code path during development and crashed the whole
    process with an uncatchable Objective-C exception (a Python
    ``try/except`` cannot catch a native-level abort). A subprocess crash,
    by contrast, only fails this one check.

    WOR-835: this used to return a bare ``bool``, so a missing binary, a
    timeout, or any unexpected exit code read exactly like an empty keychain
    and the surface was reported clean without ever being inspected. Same rule
    as :func:`_probe_is_file` — "we couldn't look" must never be reported as
    "it isn't there" — but expressed in the return type, because unlike a file
    probe there are three distinguishable outcomes.

    ``caveats`` is required, not defaulted, for the same reason as
    :func:`_probe_is_file`: a call site that forgets it silently discards the
    UNKNOWN signal and re-creates this bug.

    Only exit 44 counts as a genuine "not there". Treating every non-zero exit
    as UNKNOWN would caveat every clean Mac on every run, which is the
    false-caveat inverse of the bug and would train users to ignore caveats.
    """
    if sys.platform != "darwin":
        return KeychainProbe.ABSENT
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input  # nosec B603
            [_SECURITY_BIN, "find-generic-password", "-s", service],
            capture_output=True,
            timeout=_KEYCHAIN_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("could not probe keychain service %s: %s", service, exc)
        _append_keychain_caveat(service, caveats, _describe_probe_failure(exc))
        return KeychainProbe.UNKNOWN

    if result.returncode == 0:
        return KeychainProbe.PRESENT
    if result.returncode == _ERR_SEC_ITEM_NOT_FOUND:
        return KeychainProbe.ABSENT

    logger.warning(
        "keychain probe for %s exited %d — treating as unknown", service, result.returncode
    )
    _append_keychain_caveat(service, caveats, f"security exited {result.returncode}")
    return KeychainProbe.UNKNOWN


def _describe_probe_failure(exc: Exception) -> str:
    """A short, non-secret reason for a caveat line."""
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timed out after {_KEYCHAIN_TIMEOUT_S}s"
    if isinstance(exc, FileNotFoundError):
        return f"{_SECURITY_BIN} not found"
    return getattr(exc, "strerror", None) or exc.__class__.__name__


def _add_caveat(caveats: list[str] | None, text: str) -> None:
    """Record a caveat once, preserving first-seen order.

    Several probes run per scan and their caveat text is deliberately
    surface-shaped, not path-shaped — naming the file would leak a home
    directory into terminal output. That makes repeats genuinely identical:
    six agent dirs with an unreadable auth-profiles.json produced the same
    sentence six times, 600+ characters of it joined into one NOTE, carrying
    no more information than one copy. A wall of repeated text reads as a
    broken tool and trains people to skip the line — which defeats the point
    of emitting it. Dedupe here rather than at each render site, so every
    consumer benefits and no caller has to remember.
    """
    if caveats is not None and text not in caveats:
        caveats.append(text)


def _append_keychain_caveat(service: str, caveats: list[str] | None, reason: str) -> None:
    """Record an unanswered keychain probe, naming the service but no secret.

    Same wording as the file-surface caveats ("could not be checked") so the
    doctor output reads consistently regardless of which probe fell short.
    """
    _add_caveat(caveats, f"macOS keychain service {service!r} could not be checked ({reason})")


def _clear_keychain_service(service: str) -> bool:
    """Best-effort delete via the ``security`` CLI. Returns True if cleared
    or already absent (idempotent) — never raises.
    """
    if sys.platform != "darwin":
        return True
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input  # nosec B603
            [_SECURITY_BIN, "delete-generic-password", "-s", service],
            capture_output=True,
            timeout=_KEYCHAIN_TIMEOUT_S,
            check=False,
        )
        # 0 = deleted; errSecItemNotFound (44) = already gone — idempotent.
        return result.returncode in (0, 44)
    except (OSError, subprocess.SubprocessError):
        return False


def _home_relative_path(*parts: str) -> Path:
    """A path under the real ``Path.home()`` — the CLI tools these surfaces
    belong to (Claude Code, Codex, Gemini, MiniMax, gcloud) all resolve
    their own state relative to the OS home directory, never
    ``WORTHLESS_HOME`` (that's Worthless's own, unrelated config root).
    """
    return Path.home().joinpath(*parts)


def _probe_is_file(path: Path, surface_label: str, caveats: list[str] | None) -> bool:
    """Presence probe that can never raise.

    ``Path.is_file()`` does NOT swallow ``EACCES`` — pathlib ignores only
    ENOENT/ENOTDIR/EBADF/ELOOP — so a credential directory this process
    can't traverse propagates ``PermissionError`` and takes down the whole
    scan. Treat an un-probeable surface as absent, but record a caveat:
    "we couldn't look" must never be reported as "it isn't there", which is
    exactly the false all-clear this module exists to prevent.

    The caveat names the surface, never the path — caveats surface in CLI
    output and CI logs, and a home-relative path is needless detail there
    (the full path goes to the debug log instead).
    """
    try:
        return path.is_file()
    except OSError as exc:
        logger.warning("could not probe %s at %s: %s", surface_label, path, exc)
        _add_caveat(
            caveats, f"{surface_label} could not be checked ({exc.strerror or 'unreadable'})"
        )
        return False


def _detect_claude_cli(
    findings: list[UnshardableCredentialFinding], caveats: list[str] | None = None
) -> None:
    # Surface 1 — OS keychain "Claude Code-credentials" (cli-credentials.ts:18).
    if _keychain_probe(CLAUDE_CLI_KEYCHAIN_SERVICE, caveats) is KeychainProbe.PRESENT:
        findings.append(
            UnshardableCredentialFinding(
                surface_id="claude_cli_keychain",
                description=(
                    "Claude Code CLI OAuth credentials in the macOS keychain "
                    f"(service {CLAUDE_CLI_KEYCHAIN_SERVICE!r})"
                ),
                location=f"keychain:{CLAUDE_CLI_KEYCHAIN_SERVICE}",
                clear_kind="keychain",
            )
        )

    # Surface 2 — ~/.claude/.credentials.json (cli-credentials.ts:13).
    path = _home_relative_path(".claude", ".credentials.json")
    if _probe_is_file(path, "Claude Code CLI credentials file", caveats):
        findings.append(
            UnshardableCredentialFinding(
                surface_id="claude_cli_file",
                description="Claude Code CLI OAuth credentials file",
                location=str(path),
                clear_kind="file",
            )
        )


def _detect_codex_cli(
    findings: list[UnshardableCredentialFinding], caveats: list[str] | None = None
) -> None:
    # Surface 3 — ~/.codex/auth.json + its own keychain entry.
    if _keychain_probe(CODEX_CLI_KEYCHAIN_SERVICE, caveats) is KeychainProbe.PRESENT:
        findings.append(
            UnshardableCredentialFinding(
                surface_id="codex_cli_keychain",
                description=(
                    "Codex CLI OAuth credentials in the macOS keychain "
                    f"(service {CODEX_CLI_KEYCHAIN_SERVICE!r})"
                ),
                location=f"keychain:{CODEX_CLI_KEYCHAIN_SERVICE}",
                clear_kind="keychain",
            )
        )

    path = _home_relative_path(".codex", "auth.json")
    if _probe_is_file(path, "Codex CLI credentials file", caveats):
        findings.append(
            UnshardableCredentialFinding(
                surface_id="codex_cli_file",
                description="Codex CLI OAuth credentials file",
                location=str(path),
                clear_kind="file",
            )
        )


def _detect_gemini_cli(
    findings: list[UnshardableCredentialFinding], caveats: list[str] | None = None
) -> None:
    # Surface 4 — ~/.gemini/oauth_creds.json (cli-credentials.ts:16).
    path = _home_relative_path(".gemini", "oauth_creds.json")
    if _probe_is_file(path, "Gemini CLI credentials file", caveats):
        findings.append(
            UnshardableCredentialFinding(
                surface_id="gemini_cli_file",
                description="Gemini CLI OAuth credentials file",
                location=str(path),
                clear_kind="file",
            )
        )


def _detect_minimax_cli(
    findings: list[UnshardableCredentialFinding], caveats: list[str] | None = None
) -> None:
    # Surface 5 — ~/.minimax/oauth_creds.json (cli-credentials.ts:15).
    path = _home_relative_path(".minimax", "oauth_creds.json")
    if _probe_is_file(path, "MiniMax CLI credentials file", caveats):
        findings.append(
            UnshardableCredentialFinding(
                surface_id="minimax_cli_file",
                description="MiniMax CLI OAuth credentials file",
                location=str(path),
                clear_kind="file",
            )
        )


def _detect_auth_profiles_oauth_token(
    findings: list[UnshardableCredentialFinding],
    caveats: list[str] | None = None,
) -> None:
    """Surfaces 6/7 — OpenClaw's OWN auth-profiles.json entries with
    ``type: "oauth"`` or ``type: "token"``. Only ``type: "api_key"`` entries
    are ever routed through the shard proxy (see WOR-796's
    ``_scrub_auth_profiles_json``, which already skips anything else).

    ``_openclaw_state_dir`` resolves relative to the MACHINE home
    (``Path.home()``, matching real OpenClaw's own ``$OPENCLAW_STATE_DIR``
    / ``~/.openclaw`` convention) — not Worthless's own ``WORTHLESS_HOME``,
    which is a separate, unrelated config root.
    """
    state_dir = _openclaw_state_dir(Path.home())
    config_path = state_dir / "openclaw.json"
    try:
        config = _config_mod.read_config(config_path, permission_as_missing=True)
    except Exception:  # noqa: BLE001 - SR-04 scrub; missing/corrupt config isn't fatal here
        config = None

    for agent_dir in _agent_auth_store_dirs(state_dir, config):
        auth_profiles_path = agent_dir / "auth-profiles.json"
        try:
            data = json.loads(auth_profiles_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, NotADirectoryError):
            # Genuinely absent — the common case (most installs have no auth
            # profiles at all). "Not there" is a real answer, not a coverage
            # gap, so it must NOT raise a caveat or every user would see one.
            continue
        except (OSError, ValueError) as exc:
            # Present but unreadable or half-written: skipping silently would
            # drop EVERY oauth/token profile inside it and still report "no
            # unshardable credentials found" — a false all-clear caused by a
            # file we couldn't parse. Skip it, but say so.
            logger.warning("could not read %s: %s", auth_profiles_path, exc)
            _add_caveat(
                caveats,
                "an OpenClaw auth-profiles.json could not be read — any "
                "OAuth/token profiles inside it were not checked",
            )
            continue
        profiles = data.get("profiles")
        if not isinstance(profiles, dict):
            continue
        for profile_id, cred in profiles.items():
            if not isinstance(cred, dict):
                continue
            cred_type = cred.get("type")
            if cred_type not in ("oauth", "token"):
                continue
            findings.append(
                UnshardableCredentialFinding(
                    surface_id=f"auth_profile_{cred_type}",
                    description=(
                        f"OpenClaw auth-profiles.json entry {profile_id!r} (type: {cred_type!r})"
                    ),
                    location=f"{auth_profiles_path}#{profile_id}",
                    clear_kind="auth_profile_entries",
                )
            )


def _vertex_adc_path() -> Path | None:
    """Mirrors real OpenClaw's ``resolveGoogleApplicationCredentialsPath``
    (vertex-adc.ts:39-62): explicit ``$GOOGLE_APPLICATION_CREDENTIALS`` env
    var first, else the default ADC location under the home dir.
    """
    explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if explicit:
        return Path(explicit)
    return _home_relative_path(".config", "gcloud", "application_default_credentials.json")


def _detect_vertex_adc(
    findings: list[UnshardableCredentialFinding], caveats: list[str] | None = None
) -> None:
    # Surface 8 — Vertex ADC (vertex-adc.ts:20,39-86). No static key; the
    # safety-critical throw for a MISSING file lives at
    # resolveGoogleVertexAuthorizedUserHeaders (:169-187) — caught one level
    # up as a normal per-request failure, not a process crash, but with no
    # in-app re-login flow. That's why this is the one surface whose clear
    # path needs an explicit remediation message.
    path = _vertex_adc_path()
    if path is not None and _probe_is_file(path, "Vertex AI ADC file", caveats):
        findings.append(
            UnshardableCredentialFinding(
                surface_id="vertex_adc",
                description="Google Vertex AI application-default credentials",
                location=str(path),
                clear_kind="file",
                needs_vertex_reauth_notice=True,
            )
        )


def detect_unshardable_credentials(
    caveats: list[str] | None = None,
) -> list[UnshardableCredentialFinding]:
    """Enumerate every unshardable credential surface currently present.

    All 8 surfaces resolve relative to the real OS home directory
    (``Path.home()``) — none of them depend on ``WORTHLESS_HOME``, which is
    Worthless's own, separate config root.

    Best-effort: a surface this process can't read (permission error,
    corrupt file, keychain backend unavailable) is treated as "not found"
    here, never raised — matches the read side of every surface's own
    fail-soft contract in real OpenClaw.

    Pass a list as *caveats* to collect what could NOT be inspected. A
    surface that failed to probe is reported as absent, so without this the
    caller cannot distinguish "checked, nothing there" from "couldn't look" —
    and would present the second as a clean bill of health (WOR-823).
    """
    findings: list[UnshardableCredentialFinding] = []
    _detect_claude_cli(findings, caveats)
    _detect_codex_cli(findings, caveats)
    _detect_gemini_cli(findings, caveats)
    _detect_minimax_cli(findings, caveats)
    _detect_auth_profiles_oauth_token(findings, caveats)
    _detect_vertex_adc(findings, caveats)
    return findings


def detection_caveats() -> list[str]:
    """Human-readable notes about detection coverage gaps.

    A clean scan (0 findings) must never read as "verified clean" when
    part of the scan genuinely couldn't run — the whole point of this
    feature is honesty about what ``lock`` can and can't see. Keychain
    access (surfaces 1 and 3) is macOS-only; on any other platform those
    two surfaces are silently skipped by ``_keychain_probe``,
    so callers surface this explicitly rather than let a 0-finding result
    imply they were checked and came back clean.
    """
    if sys.platform != "darwin":
        return [
            "keychain-based surfaces (Claude Code, Codex) could not be "
            "checked — keychain access is macOS-only"
        ]
    return []


def _clear_file(location: str) -> bool:
    path = Path(location)
    if path.is_symlink():
        # Unlinking would remove only the link, silently leaving the real
        # credential live at whatever it points to — the scan would then
        # report a clean clear while the token still fully exists. Refuse
        # rather than declare a false victory (matches
        # _clear_auth_profile_entries's F-CFG-15 symlink handling).
        logger.warning("refusing to clear %s — it is a symlink (F-CFG-15)", location)
        return False
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return True  # already gone — idempotent
    except OSError:
        logger.warning("could not remove %s", location)
        return False


def _clear_auth_profile_entries(location: str) -> bool:
    """*location* is ``<auth-profiles.json path>#<profile_id>`` as built by
    :func:`_detect_auth_profiles_oauth_token`. Removes just that one entry —
    matches the exact-match precision WOR-796's scrub/restore already use,
    so an unrelated profile in the same file is never touched.
    """
    # rpartition, not partition: an auth-profiles.json path may itself contain
    # a '#' (valid in POSIX paths). The profile-id separator is the LAST '#',
    # so splitting on the first would corrupt both the path and the id.
    path_str, _, profile_id = location.rpartition("#")
    path = Path(path_str)
    try:
        with _config_mod._file_lock(path):
            _config_mod._refuse_if_symlink(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            profiles = data.get("profiles")
            if not isinstance(profiles, dict) or profile_id not in profiles:
                return True  # already gone — idempotent
            del profiles[profile_id]
            _config_mod._atomic_write_json(path, data)
            return True
    except (OSError, ValueError, _config_mod.OpenclawConfigError):
        logger.warning("could not clear auth-profiles.json entry %s", location)
        return False


def clear_unshardable_credential(finding: UnshardableCredentialFinding) -> bool:
    """Best-effort clear of one detected surface. Never raises.

    Returns True if cleared (or already gone). Callers needing the Vertex
    re-auth notice should check ``finding.needs_vertex_reauth_notice`` and
    print :data:`VERTEX_REAUTH_COMMAND` themselves — this function only
    performs the removal, matching this codebase's separation of mutation
    from user-facing messaging (see ``lock.py``'s own print helpers).
    """
    if finding.clear_kind == "file":
        return _clear_file(finding.location)
    if finding.clear_kind == "keychain":
        service = finding.location.split(":", 1)[1]
        return _clear_keychain_service(service)
    if finding.clear_kind == "auth_profile_entries":
        return _clear_auth_profile_entries(finding.location)
    return False  # pragma: no cover — exhaustive over the 3 clear_kind values above

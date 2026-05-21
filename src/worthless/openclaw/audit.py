"""OpenClaw secrets audit gate for ``worthless lock`` (WOR-515 Phase 1).

Pre-flight and post-flight hooks that shell ``openclaw secrets audit --json``
before and after the lock-core write. Fail closed on plaintext findings;
exit 87 on subprocess failure; exit 73 on in-scope plaintext found.

M0 findings (2026-05-21, ghcr.io/openclaw/openclaw:2026.5.3-1):
- ``secrets audit --json`` schema: version/status/filesScanned/summary/findings
- ``configure --apply --yes`` still prompts (no non-interactive path exists)
- ``filesScanned[]`` is the authoritative file-scope list (no per-finding inScope)
- auth-profiles.json is in filesScanned but audit NEVER emits PLAINTEXT_FOUND for it;
  worthless reads it directly and applies KEY_PATTERN matching
- wl-shardA values in a properly-structured config trigger PLAINTEXT_FOUND →
  exact-name allowlist (not prefix) is required for AC 6
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from worthless.cli.key_patterns import KEY_PATTERN

# --- Constants ----------------------------------------------------------------

#: Exact provider names that worthless itself writes. NOT a prefix match —
#: a prefix would allow "worthless-evil" to bypass the gate (security crit #1).
WORTHLESS_OWN_PROVIDERS: frozenset[str] = frozenset(
    ["worthless-openai", "worthless-anthropic", "worthless-gemini"]
)

#: Finding codes that are advisory only and never block lock.
ADVISORY_CODES: frozenset[str] = frozenset(["REF_UNRESOLVED", "REF_SHADOWED", "LEGACY_RESIDUE"])

#: jsonPath values that are out of worthless scope (OpenClaw internals).
IGNORE_JSON_PATHS: frozenset[str] = frozenset(["gateway.auth.token"])

#: Minimum OpenClaw version that supports ``secrets audit --json``.
MIN_OPENCLAW_VERSION = "2026.5.3-1"

#: Default subprocess timeout in seconds.
_DEFAULT_TIMEOUT = 30.0

#: jsonPath prefix that identifies provider API key findings.
_PROVIDER_APIKEY_RE = re.compile(r"^models\.providers\.(?P<provider>[^.]+)\.apiKey$")

# --- Data classes -------------------------------------------------------------


@dataclass(frozen=True)
class AuditFinding:
    """A single finding from ``openclaw secrets audit --json``."""

    code: str
    severity: str
    file: str
    json_path: str
    message: str
    provider: str | None = None


@dataclass(frozen=True)
class AuditResult:
    """Parsed result from ``openclaw secrets audit --json``."""

    version: int
    status: str
    files_scanned: tuple[str, ...]
    plaintext_count: int
    findings: tuple[AuditFinding, ...]
    file_hashes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BlockingFinding:
    """A finding that blocks ``worthless lock`` from proceeding."""

    file: str
    json_path: str
    provider: str | None
    message: str
    source: str  # "audit" | "auth-profiles-direct"


@dataclass(frozen=True)
class AuditClassification:
    """Result of classify_findings()."""

    blocking: tuple[BlockingFinding, ...]
    advisory_count: int
    unknown_codes: tuple[str, ...]


class AuditGateError(Exception):
    """Raised when the audit subprocess fails (maps to exit 87)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- Internal helpers ---------------------------------------------------------


def _parse_audit_result(data: dict) -> AuditResult:
    findings = tuple(
        AuditFinding(
            code=f["code"],
            severity=f["severity"],
            file=f["file"],
            json_path=f["jsonPath"],
            message=f["message"],
            provider=f.get("provider"),
        )
        for f in data.get("findings", [])
    )
    return AuditResult(
        version=data["version"],
        status=data["status"],
        files_scanned=tuple(data.get("filesScanned", [])),
        plaintext_count=data.get("summary", {}).get("plaintextCount", 0),
        findings=findings,
    )


# --- Public API ---------------------------------------------------------------


def resolve_openclaw_bin(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the openclaw binary to an absolute path.

    Checks ``WORTHLESS_OPENCLAW_BIN`` env var first; falls back to
    ``shutil.which``. Raises :exc:`AuditGateError` if no absolute path
    is found — never trusts a relative PATH lookup.

    Args:
        env: environment dict to check (defaults to ``os.environ``).

    Raises:
        AuditGateError: if the binary cannot be resolved to an absolute path.
    """
    if env is None:
        env = os.environ

    bin_path = env.get("WORTHLESS_OPENCLAW_BIN")
    if bin_path is not None:
        p = Path(bin_path)
        if not p.is_absolute():
            raise AuditGateError(f"WORTHLESS_OPENCLAW_BIN={bin_path!r} is not an absolute path")
        return p

    which_result = shutil.which("openclaw")
    if which_result is None:
        raise AuditGateError(
            "openclaw binary not found — set WORTHLESS_OPENCLAW_BIN to an absolute path"
        )

    p = Path(which_result)
    if not p.is_absolute():
        raise AuditGateError(
            f"openclaw resolved to relative path {which_result!r} — "
            "set WORTHLESS_OPENCLAW_BIN to an absolute path (security crit #6)"
        )

    return p


def run_audit(
    openclaw_bin: Path,
    timeout: float = _DEFAULT_TIMEOUT,
) -> AuditResult:
    """Run ``openclaw secrets audit --json`` and return the parsed result.

    Retries once on failure before raising :exc:`AuditGateError`.
    A non-zero exit code, unparsable stdout, or timeout all raise.

    Args:
        openclaw_bin: absolute path to the openclaw binary.
        timeout: subprocess timeout in seconds.

    Raises:
        AuditGateError: on subprocess failure after one retry.
    """
    cmd = [str(openclaw_bin), "secrets", "audit", "--json"]

    def _attempt() -> AuditResult:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise AuditGateError(f"openclaw secrets audit exited {proc.returncode}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AuditGateError(f"openclaw secrets audit output is not valid JSON: {exc}") from exc
        return _parse_audit_result(data)

    last_exc: AuditGateError | subprocess.TimeoutExpired | None = None
    for _ in range(2):
        try:
            return _attempt()
        except (AuditGateError, subprocess.TimeoutExpired) as exc:
            last_exc = exc

    if isinstance(last_exc, subprocess.TimeoutExpired):
        raise AuditGateError(
            f"openclaw secrets audit timed out after {timeout}s — exit 87"
        ) from last_exc
    raise last_exc  # type: ignore[misc]  # already an AuditGateError


def snapshot_hashes(files_scanned: Sequence[str]) -> dict[str, str]:
    """SHA-256 each file in files_scanned for TOCTOU pre-filter.

    Silently skips files that cannot be read (e.g. permissions).
    """
    result: dict[str, str] = {}
    for path_str in files_scanned:
        try:
            data = Path(path_str).read_bytes()
            result[path_str] = hashlib.sha256(data).hexdigest()
        except OSError:
            pass
    return result


def check_auth_profiles_direct(
    files_scanned: Sequence[str],
) -> list[BlockingFinding]:
    """Read auth-profiles.json files directly and detect plaintext API keys.

    OpenClaw audit never emits PLAINTEXT_FOUND for auth-profiles (M0 probe 1).
    Worthless applies KEY_PATTERN matching on every string value in the file.

    Args:
        files_scanned: list of absolute paths from audit's filesScanned[].

    Returns:
        List of :class:`BlockingFinding` for each plaintext key found.
    """
    findings: list[BlockingFinding] = []

    def _walk(
        obj: object,
        file_path: str,
        out: list[BlockingFinding],
        json_path: str = "",
    ) -> None:
        if isinstance(obj, str):
            if KEY_PATTERN.search(obj):
                out.append(
                    BlockingFinding(
                        file=file_path,
                        json_path=json_path or "<root>",
                        provider=None,
                        message=f"Plaintext API key found in auth-profiles at {json_path}",
                        source="auth-profiles-direct",
                    )
                )
        elif isinstance(obj, dict):
            for k, v in obj.items():
                child = f"{json_path}.{k}" if json_path else k
                _walk(v, file_path, out, child)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, file_path, out, f"{json_path}[{i}]")

    for path_str in files_scanned:
        p = Path(path_str)
        if p.name != "auth-profiles.json":
            continue
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        _walk(data, path_str, findings)

    return findings


def classify_findings(
    result: AuditResult,
    auth_profiles_blocking: list[BlockingFinding] | None = None,
) -> AuditClassification:
    """Classify audit findings into blocking vs advisory vs unknown.

    Blocking findings:
    - PLAINTEXT_FOUND for models.providers.<X>.apiKey where X not in allowlist
    - auth-profiles findings from direct read (passed in as auth_profiles_blocking)

    Advisory findings (never block):
    - ADVISORY_CODES: REF_UNRESOLVED, REF_SHADOWED, LEGACY_RESIDUE
    - gateway.auth.token jsonPath
    - worthless-own-provider jsonPaths (WORTHLESS_OWN_PROVIDERS)

    Default-deny: unknown codes → AuditGateError (exit 87, not 73).

    Args:
        result: parsed audit result.
        auth_profiles_blocking: pre-computed auth-profiles direct-read findings.

    Returns:
        :class:`AuditClassification` with blocking, advisory_count, unknown_codes.
    """
    blocking: list[BlockingFinding] = list(auth_profiles_blocking or [])
    advisory_count = 0
    unknown_codes: list[str] = []

    for finding in result.findings:
        # Advisory codes never block
        if finding.code in ADVISORY_CODES:
            advisory_count += 1
            continue

        # Known ignored paths are advisory
        if finding.json_path in IGNORE_JSON_PATHS:
            advisory_count += 1
            continue

        if finding.code == "PLAINTEXT_FOUND":
            # File scope: only trust findings where file is in filesScanned
            if finding.file not in result.files_scanned:
                advisory_count += 1
                continue

            m = _PROVIDER_APIKEY_RE.match(finding.json_path)
            if m:
                provider = m.group("provider")
                if provider in WORTHLESS_OWN_PROVIDERS:
                    # Bootstrap paradox: worthless-own provider key is advisory
                    advisory_count += 1
                    continue
                blocking.append(
                    BlockingFinding(
                        file=finding.file,
                        json_path=finding.json_path,
                        provider=finding.provider,
                        message=finding.message,
                        source="audit",
                    )
                )
            else:
                # PLAINTEXT_FOUND for non-provider-apiKey path → advisory
                advisory_count += 1
        else:
            # Unknown finding code → default-deny posture
            unknown_codes.append(finding.code)

    return AuditClassification(
        blocking=tuple(blocking),
        advisory_count=advisory_count,
        unknown_codes=tuple(dict.fromkeys(unknown_codes)),
    )


def format_gate_error_message(
    blocking: Sequence[BlockingFinding],
) -> str:
    """Format the user-facing exit 73 error message.

    Lists ALL blocking findings (multi-provider aggregation, no short-circuit).
    Names remediation: ``openclaw secrets configure`` (no flags — requires TTY).
    Sanitises file paths and jsonPath values to prevent log injection.
    """
    lines = [
        "worthless lock aborted: plaintext API keys detected in OpenClaw configuration.",
        "",
        "Blocking findings:",
    ]
    for b in blocking:
        file_safe = sanitise_for_message(b.file)
        path_safe = sanitise_for_message(b.json_path)
        lines.append(f"  - {file_safe}: {path_safe}")

    lines.extend(
        [
            "",
            "To resolve: run `openclaw secrets configure` in your terminal",
            "to migrate keys to SecretRefs, then re-run `worthless lock`.",
        ]
    )
    return "\n".join(lines)


def sanitise_for_message(value: str) -> str:
    """Strip control characters and terminal escapes from a user-facing string."""
    return re.sub(r"[\x00-\x1f\x7f]", "", value)

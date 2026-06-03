"""OpenClaw secrets audit gate for ``worthless lock`` (WOR-515 Phase 1).

Pre-flight and post-flight hooks that shell ``openclaw secrets audit --json``
before and after the lock-core write. Fail closed on plaintext findings;
exit 87 on subprocess failure; exit 73 on in-scope plaintext found.

M0 findings (2026-05-21, ghcr.io/openclaw/openclaw:2026.5.3-1):
- ``secrets audit --json`` schema: version/status/filesScanned/summary/findings
- ``configure --apply --yes`` still prompts (no non-interactive path exists)
- ``filesScanned[]`` is the authoritative file-scope list (no per-finding inScope)
- Provider API keys live in ``agents/main/agent/models.json``, NOT in ``openclaw.json``.
  The audit jsonPath format is ``providers.<name>.apiKey`` (no ``models.`` prefix).
- ``openclaw setup`` (non-interactive) is required before audit; hand-crafted configs
  produce ``REF_UNRESOLVED at <root>`` and never emit PLAINTEXT_FOUND.
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
import stat
import subprocess  # nosec B404
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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

#: Default subprocess timeout in seconds.
_DEFAULT_TIMEOUT = 30.0

#: Total subprocess attempts for run_audit (1 initial + 1 retry on transient failure).
#: Timeouts are never retried regardless of this value.
_MAX_AUDIT_ATTEMPTS = 2

#: Maximum recursion depth for _walk in check_auth_profiles_direct.
#: OpenClaw's auth-profiles schema nests at most 4 levels; 6 gives headroom
#: while bounding CPU on adversarially deep JSON inputs.
_AUTH_PROFILES_MAX_DEPTH = 6

#: jsonPath pattern that identifies provider API key findings in models.json.
#: OpenClaw 2026.5.3-1 emits ``providers.<name>.apiKey`` (no ``models.`` prefix) —
#: confirmed by M0 probe against the real container.
_PROVIDER_APIKEY_RE = re.compile(r"^providers\.(?P<provider>[^.]+)\.apiKey$")

#: Strips ASCII control chars, C1 controls, and Unicode bidi/direction-override
#: characters from user-facing strings to prevent terminal log injection.
#: Covers: C0 (U+0000–001F), DEL (U+007F), C1 (U+0080–009F),
#: zero-width/direction marks (U+200B–200F), bidi embeddings/overrides
#: (U+202A–202E), bidi isolates (U+2066–2069), and BOM (U+FEFF).
_SANITISE_RE = re.compile(
    # Literal Unicode bidi/direction-override characters are written as \u escapes
    # here to avoid embedding bidi control chars in the source file itself
    # (Bandit B602, Semgrep bidi finding).
    "[\x00-\x1f\x7f\x80-\x9f"
    "\u200b-\u200f"  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066-\u2069"  # LRI, RLI, FSI, PDI
    "\ufeff"  # BOM
    "]"
)

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


@dataclass(frozen=True)
class BlockingFinding:
    """A finding that blocks ``worthless lock`` from proceeding."""

    file: str
    json_path: str
    provider: str | None
    message: str
    source: Literal["audit", "auth-profiles-direct"]


@dataclass(frozen=True)
class AuditClassification:
    """Result of classify_findings()."""

    blocking: tuple[BlockingFinding, ...]
    advisory_count: int
    unknown_codes: tuple[str, ...]


@dataclass
class AuditGateHandle:
    """Pre-flight state passed to post-flight for TOCTOU hash comparison.

    ``pre_hashes`` maps each scanned file path to its SHA-256 hex digest at
    pre-flight time. Post-flight re-hashes the same paths; if nothing changed
    the second ``run_audit`` subprocess is skipped entirely.
    """

    openclaw_bin: Path
    pre_hashes: dict[str, str]


class AuditGateError(Exception):
    """Raised when the audit subprocess fails (maps to exit 87)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- Internal helpers ---------------------------------------------------------


def parse_audit_result(data: dict) -> AuditResult:
    """Parse a raw ``openclaw secrets audit --json`` dict into :class:`AuditResult`.

    Maps camelCase wire fields (``jsonPath``, ``filesScanned``) to snake_case.
    Callers that receive raw JSON from the container (e.g. Docker integration
    tests) should use this rather than going through :func:`run_audit`.
    """
    try:
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
    except (KeyError, TypeError) as exc:
        raise AuditGateError(f"openclaw secrets audit output has unexpected schema: {exc}") from exc


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

    Retries once on transient failure before raising :exc:`AuditGateError`.
    Timeouts are never retried — they raise immediately.
    A non-zero exit code, unparsable stdout, or timeout all raise.

    Args:
        openclaw_bin: absolute path to the openclaw binary.
        timeout: subprocess timeout in seconds.

    Raises:
        AuditGateError: on subprocess failure after one retry, or on timeout.
    """
    cmd = [str(openclaw_bin), "secrets", "audit", "--json"]

    def _attempt() -> AuditResult:
        try:
            proc = subprocess.run(  # nosec B603 — cmd[0] validated absolute by resolve_openclaw_bin
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise AuditGateError(
                f"openclaw secrets audit timed out after {timeout}s — exit 87"
            ) from exc
        except FileNotFoundError as exc:
            raise AuditGateError(
                f"openclaw binary not found at {openclaw_bin} — set WORTHLESS_OPENCLAW_BIN"
            ) from exc
        if proc.returncode != 0:
            raise AuditGateError(f"openclaw secrets audit exited {proc.returncode}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AuditGateError(f"openclaw secrets audit output is not valid JSON: {exc}") from exc
        return parse_audit_result(data)

    last_exc: AuditGateError | None = None
    for _ in range(_MAX_AUDIT_ATTEMPTS):
        try:
            return _attempt()
        except AuditGateError as exc:
            # Timeout is already wrapped as AuditGateError but should not be retried.
            # Check the original cause to avoid 2× the wait on a hung binary.
            if isinstance(exc.__cause__, subprocess.TimeoutExpired):
                raise
            last_exc = exc

    raise last_exc  # type: ignore[misc]  # always an AuditGateError after 2 attempts


def snapshot_hashes(files_scanned: Iterable[str]) -> dict[str, str]:
    """SHA-256 each file in files_scanned for TOCTOU pre-filter.

    Files that cannot be read are recorded with sentinel ``"UNREADABLE"``
    rather than silently omitted — a file unreadable at pre-flight that becomes
    readable and modified at post-flight would otherwise produce identical dicts
    and bypass the TOCTOU guard.
    """
    result: dict[str, str] = {}
    for path_str in files_scanned:
        try:
            # Reject non-regular files (FIFOs, devices, sockets) before opening.
            # filesScanned is attacker-influenced output from the openclaw binary;
            # a rogue path pointing at /dev/zero or a FIFO with no writer would
            # block the chunked read loop forever.
            if not stat.S_ISREG(Path(path_str).stat().st_mode):
                result[path_str] = "UNREADABLE"
                continue
            # Chunked read — never load the full file into memory.
            h = hashlib.sha256()
            with open(path_str, "rb") as fh:  # noqa: PTH123
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            result[path_str] = h.hexdigest()
        except OSError:
            result[path_str] = "UNREADABLE"
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
        depth: int = 0,
    ) -> None:
        if depth > _AUTH_PROFILES_MAX_DEPTH:
            return
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
                _walk(v, file_path, out, child, depth + 1)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, file_path, out, f"{json_path}[{i}]", depth + 1)

    for path_str in files_scanned:
        p = Path(path_str)
        if p.name != "auth-profiles.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
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
    - PLAINTEXT_FOUND for providers.<X>.apiKey where X not in allowlist
    - auth-profiles findings from direct read (passed in as auth_profiles_blocking)

    Advisory findings (never block):
    - ADVISORY_CODES: REF_UNRESOLVED, REF_SHADOWED, LEGACY_RESIDUE
    - gateway.auth.token jsonPath
    - worthless-own-provider jsonPaths (WORTHLESS_OWN_PROVIDERS)

    Default-deny: unknown codes are returned in ``AuditClassification.unknown_codes``
    rather than raising here — callers (lock pre-flight, doctor check) map them
    to exit 87. This keeps classify_findings pure so doctor and lock can surface
    unknown codes differently.

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
        if finding.code in ADVISORY_CODES:
            advisory_count += 1
            continue

        if finding.json_path in IGNORE_JSON_PATHS:
            advisory_count += 1
            continue

        if finding.code == "PLAINTEXT_FOUND":
            # File scope: only trust findings where file is in filesScanned.
            # A PLAINTEXT_FOUND for a file not in filesScanned is internally
            # inconsistent audit output — OpenClaw cannot report a finding for a
            # file it did not scan. Treat as unknown (exit 87), not advisory:
            # silently passing here would allow a rogue binary to suppress a
            # real plaintext finding by omitting the file from filesScanned.
            if finding.file not in result.files_scanned:
                unknown_codes.append("PLAINTEXT_FOUND[file_not_in_filesScanned]")
                continue

            m = _PROVIDER_APIKEY_RE.match(finding.json_path)
            if m:
                provider = m.group("provider")
                if provider in WORTHLESS_OWN_PROVIDERS:
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
                advisory_count += 1
        else:
            unknown_codes.append(finding.code)

    return AuditClassification(
        blocking=tuple(blocking),
        advisory_count=advisory_count,
        unknown_codes=tuple(dict.fromkeys(unknown_codes)),
    )


def run_and_classify(
    openclaw_bin: Path,
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[AuditResult, AuditClassification]:
    """Run the audit and classify findings in one call.

    Convenience wrapper used by both pre-flight and post-flight so callers
    don't duplicate the ``run_audit → check_auth_profiles_direct →
    classify_findings`` sequence.

    Args:
        openclaw_bin: absolute path to the openclaw binary.
        timeout: subprocess timeout passed to :func:`run_audit`.

    Raises:
        AuditGateError: on subprocess failure (propagated from :func:`run_audit`).
    """
    result = run_audit(openclaw_bin, timeout=timeout)
    direct_blocking: list[BlockingFinding] = check_auth_profiles_direct(result.files_scanned)
    classification = classify_findings(result, direct_blocking)
    return result, classification


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
    return _SANITISE_RE.sub("", value)

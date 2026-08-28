"""WOR-797: enumerate credential surfaces ``lock`` cannot shard.

Worthless shards a metered API key. Most credentials OpenClaw actually
caches for CLI-based providers (Claude Code, Codex, Gemini, MiniMax) are
OAuth refresh tokens, and OpenClaw's own ``auth-profiles.json`` can hold
``oauth``/``token`` entries too — none of these are a static API key, so
none can be routed through the split-the-key proxy. This check enumerates
all 8 such surfaces (see :mod:`worthless.openclaw.unshardable_credentials`
for the full source-verified list) so the user gets an honest "the proxy
isn't load-bearing for this credential" signal instead of assuming ``lock``
already covers it, and can clear any of them via ``--fix``.

Vertex ADC is the one surface with no in-app re-login flow of its own
(real OpenClaw throws instead of returning ``null`` on a missing ADC file) —
its ``fixed`` entry carries an explicit ``gcloud auth
application-default login`` remediation string.
"""

from __future__ import annotations

from pathlib import Path

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.openclaw.unshardable_credentials import (
    VERTEX_REAUTH_COMMAND,
    clear_unshardable_credential,
    detect_unshardable_credentials,
    detection_caveats,
)

check_id = "unshardable_credentials"


def _unfixed_reason(finding) -> str:  # noqa: ANN001 - UnshardableCredentialFinding
    """Human-readable reason a clear was attempted but did not remove the
    credential — so ``--fix`` never leaves a live token silently listed.
    """
    if finding.clear_kind in ("file", "auth_profile_entries"):
        # auth_profile locations are "<path>#<profile_id>" — the path is
        # everything before the LAST '#' (see _clear_auth_profile_entries).
        path_str = (
            finding.location.rpartition("#")[0]
            if finding.clear_kind == "auth_profile_entries"
            else finding.location
        )
        try:
            if Path(path_str).is_symlink():
                return (
                    "refused — the credential is a symlink; clearing it would "
                    "unlink only the pointer and leave the real token live"
                )
        except OSError:
            pass
    return "could not remove — permission denied or I/O error (see logs)"


def _clear_finding(finding) -> tuple[str, dict]:  # noqa: ANN001 - UnshardableCredentialFinding
    """Clear one finding. Returns ``("fixed", entry)`` on success or
    ``("unfixed", entry)`` with a reason when the clear was refused/failed —
    so a partial ``--fix`` tells the user exactly what it couldn't touch.
    Extracted to keep :func:`run` under xenon's budget.
    """
    if not clear_unshardable_credential(finding):
        return "unfixed", {
            "surface_id": finding.surface_id,
            "description": finding.description,
            "reason": _unfixed_reason(finding),
        }
    entry = {"surface_id": finding.surface_id, "description": finding.description}
    if finding.needs_vertex_reauth_notice:
        entry["remediation"] = f"cleared — re-authenticate with: {VERTEX_REAUTH_COMMAND}"
    return "fixed", entry


def _summarize(n: int, caveats: list[str]) -> str:
    base = (
        "No unshardable OAuth/token credentials found."
        if n == 0
        else (
            f"{n} unshardable credential{'s' if n != 1 else ''} found (OAuth/token — "
            "the proxy is not load-bearing for these; lock cannot protect them)"
        )
    )
    # A 0-finding scan must never read as "verified clean" when part of it
    # couldn't run at all — that's the one thing that would undermine this
    # check's entire reason for existing.
    if caveats:
        base += " NOTE: " + "; ".join(caveats) + "."
    return base


def run(ctx: CheckContext) -> CheckResult:
    # WOR-823: collect surfaces that could not be inspected at all (unreadable
    # dir, unparsable auth-profiles.json). They come back as "absent", so
    # without this a scan that couldn't look would read as a clean bill of
    # health — the exact false all-clear this check exists to prevent.
    probe_caveats: list[str] = []
    findings_data = detect_unshardable_credentials(probe_caveats)
    findings = [
        {"surface_id": f.surface_id, "description": f.description, "location": f.location}
        for f in findings_data
    ]
    caveats = detection_caveats() + probe_caveats

    fixed: list[dict] = []
    unfixed: list[dict] = []
    if ctx.fix and findings_data and not ctx.dry_run:
        for f in findings_data:
            kind, entry = _clear_finding(f)
            (fixed if kind == "fixed" else unfixed).append(entry)
    status = "ok" if len(fixed) == len(findings_data) else "warn"

    summary = _summarize(len(findings_data), caveats)
    if unfixed:
        # An honesty feature must not report a partial --fix as done: name how
        # many surfaces it could NOT clear right in the summary a terminal user
        # reads, with the per-surface reason available in the structured field.
        summary += f" ({len(unfixed)} could not be cleared — see 'unfixed' for why)"

    result = CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=summary,
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )
    if unfixed:
        result["unfixed"] = unfixed
    # WOR-797 (Gap 3): expose coverage gaps as structured data, not just prose
    # buried in the summary string — a JSON consumer on Linux/WSL (the target
    # platform, where the 2 macOS-keychain surfaces can't be checked) can now
    # SEE what wasn't inspected. Advisory only: status is unchanged, so a clean
    # scan doesn't falsely fail. Omitted when empty (e.g. on macOS).
    if caveats:
        result["caveats"] = caveats
    return result

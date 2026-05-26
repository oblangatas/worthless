#!/usr/bin/env python3
"""Block `git push` / `gh pr create` when risky code lacks a fresh live round-trip.

Two modes:

  (hook)  No args. Reads a Claude Code PreToolUse JSON event on stdin. If the
          tool command publishes code (`git push` / `gh pr create`), the diff to
          be published touches risky paths, and there is no fresh live-PASS
          matching the current risky-file content, emit a deny decision.
          Otherwise allow. Stdlib-only and fast: a non-publish command returns in
          microseconds and makes zero git calls, so it is safe on the Bash
          matcher that fires for every command.

  --run   Run the real provider round-trip (`pytest -m live`) and, on success,
          write the evidence file the hook checks. This is the blessed way to
          produce evidence. The hook trusts it only via a content-hash match, and
          CI re-runs the hermetic suites from scratch regardless, so a stale or
          hand-edited file cannot fool the merge gate.

Risky paths mirror the union of the install-docker.yml and user-flows.yml CI
path filters: the product code whose breakage the hermetic suites cannot see
until a real provider round-trip exercises it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# A change under these paths can break the real round-trip in a way mocks and
# unit tests miss, so publishing it requires a fresh live-PASS.
RISKY_PATHSPECS = [
    "src/worthless/cli",
    "src/worthless/proxy",
    "src/worthless/storage",
    "src/worthless/crypto",
    "install.sh",
    "pyproject.toml",
    "uv.lock",
]

EVIDENCE_RELPATH = ".worthless/e2e-evidence.json"
BASE_REF = "origin/main"
EVIDENCE_SCHEMA = 1

# Commands whose execution means "I am publishing this code".
_PUBLISH_RE = re.compile(r"\bgit\s+push\b|\bgh\s+pr\s+create\b")


def _git(*args: str) -> str:
    """Run a git command, returning stdout (empty string on any failure)."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            ["git", *args],  # noqa: S607 — git resolved from PATH by design
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return proc.stdout


def repo_root() -> Path | None:
    top = _git("rev-parse", "--show-toplevel").strip()
    return Path(top) if top else None


def scoped_state_hash(root: Path) -> str:
    """Content identity of risky files: committed tree + uncommitted + untracked.

    Dirty and untracked risky files are folded in so stale evidence cannot pass
    once the code under test has changed — the omission that would make this gate
    decorative.
    """
    h = hashlib.sha256()
    # Committed content of risky files at HEAD (mode/type/sha/path lines).
    h.update(_git("ls-tree", "-r", "HEAD", "--", *RISKY_PATHSPECS).encode())
    h.update(b"\0")
    # Staged + unstaged changes to tracked risky files.
    h.update(_git("diff", "HEAD", "--", *RISKY_PATHSPECS).encode())
    h.update(b"\0")
    # Untracked risky files (name + bytes).
    others = _git("ls-files", "--others", "--exclude-standard", "--", *RISKY_PATHSPECS)
    for name in sorted(n for n in others.splitlines() if n):
        h.update(name.encode())
        try:
            h.update((root / name).read_bytes())
        except OSError:
            pass
        h.update(b"\0")
    return h.hexdigest()


def published_risky_files(root: Path) -> list[str]:
    """Risky files in the commits a push would publish (vs origin/main).

    When no merge-base exists (a branch sharing no history with origin/main),
    fall back conservatively to every tracked risky file so the gate still fires.
    """
    base = _git("merge-base", "HEAD", BASE_REF).strip()
    if base:
        names = _git("diff", "--name-only", f"{base}..HEAD", "--", *RISKY_PATHSPECS)
    else:
        names = _git("ls-files", "--", *RISKY_PATHSPECS)
    return [n for n in names.splitlines() if n]


def read_evidence(root: Path) -> dict | None:
    try:
        return json.loads((root / EVIDENCE_RELPATH).read_text())
    except (OSError, json.JSONDecodeError):
        return None


def write_evidence(root: Path, result: str, duration_s: float) -> Path:
    path = root / EVIDENCE_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": EVIDENCE_SCHEMA,
        "result": result,
        "tree_hash": scoped_state_hash(root),
        "head_sha": _git("rev-parse", "HEAD").strip(),
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "duration_seconds": round(duration_s, 2),
        "command": "pytest -m live",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


def run_mode() -> int:
    root = repo_root()
    if root is None:
        print("live-e2e: not inside a git repo", file=sys.stderr)
        return 1
    print("live-e2e: running real provider round-trip (pytest -m live)...", file=sys.stderr)
    start = time.monotonic()
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pytest",
            "-x",
            "-v",
            "-s",
            "-m",
            "live",
            "-o",
            "addopts=--strict-markers --timeout=120",
        ],
        cwd=root,
        check=False,
    )
    elapsed = time.monotonic() - start
    result = "PASS" if proc.returncode == 0 else "FAIL"
    path = write_evidence(root, result, elapsed)
    print(f"live-e2e: {result} in {elapsed:.1f}s -> {path}", file=sys.stderr)
    return proc.returncode


def _deny_reason(risky: list[str], evidence: dict | None) -> str:
    if evidence is None:
        why = "no live round-trip evidence found"
    elif evidence.get("result") != "PASS":
        why = f"last live round-trip result was {evidence.get('result')!r}"
    else:
        why = "code changed since the last live round-trip (evidence is stale)"
    shown = "\n".join(f"  - {f}" for f in risky[:10])
    extra = "" if len(risky) <= 10 else f"\n  ...and {len(risky) - 10} more"
    return (
        "Live end-to-end round-trip required before publishing risky changes.\n"
        f"Reason: {why}.\n"
        f"Risky files in this push:\n{shown}{extra}\n"
        "Run the real round-trip, then retry:\n"
        "  uv run python scripts/hooks/live_e2e_gate.py --run\n"
        "(runs `pytest -m live` against a real provider with your local key; "
        "writes .worthless/e2e-evidence.json on PASS)"
    )


def _emit_deny(reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )


def hook_mode() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0  # malformed event: never block on our own parse failure
    command = (event.get("tool_input") or {}).get("command", "")
    if not command or not _PUBLISH_RE.search(command):
        return 0  # not a publish action: allow, with zero git calls

    root = repo_root()
    if root is None:
        return 0
    risky = published_risky_files(root)
    if not risky:
        return 0  # nothing risky being published: allow

    evidence = read_evidence(root)
    fresh_pass = (
        evidence is not None
        and evidence.get("result") == "PASS"
        and evidence.get("tree_hash") == scoped_state_hash(root)
    )
    if fresh_pass:
        return 0

    _emit_deny(_deny_reason(risky, evidence))
    return 0


def main(argv: list[str]) -> int:
    if "--run" in argv:
        return run_mode()
    return hook_mode()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

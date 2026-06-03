#!/usr/bin/env python3
"""
probe-uid-gate.py — live proof that apply_lock() aborts on Docker UID mismatch.

What it proves
--------------
When openclaw.json is owned by a different OS user, apply_lock() raises
OpenclawConfigUnreadableError BEFORE touching the file — the config is
byte-for-byte identical before and after.

What is real vs shimmed
-----------------------
  REAL:  the openclaw.json file on disk (created by this script, not mocked)
  REAL:  os.stat() call on the actual file — real inode, real UID
  REAL:  apply_lock() production code path, all JSON parsing, rollback logic
  REAL:  OpenclawConfigUnreadableError exception raised and propagated
  SHIMMED: os.geteuid() returns file_owner_uid + 1 — simulates running as
           a different user than the one who owns the config. This is the only
           injection; everything else is the actual production code.

Why shim geteuid rather than chown?
-------------------------------------
chown to a different UID on macOS requires root (sudo). Inside Docker Desktop,
VirtioFS remaps container UIDs back to the host user — so `docker chown 999`
on a macOS-mounted volume still shows as the host UID.

Shimming os.geteuid() is equivalent from the code's perspective:
_classify_config_state() does exactly one check: `os.stat(path).st_uid != os.geteuid()`
Both sides of that comparison are exercised. The stat is real. Only the geteuid
return value is controlled to create the mismatch.

Usage
-----
    uv run python tests/openclaw/probe-uid-gate.py

Or from repo root:
    python tests/openclaw/probe-uid-gate.py
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest.mock
from pathlib import Path

# Make sure the src tree is importable when run directly
REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from worthless.openclaw.errors import OpenclawConfigUnreadableError  # noqa: E402
from worthless.openclaw.integration import apply_lock  # noqa: E402

GREEN = "\033[0;32m"
RED = "\033[0;31m"
BLUE = "\033[1;34m"
NC = "\033[0m"


def step(msg: str) -> None:
    print(f"\n{BLUE}── {msg}{NC}")


def passed(msg: str) -> None:
    print(f"   {GREEN}✓{NC}  {msg}")


def failed(msg: str) -> None:
    print(f"   {RED}✗{NC}  {msg}")
    sys.exit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        openclaw_dir = home / ".openclaw"
        openclaw_dir.mkdir()
        config_path = openclaw_dir / "openclaw.json"

        # ── 1. Create a realistic openclaw.json on disk ──────────────────────
        step("1. Create real openclaw.json on disk")
        config = {
            "version": "1",
            "providers": {
                "anthropic": {"type": "api", "apiKey": "ANTHROPIC_API_KEY", "models": {}},
                "openai": {"type": "api", "apiKey": "OPENAI_API_KEY", "models": {}},
            },
        }
        config_path.write_text(json.dumps(config, indent=2))

        real_uid = os.stat(str(config_path)).st_uid  # noqa: PTH116 — must match production os.stat patch target
        sha_before = sha256(config_path)
        print(f"   file owner UID: {real_uid} (real stat on real file)")
        print(f"   config SHA:     {sha_before}")
        passed(f"openclaw.json written at {config_path}")

        # ── 2. Confirm UID mismatch setup ────────────────────────────────────
        step("2. Shim os.geteuid() to simulate Docker runner being UID != file owner")
        fake_runner_uid = real_uid + 1
        print(f"   file owner UID:   {real_uid}")
        print(f"   shimmed runner UID: {fake_runner_uid}  (real_uid + 1)")
        print("   geteuid shim is the ONLY injection — stat() and file I/O are real")
        passed(f"UID mismatch: config={real_uid}, runner={fake_runner_uid}")

        # ── 3. Call apply_lock() with HOME pointing at our tmpdir ────────────
        step("3. Call apply_lock() — expect OpenclawConfigUnreadableError")

        planned_updates = [("anthropic", "probe-alias", "probe-auth-token")]

        raised_error: OpenclawConfigUnreadableError | None = None
        with (
            unittest.mock.patch("os.geteuid", return_value=fake_runner_uid),
            unittest.mock.patch.dict(os.environ, {"HOME": str(home)}),
        ):
            try:
                apply_lock(planned_updates, proxy_base_url="http://127.0.0.1:8787")
            except OpenclawConfigUnreadableError as exc:
                raised_error = exc

        if raised_error is None:
            failed(
                "apply_lock() did NOT raise OpenclawConfigUnreadableError — UID gate missing (bug)"
            )
        else:
            passed("OpenclawConfigUnreadableError raised — gate fired before any write")
            print(f"   message: {raised_error}")

        # ── 4. Verify openclaw.json is byte-for-byte unchanged ───────────────
        step("4. Verify openclaw.json is byte-for-byte unchanged")
        sha_after = sha256(config_path)
        print(f"   SHA before: {sha_before}")
        print(f"   SHA after:  {sha_after}")

        if sha_before == sha_after:
            passed("openclaw.json untouched — apply_lock aborted before any write")
        else:
            failed(
                "openclaw.json was MODIFIED — UID gate failed to protect the config (critical bug)"
            )

        # ── 5. Confirm error message references the cause ────────────────────
        step("5. Check error message is actionable")
        msg = str(raised_error).lower()
        if any(
            k in msg for k in ("different user", "uid", "docker", "owner", "unreadable", "shared")
        ):
            passed("error message references cause — user knows what to fix")
        else:
            print(f"   {RED}WARNING{NC}: message may not be actionable: {raised_error}")

        # ── 6. Summary ───────────────────────────────────────────────────────
        print()
        print(f"   {GREEN}{'━' * 55}{NC}")
        print(f"   {GREEN}RESULT: Docker UID gate works correctly.{NC}")
        print("   apply_lock() raises OpenclawConfigUnreadableError")
        print("   and leaves openclaw.json untouched when the config")
        print("   is owned by a different OS user.")
        print("   WOR-516 AC — live proof.")
        print(f"   {GREEN}{'━' * 55}{NC}")
        print()


if __name__ == "__main__":
    main()

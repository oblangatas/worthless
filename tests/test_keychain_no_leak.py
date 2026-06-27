"""WOR-463: prove subprocess `worthless` invocations do not pollute the host keychain.

Asserts the no-leak invariant end-to-end on real macOS:
1. Count `fernet-key-*` entries in the user's login keychain BEFORE
2. Spawn a subprocess that calls `store_fernet_key()` directly (mimics what
   `worthless lock` does on a fresh home_dir), with `WORTHLESS_KEYRING_BACKEND=null`
3. Count AFTER, assert delta == 0

Why a subprocess rather than calling `store_fernet_key` in-process: the parent
pytest sets `keyring.set_keyring(keyring.backends.null.Keyring())` in
`tests/conftest.py:31`, which already prevents in-process writes. The leak
only happens via subprocesses that load `keyring` fresh — exactly what this
test exercises.

Marked `user_flow` (opt-in) and `skipif !darwin` because:
- The `security` CLI is macOS-specific
- The leak symptom (orphaned `fernet-key-*` in macOS Keychain) was the
  motivation; on Linux/Windows the keyring backends are different and the
  parent-process null-backend convention works adequately.

Run with: `uv run pytest -m user_flow tests/test_keychain_no_leak.py`
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REQUIRES_DARWIN = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="`security` CLI and macOS Keychain are Darwin-only",
)

# Full path: macOS `security` always lives at /usr/bin/security; using a
# fully-qualified path satisfies the S607 lint and removes any PATH-shadowing
# attack surface from the test process.
_SECURITY = "/usr/bin/security"


def _count_fernet_keys() -> int:
    """Count `fernet-key-*` entries in the user's macOS login keychain."""
    proc = subprocess.run(  # noqa: S603
        [_SECURITY, "dump-keychain"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        # `security` returns non-zero if there are partial errors but still
        # produces useful output; treat as fatal only if there's no output.
        if not proc.stdout:
            raise RuntimeError(f"`security dump-keychain` failed: {proc.stderr}")
    return proc.stdout.count('"acct"<blob>="fernet-key-')


@pytest.mark.user_flow
@REQUIRES_DARWIN
def test_subprocess_with_env_var_does_not_leak_keychain_entry(tmp_path: Path) -> None:
    """Env-var-null subprocess writes zero new keychain entries.

    Pre-WOR-463 this test would have FAILED on macOS: the parent pytest's
    null-backend convention doesn't propagate, the subprocess loads keyring
    fresh, finds the macOS Keychain backend, and writes a `fernet-key-<hash>`
    entry. Multiplied by months of dev cycles, that's how the user
    accumulated 128 orphans.

    Post-WOR-463: the env var forces `keyring_available()` to False at the
    gate, before the OS keyring backend is ever consulted.
    """
    home = tmp_path / ".worthless-WOR-463-test"
    home.mkdir()

    before = _count_fernet_keys()

    # Invoke the keystore module directly in a subprocess. This mirrors what
    # an e2e test does when it spawns `worthless lock` (which calls into
    # ensure_home → store_fernet_key) but is more surgical: no proxy startup,
    # no .env scanning, just the keystore write that would leak.
    program = (
        "import sys\n"
        "from worthless.cli.keystore import store_fernet_key\n"
        "from pathlib import Path\n"
        f"store_fernet_key(b'test-key-WOR-463', home_dir=Path({str(home)!r}))\n"
        "sys.exit(0)\n"
    )
    env = {
        **os.environ,
        "WORTHLESS_KEYRING_BACKEND": "null",
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", program],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, (
        f"subprocess store_fernet_key failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    after = _count_fernet_keys()

    # Sanity: the file fallback should have written the key on disk
    # (proves the function actually ran end-to-end, not silently no-op'd).
    assert (home / "fernet.key").exists(), (
        "store_fernet_key should have written to file when env forces null backend"
    )

    # The critical invariant.
    assert after == before, (
        f"WOR-463 leak detected: keychain `fernet-key-*` count went from "
        f"{before} to {after} after a subprocess call to store_fernet_key "
        f"with WORTHLESS_KEYRING_BACKEND=null. The env-var override is "
        f"not preventing the keychain write."
    )


@pytest.mark.user_flow
@REQUIRES_DARWIN
def test_subprocess_without_env_var_would_leak_baseline(tmp_path: Path) -> None:
    """Baseline: a subprocess WITHOUT the env var DOES write to keychain.

    This proves the test machinery actually exercises the leak path —
    otherwise the previous test could trivially "pass" by exercising
    nothing. We do leak ONE entry deliberately, then immediately delete
    it so the test is self-cleaning and the radar doesn't flag it.

    If this test ever stops finding a leak even WITHOUT the env var, that
    means either:
    - The keychain backend defaults changed (good — investigate)
    - Test machinery is broken (the previous test became a no-op)
    Both warrant attention.
    """
    home = tmp_path / ".worthless-WOR-463-baseline"
    home.mkdir()

    before = _count_fernet_keys()

    program = (
        "import sys\n"
        "from worthless.cli.keystore import store_fernet_key, _keyring_username\n"
        "from pathlib import Path\n"
        f"home = Path({str(home)!r})\n"
        "store_fernet_key(b'test-key-baseline', home_dir=home)\n"
        "print(_keyring_username(home))\n"
        "sys.exit(0)\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "WORTHLESS_KEYRING_BACKEND"}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", program],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, (
        f"baseline subprocess failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    leaked_account = result.stdout.strip()

    after = _count_fernet_keys()

    # Self-cleaning: delete the leaked entry IMMEDIATELY before any assertion
    # so the test suite doesn't leave residue even on failure.
    subprocess.run(  # noqa: S603
        [_SECURITY, "delete-generic-password", "-s", "worthless", "-a", leaked_account],
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert after > before, (
        "Baseline test expected to find a NEW keychain entry (proving the "
        "leak path is real and the machinery works). If this fails, either "
        "the macOS keyring backend is no longer default, or the subprocess "
        "test path is no-op. Investigate before trusting the no-leak test."
    )

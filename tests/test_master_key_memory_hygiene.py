"""SR-02: the master Fernet key must not outlive the process that read it.

Two leaks, same parent (worthless-1ige):

  * worthless-m7n0 — ``WorthlessHome._cached_fernet_key`` is a per-invocation
    cache with no ``__del__``, no ``atexit`` hook and no explicit zero. Every
    ``lock`` / ``unlock`` / ``doctor`` / ``status`` / ``up`` handed the
    interpreter a bytearray of live master-key bytes to garbage-collect.
  * worthless-g648 — ``doctor`` zeroed its own buffer but never called
    ``repo.close()``, so ``ShardRepository._fernet_key_bytes`` (a second copy)
    survived for the rest of the process.

These assert on the BYTES, not on a call. A test that only checks "close() was
invoked" would pass against an implementation that rebinds the reference and
leaves the original allocation intact — which is precisely the bug.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from worthless.cli import bootstrap
from worthless.cli.bootstrap import (
    WorthlessHome,
    _track_home_holding_key,
    _tracked_homes_holding_key,
    _zero_cached_fernet_keys_at_exit,
)
from worthless.storage.repository import ShardRepository

# A REAL Fernet key (32 url-safe base64 bytes) — ShardRepository constructs a
# Fernet from it, so a malformed value fails in the constructor and never
# reaches the code under test. Deliberately non-zero: an all-zero key would
# make every "is it zeroed?" assertion below pass vacuously.
_KEY = base64.urlsafe_b64encode(bytes(range(1, 33)))


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give each test its own tracking list.

    The registry and the exit hook are process-global by design. Under xdist a
    worker runs many test modules, so calling the real hook here would zero the
    cached key of a WorthlessHome belonging to some unrelated test that is
    mid-run. Swap the list per test so these stay hermetic.
    """
    monkeypatch.setattr(bootstrap, "_HOMES_HOLDING_KEY", [])


def test_seeding_the_cache_registers_the_home_for_zeroing(tmp_path: Path) -> None:
    home = WorthlessHome(base_dir=tmp_path)
    assert home not in _tracked_homes_holding_key(), "a home with no key must not be tracked"

    home._seed_cached_fernet_key(_KEY)
    assert any(h is home for h in _tracked_homes_holding_key()), (
        "a home that now holds key bytes must be tracked, or the exit hook cannot find it"
    )


def test_zeroing_wipes_the_buffer_in_place(tmp_path: Path) -> None:
    """In place, not rebound — a dropped reference leaves the bytes readable."""
    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)

    buf = home._cached_fernet_key
    assert buf is not None and bytes(buf) == _KEY

    home.zero_cached_fernet_key()

    assert buf is not None, "must not rebind to None — the old buffer would survive"
    assert bytes(buf) == b"\x00" * len(_KEY), "the original allocation must be zeroed"
    assert _KEY[:8] not in bytes(buf)


def test_exit_hook_zeroes_a_live_cached_key(tmp_path: Path) -> None:
    """The atexit path is what actually fires on a normal CLI exit."""
    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)
    buf = home._cached_fernet_key
    assert buf is not None

    _zero_cached_fernet_keys_at_exit()

    assert bytes(buf) == b"\x00" * len(_KEY), (
        "the registered exit hook must wipe every tracked home's key"
    )


def test_zeroing_is_idempotent_and_safe_without_a_cache(tmp_path: Path) -> None:
    """Called on a home that never read a key, and twice on one that did."""
    WorthlessHome(base_dir=tmp_path).zero_cached_fernet_key()  # must not raise

    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)
    home.zero_cached_fernet_key()
    home.zero_cached_fernet_key()
    assert bytes(home._cached_fernet_key or b"") == b"\x00" * len(_KEY)


def test_exit_hook_survives_a_home_that_raises(tmp_path: Path) -> None:
    """Shutdown must never turn a successful command into a crash.

    One broken instance must not stop the others being wiped.
    """

    class Exploding(WorthlessHome):
        def zero_cached_fernet_key(self) -> None:
            raise RuntimeError("interpreter is already tearing down")

    bad = Exploding(base_dir=tmp_path)
    _track_home_holding_key(bad)

    good = WorthlessHome(base_dir=tmp_path)
    good._seed_cached_fernet_key(_KEY)
    buf = good._cached_fernet_key
    assert buf is not None

    _zero_cached_fernet_keys_at_exit()  # must not propagate

    assert bytes(buf) == b"\x00" * len(_KEY), "a raising peer must not block other wipes"


# --- worthless-g648 -------------------------------------------------------


def test_repository_close_zeroes_its_own_copy(tmp_path: Path) -> None:
    """The copy `doctor` was leaking: the repository's, not the caller's."""
    key = bytearray(_KEY)
    repo = ShardRepository(str(tmp_path / "w.db"), key)

    inner = repo._fernet_key_bytes
    assert inner is not None and bytes(inner) == _KEY, "repo holds its own copy"

    repo.close()

    assert bytes(inner) == b"\x00" * len(_KEY), "close() must zero the repo's copy in place"
    assert repo._fernet is None, "the Fernet instance must be released"


def test_every_repository_construction_site_is_closed() -> None:
    """Every ShardRepository(...) in the CLI must have a close() in its module.

    Replaces an earlier test that grepped for `repo.close()` near the last
    `finally:` in one file. That version was brittle (it would pass on a
    commented-out call) and, worse, it passed while the DEFAULT `doctor` path
    leaked two copies — it only ever looked at runner.py. Reviewers caught it;
    the test did not.

    Still static, because constructing a real repository needs a provisioned
    home. But it now covers every site rather than one, so a NEW leak in a new
    command fails here instead of shipping.
    """
    cli = Path(__file__).resolve().parents[1] / "src/worthless/cli"
    offenders: list[str] = []
    checked = 0

    for path in sorted(cli.rglob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        closes = any(".close()" in ln for ln in lines)

        for lineno, line in enumerate(lines, 1):
            if "ShardRepository(" not in line or "import" in line:
                continue
            # Per-SITE, not per-module: service/_common.py builds one repository
            # from PLACEHOLDER_FERNET_KEY (it only needs the DB, never decrypts)
            # while a different function in the same file touches the real key.
            # A module-level check called that a master-key leak. It is not.
            if "placeholder" in line.lower():
                continue
            checked += 1
            if not closes:
                offenders.append(
                    f"{path.relative_to(cli.parents[2])}:{lineno} builds a "
                    "ShardRepository from real key material but the module never "
                    "closes one — the repository's copy survives the command"
                )

    assert checked >= 4, (
        f"only {checked} real-key ShardRepository sites found; the glob or the "
        "layout moved and this test no longer covers what it claims"
    )
    assert not offenders, "Un-closed ShardRepository (worthless-g648):\n" + "\n".join(offenders)


def test_zero_buf_runs_before_close_in_cleanup_paths() -> None:
    """A raising close() must not leave the caller's key live.

    Ordering matters in the `finally`: zero the buffer we own first, then close.
    The reverse order means a close() failure both skips the zeroing and masks
    the original exception.
    """
    root = Path(__file__).resolve().parents[1]
    for rel in (
        "src/worthless/cli/commands/doctor/runner.py",
        "src/worthless/cli/commands/up.py",
    ):
        text = (root / rel).read_text(encoding="utf-8")
        block = text[text.rindex("finally:") :]
        # Strip comments: an explanatory comment mentioning close() would
        # otherwise be matched as the call itself (it was, first time round).
        block = "\n".join(ln.split("#", 1)[0] for ln in block.splitlines())
        if "zero_buf" not in block or "close()" not in block:
            continue
        assert block.index("zero_buf") < block.index("close()"), (
            f"{rel}: zero_buf must precede close() in the cleanup path"
        )

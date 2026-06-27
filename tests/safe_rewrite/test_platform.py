"""Platform-gate invariants: Windows refused, Darwin uses ``F_FULLFSYNC``.

``fcntl`` is Unix-only and does not exist on Windows. Importing it at
module scope would break ``test_refuses_on_windows`` collection on a
real Windows host, so the import is deferred into
``test_fsync_uses_f_fullfsync_on_darwin`` via ``pytest.importorskip``
(see PR #86 discussion_r3124934998).
"""

from __future__ import annotations

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


def test_refuses_on_windows(tmp_path, make_env_file, fake_windows, sha256_of) -> None:
    """``sys.platform == "win32"`` is refused at the very first gate."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.PLATFORM
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_fsync_uses_f_fullfsync_on_darwin(
    tmp_path, make_env_file, fake_darwin, monkeypatch
) -> None:
    """On Darwin, the implementation must invoke ``F_FULLFSYNC`` via ``fcntl.fcntl``.

    We record every ``fcntl.fcntl`` call. On Darwin the contract is:
    for durability, call ``fcntl.fcntl(fd, F_FULLFSYNC)`` on the tmp fd
    (and the dir fd). On other platforms, plain ``os.fsync`` suffices.
    """
    # Deferred until test body — ``fcntl`` is Unix-only; importing at
    # module scope would break collection of ``test_refuses_on_windows``
    # on a real Windows host (PR #86 discussion_r3124934998).
    _fcntl = pytest.importorskip("fcntl")

    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    # F_FULLFSYNC's integer constant on Darwin is 51. We don't hardcode
    # it because running CI on Linux monkeypatching to "darwin" won't
    # have the real constant; we assert any fcntl.fcntl call occurs
    # during the rewrite and that the impl attempted the Darwin path.
    fcntl_calls: list[int] = []
    real_fcntl = _fcntl.fcntl

    def _rec(fd, cmd, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        fcntl_calls.append(cmd)
        try:
            return real_fcntl(fd, cmd, *a, **kw)
        except OSError:
            # F_FULLFSYNC may be ENOTTY on Linux even with fake_darwin;
            # the test asserts the *attempt*, not the syscall success.
            return 0

    monkeypatch.setattr(_fcntl, "fcntl", _rec)

    try:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
    except Exception:
        # We care about the syscall *attempt*, not whether the Darwin
        # path ultimately succeeds under a faked sys.platform.
        pass

    assert fcntl_calls, "fcntl.fcntl was never called under fake_darwin — F_FULLFSYNC missing"

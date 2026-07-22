"""In-process unit coverage for the sidecar hardening helpers (WOR-826/831).

The leak/e2e tests in this package drive the sidecar via subprocesses, which
coverage.py can't see. These call the pure helpers directly so their branches —
the WARN paths, the excepthook fallback, the piped-core breadcrumb — are
exercised in-process and counted.
"""

from __future__ import annotations

import logging
import sys

import pytest

from worthless.cli.log_redaction import redact
from worthless.sidecar import __main__ as sidecar_main
from worthless.sidecar import _hardening

from ._sentinels import PROVIDER_TOKEN

pytestmark = pytest.mark.real_ipc


def test_redact_public_wrapper() -> None:
    assert redact(f"x {PROVIDER_TOKEN}") == "x [REDACTED]"
    assert redact("nothing here") == "nothing here"


def test_configure_logging_installs_filter_and_excepthook(monkeypatch: pytest.MonkeyPatch) -> None:
    # monkeypatch restores the real excepthook at teardown even though
    # _configure_logging reassigns it directly.
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    sidecar_main._configure_logging(logging.INFO)
    root = logging.getLogger()
    assert any(type(f).__name__ == "RedactingFilter" for h in root.handlers for f in h.filters)
    assert sys.excepthook is sidecar_main._redacting_excepthook


def test_redacting_excepthook_redacts_token(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        raise ValueError(f"boom {PROVIDER_TOKEN}")
    except ValueError as exc:
        sidecar_main._redacting_excepthook(type(exc), exc, exc.__traceback__)
    err = capsys.readouterr().err
    assert "[REDACTED]" in err
    assert PROVIDER_TOKEN not in err


def test_redacting_excepthook_fallback_when_redact_raises(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(_text: str) -> str:
        raise RuntimeError("scrubber broke")

    monkeypatch.setattr(sidecar_main, "redact", _boom)
    try:
        raise ValueError("supersecret")
    except ValueError as exc:
        sidecar_main._redacting_excepthook(type(exc), exc, exc.__traceback__)
    err = capsys.readouterr().err
    assert "traceback suppressed" in err
    assert "supersecret" not in err


def test_disable_core_dumps_sets_zero() -> None:
    import resource

    _hardening.disable_core_dumps()
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


def test_disable_core_dumps_no_resource_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_hardening, "resource", None)
    _hardening.disable_core_dumps()  # must be a no-op, not raise


def test_disable_core_dumps_warns_on_setrlimit_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class _Res:
        RLIMIT_CORE = 4

        @staticmethod
        def setrlimit(*_a: object) -> None:
            raise OSError("denied")

        @staticmethod
        def getrlimit(*_a: object) -> tuple[int, int]:
            return (0, 0)

    monkeypatch.setattr(_hardening, "resource", _Res)
    with caplog.at_level(logging.WARNING):
        _hardening.disable_core_dumps()
    assert "could not disable core dumps" in caplog.text


def test_disable_core_dumps_warns_on_readback_mismatch(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class _Res:
        RLIMIT_CORE = 4

        @staticmethod
        def setrlimit(*_a: object) -> None:
            return None

        @staticmethod
        def getrlimit(*_a: object) -> tuple[int, int]:
            return (1, 1)  # readback disagrees

    monkeypatch.setattr(_hardening, "resource", _Res)
    with caplog.at_level(logging.WARNING):
        _hardening.disable_core_dumps()
    assert "RLIMIT_CORE not" in caplog.text


def test_warn_if_core_pattern_piped(
    monkeypatch: pytest.MonkeyPatch, tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    f = tmp_path / "core_pattern"
    f.write_text("|/usr/lib/systemd/systemd-coredump\n")
    monkeypatch.setattr(_hardening, "_CORE_PATTERN_FILE", f)
    with caplog.at_level(logging.WARNING):
        _hardening.warn_if_core_pattern_piped()
    assert "core_pattern pipes cores" in caplog.text


def test_warn_if_core_pattern_not_piped_is_silent(
    monkeypatch: pytest.MonkeyPatch, tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    f = tmp_path / "core_pattern"
    f.write_text("core.%p\n")
    monkeypatch.setattr(_hardening, "_CORE_PATTERN_FILE", f)
    with caplog.at_level(logging.WARNING):
        _hardening.warn_if_core_pattern_piped()
    assert "pipes cores" not in caplog.text


def test_warn_if_core_pattern_missing_file_is_silent(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(_hardening, "_CORE_PATTERN_FILE", tmp_path / "does-not-exist")
    _hardening.warn_if_core_pattern_piped()  # OSError swallowed, no raise

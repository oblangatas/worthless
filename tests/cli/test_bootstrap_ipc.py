"""Tests for bootstrap's IPC-attestation path (WOR-465 A3b).

Pinned invariants for the WORTHLESS_FERNET_IPC_ONLY=1 path:

* ``ensure_home`` MUST attest via the sidecar (``attest`` op with
  ``purpose='bootstrap-validate'``) instead of reading ``home.fernet_key``.
* If no sidecar is reachable, ``ensure_home`` MUST raise
  ``WorthlessError(SIDECAR_NOT_READY)`` — never silently fall back to
  reading the key file or the keyring.
* When the flag is UNSET, today's behaviour is unchanged (positive control
  for the regression direction).
* Malformed evidence (wrong length / type) MUST raise rather than be
  trusted blindly — even though we cannot verify the MAC locally without
  the key, structural validation is the minimal contract.

The proxy container is the only place that sets the flag; entrypoint
starts the sidecar before any CLI invocation runs inside the container.
Bare metal never sets the flag and is therefore untouched.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.errors import ErrorCode, WorthlessError


_BOOTSTRAP_PURPOSE = "bootstrap-validate"


# ---------------------------------------------------------------------------
# Fake IPC client — drop-in for the real one. Records attest() calls so the
# tests can assert on shape (nonce, purpose) without spinning up a real
# sidecar.
# ---------------------------------------------------------------------------


class _FakeIPCClient:
    """Stand-in IPC client whose ``attest`` returns 32 bytes of fake evidence.

    Mirrors the real ``IPCClient`` async-context-manager surface so
    ``ensure_home`` can use ``async with`` against it.
    """

    def __init__(
        self,
        *,
        evidence: bytes = b"\x00" * 32,
        raise_on_attest: BaseException | None = None,
    ) -> None:
        self._evidence = evidence
        self._raise = raise_on_attest
        self.attest_calls: list[tuple[bytes, str | None]] = []

    async def __aenter__(self) -> _FakeIPCClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def attest(self, nonce: bytes, purpose: str | None = None) -> bytes:
        self.attest_calls.append((bytes(nonce), purpose))
        if self._raise is not None:
            raise self._raise
        return self._evidence


@pytest.fixture(autouse=True)
def _force_file_fallback() -> Iterator[None]:
    """Force keystore file fallback so flag-OFF regression tests stay hermetic."""
    with patch("worthless.cli.keystore.keyring_available", return_value=False):
        yield


@pytest.fixture
def flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable WORTHLESS_FERNET_IPC_ONLY=1 for the duration of the test."""
    monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")


@pytest.fixture
def fake_socket_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A non-binding sidecar socket path the test can point ensure_home at.

    The file is touched so ``socket_path.exists()`` returns True — simulating
    a running sidecar. WOR-465 A4: ensure_home skips validation when the
    socket is absent (first-boot bootstrap before start.py spawns the sidecar).
    """
    sock = tmp_path / "sidecar.sock"
    sock.touch()  # exists() → True → validation fires (happy-path tests)
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(sock))
    return sock


# ---------------------------------------------------------------------------
# Flag ON — ensure_home routes through IPC
# ---------------------------------------------------------------------------


def test_ensure_home_with_flag_attests_via_sidecar_not_fernet_key(
    flag_on: None,
    fake_socket_path: Path,
    tmp_path: Path,
) -> None:
    """When the flag is on, ensure_home MUST call ``attest`` and MUST NOT
    invoke ``home.fernet_key``.

    Pre-existing marker so the post-bootstrap branch is exercised — a
    proxy container always has the marker after first deploy.
    """
    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    fake = _FakeIPCClient(evidence=b"\xab" * 32)

    fernet_key_reads: list[None] = []

    def _record_key_read(self):
        fernet_key_reads.append(None)
        raise AssertionError(
            "home.fernet_key MUST NOT be read on the flag-on path; attest via the sidecar instead."
        )

    with (
        patch(
            "worthless.cli.bootstrap.IPCClient",
            return_value=fake,
        ),
        patch(
            "worthless.cli.bootstrap.WorthlessHome.fernet_key",
            new_callable=lambda: property(_record_key_read),
        ),
    ):
        ensure_home(base_dir=base)

    assert fernet_key_reads == [], "no home.fernet_key reads expected under flag"
    assert len(fake.attest_calls) == 1, "exactly one attest call expected"
    nonce, purpose = fake.attest_calls[0]
    assert purpose == _BOOTSTRAP_PURPOSE, (
        f"attest purpose must be {_BOOTSTRAP_PURPOSE!r}, got {purpose!r}"
    )
    assert isinstance(nonce, bytes) and len(nonce) >= 16, "attest nonce must be at least 128 bits"


def test_ensure_home_with_flag_no_sidecar_raises_WRTLS_114(
    flag_on: None,
    fake_socket_path: Path,
    tmp_path: Path,
) -> None:
    """Flag on + sidecar unreachable MUST raise SIDECAR_NOT_READY.

    Crucially: this branch MUST NOT silently fall back to reading the key
    file or the keyring — that would defeat the whole point of the flag.
    """
    from worthless.ipc.client import IPCProtocolError

    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    class _ConnectRefused:
        async def __aenter__(self):
            raise IPCProtocolError("sidecar connect refused")

        async def __aexit__(self, *_exc):
            return None

    with patch("worthless.cli.bootstrap.IPCClient", return_value=_ConnectRefused()):
        with pytest.raises(WorthlessError) as excinfo:
            ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY, (
        f"expected SIDECAR_NOT_READY (114), got {excinfo.value.code!r}"
    )


def test_ensure_home_with_flag_rejects_malformed_evidence(
    flag_on: None,
    fake_socket_path: Path,
    tmp_path: Path,
) -> None:
    """Evidence shorter than HMAC-SHA256's 32 bytes MUST be rejected.

    We cannot verify the MAC locally (the CLI uid does not hold the key
    on the flag-on proxy-container path) but structural validation is the
    minimum bar — a stub sidecar returning empty bytes must not be
    accepted as a successful attestation.
    """
    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    # 8 bytes — clearly wrong length for HMAC-SHA256.
    fake = _FakeIPCClient(evidence=b"\x00" * 8)

    with patch("worthless.cli.bootstrap.IPCClient", return_value=fake):
        with pytest.raises(WorthlessError) as excinfo:
            ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY


# ---------------------------------------------------------------------------
# Flag OFF — regression: today's behaviour must not change
# ---------------------------------------------------------------------------


def test_ensure_home_without_flag_uses_existing_keystore_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag UNSET MUST behave exactly as it did before A3b.

    No sidecar lookup, no IPC client instantiation, no SIDECAR_NOT_READY.
    The keystore cascade still runs and generates a key on first run.
    """
    monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
    base = tmp_path / ".worthless"

    instantiated: list[None] = []

    def _no_ipc(*_args, **_kwargs):
        instantiated.append(None)
        raise AssertionError(
            "IPCClient MUST NOT be instantiated when WORTHLESS_FERNET_IPC_ONLY is unset"
        )

    with patch("worthless.cli.bootstrap.IPCClient", side_effect=_no_ipc):
        home = ensure_home(base_dir=base)

    assert instantiated == [], "no IPCClient on the bare-metal path"
    assert home.fernet_key_path.exists(), "first-run must still generate a key"


def test_ensure_home_without_flag_does_not_call_attest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt-and-suspenders: flag UNSET → no attest call ever.

    Even if a future refactor accidentally imports the IPC path, this
    test pins the contract that bare metal never round-trips to a sidecar.
    """
    monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
    base = tmp_path / ".worthless"

    fake = _FakeIPCClient()
    with patch("worthless.cli.bootstrap.IPCClient", return_value=fake):
        ensure_home(base_dir=base)

    assert fake.attest_calls == [], (
        f"attest must not be called on the bare-metal path; got {fake.attest_calls!r}"
    )


# ---------------------------------------------------------------------------
# Adversarial: socket env edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bogus_length", [0, 1, 8, 16, 31, 33, 48, 64])
def test_ensure_home_with_flag_rejects_non_32_byte_evidence(
    flag_on: None,
    fake_socket_path: Path,
    tmp_path: Path,
    bogus_length: int,
) -> None:
    """Evidence of ANY length other than 32 MUST be rejected.

    Off-by-one cases (31, 33) are the most likely real failure mode if a
    backend swaps HMAC algorithms. Both must surface as SIDECAR_NOT_READY
    rather than be accepted as a valid attestation.
    """
    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    fake = _FakeIPCClient(evidence=b"\xab" * bogus_length)

    with patch("worthless.cli.bootstrap.IPCClient", return_value=fake):
        with pytest.raises(WorthlessError) as excinfo:
            ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY, (
        f"evidence length={bogus_length} must be rejected with SIDECAR_NOT_READY"
    )


def test_ensure_home_with_flag_rejects_non_bytes_evidence(
    flag_on: None,
    fake_socket_path: Path,
    tmp_path: Path,
) -> None:
    """Non-bytes evidence (str, int, None) MUST raise SIDECAR_NOT_READY.

    A bug in a future backend could plausibly return ``str`` if it
    forgets to call ``.encode()``. Type-check must catch it cleanly
    instead of crashing with AttributeError or producing a confusing
    inner exception.
    """
    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    fake = _FakeIPCClient(evidence="this-is-a-string-not-bytes")  # type: ignore[arg-type]

    with patch("worthless.cli.bootstrap.IPCClient", return_value=fake):
        with pytest.raises(WorthlessError) as excinfo:
            ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY


def test_ensure_home_with_flag_socket_is_regular_file_raises_cleanly(
    flag_on: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WORTHLESS_SIDECAR_SOCKET pointing at a regular file MUST raise
    SIDECAR_NOT_READY cleanly — not crash with a confusing inner error.

    Real misconfig: operator mounts a config file at the socket path by
    mistake. asyncio.open_unix_connection refuses to connect with ENOTSOCK
    or similar; the wrapper must surface that as our friendly error code.
    """
    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)

    bogus_socket = tmp_path / "not-a-socket.txt"
    bogus_socket.write_bytes(b"i am a regular file")
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(bogus_socket))

    # Use the REAL IPCClient — we want to exercise the connect-failure
    # path, not a mocked __aenter__. The real client should fail with
    # IPCProtocolError when opening a regular file as a UDS, which
    # _validate_via_sidecar maps to WorthlessError(SIDECAR_NOT_READY).
    with pytest.raises(WorthlessError) as excinfo:
        ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY


def test_ensure_home_post_bootstrap_missing_socket_raises_sidecar_not_ready(
    flag_on: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag on + .bootstrapped marker present + socket absent → SIDECAR_NOT_READY.

    After the first successful boot the sidecar should always be running.
    A missing socket means it crashed — fail hard with a useful error instead
    of falling through to key generation (which would attempt a direct read of
    a fernet.key the proxy uid cannot access).

    Contrast with the first-boot test below: no marker → falls through.
    This is the post-boot regression direction for the Thread 2 fix.
    """
    absent_sock = tmp_path / "nonexistent-sidecar.sock"
    assert not absent_sock.exists(), "precondition: socket must be absent"
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(absent_sock))

    base = tmp_path / ".worthless"
    base.mkdir(mode=0o700)
    (base / ".bootstrapped").touch(mode=0o600)  # simulate post-bootstrap state

    with patch("worthless.cli.bootstrap.IPCClient") as mock_ipc:
        with pytest.raises(WorthlessError) as excinfo:
            ensure_home(base_dir=base)

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY, (
        f"post-bootstrap missing socket must raise SIDECAR_NOT_READY, got {excinfo.value.code!r}"
    )
    mock_ipc.assert_not_called(), "IPCClient must not be instantiated when socket is absent"


def test_ensure_home_with_flag_no_socket_skips_validation_on_first_boot(
    flag_on: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WOR-465 A4: when the sidecar socket does not exist, ensure_home MUST
    skip IPC validation and succeed.

    Rationale: entrypoint.sh calls ``get_home()`` on first boot BEFORE
    ``start.py`` spawns the sidecar, so the socket is absent at that point.
    Failing here would make every fresh container unbootstrappable. The proxy
    hard-fails without a live sidecar (WOR-309), so the security claim is
    preserved — attestation is just deferred to the first CLI invocation after
    the sidecar is running.

    Regression direction: this test goes RED if someone reverts the
    ``socket_path.exists()`` guard back to an unconditional
    ``_validate_via_sidecar()`` call.
    """
    absent_sock = tmp_path / "nonexistent-sidecar.sock"
    assert not absent_sock.exists(), "precondition: socket must be absent"
    monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(absent_sock))

    base = tmp_path / ".worthless"

    instantiated: list[None] = []

    def _no_ipc(*_args, **_kwargs) -> None:
        instantiated.append(None)
        raise AssertionError(
            "IPCClient MUST NOT be instantiated when the sidecar socket is absent "
            "(first-boot bootstrap before start.py spawns the sidecar)."
        )

    with patch("worthless.cli.bootstrap.IPCClient", side_effect=_no_ipc):
        home = ensure_home(base_dir=base)

    assert instantiated == [], "no IPCClient call expected when socket is absent"
    assert home is not None, "ensure_home must return a home object even without the sidecar"


def test_validate_via_sidecar_with_embedded_null_path_raises_cleanly(
    tmp_path: Path,
) -> None:
    """Calling the validator with a NUL-bearing socket path MUST raise
    SIDECAR_NOT_READY — not propagate the raw ValueError.

    OS env vars cannot actually hold a NUL byte (the kernel rejects it
    at setenv) so this path is only reachable when the validator is
    invoked programmatically — e.g. a future configuration loader that
    builds the Path from a config file rather than the environment.
    Abstract-namespace AF_UNIX paths are explicitly unsupported by the
    sidecar (see ``start_sidecar``); the client side must mirror that
    refusal with our friendly error code.
    """
    from worthless.cli.bootstrap import _validate_via_sidecar

    with pytest.raises(WorthlessError) as excinfo:
        _validate_via_sidecar(Path("\x00abstract"))

    assert excinfo.value.code is ErrorCode.SIDECAR_NOT_READY

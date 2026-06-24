"""Proxy configuration from environment variables."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.keystore import read_fernet_key
from worthless.defaults import GLOBAL_CEILING_TOKENS  # noqa: F401 — re-exported for proxy consumers

#: Capabilities the proxy expects from the sidecar HELLO frame (WOR-309).
#: Caps shrinking across reconnects is fatal — see C3 in
#: ``.research/10-security-signoff.md``.
DEFAULT_SIDECAR_CAPS: frozenset[str] = frozenset({"open", "seal", "attest", "mac"})

#: IPC protocol version (msgpack envelope schema). Bump on breaking changes.
DEFAULT_SIDECAR_PROTOCOL_VERSION: int = 1

#: Default Unix Domain Socket path. Single-container deployment puts the
#: socket on a tmpfs volume shared by the proxy and sidecar uids.
DEFAULT_SIDECAR_SOCKET_PATH: str = "/run/worthless/sidecar.sock"


_PAAS_ENV_VARS: tuple[str, ...] = ("RENDER", "FLY_APP_NAME", "KUBERNETES_SERVICE_HOST")

_PRIVATE_CIDRS: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr) for cidr in _PRIVATE_CIDRS
)


class DeployMode(str, Enum):
    """Where worthless-proxy is running. Each mode pins one trust boundary.

    LOOPBACK
        Laptop / single-machine. Bind 127.0.0.1 only.
    LAN
        Docker / private network. Bind a private CIDR; trusted_proxies optional.
    PUBLIC
        PaaS (Render/Fly/etc) behind an edge. Bind 0.0.0.0; trusted_proxies REQUIRED.
        ``WORTHLESS_ALLOW_INSECURE`` is FORBIDDEN — operators must list the edge CIDR.
    """

    LOOPBACK = "loopback"
    LAN = "lan"
    PUBLIC = "public"


class ConfigError(ValueError):
    """Raised when ProxySettings.validate() finds an unsafe combination."""


def _default_db_path() -> str:
    return str(Path.home() / ".worthless" / "worthless.db")


def _env_bool(name: str) -> bool:
    """Return ``True`` when the environment variable *name* is a truthy string.

    DELIBERATELY does NOT strip — flipping ``WORTHLESS_ALLOW_INSECURE`` from
    secure to insecure on a copy-paste typo is the wrong direction. The
    IPC-only flag has a stricter parser inlined at its call site that DOES
    strip (because its fail-secure direction is the opposite — see
    ``_read_fernet_key`` below).
    """
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


def _read_deploy_mode() -> DeployMode:
    raw = os.environ.get("WORTHLESS_DEPLOY_MODE", DeployMode.LOOPBACK.value).strip().lower()
    try:
        return DeployMode(raw)
    except ValueError as exc:
        valid = ", ".join(m.value for m in DeployMode)
        raise ConfigError(
            f"WORTHLESS_DEPLOY_MODE={raw!r} is not valid. Choose one of: {valid}."
        ) from exc


def _read_trusted_proxies() -> tuple[str, ...]:
    raw = os.environ.get("WORTHLESS_TRUSTED_PROXIES", "").strip()
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _read_default_host(mode: DeployMode) -> str:
    """Pick the bind host: explicit env wins, otherwise a mode-safe default."""
    explicit = os.environ.get("WORTHLESS_HOST", "").strip()
    if explicit:
        return explicit
    if mode in (DeployMode.PUBLIC, DeployMode.LAN):
        return "0.0.0.0"  # noqa: S104  # nosec B104 — lan/public modes bind all ifaces by design
    return "127.0.0.1"


def resolve_bind_host() -> str:
    """Return the uvicorn bind host for the current deploy mode + env overrides.

    Public entry-point so ``cli.process`` can populate ``WORTHLESS_HOST`` in
    the subprocess env dict without calling private helpers cross-module.
    """
    return _read_default_host(_read_deploy_mode())


def _read_fernet_key() -> bytearray:
    """Read Fernet key: fd (secure pipe) -> keystore (env/keyring/file).

    WOR-465 A3b 3/3: under ``WORTHLESS_FERNET_IPC_ONLY=1`` this returns
    an empty bytearray WITHOUT ever calling ``read_fernet_key``. The
    proxy uid then never holds key material in memory; every crypto
    op routes through the sidecar over IPC instead.
    """
    if fernet_ipc_only_enabled():
        # WOR-465 invariant: proxy uid MUST NOT touch the keystore on
        # the flag-on path. Returning empty here is the contract — the
        # sidecar holds the key, the proxy delegates over IPC.
        return bytearray()

    fd_str = os.environ.get("WORTHLESS_FERNET_FD")
    if fd_str:
        try:
            fd = int(fd_str)
        except ValueError:
            pass
        else:
            try:
                raw = os.read(fd, 4096)
                return bytearray(raw.strip())
            except OSError:
                pass
            finally:
                os.close(fd)

    try:
        home_env = os.environ.get("WORTHLESS_HOME")
        home_dir = Path(home_env) if home_env else None
        return read_fernet_key(home_dir)
    except Exception:
        return bytearray()


def _detected_paas_vars() -> list[str]:
    return [name for name in _PAAS_ENV_VARS if os.environ.get(name)]


def _is_private_ipv4_or_v6(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


@dataclass
class ProxySettings:
    """Proxy configuration loaded from environment variables.

    The Fernet reader is exposed as a class-level callable
    (:attr:`_fernet_reader`) so tests can swap it via
    ``monkeypatch.setattr(ProxySettings, "_fernet_reader", ...)`` without
    racing module-attribute patches against pytest-rerunfailures + xdist
    + parenthesized-with on py3.10. See WOR-309 PR #112 for the trail.
    """

    # Class-level Fernet reader hook. Tests patch this via
    # ``monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(fn))``.
    # Intentionally unannotated so the dataclass machinery doesn't treat it
    # as an instance field, AND pyright resolves the staticmethod descriptor
    # correctly through the class. Production callers should leave it alone.
    _fernet_reader = staticmethod(_read_fernet_key)

    db_path: str = field(
        default_factory=lambda: os.environ.get("WORTHLESS_DB_PATH", _default_db_path())
    )
    fernet_key: bytearray = field(default_factory=lambda: ProxySettings._fernet_reader())
    default_rate_limit_rps: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_RATE_LIMIT_RPS", "100.0"))
    )
    upstream_timeout: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_UPSTREAM_TIMEOUT", "120.0"))
    )
    streaming_timeout: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_STREAMING_TIMEOUT", "300.0"))
    )
    # WOR-696: total wall-clock cap on a single streaming response. Anthropic's
    # own docs recommend batch API beyond ~15min (system timeouts + open
    # connection limits). 15min covers Claude Code agentic loops (8-12 min
    # legit) while killing slow-drip attackers who keep streams open forever.
    max_stream_duration_seconds: float = field(
        default_factory=lambda: float(
            os.environ.get("WORTHLESS_MAX_STREAM_DURATION_SECONDS", "900.0")
        )
    )
    # WOR-696: hard cut when a stream goes silent between chunks. 90s covers
    # Anthropic extended-thinking pauses (45-60s legit; documented `ping`
    # events keep the connection alive) while killing slow-drip variants
    # where an attacker drips bytes minutes apart.
    max_idle_between_chunks_seconds: float = field(
        default_factory=lambda: float(
            os.environ.get("WORTHLESS_MAX_IDLE_BETWEEN_CHUNKS_SECONDS", "90.0")
        )
    )
    # Sweeper background task: how often to run and how old a hold must be
    # before it gets billed at estimate (fail-closed: bill orphans, never refund).
    sweep_interval_seconds: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_SWEEP_INTERVAL_SECONDS", "60.0"))
    )
    sweep_max_age_seconds: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_SWEEP_MAX_AGE_SECONDS", "300.0"))
    )
    allow_insecure: bool = field(default_factory=lambda: _env_bool("WORTHLESS_ALLOW_INSECURE"))
    sidecar_socket_path: str = field(
        default_factory=lambda: os.environ.get(
            "WORTHLESS_SIDECAR_SOCKET", DEFAULT_SIDECAR_SOCKET_PATH
        )
    )
    sidecar_protocol_version: int = field(
        default_factory=lambda: int(
            os.environ.get(
                "WORTHLESS_SIDECAR_PROTOCOL_VERSION", str(DEFAULT_SIDECAR_PROTOCOL_VERSION)
            )
        )
    )
    sidecar_expected_caps: frozenset[str] = field(default_factory=lambda: DEFAULT_SIDECAR_CAPS)
    sidecar_max_concurrency: int = field(
        default_factory=lambda: int(os.environ.get("WORTHLESS_SIDECAR_MAX_CONCURRENCY", "32"))
    )
    sidecar_request_timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("WORTHLESS_SIDECAR_REQUEST_TIMEOUT", "2.0"))
    )
    deploy_mode: DeployMode = field(default_factory=_read_deploy_mode)
    host: str = field(default="")
    trusted_proxies: tuple[str, ...] = field(default_factory=_read_trusted_proxies)

    def __post_init__(self) -> None:
        if not self.host:
            self.host = _read_default_host(self.deploy_mode)

    def validate(self) -> None:
        """Refuse startup on unsafe deploy-mode combinations.

        WOR-309: ``fernet_key`` is no longer required at proxy boot. The
        sidecar holds the key; the proxy only reads ciphertext-at-rest and
        delegates ``open()`` over IPC. Existing setups still load the key
        for backwards-compat (e.g. CLI flows reused by the proxy container)
        but the proxy itself never decrypts. The deploy-mode / trusted-
        proxies validation still runs because it gates header trust before
        any request reaches the IPC peer.
        """
        self._validate_deploy_mode()
        self._validate_single_worker()

    def _validate_single_worker(self) -> None:
        """Refuse multi-worker launch — the spend cap is only exact per process.

        WOR-662: spend-cap and token-budget reservations live in process-local
        memory and are only correct with a single owning process per database.
        ``WEB_CONCURRENCY``/``uvicorn --workers`` would spawn N processes that
        each reserve independently against the same stale ``spend_log`` SUM,
        overshooting the cap ~Nx. We refuse it here with a clear message. This
        is the interim fail-closed guard; durable cross-process correctness
        (and relaxing this check) lands with the WOR-659 pre-charge ledger.
        Scale today with replicas that each own a distinct ``WORTHLESS_DB_PATH``.
        """
        raw = os.environ.get("WEB_CONCURRENCY", "").strip()
        if not raw:
            return
        try:
            workers = int(raw)
        except ValueError as exc:
            raise ConfigError(
                f"WEB_CONCURRENCY={raw!r} is not an integer. Unset it or set it to 1 — "
                "worthless-proxy runs a single worker per database (WOR-662)."
            ) from exc
        if workers > 1:
            raise ConfigError(
                f"WEB_CONCURRENCY={workers} is unsupported: worthless-proxy enforces a "
                "single worker per database so the hard spend cap stays exact (WOR-662). "
                "Set WEB_CONCURRENCY=1 and scale with replicas that each own a distinct "
                "WORTHLESS_DB_PATH."
            )

    def _validate_deploy_mode(self) -> None:
        paas = _detected_paas_vars()
        if (
            paas
            and self.deploy_mode is DeployMode.LOOPBACK
            and "WORTHLESS_DEPLOY_MODE" not in os.environ
        ):
            raise ConfigError(
                f"Detected PaaS env var(s) {paas!r} but WORTHLESS_DEPLOY_MODE is unset. "
                "Refusing silent loopback default. Set WORTHLESS_DEPLOY_MODE=public "
                "(with WORTHLESS_TRUSTED_PROXIES) or =loopback explicitly."
            )

        if self.deploy_mode is DeployMode.LOOPBACK:
            if self.host != "127.0.0.1":
                raise ConfigError(
                    f"deploy_mode=loopback requires host=127.0.0.1, got {self.host!r}. "
                    "Set WORTHLESS_DEPLOY_MODE=lan or =public to bind anything else."
                )
            return

        if self.deploy_mode is DeployMode.LAN:
            if self.host not in ("127.0.0.1", "0.0.0.0") and not _is_private_ipv4_or_v6(  # noqa: S104  # nosec B104
                self.host
            ):
                raise ConfigError(
                    f"deploy_mode=lan requires host in a private CIDR, got {self.host!r}. "
                    f"Allowed: 127.0.0.1, 0.0.0.0, or any address in {list(_PRIVATE_CIDRS)!r}."
                )
            return

        # PUBLIC
        if self.allow_insecure:
            raise ConfigError(
                "WORTHLESS_ALLOW_INSECURE is FORBIDDEN when deploy_mode=public. "
                "Set WORTHLESS_TRUSTED_PROXIES=<edge-CIDR> instead — the proxy then trusts "
                "X-Forwarded-Proto only from those peers."
            )
        if not self.trusted_proxies:
            raise ConfigError(
                "deploy_mode=public requires WORTHLESS_TRUSTED_PROXIES (CIDR list of the "
                "edge layer, e.g. Render/Fly internal CIDR). "
                "Refusing to trust X-Forwarded-Proto from arbitrary peers."
            )
        for entry in self.trusted_proxies:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ConfigError(
                    f"WORTHLESS_TRUSTED_PROXIES entry {entry!r} is not a valid CIDR. "
                    "Replace placeholders (e.g. 'REPLACE_WITH_EDGE_CIDR') with the actual "
                    "edge CIDR — uvicorn would otherwise trust no peer and every public "
                    "request would 401."
                ) from exc

"""Single-container Docker entrypoint: spawn sidecar, then exec uvicorn proxy.

Mirrors the lifecycle that ``worthless up`` runs in the foreground:
1. Read fernet key from disk
2. ``split_to_tmpfs`` -> share files in ``$WORTHLESS_HOME/run/<pid>/``
3. ``spawn_sidecar`` -> ``python -m worthless.sidecar`` listening on a Unix socket
4. ``os.execvp`` uvicorn with the right env contract

tini supervises both children so SIGTERM propagates correctly. We do NOT call
into the foreground supervisor (no signal flag, no health-poll wrapper) — that's
the ``worthless up`` user-facing flow. Containers want a flat process tree where
tini is PID 1 and both sidecar + uvicorn are siblings.

Env contract on entry (set by ``deploy/entrypoint.sh``):
    WORTHLESS_HOME              base dir (default ``/data``)
    WORTHLESS_FERNET_KEY_PATH   fernet key location (optional, defaults to
                                ``$WORTHLESS_HOME/fernet.key``)
    PORT                        port for the proxy to bind (default 8787)
    WORTHLESS_DEPLOY_MODE       loopback | lan | public (default loopback)
    WORTHLESS_HOST              explicit bind host (optional)
    WORTHLESS_TRUSTED_PROXIES   CSV of CIDRs (required when mode=public)

The Fernet key is loaded from disk here rather than passed via fd because
the sidecar reads it back from a share file the parent writes — no fd
inheritance subtlety needed.
"""

from __future__ import annotations

import logging
import os
import pwd
import threading
from pathlib import Path

from worthless.cli.bootstrap import ensure_home
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.sidecar_lifecycle import ServiceUids, spawn_sidecar, split_to_tmpfs
from worthless.crypto.types import zero_buf

# WOR-310 C3: priv-drop gate constants. Names + uids match the Dockerfile.
# The env signal is set by deploy/entrypoint.sh — bare-metal install.sh
# never sets it, so the bare-metal path returns ``None`` from
# ``_resolve_service_uids`` regardless of euid.
_PRIVDROP_REQUIRED_ENV = "WORTHLESS_DOCKER_PRIVDROP_REQUIRED"
_PROXY_USER = "worthless-proxy"
_PROXY_UID = 10001
_CRYPTO_USER = "worthless-crypto"
_CRYPTO_UID = 10002
# Shared `worthless` group — both service users belong to it.  The
# Dockerfile creates it as gid 10001 (`groupadd -r -g 10001 worthless`).
# Pinned here so a /etc/group drift (or a hostile shadowed /etc/passwd
# that resolves both users to a different group) is caught before any
# chown / setresgid runs.
_WORTHLESS_GID = 10001


def _resolve_service_uids() -> ServiceUids | None:
    """Return the priv-drop ``ServiceUids`` when running in Docker as root.

    Gateway between bare-metal and Docker:

    * Bare metal (env unset) → ``None``. Even ``sudo worthless up`` is
      treated as bare metal — the env signal is the ONLY trigger for
      the drop dance.

    * Docker (env=1) + euid != 0 → ``WorthlessError``. ``docker run -u
      10001:10001`` would silently degrade the security claim; refuse
      to start instead.

    * Docker (env=1) + euid == 0 → ``ServiceUids(10001, 10002, 10001)``,
      after literal-uid pin against the Dockerfile-baked values.
      ``pwd.getpwnam`` failures (Dockerfile drift) raise ``WorthlessError``.
    """
    if os.environ.get(_PRIVDROP_REQUIRED_ENV) != "1":
        return None

    if os.geteuid() != 0:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"{_PRIVDROP_REQUIRED_ENV}=1 but euid={os.geteuid()}; "
            "container started non-root would silently degrade the uid wall. "
            "Refusing to start.",
        )

    try:
        proxy = pwd.getpwnam(_PROXY_USER)
        crypto = pwd.getpwnam(_CRYPTO_USER)
    except KeyError as exc:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"required user missing from /etc/passwd ({exc}); Dockerfile drift?",
        ) from exc

    if proxy.pw_uid != _PROXY_UID:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"{_PROXY_USER}.pw_uid={proxy.pw_uid} != Dockerfile literal {_PROXY_UID}; "
            "shadowed /etc/passwd or Dockerfile drift. Refusing.",
        )
    if crypto.pw_uid != _CRYPTO_UID:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"{_CRYPTO_USER}.pw_uid={crypto.pw_uid} != Dockerfile literal {_CRYPTO_UID}; "
            "shadowed /etc/passwd or Dockerfile drift. Refusing.",
        )

    # CR-3204010085 (MAJOR): pin the shared `worthless` GID too.
    # Both service users belong to gid 10001 by Dockerfile contract.
    # An /etc/group drift that resolves either user to a different
    # primary group would have us chown share files / chmod the
    # run_dir to an unexpected gid, breaking the kernel-enforced
    # group-traversal model.  Refuse on drift before any chown runs.
    if proxy.pw_gid != _WORTHLESS_GID:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"{_PROXY_USER}.pw_gid={proxy.pw_gid} != Dockerfile literal "
            f"{_WORTHLESS_GID}; /etc/group drift. Refusing.",
        )
    if crypto.pw_gid != _WORTHLESS_GID:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"{_CRYPTO_USER}.pw_gid={crypto.pw_gid} != Dockerfile literal "
            f"{_WORTHLESS_GID}; /etc/group drift. Refusing.",
        )

    return ServiceUids(
        proxy_uid=proxy.pw_uid,
        crypto_uid=crypto.pw_uid,
        worthless_gid=_WORTHLESS_GID,  # use pinned constant, not pw_gid (drift-safe)
    )


def _socket_path(run_dir: Path) -> Path:
    """Return the AF_UNIX socket path inside the run dir."""
    return run_dir / "sidecar.sock"


def _resolve_bind(mode: str) -> str:
    """Pick the uvicorn bind host for *mode*.

    Mirrors :func:`worthless.proxy.config._read_default_host` — explicit
    ``WORTHLESS_HOST`` always wins; otherwise ``public`` defaults to
    ``0.0.0.0`` (PaaS edge) and the others to loopback. ProxySettings'
    own ``validate()`` re-checks the (mode, host) tuple before the app
    binds, so a misconfigured combination still refuses to start.
    """
    explicit = os.environ.get("WORTHLESS_HOST", "").strip()
    if explicit:
        return explicit
    if mode == "public":
        return "0.0.0.0"  # noqa: S104 — public mode binds the edge-facing iface by design
    return "127.0.0.1"


def _build_uvicorn_argv(port: str) -> list[str]:
    mode = os.environ.get("WORTHLESS_DEPLOY_MODE", "loopback").strip().lower() or "loopback"
    host = _resolve_bind(mode)
    argv: list[str] = [
        "uvicorn",
        "worthless.proxy.app:create_app",
        "--factory",
        "--host",
        host,
        "--port",
        port,
    ]
    trusted = os.environ.get("WORTHLESS_TRUSTED_PROXIES", "").strip()
    # ``public`` REQUIRES the trusted-proxy list (entrypoint.sh refuses
    # boot without it). ``lan`` enables --proxy-headers iff the operator
    # opted in by setting the env. ``loopback`` never trusts forwarded
    # headers — there is no edge.
    if mode == "public" or (mode == "lan" and trusted):
        argv += ["--proxy-headers", f"--forwarded-allow-ips={trusted}"]
    return argv


def main() -> None:
    home_dir = Path(os.environ.get("WORTHLESS_HOME", "/data"))
    home = ensure_home(home_dir)
    port = os.environ.get("PORT", "8787")

    # WOR-310 C3: resolve the priv-drop ServiceUids BEFORE we touch any
    # secret material. Docker (env=1, euid=0) returns the uid triple;
    # bare metal returns None. A misconfigured Docker (env=1, non-root)
    # raises here so we never proceed to load the fernet key.
    service_uids = _resolve_service_uids()

    # ``ensure_home`` pinned ``home.base_dir`` to mode 0o700 — owner-only.
    # In Docker that breaks the sidecar (worthless-crypto, group worthless)
    # which needs to traverse ``/data`` to reach ``/data/run/<pid>/``.
    # Bump to 0o710: owner rwx for worthless-proxy (full data access for
    # SQLite WAL/SHM, fernet.key, shard_a/), worthless group --x for
    # traverse only — sidecar can cd through but cannot list sibling
    # files in /data.  Bare-metal path (service_uids=None) keeps the
    # tighter 0o700 since proxy and sidecar share the same uid there.
    if service_uids is not None:
        os.chmod(home.base_dir, 0o710)  # noqa: PTH101, S103

    # CR-3197215771 / 3204010085 (CRITICAL/MAJOR): refuse a multi-
    # threaded entrypoint BEFORE we read the fernet key or call
    # split_to_tmpfs.  BPO-34394 (fork from multi-threaded = undefined)
    # is a security-relevant invariant, and on the failure path we
    # would otherwise have already written share files and held
    # plaintext shard bytearrays in memory before raising.
    active = threading.active_count()
    if active != 1:
        raise WorthlessError(
            ErrorCode.SIDECAR_NOT_READY,
            f"deploy/start.py expects single-threaded entry; got {active} "
            "threads. Forking with threads alive is undefined per BPO-34394 — "
            "refusing to spawn sidecar.",
        )

    fernet_key = home.fernet_key
    try:
        shares = split_to_tmpfs(fernet_key, home.base_dir)
    finally:
        # SR-02: fernet bytes are no longer needed once split into shares.
        zero_buf(fernet_key)

    socket_path = _socket_path(shares.run_dir)

    # WOR-310 C4: hand share files to the crypto uid BEFORE spawn so the
    # forked sidecar (uid 10002) can read them. split_to_tmpfs creates the
    # files at 0o600 owned by the running uid (root in Docker); without
    # chown the sidecar gets EPERM at startup. We chown the per-PID run_dir
    # too so cleanup-by-anyone-in-the-worthless-group works post-shutdown.
    #
    # The parent ``/data/run/`` dir ALSO needs the worthless group with
    # the execute bit so the sidecar (uid 10002) can traverse into the
    # per-PID dir below it.  split_to_tmpfs creates the parent at
    # 0o700 owned by whoever runs it (root in Docker), which would
    # block the sidecar at the directory-walk before it ever opens
    # share_a.bin.  Move parent ownership to ``root:worthless`` mode
    # 0o710 (root rwx, worthless group --x, others nothing) so the
    # sidecar can cd through but not enumerate sibling per-PID dirs.
    if service_uids is not None:
        parent_run_dir = shares.run_dir.parent
        os.chown(parent_run_dir, 0, service_uids.worthless_gid)
        # ``os.chmod`` (not ``Path.chmod``) so monkeypatch.setattr(mod.os,
        # "chmod", ...) intercepts it in tests — pathlib routes through
        # _accessor.chmod which is harder to mock cleanly.
        os.chmod(parent_run_dir, 0o710)  # noqa: PTH101, S103
        os.chown(shares.run_dir, service_uids.crypto_uid, service_uids.worthless_gid)
        # Per-PID run_dir holds both the share files (which only the
        # crypto uid reads) AND the sidecar's Unix socket (which the
        # proxy uid connects to).  split_to_tmpfs created it at 0o700
        # (owner-only); the proxy needs group --x to traverse in and
        # connect() to sidecar.sock.  0o710 with crypto:worthless: the
        # crypto uid keeps full rwx, the worthless group (which the
        # proxy is in) gets traverse-only — proxy can connect to the
        # socket but cannot ls or read share_a/b.bin (those have file
        # mode 0o600 owner-rw which the group bits don't expand).
        os.chmod(shares.run_dir, 0o710)  # noqa: PTH101, S103
        os.chown(shares.share_a_path, service_uids.crypto_uid, service_uids.worthless_gid)
        os.chown(shares.share_b_path, service_uids.crypto_uid, service_uids.worthless_gid)

    # When dropping privs, the proxy uid is the only one that may connect
    # to the sidecar's socket. On bare metal (service_uids is None), the
    # current uid is the only consumer.
    spawn_allowed_uid = service_uids.proxy_uid if service_uids is not None else os.getuid()
    try:
        spawn_sidecar(
            socket_path,
            shares,
            allowed_uid=spawn_allowed_uid,
            service_uids=service_uids,
        )
    except BaseException:
        # Mirror up.py's failure path: unlink share files, rmdir run_dir,
        # zero shard bytearrays, then re-raise.
        for path in (shares.share_a_path, shares.share_b_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            shares.run_dir.rmdir()
        except OSError:
            pass
        zero_buf(shares.shard_a)
        zero_buf(shares.shard_b)
        raise

    # Sidecar has read the share files from disk; unlink them now so they
    # do not persist as readable files on the tmpfs for the sidecar's entire
    # lifetime.  The sidecar holds the key material in memory (and zeroes it
    # via FernetBackend.__del__ / explicit close); it does not re-read the
    # files after startup.  Unlink failures are best-effort — a non-writable
    # tmpfs mount is unusual but should not abort the start sequence.
    for _share_path in (shares.share_a_path, shares.share_b_path):
        try:
            _share_path.unlink(missing_ok=True)
        except OSError as _exc:
            # Log but do not abort — the sidecar is already running.
            logging.getLogger("worthless.start").warning(
                "could not unlink share file %s after sidecar ready: %s", _share_path, _exc
            )

    # In-memory shard buffers in this process are also redundant now.
    # Zero before exec replaces the process.
    zero_buf(shares.shard_a)
    zero_buf(shares.shard_b)

    os.environ["WORTHLESS_SIDECAR_SOCKET"] = str(socket_path)

    # WOR-466: Create a stable well-known symlink so the Docker HEALTHCHECK
    # process can discover the PID-scoped socket path.  HEALTHCHECK processes
    # run in a fresh process tree that only inherits Dockerfile ENV — they
    # never see os.environ mutations made here.  The Dockerfile sets
    # WORTHLESS_SIDECAR_SOCKET=/run/worthless/sidecar.sock (stable); this
    # symlink points it at the real per-PID socket that the sidecar bound.
    # Must be created here (still root) before the privilege drop below.
    # OSError is caught because /run/worthless/ only exists inside Docker
    # (created by the Dockerfile RUN); bare-metal and test environments skip.
    stable_socket = Path("/run/worthless/sidecar.sock")
    try:
        stable_socket.unlink(missing_ok=True)
        stable_socket.symlink_to(socket_path)
    except OSError:
        pass

    # WOR-310 C3: drop self to worthless-proxy before exec uvicorn. Mirrors
    # the preexec_fn dance in the sidecar's forked child:
    #   1. setresgid(gid, gid, gid)  — first, still has CAP_SETGID
    #   2. setgroups([])             — clear inherited supplementary groups
    #   3. setresuid(uid, uid, uid)  — last, drops cap_set*
    # OSError from any step is wrapped as WorthlessError so the orchestrator
    # log shows a structured WRTLS-114 instead of a raw stack trace.
    # Verification post-drop: getresuid() (3-tuple) — getuid() alone could
    # leave saved-uid as 0, breaking the security claim silently.
    if service_uids is not None:
        gid = service_uids.worthless_gid
        proxy_uid = service_uids.proxy_uid
        try:
            os.setresgid(gid, gid, gid)
            os.setgroups([])
            os.setresuid(proxy_uid, proxy_uid, proxy_uid)
        except OSError as exc:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                f"parent priv-drop failed during {exc.__class__.__name__}({exc.errno}); "
                f"refusing to exec uvicorn as root. Original: {exc}",
            ) from exc

        actual = os.getresuid()
        expected = (proxy_uid, proxy_uid, proxy_uid)
        if actual != expected:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                f"post-drop verification failed: getresuid()={actual}, expected {expected}. "
                f"setresuid silently no-op'd or kernel didn't lock saved-uid. Refusing exec.",
            )

        # CR-3197215782: getresgid + getgroups verification.  Same
        # rationale as the getresuid 3-tuple check above — a saved-gid
        # of 0 would let a future bug call setgid(0) and re-acquire
        # group privs, and stray supplementary groups widen the blast
        # radius beyond the threat model (the worthless gid is the
        # ONLY group letting the proxy reach the AF_UNIX socket; any
        # extra groups carry their own access rights).
        actual_gid = os.getresgid()
        expected_gid = (gid, gid, gid)
        if actual_gid != expected_gid:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                f"post-drop verification failed: getresgid()={actual_gid}, "
                f"expected {expected_gid}. setresgid silently no-op'd or "
                "kernel didn't lock saved-gid. Refusing exec.",
            )

        actual_groups = os.getgroups()
        if actual_groups:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                f"post-drop verification failed: getgroups()={actual_groups}, "
                "expected []. Stray supplementary groups widen the blast "
                "radius beyond the WOR-310 threat model. Refusing exec.",
            )

    uvicorn_argv = _build_uvicorn_argv(port)
    # uvicorn_argv is static (no user input apart from CIDR allowlist
    # which uvicorn parses); no shell, no injection surface.
    os.execvp(uvicorn_argv[0], uvicorn_argv)  # noqa: S606


if __name__ == "__main__":
    main()

"""OpenClaw integration entry points.

Phase 2.a ships ``detect()`` + ``IntegrationState`` (pure detection).
Phase 2.b adds ``apply_lock()`` + ``OpenclawApplyResult`` (Stage-3 hook
called from ``worthless lock`` after .env + DB are committed).
``apply_unlock()`` and ``health_check()`` arrive in Phases 2.c–2.d.

``detect()`` is **pure**: no file writes, no network, no daemon probes.
It runs unconditionally on every CLI invocation, so any I/O cost here
becomes startup latency. The detection predicate is::

    openclaw_present = config_present OR workspace_dir_present

where ``config_present`` is delegated to Phase 1's
:func:`worthless.openclaw.config.locate_config_path` (which already
covers the project-local + ``~/.openclaw/`` + XDG fallback chain) and
``workspace_dir_present`` requires
``~/.openclaw/workspace/`` to exist, be a directory, and be readable
(per failure-mode rows F02–F04 and F36).

Spec: ``.claude/plans/graceful-dreaming-reef.md`` §"OpenClaw Detection
Predicate" and §"Failure modes" rows F01–F04, F36.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# pwd is POSIX-only. worthless refuses native Windows (WRTLS-110) but the
# module must still be *importable* on Windows so the CLI can print the error.
if sys.platform != "win32":
    import pwd as _pwd
else:
    _pwd = None  # type: ignore[assignment]

from worthless.openclaw import config as _config_mod
from worthless.openclaw import skill as _skill_mod
from worthless.openclaw.config import (
    OpenclawConfigError,
    _global_config_candidates,
)
from worthless.openclaw.errors import (
    OpenclawErrorCode,
    OpenclawIntegrationError,
    OpenclawIntegrationEvent,
)

_SKILL_SUBPATH = ("skills", "worthless")
_DEFAULT_PROXY_BASE_URL = "http://127.0.0.1:8787"
_DEFAULT_PROXY_PORT = 8787


def _resolve_proxy_base_url() -> str:
    """Return the proxy base URL reachable from OpenClaw's network context.

    OpenClaw typically runs as a Docker container.  Inside a Docker bridge
    network, ``127.0.0.1`` is the container's own loopback — not the host.
    We detect Docker availability at lock-time and emit the right address:

    * macOS / Windows (Docker Desktop): ``host.docker.internal`` — Docker
      Desktop adds this name to ``/etc/hosts`` on both the host *and* inside
      every container, so it resolves correctly in both contexts.
    * Linux with Docker: the ``docker0`` bridge gateway IP (default
      ``172.17.0.1``).  We ask Docker itself to avoid hard-coding.
    * Docker unavailable or detection fails: ``127.0.0.1`` (native install).

    Called once per ``apply_lock`` invocation — not at import time — so the
    ``docker info`` subprocess never adds startup latency.
    """
    docker_bin = shutil.which("docker")
    if docker_bin is None:
        return _DEFAULT_PROXY_BASE_URL
    try:
        probe = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if probe.returncode != 0 or not probe.stdout.strip():
            return _DEFAULT_PROXY_BASE_URL
        # Docker is reachable.
        if sys.platform in ("darwin", "win32"):
            # Docker Desktop exposes host.docker.internal on macOS + Windows.
            return f"http://host.docker.internal:{_DEFAULT_PROXY_PORT}"
        # Linux: read the docker0 bridge gateway so we're not guessing.
        bridge = subprocess.run(
            [
                docker_bin,
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
        ip = bridge.stdout.strip()
        if bridge.returncode == 0 and ip:
            return f"http://{ip}:{_DEFAULT_PROXY_PORT}"
        return f"http://172.17.0.1:{_DEFAULT_PROXY_PORT}"
    except (subprocess.TimeoutExpired, OSError):
        return _DEFAULT_PROXY_BASE_URL


# OpenClaw daemon requires the `api` field to identify the wire protocol
# of each provider. Without it, skills may be visible but tool calls go
# nowhere. Maps worthless provider IDs (the keys in the splitter's
# provider registry) to the OpenClaw `api` schema string. Live-verified
# against ghcr.io/openclaw/openclaw:latest.
_PROVIDER_API: dict[str, str] = {
    "openai": "openai-completions",
    "anthropic": "anthropic-messages",
}


@dataclass(frozen=True)
class IntegrationState:
    """Read-only snapshot of OpenClaw presence on this host.

    ``present`` is the OR of config-present and workspace-present (per
    spec predicate). ``notes`` collects human-readable reasons we
    arrived at the verdict — useful for ``--json`` debug output and for
    ``doctor``'s diagnostic surface in Phase 2.d.

    ``home_mismatch`` is True when $HOME differs from the effective
    user's home directory (F-XS-47: ``sudo -E`` pattern). ``apply_lock``
    emits a ``HOME_MISMATCH`` warn event when this flag is set.
    """

    present: bool
    config_path: Path | None
    workspace_path: Path | None
    skill_path: Path | None
    home_dir: Path | None
    notes: tuple[str, ...]
    home_mismatch: bool = False


def _detect_home_mismatch(home: Path) -> bool:
    """F-XS-47: True when $HOME differs from the effective user's home dir.

    On ``sudo -E``, $HOME keeps the invoking user's path while
    ``os.geteuid()`` returns 0 (root). Wiring OpenClaw to the wrong home
    directory silently installs into root's ``~/.openclaw/`` while the user
    expected their own. We detect and warn; we do not refuse (the user may
    have intentionally privileged the invocation).

    Returns False on Windows (no pwd) or when the lookup fails.
    """
    if _pwd is None:
        return False
    try:
        uid_home = Path(_pwd.getpwuid(os.geteuid()).pw_dir)
        return uid_home.resolve() != home.resolve()
    except (KeyError, OSError):
        return False


def _resolve_home() -> tuple[Path | None, list[str]]:
    """Return ``(home, notes)`` where ``home`` is the resolved home dir
    or ``None`` if it can't be determined / isn't writable.

    F01: broken HOME → return None with a debug note.
    F36: read-only HOME → return None with a debug note (we can't promise
    an install we can't deliver).
    """
    notes: list[str] = []
    try:
        home = Path.home()
    except (RuntimeError, KeyError, OSError) as exc:
        notes.append(f"home unresolvable: {exc}")
        return None, notes

    # Path.home() is already absolute on POSIX; resolve() would walk every
    # path component (slow on /mnt/c WSL targets). One stat is enough.
    try:
        if not home.is_dir():
            notes.append(f"home is not a directory: {home}")
            return None, notes
    except OSError as exc:
        notes.append(f"home unresolvable: {exc}")
        return None, notes

    if not os.access(home, os.W_OK):
        notes.append(f"home is not writable (read-only): {home}")
        return None, notes

    return home, notes


def _classify(path: Path) -> tuple[str, str | None]:
    """Classify a path with one ``lstat`` syscall (+1 follow if symlink).

    Returns ``(kind, detail)`` where ``kind`` is one of:
    ``missing`` / ``dangling`` (broken symlink) / ``file`` / ``dir`` /
    ``symlink-to-file`` / ``symlink-to-dir``. ``detail`` carries an
    OS-level error string when the probe was inconclusive (treated as
    ``missing`` for safety).

    Collapses 3-4 separate ``is_symlink``/``exists``/``is_dir`` stat
    syscalls per path into one — material on slow filesystems
    (``/mnt/c`` WSL targets per project_target_users.md).
    """
    try:
        st = path.lstat()
    except FileNotFoundError:
        return "missing", None
    except OSError as exc:
        return "missing", str(exc)

    if stat.S_ISLNK(st.st_mode):
        try:
            target = path.stat()
        except FileNotFoundError:
            return "dangling", None
        except OSError as exc:
            return "missing", str(exc)
        if stat.S_ISDIR(target.st_mode):
            return "symlink-to-dir", None
        return "symlink-to-file", None

    if stat.S_ISDIR(st.st_mode):
        return "dir", None
    return "file", None


def _probe_workspace(home: Path) -> tuple[Path | None, list[str]]:
    """Return ``(workspace_path or None, notes)`` for the workspace probe.

    F02: ``~/.openclaw`` is a regular file → absent.
    F03: ``~/.openclaw/workspace`` is a dangling symlink → absent.
    F04: workspace dir not readable → absent + warn note.
    """
    notes: list[str] = []
    openclaw_dir = home / ".openclaw"
    kind, detail = _classify(openclaw_dir)
    if kind == "dangling":
        notes.append(f"~/.openclaw is a dangling symlink: {openclaw_dir}")
        return None, notes
    if kind in {"file", "symlink-to-file"}:
        notes.append(f"~/.openclaw is a file, not a dir: {openclaw_dir}")
        return None, notes
    if kind == "missing":
        if detail:
            notes.append(f"~/.openclaw probe error: {detail}")
        return None, notes

    workspace = openclaw_dir / "workspace"
    kind, detail = _classify(workspace)
    if kind == "dangling":
        notes.append(f"workspace is a dangling symlink: {workspace}")
        return None, notes
    if kind in {"file", "symlink-to-file"}:
        notes.append(f"workspace is not a directory: {workspace}")
        return None, notes
    if kind == "missing":
        if detail:
            notes.append(f"workspace probe error: {detail}")
        return None, notes

    if not os.access(workspace, os.R_OK):
        notes.append(f"workspace not readable (no R_OK access): {workspace}")
        return None, notes

    try:
        return workspace.resolve(), notes
    except OSError as exc:
        notes.append(f"workspace unresolvable: {exc}")
        return None, notes


def _probe_config() -> tuple[Path | None, list[str]]:
    """Return ``(openclaw.json path or None, notes)`` — symmetric with siblings.

    Probes only **global** OpenClaw paths (``~/.openclaw/openclaw.json`` and
    the XDG fallback). The project-local ``./openclaw.json`` is intentionally
    skipped here: ``detect()`` answers "is OpenClaw installed on this machine?"
    and a repo that happens to contain a local ``openclaw.json`` must not be
    treated as an OpenClaw host. ``apply_lock()``/``apply_unlock()`` use
    ``locate_config_path()`` directly for the actual read-modify-write path,
    where the project-local file is the correct write target.
    """
    notes: list[str] = []
    locked_candidate: Path | None = None

    try:
        candidates = _global_config_candidates()
    except OSError as exc:
        notes.append(f"config probe failed: {exc}")
        return None, notes

    for p in candidates:
        try:
            p.stat()
        except FileNotFoundError:
            continue
        except PermissionError:
            # The file's *parent dir* is locked (e.g. openclaw sets its config
            # dir to 0700 on startup — DV-01).  ``p.exists()`` catches this and
            # returns False, making detect() silently report present=False.
            # ``p.stat()`` surfaces the distinction so we can store the path
            # and return present=True with an actionable diagnostic note.
            if locked_candidate is None:
                locked_candidate = p
                notes.append(
                    f"openclaw config dir locked ({p.parent}): PermissionError "
                    "on stat — openclaw has likely set the dir to 0700 on "
                    "startup. Stop openclaw before re-locking to restore write "
                    "access (worthless-eq5c)."
                )
            continue
        except OSError:
            continue

        # stat() succeeded — the file is accessible. Apply F-CFG-15 symlink
        # check: do NOT call .resolve() on a symlink — that dereferences the
        # link and hides the attack vector. For non-symlinks resolve for F35
        # (case-insensitive FS canonical compare).
        try:
            if p.is_symlink():
                notes.append(f"config is a symlink (refused for safety): {p}")
                return p, notes
            return p.resolve(), notes
        except OSError as exc:
            notes.append(f"config unresolvable: {exc}")
            return None, notes

    # No accessible config found. If we hit a locked dir, return that path so
    # detect() can report present=True and surface the diagnostic to the user.
    return locked_candidate, notes


def detect() -> IntegrationState:
    """Determine OpenClaw presence on this host. Pure: no writes, no network.

    Returns a frozen :class:`IntegrationState` snapshot. Callers must not
    cache the result across CLI invocations — the user could install or
    uninstall OpenClaw between runs.
    """
    home, notes = _resolve_home()
    if home is None:
        return IntegrationState(
            present=False,
            config_path=None,
            workspace_path=None,
            skill_path=None,
            home_dir=None,
            notes=tuple(notes),
        )

    workspace, ws_notes = _probe_workspace(home)
    notes.extend(ws_notes)

    config, cfg_notes = _probe_config()
    notes.extend(cfg_notes)

    skill_path = workspace.joinpath(*_SKILL_SUBPATH).resolve() if workspace is not None else None

    # Spec: openclaw_present = config_present OR workspace_dir_present.
    present = config is not None or workspace is not None

    # F-XS-47: sudo -E HOME mismatch detection.
    home_mismatch = _detect_home_mismatch(home)
    if home_mismatch:
        notes.append(
            "home mismatch: $HOME differs from effective-uid home (F-XS-47) — check sudo -E usage"
        )

    return IntegrationState(
        present=present,
        config_path=config,
        workspace_path=workspace,
        skill_path=skill_path,
        home_dir=home,
        notes=tuple(notes),
        home_mismatch=home_mismatch,
    )


# ---------------------------------------------------------------------------
# Phase 2.b — apply_lock()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenclawApplyResult:
    """Result of an :func:`apply_lock` invocation.

    Surfaces in ``worthless lock --json`` so downstream agents (Pi) can
    confirm what we did and what we skipped without parsing logs.

    Per locked decisions L1/L2: a partial-success state with non-empty
    ``providers_skipped`` or non-empty failure ``events`` is still a
    "lock succeeded" outcome from the CLI's perspective — the .env and
    DB are already committed by the time this struct is built.
    """

    detected: bool
    config_path: Path | None
    workspace_path: Path | None
    skill_path: Path | None
    providers_set: tuple[str, ...] = ()
    providers_skipped: tuple[tuple[str, str], ...] = ()
    skill_installed: bool = False
    events: tuple[OpenclawIntegrationEvent, ...] = field(default_factory=tuple)

    @property
    def has_failure(self) -> bool:
        """Did this stage hit a genuine failure that should trigger trust-fix exit?

        Trust-fix classification (per spec § L2 revised 2026-05-08):
        only ``error``-level events count. ``provider_conflict``
        (warn-level) means the user configured the provider themselves
        and we respected it — that is a CLEAN state, not a partial
        failure. ``symlink_refused`` IS error-level because the user's
        home is in a genuinely unsafe state. ``config_missing`` on
        unlock is warn-level (idempotent no-op).

        Single-source the rule so it cannot drift between the lock and
        unlock call sites.
        """
        return any(e.level == "error" for e in self.events)


def _resolve_active_config_path(state: IntegrationState, home: Path | None) -> Path:
    """Pick the config file path to write to.

    If ``detect()`` already located one we use it; otherwise default to
    ``~/.openclaw/openclaw.json`` so set_provider can recreate it
    (covers F-CFG-23: the file vanished between detect and write).
    """
    if state.config_path is not None:
        return state.config_path
    base = home if home is not None else Path.home()
    return base / ".openclaw" / "openclaw.json"


def _check_world_writable(config_path: Path, events: list[OpenclawIntegrationEvent]) -> None:
    """Surface filesystem-integrity risks on ``config_path`` as warnings.

    Two checks, both append WRITE_FAILED level=warn so doctor can flag
    them. We don't refuse the lock — these are advisories, not policy
    failures, and the user may have a legitimate reason for the state
    (dotfiles tooling, multi-user dev box).

    1. F-CFG-16: world/group-writable mode (``0o**6``). Don't chmod —
       respect the user's umask choice.
    2. Hardlink defense-in-depth: ``st_nlink > 1`` means
       ``openclaw.json`` shares an inode with another path. ``os.replace``
       creates a NEW inode + rebinds the name, so the OTHER hardlink
       (e.g., a copy of ``~/.bashrc``) survives the swap unmodified —
       no destruction. But the configuration just opaquely diverged
       from "wherever the user thinks the other hardlink points," which
       is a state the user almost certainly didn't intend. Surface it.

    Reuses one WRITE_FAILED code for both — adding a dedicated
    ``HARDLINK_DETECTED`` code is over-engineering when both flow into
    the same advisory channel.
    """
    try:
        st = config_path.stat()
    except OSError:
        return
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.WRITE_FAILED,
                level="warn",
                detail=(
                    f"openclaw.json is world/group-writable: "
                    f"{config_path} (mode {st.st_mode & 0o777:o})"
                ),
            )
        )
    if st.st_nlink > 1:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.WRITE_FAILED,
                level="warn",
                detail=(
                    f"openclaw.json has {st.st_nlink} hardlinks at {config_path} — "
                    "atomic-write will rebind only this name; the other hardlink "
                    "(e.g. ~/.bashrc) is preserved but config now diverges from it"
                ),
                extra={"path": str(config_path), "nlink": str(st.st_nlink)},
            )
        )


def _is_proxy_url(url: str, proxy_base_url: str) -> bool:
    """Return True if ``url`` was written by a previous ``worthless lock``.

    Used by F-CFG-13 to distinguish a worthless-managed entry (safe to
    overwrite / update) from a user's manual override (must not stomp).

    We match on **two** criteria to survive cross-environment re-locks:

    1. Primary: the URL starts with the *current* resolved proxy base URL.
       This is the exact match and the common fast path.

    2. Secondary: the URL is on the same port as ``proxy_base_url`` (regardless
       of host).  This handles the scenario where a previous ``lock`` wrote
       the entry with a different host alias — e.g. ``http://127.0.0.1:<port>/…``
       when Docker was absent, and the current run resolves to
       ``http://172.17.0.1:<port>`` via the Docker bridge.  The port is derived
       from ``proxy_base_url`` so non-default deployments (``--port`` /
       ``WORTHLESS_PORT``) are recognised too — without this, a user running
       on port 9090 would have their re-lock silently skip the apiKey refresh.

    Without the secondary check the existing entry would be misclassified as
    a third-party conflict and silently skipped, leaving the ``apiKey`` stale.

    Architectural follow-up tracked in WOR-487 — replace the port-based
    heuristic with an explicit ``managedBy`` marker on each entry.
    """
    if not isinstance(url, str):
        return False
    if url.startswith(proxy_base_url.rstrip("/") + "/"):
        return True
    # Derive the fallback port from proxy_base_url so non-default deployments
    # (--port / WORTHLESS_PORT) work too.
    port = urlsplit(proxy_base_url).port
    if port is None:
        return False
    return re.match(rf"^https?://[^/]*:{port}/", url) is not None


def _get_provider_for_lock(
    config_path: Path,
    provider_name: str,
) -> tuple[dict | None, Exception | None]:
    """Return ``(existing_entry_or_None, skip_error_or_None)``.

    ``skip_error`` is non-None when the caller must skip the provider (corrupt
    config, raw OSError).  ``None`` means either the entry was read cleanly or
    the file is unreadable due to a ``PermissionError`` (foreign-owned in the
    Docker shared-volume setup) — in that case ``set_provider`` handles it via
    ``permission_as_missing=True`` and the atomic-replace path.
    """
    try:
        return _config_mod.get_provider(config_path, provider_name), None
    except OpenclawConfigError as exc:
        if isinstance(exc.__cause__, PermissionError):
            # File unreadable — can't detect conflicts, but set_provider can
            # still write atomically. Fall through; do not skip.
            return None, None
        return None, exc
    except OSError as exc:
        return None, exc


def apply_lock(
    planned_updates: list[tuple[str, str, str]],
    *,
    proxy_base_url: str | None = None,
) -> OpenclawApplyResult:
    """Wire OpenClaw to route through worthless. Idempotent. Best-effort.

    Stage 3 of ``worthless lock``. Runs AFTER .env + DB are committed.
    Per L1/L2: failures here NEVER roll back lock-core. They surface as
    structured events in the returned :class:`OpenclawApplyResult`.

    Args:
        planned_updates: list of ``(provider, alias, shard_a)`` triples
            for keys that were just locked. ``shard_a`` is a UTF-8 string
            (lock.py decodes the bytearray before calling us).
        proxy_base_url: override for the proxy host. Defaults to
            ``http://127.0.0.1:8787`` (the canonical worthless port).

    Returns:
        :class:`OpenclawApplyResult` describing what we did.

    Spec: ``engineering/research/openclaw-WOR-431-phase-2-spec.md``
    §"Phase 2.b" / §"`apply_lock()` contract".
    """
    # Resolve the proxy base URL here (not at import time) so the Docker
    # probe runs only when apply_lock is actually called.  Callers may
    # override for tests or custom proxy ports.
    resolved_proxy_base_url = (
        proxy_base_url if proxy_base_url is not None else _resolve_proxy_base_url()
    )

    state = detect()
    if not state.present:
        return OpenclawApplyResult(
            detected=False,
            config_path=None,
            workspace_path=None,
            skill_path=None,
        )

    events: list[OpenclawIntegrationEvent] = []
    providers_set: list[str] = []
    providers_skipped: list[tuple[str, str]] = []

    # F-XS-47: warn if $HOME differs from the effective-uid home dir.
    # We still proceed — the write goes to $HOME, which may be intentional
    # (e.g. a privileged installer). Doctor surfaces this for the user.
    if state.home_mismatch:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.HOME_MISMATCH,
                level="warn",
                detail=(
                    "HOME mismatch (F-XS-47): $HOME differs from the effective "
                    "user's home directory. OpenClaw wiring targets $HOME — "
                    "check sudo -E usage."
                ),
            )
        )

    config_path = _resolve_active_config_path(state, state.home_dir)
    _check_world_writable(config_path, events)

    # F-CFG-15: refuse symlinked openclaw.json BEFORE any read or write.
    # ``os.replace`` would clobber the link target, so even an invalid
    # symlink is unsafe — and a valid one is exactly the attack vector
    # (point ~/.openclaw/openclaw.json at ~/.bashrc, run worthless lock,
    # watch ~/.bashrc get destroyed). Defensive depth: set_provider /
    # unset_provider also have _refuse_if_symlink inside the flock, but
    # we short-circuit here so the event is correctly tagged
    # SYMLINK_REFUSED instead of CONFIG_UNREADABLE (which would fire
    # when get_provider tried to JSON-parse the link target).
    try:
        is_link = config_path.is_symlink()
    except OSError:
        is_link = False
    if is_link:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.SYMLINK_REFUSED,
                level="error",
                detail=(
                    f"refusing to follow symlink at {config_path} (F-CFG-15) — "
                    "symlinked openclaw.json is a known attack vector"
                ),
                extra={"path": str(config_path)},
            )
        )
        # Refuse the whole transaction. Stage B (skill install) is
        # technically independent (writes to workspace/skills/), but a
        # symlinked config means the user's home is in an unsafe state
        # and we don't want to half-install. doctor --fix can recover
        # once the user removes the symlink.
        return OpenclawApplyResult(
            detected=True,
            config_path=config_path,
            workspace_path=state.workspace_path,
            skill_path=None,
            providers_set=(),
            providers_skipped=tuple(
                (f"worthless-{provider}", "symlink_refused")
                for provider, _alias, _shard in planned_updates
            ),
            skill_installed=False,
            events=tuple(events),
        )

    # ---- Stage A: write providers ----------------------------------------
    # In all-container Docker setups the openclaw daemon chmods its config
    # dir to 0700 on startup.  If apply_lock reaches here it means the dir
    # was accessible at detect() time (proxy ran first and created the dir),
    # but the file may still be 0600 (foreign-owned) after openclaw's
    # atomic-write cycle.  read_config() returns {} on PermissionError so
    # set_provider can still write via atomic replace (dir is 777 when proxy
    # created it before openclaw started).  Emit one warn-level event so the
    # operator knows non-worthless config keys (gateway auth etc.) were reset.
    try:
        _file_exists = config_path.exists()
        _file_readable = (not _file_exists) or os.access(str(config_path), os.R_OK)
    except OSError:
        _file_readable = True  # can't tell — don't emit the advisory
    if not _file_readable:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.WRITE_FAILED,
                level="warn",
                detail=(
                    "openclaw.json is not readable by the current user "
                    f"({config_path}). Writing fresh provider entries — "
                    "non-worthless config fields (gateway auth token etc.) "
                    "will be regenerated by openclaw on container restart. "
                    "This is expected when openclaw has rewritten the shared "
                    "Docker volume config as a foreign-owned file."
                ),
                extra={"path": str(config_path)},
            )
        )

    for provider, alias, shard_a in planned_updates:
        provider_name = f"worthless-{provider}"
        base_url = f"{resolved_proxy_base_url.rstrip('/')}/{alias}/v1"

        # F-CFG-13: pre-existing entry pointing somewhere that isn't our
        # proxy is a manual override. Skip + emit conflict event.
        # PermissionError is handled transparently by _get_provider_for_lock —
        # see its docstring for the DV-01/DV-02 fall-through rationale.
        existing, read_err = _get_provider_for_lock(config_path, provider_name)
        if read_err is not None:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.CONFIG_UNREADABLE,
                    level="error",
                    detail=f"could not read {config_path}: {read_err}",
                )
            )
            providers_skipped.append((provider_name, "config_unreadable"))
            continue

        if existing is not None:
            existing_url = existing.get("baseUrl", "")
            if existing_url and not _is_proxy_url(existing_url, resolved_proxy_base_url):
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.PROVIDER_CONFLICT,
                        level="warn",
                        detail=(
                            f"refusing to overwrite {provider_name}: "
                            f"existing baseUrl {existing_url!r} is not a worthless proxy"
                        ),
                        extra={"provider": provider_name, "baseUrl": existing_url},
                    )
                )
                providers_skipped.append((provider_name, "provider_conflict"))
                continue

        try:
            _config_mod.set_provider(
                config_path,
                provider_name,
                base_url,
                api_key=shard_a,
                # Required by OpenClaw daemon — without these the daemon
                # rejects the config with "Invalid input: expected array,
                # received undefined". Verified live (WOR-431 evidence).
                api=_PROVIDER_API.get(provider),
                # `models=[]` default is applied inside set_provider when
                # the entry is new. Existing arrays are preserved.
            )
        except OpenclawConfigError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.CONFIG_UNREADABLE,
                    level="error",
                    detail=f"set_provider refused: {exc}",
                    extra={"provider": provider_name},
                )
            )
            providers_skipped.append((provider_name, "config_unreadable"))
            continue
        except OSError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.WRITE_FAILED,
                    level="error",
                    detail=f"failed to write {config_path}: {exc}",
                    extra={"provider": provider_name},
                )
            )
            providers_skipped.append((provider_name, "write_failed"))
            continue

        providers_set.append(provider_name)
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.CONFIG_UPDATED,
                level="info",
                detail=f"wrote {provider_name} to {config_path}",
                extra={"provider": provider_name, "baseUrl": base_url},
            )
        )

    # ---- Stage B: install skill ------------------------------------------
    skill_installed = False
    skill_path: Path | None = None
    workspace = state.workspace_path
    if workspace is not None:
        try:
            skill_path = _skill_mod.install(workspace / "skills")
            skill_installed = True
        except OpenclawIntegrationError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=getattr(exc, "code", OpenclawErrorCode.SKILL_INSTALL_FAILED),
                    level="error",
                    detail=str(exc),
                )
            )
        except OSError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.SKILL_INSTALL_FAILED,
                    level="error",
                    detail=f"skill install failed: {exc}",
                )
            )

    return OpenclawApplyResult(
        detected=True,
        config_path=config_path,
        workspace_path=workspace,
        skill_path=skill_path,
        providers_set=tuple(providers_set),
        providers_skipped=tuple(providers_skipped),
        skill_installed=skill_installed,
        events=tuple(events),
    )


# ---------------------------------------------------------------------------
# Phase 2.c — apply_unlock()
# ---------------------------------------------------------------------------


def apply_unlock(
    aliases: list[tuple[str, str]],
    *,
    remove_skill: bool = True,
) -> OpenclawApplyResult:
    """Reverse Phase 2.b's :func:`apply_lock`. Idempotent. Best-effort.

    Stage 3 of ``worthless unlock``. Per L1/L2 in
    ``engineering/research/openclaw-WOR-431-phase-2-spec.md``: failures
    here NEVER cause unlock-core to fail. If the user runs ``unlock`` and
    we can't clean up OpenClaw's config, they still get their ``.env``
    restored — surfaced as structured events instead of exceptions.

    Args:
        aliases: list of ``(provider, alias)`` pairs whose ``worthless-*``
            entries should be removed from ``openclaw.json``. Same shape as
            :func:`apply_lock` minus ``shard_a`` (we don't need it for undo).
        remove_skill: when True (default) sweep
            ``~/.openclaw/workspace/skills/worthless/`` too. Pass False to
            tear down only provider entries — useful for ``doctor --fix``
            paths that want to refresh providers without reinstalling.

    Returns:
        :class:`OpenclawApplyResult`. ``providers_set`` lists the
        ``worthless-*`` entries we actually removed (we reuse the field
        with "providers we changed" semantics — symmetric with
        ``apply_lock``); ``providers_skipped`` lists ones we couldn't
        remove and the reason.

    Spec: ``engineering/research/openclaw-WOR-431-phase-2-spec.md``
    §"Phase 2.c — ``unlock`` integration", failure-mode rows RT-01/02/03,
    F-XS-40 / F-XS-41, locked decisions L1, L2, L3.
    """
    state = detect()
    if not state.present:
        return OpenclawApplyResult(
            detected=False,
            config_path=None,
            workspace_path=None,
            skill_path=None,
        )

    events: list[OpenclawIntegrationEvent] = []
    providers_removed: list[str] = []
    providers_skipped: list[tuple[str, str]] = []

    config_path = _resolve_active_config_path(state, state.home_dir)

    # F-CFG-15 (symmetric with apply_lock): refuse symlinked openclaw.json.
    # _refuse_if_symlink inside unset_provider's flock is a last line of
    # defense, but raises OpenclawConfigError which would tag the event
    # CONFIG_UNREADABLE — wrong code, wrong story. Short-circuit here so
    # the event is correctly tagged SYMLINK_REFUSED and Stage A doesn't
    # iterate uselessly through every alias hitting the same flock check.
    try:
        is_link = config_path.is_symlink()
    except OSError:
        is_link = False
    if is_link:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.SYMLINK_REFUSED,
                level="error",
                detail=(
                    f"refusing to follow symlink at {config_path} (F-CFG-15) — "
                    "symlinked openclaw.json is a known attack vector"
                ),
                extra={"path": str(config_path)},
            )
        )
        return OpenclawApplyResult(
            detected=True,
            config_path=config_path,
            workspace_path=state.workspace_path,
            skill_path=None,
            providers_set=(),
            providers_skipped=tuple(
                (f"worthless-{provider}", "symlink_refused") for provider, _alias in aliases
            ),
            skill_installed=False,
            events=tuple(events),
        )

    # RT-03: config was deleted between lock and unlock. detect()'s
    # presence verdict is OR(config, workspace) — a missing config alone
    # leaves us with present=True (workspace still there). Surface the
    # named event so doctor / --json can report it; skip Stage A but
    # continue to Stage B since skill removal is still useful.
    config_missing = not config_path.exists()
    if config_missing:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.CONFIG_MISSING,
                level="warn",
                detail=(
                    f"openclaw.json not found at {config_path} — provider entries "
                    "already absent; skipping Stage A"
                ),
                extra={"path": str(config_path)},
            )
        )
        for provider, _alias in aliases:
            providers_skipped.append((f"worthless-{provider}", "config_missing"))

    # ---- Stage A: remove worthless-* provider entries --------------------
    # Skipped entirely when config_missing — providers_skipped already
    # populated above with reason="config_missing", and Stage B (skill
    # removal) still runs below.
    for provider, _alias in aliases if not config_missing else []:
        provider_name = f"worthless-{provider}"
        try:
            removed = _config_mod.unset_provider(config_path, provider_name)
        except OpenclawConfigError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.CONFIG_UNREADABLE,
                    level="error",
                    detail=f"could not read {config_path}: {exc}",
                    extra={"provider": provider_name},
                )
            )
            providers_skipped.append((provider_name, "config_unreadable"))
            continue
        except OSError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.WRITE_FAILED,
                    level="error",
                    detail=f"failed to write {config_path}: {exc}",
                    extra={"provider": provider_name},
                )
            )
            providers_skipped.append((provider_name, "write_failed"))
            continue

        # ``unset_provider`` returns the removed entry dict when it found
        # something to remove, or ``{}`` when the entry was already absent
        # (idempotent no-op). Count the provider as "removed" only when
        # something was actually there — callers rely on ``providers_set``
        # being empty for a genuine no-op to avoid false-positive exits.
        if removed:
            providers_removed.append(provider_name)
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.CONFIG_UPDATED,
                level="info",
                detail=(
                    f"removed {provider_name} from {config_path}"
                    if removed
                    else f"{provider_name} already absent in {config_path}"
                ),
                extra={"provider": provider_name},
            )
        )

    # ---- Stage B: uninstall skill folder ---------------------------------
    skill_uninstalled = False
    workspace = state.workspace_path
    skill_path = state.skill_path
    if remove_skill and workspace is not None:
        try:
            skill_uninstalled = _skill_mod.uninstall(workspace / "skills")
        except OpenclawIntegrationError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=getattr(exc, "code", OpenclawErrorCode.SKILL_INSTALL_FAILED),
                    level="error",
                    detail=str(exc),
                )
            )
        except OSError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.SKILL_INSTALL_FAILED,
                    level="error",
                    detail=f"skill uninstall failed: {exc}",
                )
            )

    return OpenclawApplyResult(
        detected=True,
        config_path=config_path,
        workspace_path=workspace,
        skill_path=skill_path,
        providers_set=tuple(providers_removed),
        providers_skipped=tuple(providers_skipped),
        skill_installed=skill_uninstalled,
        events=tuple(events),
    )


# ---------------------------------------------------------------------------
# Phase 2.d — health_check()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenclawHealthReport:
    """Provider-wiring health snapshot from :func:`health_check`.

    ``providers_ok`` — names correctly wired to the proxy.
    ``providers_missing`` — names absent from ``openclaw.json``.
    ``providers_drifted`` — ``(name, actual_url, expected_url)`` triples
        where the entry exists but ``baseUrl`` points somewhere else.
    ``config_unreadable`` — True when ``openclaw.json`` could not be parsed;
        all three verdict lists are empty in that case (callers must not
        interpret an empty ``providers_ok`` as "all good").

    ``healthy`` is True only when all three trouble lists are empty.
    Consumers (``doctor``, CI scripts) should test ``healthy`` before
    showing a "✓ OpenClaw wired correctly" badge.
    """

    providers_ok: tuple[str, ...] = ()
    providers_missing: tuple[str, ...] = ()
    providers_drifted: tuple[tuple[str, str, str], ...] = ()
    config_unreadable: bool = False

    @property
    def healthy(self) -> bool:
        return (
            not self.providers_missing and not self.providers_drifted and not self.config_unreadable
        )


def health_check(
    state: IntegrationState,
    *,
    expected_providers: list[tuple[str, str]],
    proxy_port: int,
    proxy_base_url: str | None = None,
) -> OpenclawHealthReport:
    """Check provider-wiring health against the live ``openclaw.json``.

    Reads ``openclaw.json`` once per provider (inside Phase 1's flock) and
    compares each ``worthless-<provider>`` entry's ``baseUrl`` against the
    expected URL for the current proxy host.

    Used by ``worthless doctor`` (Phase 2.d) to surface drift without
    modifying any files. Pure read path — no writes, no network.

    Args:
        state: detection snapshot from :func:`detect`.
        expected_providers: list of ``(provider, alias)`` pairs drawn from
            the enrollment DB. Example: ``[("openai", "openai-aaaa1111")]``.
        proxy_port: proxy port to build the expected ``baseUrl`` when
            ``proxy_base_url`` is not provided.
        proxy_base_url: override for the proxy host.  Defaults to
            :func:`_resolve_proxy_base_url` — the same host that
            :func:`apply_lock` would write — so Docker hosts report correct
            health instead of false drift against loopback.

    Returns:
        :class:`OpenclawHealthReport` with per-provider verdicts.
    """
    if state.config_path is None:
        return OpenclawHealthReport(
            providers_missing=tuple(
                f"worthless-{provider}" for provider, _alias in expected_providers
            ),
        )

    config_path = state.config_path

    # Refuse symlinks — same defence as apply_lock/apply_unlock (read-only, but
    # a symlink pointing at /etc/passwd would parse as config_unreadable silently).
    if config_path.is_symlink():
        return OpenclawHealthReport(config_unreadable=True)

    # Resolve the proxy host once — same logic as apply_lock so the expected
    # URL matches what was actually written (avoids false drift on Docker hosts).
    if proxy_base_url is not None:
        resolved_base = proxy_base_url.rstrip("/")
    else:
        # Detect the right host for this environment (localhost vs Docker bridge
        # vs host.docker.internal), then apply the caller-specified port.
        # ``_resolve_proxy_base_url()`` always embeds the *default* port; we
        # strip it and replace with ``proxy_port`` so non-default deployments
        # (``WORTHLESS_PORT`` env or ``--port``) are not falsely flagged.
        _detected = _resolve_proxy_base_url()  # e.g. "http://172.17.0.1:8787"
        _scheme_host = _detected.rsplit(":", 1)[0]  # "http://172.17.0.1"
        resolved_base = f"{_scheme_host}:{proxy_port}"

    providers_ok: list[str] = []
    providers_missing: list[str] = []
    providers_drifted: list[tuple[str, str, str]] = []

    for provider, alias in expected_providers:
        provider_name = f"worthless-{provider}"
        expected_url = f"{resolved_base}/{alias}/v1"
        try:
            entry = _config_mod.get_provider(config_path, provider_name)
        except (OpenclawConfigError, OSError):
            # Bail early — further reads will hit the same error.
            # Zero out partial verdicts: config_unreadable means "don't trust
            # any list in this report."
            return OpenclawHealthReport(config_unreadable=True)
        if entry is None:
            providers_missing.append(provider_name)
        else:
            actual_url = entry.get("baseUrl", "")
            if actual_url == expected_url:
                providers_ok.append(provider_name)
            else:
                providers_drifted.append((provider_name, actual_url, expected_url))

    return OpenclawHealthReport(
        providers_ok=tuple(providers_ok),
        providers_missing=tuple(providers_missing),
        providers_drifted=tuple(providers_drifted),
    )

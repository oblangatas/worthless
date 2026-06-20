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

import hmac
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

# pwd is POSIX-only. worthless refuses native Windows (WRTLS-110) but the
# module must still be *importable* on Windows so the CLI can print the error.
if sys.platform != "win32":
    import pwd as _pwd
else:
    _pwd = None  # type: ignore[assignment]

from worthless.cli.key_patterns import KEY_PATTERN
from worthless.crypto.types import zero_buf
from worthless.openclaw import config as _config_mod
from worthless.openclaw import skill as _skill_mod
from worthless.openclaw.config import (
    OpenclawConfigError,
    _global_config_candidates,
)
from worthless.openclaw.errors import (
    OpenclawConfigUnreadableError,
    OpenclawErrorCode,
    OpenclawIntegrationError,
    OpenclawIntegrationEvent,
)

# G5-B sentinel: any string that ``KEY_PATTERN`` flags as key-shaped at ANY
# nesting depth in a captured OpenClaw provider entry is replaced by this
# dict before the entry is persisted as a rollback record. A dict (not a
# string placeholder) is intentional: on restore the type mismatch makes
# the substitution loud and self-documenting rather than silent partial
# leakage. See ``_deep_redact_key_strings`` and ``build_oc_rollback_entry_record``.
_DEEP_REDACT_SENTINEL = {"kind": "redacted-deep"}


_DEEP_REDACT_KEY_PLACEHOLDER = "<redacted-deep-key>"


def _deep_redact_key_strings(value: object) -> object:
    """Walk *value* recursively; replace any key-shaped string with the
    G5-B sentinel. Dicts and lists are descended into; tuples are not (the
    rollback record JSON has no tuples). Returns a NEW structure — the
    caller's input is never mutated. JSON-only precondition (cyclic Python
    dicts would recurse to ``RecursionError`` — not a valid rollback shape).

    Detection uses ``KEY_PATTERN.search`` (same SR-05 patterns the scanner
    uses), so a key embedded in a larger string (e.g.
    ``"Bearer sk-..."``) triggers replacement of the WHOLE string. False
    positives are accepted: better to redact a description that happens
    to look like a key than to leak an actual one. The user can re-paste
    nested credentials on unlock — they were never safe in the rollback
    record anyway.

    Asymmetric replacement (intentional):
    * **values** become the dict sentinel ``{"kind":"redacted-deep"}`` so
      the type-mismatch is loud on restore.
    * **dict keys** must remain hashable, so they become the literal
      string placeholder ``"<redacted-deep-key>"``. JSON dict keys are
      always strings, so this is the only path that needs the asymmetry.

    **Coverage limitation (residual; tracked).** ``KEY_PATTERN`` is a
    prefix-allowlist (``sk-``, ``sk-or-``, ``sk-ant-``, ``anthropic-``,
    ``AIza``, ``xai-``). Tokens that do NOT carry a recognized provider
    prefix — a bare UUID/JWT/hex admin token from a self-hosted gateway —
    are NOT detected and survive into the rollback record. Follow-up
    ``worthless-3l5l`` adds an entropy fallback for unprefixed tokens.
    """
    if isinstance(value, str):
        if KEY_PATTERN.search(value):
            return {"kind": "redacted-deep"}
        return value
    if isinstance(value, dict):
        return {
            (_DEEP_REDACT_KEY_PLACEHOLDER if KEY_PATTERN.search(k) else k)
            if isinstance(k, str)
            else k: _deep_redact_key_strings(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_deep_redact_key_strings(v) for v in value]
    # int, float, bool, None — nothing to redact.
    return value


_SKILL_SUBPATH = ("skills", "worthless")
_DEFAULT_PROXY_BASE_URL = "http://127.0.0.1:8787"
_DEFAULT_PROXY_PORT = 8787


def build_oc_rollback_apikey_record(kind: str, ref: dict | None = None) -> str:
    """Return the SHAPE-ONLY OpenClaw rollback apiKey record as JSON.

    WOR-651/F4. This encodes the product rule "never persist the real key":
    the returned record describes only the *shape* of the original
    OpenClaw provider apiKey so ``unlock`` (F2) can restore it from a
    client-side source — it never carries key material.

    * ``kind == "plaintext"`` → ``{"kind":"plaintext"}``. The original
      entry held an inline key; we record only that fact. The real value
      is reconstructed client-side at unlock time, never from this DB.
    * ``kind == "secretref"`` → ``{"kind":"secretref","ref":<ref>}``.
      ``ref`` is a NON-secret pointer (e.g. ``{source, provider, id}``)
      to where the real key lives (env var, secret manager) — never the
      key itself.

    A stolen DB therefore yields, at most, half a key plus a pointer —
    never a usable credential.

    Raises:
        ValueError: on any unknown ``kind``.
    """
    if kind == "plaintext":
        record: dict = {"kind": "plaintext"}
    elif kind == "secretref":
        record = {"kind": "secretref", "ref": ref}
    else:
        raise ValueError(
            f"unknown OpenClaw rollback apiKey record kind: {kind!r} "
            "(expected 'plaintext' or 'secretref')"
        )
    return json.dumps(record, separators=(",", ":"))


def build_oc_rollback_entry_record(original_entry: dict) -> str:
    """Return the FULL original provider entry as JSON, key-redacted.

    WOR-621 F2. ``unlock`` must restore the original OpenClaw provider
    entry *verbatim* (byte-identical), but ``lock`` adds fields (``api``,
    ``models``) a bare entry never had — so restoring baseUrl+apiKey alone
    leaves those behind. We therefore remember the WHOLE original entry,
    with the secret ``apiKey`` VALUE replaced by its shape record (see
    :func:`build_oc_rollback_apikey_record`):

        {"baseUrl": "...", "api": "...", "models": [...],
         "apiKey": {"kind": "plaintext"}}            # inline key
        {"baseUrl": "...", "apiKey": {"kind": "secretref", "ref": {...}}}

    Every field except the real key value is non-secret, so a stolen DB
    still yields no usable credential. ``unlock`` substitutes the real
    value (reconstructed client-side, or the SecretRef pointer) back into
    ``apiKey`` and writes the entry wholesale.
    """
    entry = dict(original_entry)
    raw_key = entry.get("apiKey")
    if isinstance(raw_key, dict):
        # apiKey is a structured pointer (e.g. {"$ref": {...}}) — a SecretRef.
        # Store the pointer verbatim (non-secret); restore it verbatim.
        shape = build_oc_rollback_apikey_record("secretref", ref=raw_key)
    else:
        # Inline string key (or absent) — plaintext shape; value dropped.
        shape = build_oc_rollback_apikey_record("plaintext")
    entry["apiKey"] = json.loads(shape)
    # G5-B Gap 2a: scrub key-shaped strings hiding in any other field
    # (e.g. ``headers.Authorization: "Bearer sk-..."``) at any nesting
    # depth. Defense-in-depth: also catches a key value mistakenly placed
    # inside a SecretRef pointer. Runs AFTER the top-level apiKey
    # substitution so the {"kind":"plaintext"|"secretref"} shape is what
    # the walk sees (and leaves untouched — those have no key bytes).
    entry = _deep_redact_key_strings(entry)
    return json.dumps(entry, separators=(",", ":"), sort_keys=True)


def _parse_oc_rollback_entry_record(
    record_json: str,
    *,
    expected_mac: str | None = None,
    recomputed_mac: str | None = None,
) -> dict:
    """Strict parse of a rollback entry record → the original entry dict
    (with ``apiKey`` still holding its shape record).

    Fail-CLOSED (decisions 3 + 4):

    * **JSON / shape** (decision 3) — any structural deviation raises
      ``ValueError`` so the caller leaves the provider on the proxy rather
      than risk synthesizing a bad/plaintext restore. Validates: top level
      is a JSON object; it has an ``apiKey`` that is itself an object with
      ``kind`` in ``{"plaintext","secretref"}``; a ``secretref`` carries a
      ``ref`` object; a ``plaintext`` carries no stray keys beyond ``kind``.
    * **MAC tamper-bind** (decision 4, G2) — when ``expected_mac`` AND
      ``recomputed_mac`` are supplied, constant-time-compare them; mismatch
      raises ``ValueError("rollback mac tampered")``. The caller computes
      ``recomputed_mac`` via the fernet-keyed HMAC (same
      ``ShardRepository._compute_decoy_hash`` the ``decoy_hash`` column
      uses) and passes it in — keeps this function sync so the unlock chain
      doesn't have to cascade async. This blocks a DB-write attacker (no
      fernet key) from flipping a stored ``secretref`` JSON to ``plaintext``
      so the next legit unlock writes the real key into a slot they can
      read. Legacy rows with no MAC pass both args as ``None`` — we fall
      back to shape-only validation (G1 behavior) for backward compat until
      a re-lock attaches a tag.
    """
    parsed = json.loads(record_json)  # raises ValueError on bad JSON
    if not isinstance(parsed, dict):
        raise ValueError("rollback entry record is not a JSON object")
    apikey_shape = parsed.get("apiKey")
    if not isinstance(apikey_shape, dict):
        raise ValueError("rollback entry record missing object apiKey shape")
    kind = apikey_shape.get("kind")
    if kind == "plaintext":
        if set(apikey_shape) - {"kind"}:
            raise ValueError("plaintext apiKey shape has unexpected keys")
    elif kind == "secretref":
        if not isinstance(apikey_shape.get("ref"), dict) or set(apikey_shape) - {"kind", "ref"}:
            raise ValueError("secretref apiKey shape malformed")
    else:
        raise ValueError(f"unknown apiKey shape kind: {kind!r}")

    # G2 tamper-bind: caller passes a freshly-recomputed MAC; we compare
    # constant-time against the one the DB returned. Caller's recompute
    # uses the same fernet-derived HMAC-SHA256 the ``decoy_hash`` column
    # uses (no new crypto, no master-key oracle). SR-07 constant-time.
    if expected_mac is not None and recomputed_mac is not None:
        if not hmac.compare_digest(recomputed_mac, expected_mac):
            raise ValueError("rollback mac tampered")
    return parsed


CaptureKind = Literal["new", "reuse_prior", "relock_no_prior", "no_entry"]


def classify_oc_entry_for_capture(
    current_entry: dict | None,
    *,
    prior_entry_record_json: str | None,
    proxy_base_url: str,
) -> tuple[CaptureKind, str | None, str | None]:
    """Decide WOR-621 F2 G3 rollback capture for one provider.

    Pure + sync — the CLI (which holds the openclaw.json read and the async
    ShardRepository) calls this for each provider it is about to lock and
    threads the returned ``(base_url, entry_record_json)`` plus a freshly
    computed MAC over ``entry_record_json`` into ``upsert_locked_shard``.

    Decisions per WOR-649 Pass-1:

    * ``current_entry is None`` AND a ``prior_entry_record_json`` exists →
      ``("reuse_prior", None, prior_entry_record_json)``. The live entry is
      gone from openclaw.json (deleted by hand, parse failure swallowed by
      :func:`_read_openclaw_providers_for_capture`'s broad except) but the
      DB row carries the genuine pre-first-lock original. Reuse it verbatim
      — same principle as the proxy-shaped reuse-prior branch below. The
      prior record IS the source of truth about what was there before lock;
      a missing live entry must NEVER null the DB column (the upsert SQL is
      ``ON CONFLICT DO UPDATE SET oc_original_api_key_json = excluded.oc_original_api_key_json``,
      so propagating ``None`` here is destructive — caught by Cursor's
      thermo-nuclear review).
    * ``current_entry is None`` AND no prior record → ``("no_entry", None, None)``.
      Truly nothing to capture (fresh install, never locked this alias).
      Lock-core still writes the new proxy entry; the rollback row stays
      NULL and unlock fail-safe-skips that alias.
    * Entry's ``baseUrl`` is proxy-shaped (a previous lock already rewrote
      it) AND a ``prior_entry_record_json`` exists in the DB → re-lock:
      reuse the prior record VERBATIM so the genuine pre-first-lock
      original is preserved across N re-locks. Decision 2. (G5-C: the
      original ``baseUrl`` lives INSIDE the MAC-bound JSON record, not in
      a separate column — Stage A unlock reads it from there.)
    * Entry proxy-shaped AND no prior record → ``relock_no_prior``: caller
      MUST warn + write NULL. We refuse to capture shard-A as "the
      original" — that would let unlock declare success on a fake
      restore. Decision 2 + WOR-514 honesty principle.
    * Otherwise (the genuine pre-lock state) → ``("new", baseUrl, record)``
      where ``record`` is :func:`build_oc_rollback_entry_record`'s
      key-redacted full entry. Decision 4 always supplies both kwargs.

    Test surface: ``tests/openclaw/test_lock_capture_oc_rollback.py``
    pins the CLI-level outcomes of each branch.
    """
    if current_entry is None:
        if prior_entry_record_json is not None:
            # Reuse-prior on missing live entry: identical principle to the
            # proxy-shaped reuse-prior branch below — a NULL live entry must
            # never erase a prior DB record.
            return ("reuse_prior", None, prior_entry_record_json)
        return ("no_entry", None, None)

    raw_url = current_entry.get("baseUrl")
    entry_url = raw_url if isinstance(raw_url, str) else ""
    if entry_url and _is_proxy_url(entry_url, proxy_base_url):
        if prior_entry_record_json is not None:
            # G5-C: the prior URL is inside ``prior_entry_record_json`` (the
            # MAC-bound source of truth); we don't echo it as a separate
            # slot any more. Middle slot is None for reuse_prior.
            return ("reuse_prior", None, prior_entry_record_json)
        # Refuse to mint a fake "original" from the proxy entry.
        return ("relock_no_prior", None, None)

    return ("new", entry_url or None, build_oc_rollback_entry_record(current_entry))


@dataclass(frozen=True)
class OcRestore:
    """One provider's restore instruction for :func:`apply_unlock`.

    Built by the CLI from the stored shard row. Carries everything needed
    to put the original OpenClaw entry back WITHOUT the DB ever having held
    the real key:

    * ``provider`` — original provider id, e.g. ``"openai"`` (the entry
      ``lock`` rewrote; no ``worthless-`` prefix any more).
    * ``alias`` — globally-unique shard-row id; the proxy URL path segment.
    * ``oc_original_api_key_json`` — the key-redacted full entry record
      (see :func:`build_oc_rollback_entry_record`). The original ``baseUrl``
      is INSIDE this MAC-bound JSON; Stage A reads it from there. (A prior
      ``oc_original_base_url`` field on this dataclass was dropped in G5-C
      because it duplicated the JSON's URL AND was not MAC-bound.)
    * ``plaintext_key`` — the real key reconstructed CLIENT-side
      (shard-A ⊕ shard-B), owned by unlock and zeroed after use; ``None``
      for the SecretRef branch (which restores a pointer, never plaintext).
      ``repr=False`` (SR-04): the key must never render in a log line or a
      traceback frame, once G4 populates it.
    * ``expected_mac`` (G5-A) — the fernet-keyed HMAC the DB returned with
      the row's ``oc_rollback_mac`` column. ``None`` for legacy pre-G2 rows.
    * ``recomputed_mac`` (G5-A) — the CLI's freshly-computed HMAC over
      ``oc_original_api_key_json`` (via
      :meth:`ShardRepository._compute_decoy_hash`). The async compute lives
      in the CLI so Stage A stays sync; Stage A constant-time-compares the
      two values via the same path
      :func:`_parse_oc_rollback_entry_record` already implements for G2.
      Both ``None`` → shape-only validation per the G1 backward-compat
      fallback (legacy NULL-MAC rows unlock cleanly).
    """

    provider: str
    alias: str
    oc_original_api_key_json: str | None
    plaintext_key: bytearray | None = field(repr=False)
    expected_mac: str | None = None
    recomputed_mac: str | None = None


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
    original_config_snapshot: dict | None = None

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


def _classify_config_state(
    path: Path,
) -> Literal["missing", "unreadable", "present"]:
    """Classify the openclaw.json config file using POSITIVE signals only.

    Using ``os.access`` to infer a Docker shared-volume topology was the
    root cause of WOR-516 case (c): ``read_config(permission_as_missing=True)``
    silently returned ``{}`` and ``set_provider`` overwrote the config with a
    blank slate.  We now require a POSITIVE signal to declare "unreadable":

    * ``WORTHLESS_OPENCLAW_CONFIG_SHARED`` set to a non-empty value — explicit
      operator override for shared Docker volume topologies.
    * UID mismatch — ``os.stat(path).st_uid != os.geteuid()`` — the file is
      owned by a different user, classic Docker two-UID layout.

    Returns "missing" when the file does not exist (first lock on a fresh
    install), "unreadable" for the two Docker signals, "present" otherwise.
    """
    try:
        file_exists = path.exists()
    except OSError:
        # Python 3.10 / macOS: PermissionError can bubble out of Path.exists()
        # when the parent directory is locked (chmod 000).  The file IS there —
        # the subsequent write will produce WRITE_FAILED through normal error
        # handling rather than the Docker-topology abort path.
        return "present"
    if not file_exists:
        return "missing"
    if os.environ.get("WORTHLESS_OPENCLAW_CONFIG_SHARED"):
        return "unreadable"
    try:
        if os.stat(str(path)).st_uid != os.geteuid():  # noqa: PTH116 — must use os.stat so tests can patch("os.stat")
            return "unreadable"
    except PermissionError:
        # Dir-locked after exists() passed: write will fail → WRITE_FAILED.
        return "present"
    except OSError:
        # Any other stat failure (e.g. ENOENT TOCTOU race): proceed and let
        # the write path surface the error.
        return "present"
    return "present"


@dataclass(frozen=True)
class LockPlan:
    """Collect-then-decide representation of an ``apply_lock`` operation.

    Built by :func:`build_lock_plan` and consumed by both ``--dry-run``
    (display only) and the live write path (execute).  Having a single
    function that produces this struct guarantees the two paths can never
    diverge in their classification logic.

    ``original_config`` is the config dict read *before* any writes.  The
    live path stores this in :attr:`OpenclawApplyResult.original_config_snapshot`
    so a caller can call :func:`rollback_config` on failure.
    """

    config_path: Path | None
    config_state: Literal["missing", "unreadable", "present"]
    providers_to_add: tuple[str, ...]
    providers_to_skip: tuple[tuple[str, str], ...]
    skill_to_install: bool
    original_config: dict | None

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation for ``--dry-run`` output."""
        return {
            "config_path": str(self.config_path) if self.config_path else None,
            "config_state": self.config_state,
            "providers_to_add": list(self.providers_to_add),
            "providers_to_skip": [list(p) for p in self.providers_to_skip],
            "skill_to_install": self.skill_to_install,
        }


def build_lock_plan(
    state: IntegrationState,
    planned_updates: list[tuple[str, str, str]],
    *,
    proxy_base_url: str,
) -> LockPlan:
    """Return a :class:`LockPlan` without performing any writes.

    Pure function used by both ``--dry-run`` (display) and the live path
    (execute) so the two can never diverge in their classification logic.
    """
    config_path = _resolve_active_config_path(state, state.home_dir)
    config_state = _classify_config_state(config_path)

    if config_state == "unreadable":
        return LockPlan(
            config_path=config_path,
            config_state="unreadable",
            providers_to_add=(),
            providers_to_skip=(),
            skill_to_install=False,
            original_config=None,
        )

    # Read the existing config once (for conflict detection + snapshot).
    original_config: dict | None = None
    if config_state == "present":
        try:
            original_config = _config_mod.read_config(config_path)
        except Exception:
            original_config = None

    providers_to_add: list[str] = []
    providers_to_skip: list[tuple[str, str]] = []

    for provider, _alias, _shard_a in planned_updates:
        provider_name = f"worthless-{provider}"
        existing_entry = (
            (original_config or {}).get("models", {}).get("providers", {}).get(provider_name)
        )
        if existing_entry is not None:
            existing_url = existing_entry.get("baseUrl", "")
            if existing_url and not _is_proxy_url(existing_url, proxy_base_url):
                providers_to_skip.append((provider_name, "provider_conflict"))
                continue
        providers_to_add.append(provider_name)

    skill_to_install = state.workspace_path is not None

    return LockPlan(
        config_path=config_path,
        config_state=config_state,
        providers_to_add=tuple(providers_to_add),
        providers_to_skip=tuple(providers_to_skip),
        skill_to_install=skill_to_install,
        original_config=original_config,
    )


def rollback_config(config_path: Path | None, original_config: dict | None) -> None:
    """Atomically restore ``config_path`` to ``original_config``.

    Called when a mid-loop ``set_provider`` write fails so that the config is
    never left in a partially-written state.  Uses the same atomic-write path
    (:func:`worthless.openclaw.config._atomic_write_json`) that ``set_provider``
    itself uses.

    ``original_config=None`` means the file was absent before the lock attempt.
    Any partial file created during the attempt is deleted.  ``{}`` means the
    file existed with empty content and must be restored to ``{}``.

    Raises :class:`OSError` on disk-full or permission failure — the caller
    surfaces both the original write error and the rollback error via events.
    """
    if config_path is None:
        return
    if original_config is None:
        # File was absent before this lock attempt — delete any partial file
        # written before the failure rather than leaving {} on disk.
        try:
            config_path.unlink()
        except FileNotFoundError:
            pass  # never created; nothing to clean up
        return
    _config_mod._atomic_write_json(config_path, original_config)


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


def _apply_lock_write_providers(
    config_path: Path,
    resolved_proxy_base_url: str,
    planned_updates: list[tuple[str, str, str]],
    events: list[OpenclawIntegrationEvent],
    providers_set: list[str],
    providers_skipped: list[tuple[str, str]],
) -> bool:
    """Stage A of apply_lock: write each provider entry.

    Returns ``True`` if a write failure occurred and rollback is required,
    ``False`` when all providers were handled cleanly (written or skipped).
    Extracted to keep :func:`apply_lock` within xenon's complexity budget.
    """
    for provider, alias, shard_a_str in planned_updates:
        # WOR-621 F1: rewrite the provider's ORIGINAL entry (e.g. ``openai``),
        # not a separate ``worthless-<id>`` decoy that OpenClaw never routes
        # through (the WOR-514 bypass).
        provider_name = provider
        base_url = f"{resolved_proxy_base_url.rstrip('/')}/{alias}/v1"

        _existing, read_err = _get_provider_for_lock(config_path, provider_name)
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

        # No conflict-skip here: locking a provider MEANS rewriting its real
        # entry (which holds the live key the user chose to lock), so a
        # non-proxy baseUrl is expected and intentionally overwritten. The
        # original is stashed for restore in F2 (unlock). DB-driven
        # recognition — so a user's UNRELATED proxy-shaped entry is never
        # adopted — lands in F3.

        try:
            _config_mod.set_provider(
                config_path,
                provider_name,
                base_url,
                api_key=shard_a_str,
                api=_PROVIDER_API.get(provider),
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
            return True  # rollback needed

        providers_set.append(provider_name)
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.CONFIG_UPDATED,
                level="info",
                detail=f"wrote {provider_name} to {config_path}",
                extra={"provider": provider_name, "baseUrl": base_url},
            )
        )
    return False  # no rollback needed


def _apply_lock_rollback(
    config_path: Path,
    original_config: dict | None,
    events: list[OpenclawIntegrationEvent],
    providers_set: list[str],
    providers_skipped: list[tuple[str, str]],
) -> None:
    """Execute transactional rollback after a Stage A write failure.

    Restores original_config atomically. Appends an error event if the
    rollback itself fails (double-fault). Marks written providers as
    rolled_back in providers_skipped and clears providers_set.
    Extracted to keep :func:`apply_lock` within xenon's complexity budget.
    """
    try:
        rollback_config(config_path, original_config)
    except OSError as rb_exc:
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.WRITE_FAILED,
                level="error",
                detail=(
                    f"rollback of {config_path} also failed: {rb_exc} — manual recovery required"
                ),
                extra={"path": str(config_path)},
            )
        )
    providers_skipped.extend((p, "rolled_back") for p in providers_set)
    providers_set.clear()


_ALLOWED_PROXY_HOSTS: frozenset[str] = frozenset(
    # "proxy" is the worthless proxy's Docker Compose service name — OpenClaw
    # reaches it over the internal network as http://proxy:8787 (see
    # deploy/docker-compose.yml). A fixed internal hostname, safe like
    # host.docker.internal.
    {"127.0.0.1", "localhost", "::1", "host.docker.internal", "proxy"}
)
# Docker's default ``docker0`` bridge gateway lives in 172.17.0.0/16 — the
# address _resolve_proxy_base_url() emits when OpenClaw runs in a container.
# Scoped to the default-bridge /16 (not the full RFC-1918 172.16.0.0/12) so an
# explicit override can't redirect to arbitrary private-range hosts.
_DOCKER_BRIDGE_CIDR = ipaddress.ip_network("172.17.0.0/16")


def _validate_proxy_base_url(url: str) -> None:
    """Raise ValueError if *url* does not resolve to a local proxy endpoint.

    Rejects remote hosts to prevent SSRF / key exfiltration via a tampered
    MCP config. Allows localhost aliases and the Docker default-bridge gateway
    range (172.17.0.0/16). Only applied to explicit caller-supplied overrides;
    the auto-resolved URL from _resolve_proxy_base_url() bypasses this check.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        in_docker_bridge = ipaddress.ip_address(host) in _DOCKER_BRIDGE_CIDR
    except ValueError:
        in_docker_bridge = False
    if parts.scheme != "http" or (host not in _ALLOWED_PROXY_HOSTS and not in_docker_bridge):
        raise ValueError(
            f"proxy_base_url must point to a local proxy endpoint "
            f"(allowed hosts: {sorted(_ALLOWED_PROXY_HOSTS)} or 172.17.0.0/16); got: {url!r}"
        )


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
        planned_updates: list of ``(provider, alias, auth_token)`` triples
            for keys that were just locked.  ``auth_token`` is the stable
            proxy auth token (worthless-16x2) — an opaque URL-safe base64
            string — NOT shard-A.  The same token is written to every
            provider entry so all aliases share one secret, rotated on
            ``worthless relock``.
        proxy_base_url: override for the proxy host. Defaults to
            ``http://127.0.0.1:8787`` (the canonical worthless port).

    Returns:
        :class:`OpenclawApplyResult` describing what we did.

    Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md``
    §"Phase 2.b" / §"`apply_lock()` contract".
    """
    if proxy_base_url is not None:
        _validate_proxy_base_url(proxy_base_url)

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

    # WOR-516 case (c): detect Docker two-UID topology BEFORE any writes.
    # The old code used os.access() + warn-and-proceed, which allowed
    # read_config(permission_as_missing=True) to return {} and set_provider
    # to overwrite the config with a blank slate.  Now we abort hard.
    config_state = _classify_config_state(config_path)
    if config_state == "unreadable":
        raise OpenclawConfigUnreadableError(
            f"openclaw.json at {config_path} is owned by a different user "
            f"(Docker two-UID topology detected) or WORTHLESS_OPENCLAW_CONFIG_SHARED is set. "
            f"Re-run worthless lock as the openclaw user, or set WORTHLESS_OPENCLAW_CONFIG_SHARED "
            f"only when the shared-volume layout is intentional."
        )

    # Snapshot the original config BEFORE any writes so rollback_config can
    # restore it atomically if a mid-loop set_provider fails.
    # None = file was absent (rollback → delete any partial file).
    # {}   = file existed with empty content (rollback → restore {}).
    # Any other dict = restore that content.
    original_config: dict | None = None
    if config_state == "present":
        try:
            original_config = _config_mod.read_config(config_path)
        except OpenclawConfigError as exc:
            # read_config wraps PermissionError as OpenclawConfigError.
            # Two sub-cases both arrive here as config_state=="present":
            #
            # a) Directory locked (chmod 000 on parent dir): stat will also fail
            #    → proceed so write attempt surfaces WRITE_FAILED (DV-01 path).
            # b) File locked (chmod 000 on file itself, same UID): directory is
            #    accessible so set_provider's permission_as_missing=True would
            #    silently create a new file, overwriting siblings — the WOR-516
            #    case (c) bug.  Abort now before any write happens.
            #
            # Distinguish via __cause__: PermissionError + stat succeeds → (b).
            if isinstance(exc.__cause__, PermissionError):
                try:
                    config_path.stat()
                    # Directory accessible → file-locked → abort.
                    events.append(
                        OpenclawIntegrationEvent(
                            code=OpenclawErrorCode.CONFIG_UNREADABLE,
                            level="error",
                            detail=(
                                f"openclaw.json at {config_path} exists but is not readable "
                                "(permission denied) — aborting to avoid overwriting your config. "
                                "Run: chmod u+r openclaw.json"
                            ),
                            extra={"path": str(config_path)},
                        )
                    )
                    return OpenclawApplyResult(
                        detected=True,
                        config_path=config_path,
                        workspace_path=state.workspace_path,
                        skill_path=state.skill_path,
                        providers_set=(),
                        providers_skipped=tuple(
                            (f"worthless-{p}", "config_unreadable") for p, *_ in planned_updates
                        ),
                        skill_installed=False,
                        events=tuple(events),
                        original_config_snapshot=None,
                    )
                except PermissionError:
                    pass  # directory also locked → proceed, write will hit WRITE_FAILED
            # All other read failures: proceed; set_provider surfaces WRITE_FAILED.
            original_config = {}
        except Exception:
            # Other exceptions (JSON decode error, OS error, etc.): proceed.
            original_config = {}

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
                # F1: report the bare provider name lock writes, not the decoy.
                (provider, "symlink_refused")
                for provider, _alias, _shard_a in planned_updates
            ),
            skill_installed=False,
            events=tuple(events),
        )

    # ---- Stage A: write providers ----------------------------------------
    # F-CFG-13 / DV-01/DV-02 handling is inside _apply_lock_write_providers.
    # Extracted to keep apply_lock within xenon's complexity budget (rank C).
    rollback_needed = _apply_lock_write_providers(
        config_path,
        resolved_proxy_base_url,
        planned_updates,
        events,
        providers_set,
        providers_skipped,
    )

    # ---- Transactional rollback on write failure -------------------------
    if rollback_needed:
        _apply_lock_rollback(config_path, original_config, events, providers_set, providers_skipped)

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
        original_config_snapshot=original_config,
    )


def _apply_unlock_stage_a(
    config_path: Path,
    restores: list[OcRestore],
    events: list[OpenclawIntegrationEvent],
    providers_restored: list[str],
    providers_skipped: list[tuple[str, str]],
) -> bool:
    """Stage A of apply_unlock: restore each provider's ORIGINAL entry.

    WOR-621 F2. F1 made ``lock`` rewrite the original entry (proxy +
    shard-A), so the undo is no longer "remove a ``worthless-*`` decoy" — it
    RESTORES the original entry verbatim from the key-redacted rollback
    record (:func:`build_oc_rollback_entry_record`), offline.

    Fail-CLOSED (decision 3): a corrupt/missing record, or a plaintext
    restore with no reconstructed key, leaves the provider on the proxy and
    is surfaced as a skip — never a silent pass, never a bad/plaintext
    write. The reconstructed key is zeroed on every exit (decision 1).

    Returns ``True`` if a write failure occurred and rollback is required.
    Mutates providers_restored / providers_skipped / events in place.
    """
    for restore in restores:
        provider = restore.provider
        plaintext_key = restore.plaintext_key
        try:
            record = restore.oc_original_api_key_json
            try:
                if record is None:
                    # G5-C clarification: distinguish "never captured" from
                    # "captured then nulled." Lock writes (record=None, mac=None)
                    # together when there was no openclaw entry to capture
                    # (no_entry / relock_no_prior branches in _decide_oc_capture)
                    # — that's a clean no-op for this provider, not a failure.
                    # An attacker who nulls only the record while leaving the
                    # MAC intact still fails the (record is None AND mac is not
                    # None) tamper check below; the fernet key keeps them out
                    # of forging a matching MAC on (None, *).
                    if restore.expected_mac is None:
                        # Genuine no-rollback-captured. Skip silently.
                        continue
                    raise ValueError("rollback mac present but record missing — tamper")
                # G5-A (Gap 3a): enforce the G2 MAC tamper-bind HERE — the
                # lowest layer that touches the record — so a caller that
                # bypasses _build_oc_restores cannot skip the gate. The CLI
                # populates both fields from the DB + a fresh
                # ShardRepository._compute_decoy_hash; both-None falls
                # back to shape-only per G1 (legacy pre-G2 rows).
                entry = _parse_oc_rollback_entry_record(
                    record,
                    expected_mac=restore.expected_mac,
                    recomputed_mac=restore.recomputed_mac,
                )
            except ValueError as exc:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.CONFIG_UNREADABLE,
                        level="error",
                        detail=f"refusing to restore {provider}: invalid rollback record ({exc})",
                        extra={"provider": provider},
                    )
                )
                providers_skipped.append((provider, "rollback_record_invalid"))
                continue

            apikey_shape = entry["apiKey"]
            if apikey_shape["kind"] == "secretref":
                entry["apiKey"] = apikey_shape["ref"]
            else:  # plaintext — substitute the client-reconstructed key
                if plaintext_key is None:
                    events.append(
                        OpenclawIntegrationEvent(
                            code=OpenclawErrorCode.CONFIG_UNREADABLE,
                            level="error",
                            detail=(
                                f"refusing to restore {provider}: plaintext record "
                                "but no reconstructed key supplied"
                            ),
                            extra={"provider": provider},
                        )
                    )
                    providers_skipped.append((provider, "missing_plaintext_key"))
                    continue
                try:
                    entry["apiKey"] = plaintext_key.decode("utf-8")
                except UnicodeDecodeError:
                    events.append(
                        OpenclawIntegrationEvent(
                            code=OpenclawErrorCode.CONFIG_UNREADABLE,
                            level="error",
                            detail=(
                                f"refusing to restore {provider}: reconstructed key "
                                "is not valid UTF-8 (corrupt shard?)"
                            ),
                            extra={"provider": provider},
                        )
                    )
                    providers_skipped.append((provider, "rollback_record_invalid"))
                    continue

            try:
                _config_mod.replace_provider(config_path, provider, entry)
            except OpenclawConfigError as exc:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.CONFIG_UNREADABLE,
                        level="error",
                        detail=f"could not restore {provider} in {config_path}: {exc}",
                        extra={"provider": provider},
                    )
                )
                providers_skipped.append((provider, "config_unreadable"))
                continue
            except OSError as exc:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.WRITE_FAILED,
                        level="error",
                        detail=f"failed to write {config_path}: {exc}",
                        extra={"provider": provider},
                    )
                )
                providers_skipped.append((provider, "write_failed"))
                return True  # rollback needed

            providers_restored.append(provider)
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.CONFIG_UPDATED,
                    level="info",
                    detail=f"restored {provider} in {config_path}",
                    extra={"provider": provider},
                )
            )
        finally:
            if plaintext_key is not None:
                zero_buf(plaintext_key)
    return False


# ---------------------------------------------------------------------------
# Phase 2.c — apply_unlock()
# ---------------------------------------------------------------------------


def apply_unlock(
    restores: list[OcRestore],
    *,
    remove_skill: bool = True,
) -> OpenclawApplyResult:
    """Reverse Phase 2.b's :func:`apply_lock`. Idempotent. Best-effort.

    Stage 3 of ``worthless unlock``. Per L1/L2 in
    ``engineering/research/openclaw/WOR-431-phase-2-spec.md``: failures
    here NEVER cause unlock-core to fail. If the user runs ``unlock`` and
    we can't clean up OpenClaw's config, they still get their ``.env``
    restored — surfaced as structured events instead of exceptions.

    Args:
        restores: list of :class:`OcRestore` records — one per provider
            whose original ``openclaw.json`` entry should be restored
            verbatim from its key-redacted rollback record (WOR-621 F2).
        remove_skill: when True (default) sweep
            ``~/.openclaw/workspace/skills/worthless/`` too. Pass False to
            tear down only provider entries — useful for ``doctor --fix``
            paths that want to refresh providers without reinstalling.

    Returns:
        :class:`OpenclawApplyResult`. ``providers_set`` lists the original
        provider entries we restored (we reuse the field with "providers we
        changed" semantics — symmetric with ``apply_lock``);
        ``providers_skipped`` lists ones we couldn't restore and the reason.

    Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md``
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
    providers_restored: list[str] = []
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
            providers_skipped=tuple((r.provider, "symlink_refused") for r in restores),
            skill_installed=False,
            events=tuple(events),
        )

    # WOR-516 (symmetric guard): detect Docker two-UID topology before any
    # writes, same as apply_lock. Unlike apply_lock, unlock must NOT raise
    # (L1/L2 contract: unlock-core failures never abort the unlock).
    # Surface a CONFIG_UNREADABLE event, skip Stage A, continue to Stage B
    # (skill removal is still safe and useful regardless of config ownership).
    config_state_unlock = _classify_config_state(config_path)
    if config_state_unlock == "unreadable":
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.CONFIG_UNREADABLE,
                level="error",
                detail=(
                    f"openclaw.json at {config_path} is owned by a different user "
                    "(Docker two-UID topology) — skipping provider removal"
                ),
                extra={"path": str(config_path)},
            )
        )
        for r in restores:
            providers_skipped.append((r.provider, "config_unreadable"))
        # Fall through to Stage B — skill removal doesn't touch the config.
        config_missing = True  # prevents Stage A from running

    else:
        # RT-03: config was deleted between lock and unlock. detect()'s
        # presence verdict is OR(config, workspace) — a missing config alone
        # leaves us with present=True (workspace still there). Surface the
        # named event so doctor / --json can report it; skip Stage A but
        # continue to Stage B since skill removal is still useful.
        config_missing = config_state_unlock == "missing"
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
            for r in restores:
                providers_skipped.append((r.provider, "config_missing"))

    # ---- Stage A: restore each provider's ORIGINAL entry verbatim --------
    # Skipped entirely when config_missing — providers_skipped already
    # populated above with reason="config_missing", and Stage B still runs.
    # Extracted to _apply_unlock_stage_a to keep apply_unlock within xenon.
    # SM-2 symmetry: snapshot the config first; on a mid-restore write
    # failure, roll back so we never leave a half-restored config.
    if not config_missing:
        try:
            original_config_snapshot: dict | None = _config_mod.read_config(config_path)
        except (OpenclawConfigError, OSError):
            original_config_snapshot = None
        rollback_needed = _apply_unlock_stage_a(
            config_path, restores, events, providers_restored, providers_skipped
        )
        if rollback_needed and original_config_snapshot is not None:
            try:
                rollback_config(config_path, original_config_snapshot)
            except OSError as rb_exc:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.WRITE_FAILED,
                        level="error",
                        detail=(
                            f"rollback of {config_path} also failed: {rb_exc} — "
                            "manual recovery required"
                        ),
                        extra={"path": str(config_path)},
                    )
                )
            # Entries restored before the failure are reverted by the
            # rollback; reflect that they are no longer in restored state.
            for restored in list(providers_restored):
                providers_skipped.append((restored, "rolled_back"))
            providers_restored.clear()

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

    # Stage C (.bak residue hygiene) deferred to WOR-599 — leave .bak alone
    # until the daemon's crash-recovery semantics are fully understood.

    return OpenclawApplyResult(
        detected=True,
        config_path=config_path,
        workspace_path=workspace,
        skill_path=skill_path,
        providers_set=tuple(providers_restored),
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
            # WOR-621 F1: lock rewrites the provider's ORIGINAL entry in place
            # (e.g. ``openai``), so health reports the bare provider name — not
            # the legacy ``worthless-<provider>`` decoy that F1 no longer writes.
            providers_missing=tuple(provider for provider, _alias in expected_providers),
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
        # WOR-621 F1: lock writes the provider in place under its bare name
        # (``openai``), so look up that entry — not the legacy ``worthless-``
        # decoy. Mismatch here made every F1 install read as providers_missing.
        provider_name = provider
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

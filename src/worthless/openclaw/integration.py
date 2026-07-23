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
from collections.abc import Mapping, Sequence
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

from worthless.cli.dotenv_rewriter import shannon_entropy
from worthless.cli.key_patterns import ENTROPY_THRESHOLD, KEY_PATTERN
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


# WOR-827: KEY_PATTERN is a prefix allowlist, so an unprefixed credential — a
# bare UUID, a raw JWT, or a long hex/base64 admin token from a self-hosted /
# Azure / Enterprise gateway — slips past it. These shape + entropy rungs catch
# tokens with no recognized provider prefix. False positives are accepted (see
# _deep_redact_key_strings): over-redacting a rollback field is safe; leaking a
# key is not.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
_HEX_TOKEN_RE = re.compile(r"[0-9a-fA-F]{32,}")
# A run of base64/token characters (NO spaces or punctuation) long enough to be
# a secret. Ordinary prose can't reach 32 chars without a break; the entropy
# gate (reusing the scan-side ``ENTROPY_THRESHOLD``) then rejects long
# low-information identifiers.
_B64ISH_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def _looks_like_unprefixed_secret(s: str) -> bool:
    """True if *s* contains credential material carrying no known provider
    prefix: a UUID, a JWT, or a long hex token (matched on shape alone), or any
    32+ char base64-ish run whose Shannon entropy clears the scan threshold.

    A URL value is exempt: a provider ``baseUrl`` may legitimately embed an
    Azure subscription GUID (or similar), and restore writes it back verbatim —
    whole-redacting it would corrupt the provider entry on unlock. A real key
    inside a URL is still caught by ``KEY_PATTERN`` via :func:`_is_secret_shaped`.

    Residual (successor to WOR-827, tracked): a token shorter than 32 chars with
    no known prefix (e.g. ``secrets.token_urlsafe(16)`` = 22 chars) is NOT
    detected by this fallback.
    """
    parsed = urlsplit(s.strip())
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return False
    if _UUID_RE.search(s) or _JWT_RE.search(s) or _HEX_TOKEN_RE.search(s):
        return True
    return any(shannon_entropy(m.group(0)) >= ENTROPY_THRESHOLD for m in _B64ISH_RUN_RE.finditer(s))


def _is_secret_shaped(s: str) -> bool:
    """A known-prefix key (``KEY_PATTERN``) OR an unprefixed token (WOR-827)."""
    return bool(KEY_PATTERN.search(s)) or _looks_like_unprefixed_secret(s)


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

    **Unprefixed tokens (WOR-827).** ``KEY_PATTERN`` is a prefix-allowlist
    (``sk-``, ``sk-or-``, ``sk-ant-``, ``anthropic-``, ``AIza``, ``xai-``).
    Detection is now backed by :func:`_is_secret_shaped`, which adds a shape +
    entropy fallback (:func:`_looks_like_unprefixed_secret`) so a bare
    UUID/JWT/hex/base64 admin token from a self-hosted gateway is also scrubbed.
    """
    if isinstance(value, str):
        if _is_secret_shaped(value):
            return {"kind": "redacted-deep"}
        return value
    if isinstance(value, dict):
        return {
            (_DEEP_REDACT_KEY_PLACEHOLDER if _is_secret_shaped(k) else k)
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
    # WOR-796: the *_API_KEY var name scrub_agent_auth_stores() referenced
    # when it wrote ``${var_name}`` into agent auth stores at lock time —
    # needed to restore the EXACT ref back to plaintext, not "any env ref".
    var_name: str | None = None


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

    2. Secondary: the URL is on the same port as ``proxy_base_url`` AND on an
       allowed proxy host (loopback / Docker bridge — NOT any host; see the
       security note below).  This handles the scenario where a previous ``lock`` wrote
       the entry with a different host alias — e.g. ``http://127.0.0.1:<port>/…``
       when Docker was absent, and the current run resolves to
       ``http://172.17.0.1:<port>`` via the Docker bridge.  The port is derived
       from ``proxy_base_url`` so non-default deployments (``--port`` /
       ``WORTHLESS_PORT``) are recognised too — without this, a user running
       on port 9090 would have their re-lock silently skip the apiKey refresh.

    Without the secondary check the existing entry would be misclassified as
    a third-party conflict and silently skipped, leaving the ``apiKey`` stale.

    "Is this URL proxy-shaped?" is a *shape* test, not an ownership claim —
    WOR-650 layers DB-backed recognition on top (parse the alias, look it up
    in the ``shards`` table) to decide whether a proxy-shaped entry is one
    Worthless created. (The explicit-marker idea from WOR-487 is impossible —
    OpenClaw's ``.strict()`` schema rejects unknown keys.)
    """
    if not isinstance(url, str):
        return False
    if url.startswith(proxy_base_url.rstrip("/") + "/"):
        return True
    # Derive the fallback port from proxy_base_url so non-default deployments
    # (--port / WORTHLESS_PORT) work too. SECURITY (WOR-777 / brutus): the host
    # is NOT arbitrary — it must be a loopback / Docker-bridge proxy host, or an
    # attacker baseUrl like ``https://evil.com:<port>/<alias>/v1`` would read as
    # proxy-shaped and (a) get its plaintext finding demoted past the audit gate,
    # (b) get neutralized. Same allowlist as :func:`_validate_proxy_base_url`.
    port = urlsplit(proxy_base_url).port
    if port is None:
        return False
    # SECURITY (WOR-777 / brutus): ``url`` is attacker-influenced. On Python
    # 3.12+ ``urlsplit`` / ``.hostname`` / ``.port`` eagerly reject malformed
    # hosts — a bracketed non-IPv6 host ``http://[evil.com]:<port>/…`` (raises in
    # urlsplit itself) or a non-numeric port ``127.0.0.1:8787.evil.com`` (raises
    # on ``.port``) — with ValueError. A crafted config must read as
    # "not our proxy" (return False), never crash the gate.
    try:
        parts = urlsplit(url)
        if parts.port != port:
            return False
        # CodeRabbit (WOR-777): scheme must match too — worthless's proxy is
        # http-only (_DEFAULT_PROXY_BASE_URL), so an https:// entry on the same
        # host:port cannot be a real worthless-written entry.
        if parts.scheme != urlsplit(proxy_base_url).scheme:
            return False
        host = parts.hostname or ""
    except ValueError:
        return False
    try:
        in_docker_bridge = ipaddress.ip_address(host) in _DOCKER_BRIDGE_CIDR
    except ValueError:
        in_docker_bridge = False
    return host in _ALLOWED_PROXY_HOSTS or in_docker_bridge


# WOR-650 recognition helpers. The alias is parsed from an attacker/
# user-controllable ``baseUrl``, so the regex is restricted to the real alias
# charset (junk -> None, never echoed) and any value that reaches a log /
# event / sentinel is control-char-stripped and length-capped.
_ALIAS_FROM_BASE_URL_RE = re.compile(r"/([A-Za-z0-9_-]+)/v1(?:/|$)")
_MAX_ALIAS_LOG_LEN = 64
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\x1b]")


def _alias_from_base_url(base_url: str) -> str | None:
    """Extract the key alias from a worthless proxy ``baseUrl``.

    ``http://127.0.0.1:8787/openai-stale/v1`` -> ``openai-stale``. Restricted
    to the worthless alias charset (``[A-Za-z0-9_-]``) so a malicious baseUrl
    yields ``None`` (no recognition, no echo) rather than arbitrary bytes.
    Returns ``None`` when the URL does not match.
    """
    if not isinstance(base_url, str):
        return None
    m = _ALIAS_FROM_BASE_URL_RE.search(base_url)
    return m.group(1) if m else None


def _sanitize_alias_for_log(alias: str) -> str:
    """Make an alias safe to put in an event detail / stdout / sentinel.

    Strips control + ANSI-escape bytes (terminal-injection defense) and caps
    length (sentinel / terminal DoS defense). The extraction regex already
    bounds the charset; this is belt-and-suspenders for any other caller.
    """
    cleaned = _CONTROL_CHARS_RE.sub("", alias)
    if len(cleaned) > _MAX_ALIAS_LOG_LEN:
        cleaned = cleaned[:_MAX_ALIAS_LOG_LEN] + "…"
    return cleaned


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


@dataclass(frozen=True)
class AdoptionPolicy:
    """WOR-650: how ``apply_lock`` treats an existing OpenClaw provider entry
    that isn't recognized as one Worthless created on this machine.

    ``managed_aliases`` — the aliases in this machine's ``shards`` DB
    (``repo.list_keys()``), snapshotted by the caller BEFORE this lock's DB
    writes. ``None`` = recognition data unavailable (DB unreadable/migrating);
    treated fail-safe as "not recognized", never silently "recognized".

    ``adopt_unrecognized`` — the consent. True when the user passed ``--adopt``
    / ``--yes``, ran non-interactively, or confirmed at the prompt. When False,
    an unrecognized proxy-shaped entry is SKIPPED (left in place), not
    overwritten.

    NOT a security boundary: after a DB reset it can't tell ours from foreign,
    so it only chooses inform-vs-silent and skip-vs-write-when-unconsented. No
    code gates reconstruction on it; a planted entry is neutralized anyway —
    lock overwrites the baseUrl with Worthless's own proxy URL.
    """

    managed_aliases: set[str] | None = None
    adopt_unrecognized: bool = False


def _classify_adoption(
    existing: object,
    *,
    provider: str,
    resolved_proxy_base_url: str,
    policy: AdoptionPolicy | None,
) -> tuple[bool, OpenclawIntegrationEvent | None]:
    """Decide how to treat an existing entry under the adoption policy.

    Returns ``(skip, event)``: ``skip=True`` -> leave the entry, do NOT
    overwrite (unconsented unrecognized proxy-shaped entry); ``skip=False`` ->
    overwrite (recognized re-lock, real key, un-parseable, or consented
    adoption); ``event`` -> an info event to record, or ``None`` for the silent
    paths. Recognized + real-key paths are byte-identical to pre-WOR-650
    behavior. The parsed alias is attacker-controllable, so it is sanitized
    before it enters any event.
    """
    if policy is None or not isinstance(existing, dict):
        return False, None
    url = existing.get("baseUrl", "")
    if not isinstance(url, str) or not url or not _is_proxy_url(url, resolved_proxy_base_url):
        return False, None  # real key / no URL -> overwrite silently
    alias = _alias_from_base_url(url)
    if alias is None:
        return False, None  # un-parseable -> can't name it -> overwrite silently
    managed = policy.managed_aliases
    if managed is not None and alias in managed:
        return False, None  # recognized re-lock -> silent
    safe = _sanitize_alias_for_log(alias)
    extra = {"provider": provider, "alias": safe}
    if managed is None:
        detail = (
            f"could not check this machine's records for '{provider}' (alias "
            f"{safe!r}); proceeding without recognition."
            if policy.adopt_unrecognized
            else f"skipped '{provider}': could not check this machine's records "
            f"(alias {safe!r}). Re-run with --adopt to take it over."
        )
        return (not policy.adopt_unrecognized), OpenclawIntegrationEvent(
            code=OpenclawErrorCode.PROVIDER_RECOGNITION_UNAVAILABLE,
            level="info",
            detail=detail,
            extra=extra,
        )
    if policy.adopt_unrecognized:
        return False, OpenclawIntegrationEvent(
            code=OpenclawErrorCode.PROVIDER_ADOPTED_UNRECOGNIZED,
            level="info",
            detail=(
                f"re-linking an existing '{provider}' entry (alias {safe!r}) not in "
                f"this machine's records — likely a synced config, reinstall, or new "
                f"machine. Routing it through Worthless."
            ),
            extra=extra,
        )
    return True, OpenclawIntegrationEvent(
        code=OpenclawErrorCode.PROVIDER_ADOPTION_SKIPPED,
        level="info",
        detail=(
            f"skipped '{provider}': an existing proxy-shaped entry (alias {safe!r}) "
            f"isn't in this machine's records and wasn't adopted. Re-run with --adopt "
            f"to take it over."
        ),
        extra=extra,
    )


def _apply_lock_write_providers(
    config_path: Path,
    resolved_proxy_base_url: str,
    planned_updates: list[tuple[str, str, str]],
    events: list[OpenclawIntegrationEvent],
    providers_set: list[str],
    providers_skipped: list[tuple[str, str]],
    policy: AdoptionPolicy | None = None,
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

        # WOR-650 F3: DB-backed recognition. Classify the SAME read we are about
        # to overwrite (TOCTOU-safe — no separate snapshot). Recognized re-locks
        # and real keys overwrite silently as before; an unrecognized
        # proxy-shaped entry is adopted-with-notice (consented) or skipped
        # (unconsented). Never let recognition gate the overwrite of a key the
        # user explicitly chose to lock.
        skip_adopt, adopt_event = _classify_adoption(
            _existing,
            provider=provider,
            resolved_proxy_base_url=resolved_proxy_base_url,
            policy=policy,
        )
        if adopt_event is not None:
            events.append(adopt_event)
        if skip_adopt:
            providers_skipped.append((provider_name, "unrecognized_not_adopted"))
            continue

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


def _agent_models_json_paths(openclaw_dir: Path, env: Mapping[str, str]) -> list[Path]:
    """Enumerate per-agent ``models.json`` projections under ``<.openclaw>``.

    Mirrors OpenClaw's ``listAgentModelsJsonPaths`` (storage-scan.ts): the
    ``main`` agent, every ``agents/*/agent`` subdirectory, and an
    ``OPENCLAW_AGENT_DIR`` / ``PI_CODING_AGENT_DIR`` override if set.

    ponytail: custom per-agent dirs declared inside openclaw.json are not
    followed — add config-driven resolution if a non-standard layout needs it.
    """
    paths: set[Path] = set()
    override = (env.get("OPENCLAW_AGENT_DIR") or env.get("PI_CODING_AGENT_DIR") or "").strip()
    if override:
        paths.add(Path(override).expanduser() / "models.json")
    agents_root = openclaw_dir / "agents"
    paths.add(agents_root / "main" / "agent" / "models.json")
    try:
        for entry in agents_root.iterdir():
            if entry.is_dir():
                paths.add(entry / "agent" / "models.json")
    except OSError:
        pass  # agents/ absent or unreadable -> just the main + override paths
    return sorted(paths)


def _apply_lock_neutralize_models_json(
    config_path: Path,
    resolved_proxy_base_url: str,
    providers_set: Sequence[str],
    events: list[OpenclawIntegrationEvent],
    env: Mapping[str, str] | None = None,
) -> None:
    """Delete worthless's stale provider entries from each agent ``models.json``.

    WOR-777 Layer 2. OpenClaw runs from ``<.openclaw>/agents/*/agent/models.json``
    — a projection it regenerates each turn by MERGING openclaw.json over the
    EXISTING file, and the merge PRESERVES the existing apiKey/baseUrl
    (models-config.merge.ts). So after a re-lock rotates openclaw.json, the
    runtime keeps the OLD shard-A until the stale projection is removed. Deleting
    our entry makes the next regen take the new value wholesale (no-existing ->
    new-wins, merge.ts:227).

    Only entries whose ``baseUrl`` is worthless-proxy-shaped are removed — a
    foreign/custom entry the user put there is left untouched. A genuinely absent
    ``agents/`` dir or file is a silent no-op. An EXISTING file we cannot clean
    (symlink, foreign-owned, write failure) is a false-secure state — that agent
    still serves the OLD key — so it emits an ``error``-level event (lock reports
    partial failure), never a silent pass.

    Relies on the OpenClaw restart contract, not cross-process locking: nothing
    else writes these files during ``worthless lock``.
    """
    if not providers_set:
        return
    env = os.environ if env is None else env
    openclaw_dir = config_path.parent
    for mj_path in _agent_models_json_paths(openclaw_dir, env):
        try:
            # Never block on a FIFO/device/socket planted at an agent path — it
            # can't be a real projection, and read_config would hang forever.
            # Mirrors audit.recognize_managed_providers / snapshot_hashes.
            if mj_path.exists() and not stat.S_ISREG(mj_path.stat().st_mode):
                continue
            data = _config_mod.read_config(mj_path)
        except OSError:
            continue  # stat probe vanished/unreadable -> nothing to rotate
        except OpenclawConfigError as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.MODELS_JSON_STALE_NOT_REMOVED,
                    level="error",
                    detail=(
                        f"could not read agent models.json at {mj_path} — that agent "
                        f"still serves the OLD key after re-lock: {exc}"
                    ),
                    extra={"path": str(mj_path)},
                )
            )
            continue
        providers = data.get("providers") if isinstance(data, dict) else None
        if not isinstance(providers, dict):
            continue  # absent / non-projection file -> nothing to rotate (silent)
        for provider in providers_set:
            entry = providers.get(provider)
            if not isinstance(entry, dict):
                continue  # provider not projected in this agent -> nothing to do
            if not _is_proxy_url(str(entry.get("baseUrl", "")), resolved_proxy_base_url):
                continue  # foreign / user-customized entry -> not ours, leave it
            try:
                removed = _config_mod.unset_models_json_provider(mj_path, provider)
            except (OpenclawConfigError, OSError) as exc:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.MODELS_JSON_STALE_NOT_REMOVED,
                        level="error",
                        detail=(
                            f"could not remove stale {provider} entry from {mj_path} — "
                            f"that agent still serves the OLD key until fixed: {exc}"
                        ),
                        extra={"provider": provider, "path": str(mj_path)},
                    )
                )
                continue
            if removed:
                events.append(
                    OpenclawIntegrationEvent(
                        code=OpenclawErrorCode.MODELS_JSON_STALE_REMOVED,
                        level="info",
                        detail=(
                            f"removed stale {provider} projection from {mj_path}; OpenClaw "
                            "regenerates it with the new key on next turn — restart the "
                            "running gateway to drop the old key from memory"
                        ),
                        extra={"provider": provider, "path": str(mj_path)},
                    )
                )


# ---------------------------------------------------------------------------
# WOR-796 — scrub the real key cached in OpenClaw's OWN per-agent
# auth-profiles.json / models.json (separate from openclaw.json, which the
# provider loop above already handles).
# ---------------------------------------------------------------------------

_ENV_SECRET_REF_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def _openclaw_state_dir(home_dir: Path) -> Path:
    """OpenClaw's OWN state dir: ``$OPENCLAW_STATE_DIR`` override, else
    ``<home_dir>/.openclaw`` — the same root ``detect()`` already assumes
    for the workspace and ``openclaw.json``.
    """
    override = os.environ.get("OPENCLAW_STATE_DIR")
    if override:
        return Path(override).expanduser()
    return home_dir / ".openclaw"


def _agent_dir_overrides(config: dict | None) -> list[Path]:
    """Extra agent working dirs from openclaw.json's ``agents.list[].agentDir``.

    Real OpenClaw's ``resolveEffectiveAgentDir`` (``agent-dirs.ts``) uses a
    configured ``agentDir`` AS THE EFFECTIVE AGENT DIRECTORY ITSELF — no
    ``agent/`` subdir appended, unlike the default
    ``<state_dir>/agents/<id>/agent/`` convention. Without reading this
    override, an agent configured with a custom ``agentDir`` is invisible
    to directory listing entirely: its ``auth-profiles.json``/``models.json``
    would never be scanned, and a real key there would survive silently
    while ``lock`` still reports success.
    """
    if not isinstance(config, dict):
        return []
    agents_cfg = config.get("agents")
    if not isinstance(agents_cfg, dict):
        return []
    agent_list = agents_cfg.get("list")
    if not isinstance(agent_list, list):
        return []
    overrides: list[Path] = []
    for entry in agent_list:
        if not isinstance(entry, dict):
            continue
        agent_dir = entry.get("agentDir")
        if isinstance(agent_dir, str) and agent_dir.strip():
            overrides.append(Path(agent_dir.strip()).expanduser())
    return overrides


def _agent_auth_store_dirs(state_dir: Path, config: dict | None = None) -> list[Path]:
    """Every dir holding an ``auth-profiles.json``/``models.json`` pair.

    ``main`` is always included even if not yet created; any other agent id
    is discovered by listing ``<state_dir>/agents/`` — real OpenClaw's own
    discovery (``auth-store-paths.ts`` / ``storage-scan.ts``) globs every
    directory there, not just a configured allowlist, so a second agent
    that was never explicitly configured is still in scope for the scrub.
    *config* (parsed ``openclaw.json``, if available) additionally
    contributes any ``agents.list[].agentDir`` overrides — see
    :func:`_agent_dir_overrides` for why that's a distinct discovery path,
    not covered by listing ``agents/``.
    """
    agents_root = state_dir / "agents"
    dirs = {agents_root / "main" / "agent"}
    if agents_root.is_dir():
        for entry in agents_root.iterdir():
            if entry.is_dir():
                dirs.add(entry / "agent")
    dirs.update(_agent_dir_overrides(config))
    return sorted(dirs)


def _scrub_models_json(path: Path, provider: str, secret_ref: str) -> bool:
    """Replace a literal real-key ``providers.<provider>.apiKey`` with
    *secret_ref*. Returns True if a real key was found and replaced.
    Best-effort: any read/parse/lock/symlink failure means "nothing to
    scrub" here — this must never raise (L1/L2 contract), so a detected
    symlink degrades to a no-op rather than propagating and aborting the
    rest of ``lock``.

    flock + symlink refusal (F-CFG-15), same protection as
    :func:`worthless.openclaw.config.set_provider` — an attacker who can
    plant ``models.json`` as a symlink must not be able to redirect this
    write at an arbitrary file via ``os.replace``.
    """
    try:
        with _config_mod._file_lock(path):
            _config_mod._refuse_if_symlink(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            providers = data.get("providers")
            if not isinstance(providers, dict):
                return False
            entry = providers.get(provider)
            if not isinstance(entry, dict):
                return False
            current = entry.get("apiKey")
            if not isinstance(current, str) or not KEY_PATTERN.search(current):
                return False
            entry["apiKey"] = secret_ref
            _config_mod._atomic_write_json(path, data)
            return True
    except (OSError, ValueError, OpenclawConfigError):
        return False


def _scrub_auth_profiles_json(path: Path, provider: str, secret_ref: str) -> bool:
    """Replace a literal real-key ``profiles.<id>.key`` with *secret_ref*
    for every ``type: api_key`` credential matching *provider* (the
    canonical field is ``key``, not ``apiKey``). Same best-effort contract
    and flock + symlink refusal as :func:`_scrub_models_json`.
    """
    try:
        with _config_mod._file_lock(path):
            _config_mod._refuse_if_symlink(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            profiles = data.get("profiles")
            if not isinstance(profiles, dict):
                return False
            changed = False
            for cred in profiles.values():
                if not isinstance(cred, dict) or cred.get("provider") != provider:
                    continue
                if cred.get("type") != "api_key":
                    continue
                current = cred.get("key")
                if isinstance(current, str) and KEY_PATTERN.search(current):
                    cred["key"] = secret_ref
                    changed = True
            if changed:
                _config_mod._atomic_write_json(path, data)
            return changed
    except (OSError, ValueError, OpenclawConfigError):
        return False


def scrub_agent_auth_stores(
    home_dir: Path,
    planned_updates: list[tuple[str, str, str]],
    env_var_by_alias: dict[str, str],
    config: dict | None = None,
) -> list[OpenclawIntegrationEvent]:
    """Scrub any literal real key cached in OpenClaw's OWN per-agent
    ``auth-profiles.json`` / ``models.json``, replacing it with an env
    SecretRef (``${VAR}``) that resolves to shard-A.

    A literal real key in either file short-circuits SecretRef resolution
    in real OpenClaw (``getCustomProviderApiKey`` /
    ``resolveProfileSecretString`` both return an inline literal value
    before ever trying a ref) and is sent upstream directly — a stolen
    home dir yields the real key with zero shards needed, even though
    ``openclaw.json`` (handled separately, by the provider loop above)
    already points at the proxy.

    Best-effort: never raises (L1/L2 contract). A var name that isn't
    uppercase (``^[A-Z][A-Z0-9_]{0,127}$`` — real OpenClaw's own env-ref
    grammar, ``ENV_SECRET_TEMPLATE_RE`` / ``ENV_SECRET_REF_ID_RE`` in
    ``types.secrets.ts``) is refused rather than written: a lowercase
    ``${var}`` is NOT a valid SecretRef in real OpenClaw and would be sent
    upstream as a literal string instead of resolving — trading a real-key
    leak for a different broken state, not actually fixing anything.

    Shard-A must also reach OpenClaw's OWN ``.env``
    (``$OPENCLAW_STATE_DIR/.env`` / ``~/.openclaw/.env`` — NOT the
    project ``.env``, a different file) or the freshly-written ref
    resolves empty once OpenClaw reloads (fails closed — breaks that
    provider's traffic, but leaks nothing).

    *config* (parsed ``openclaw.json``, if the caller already has it) is
    passed to :func:`_agent_auth_store_dirs` so a custom
    ``agents.list[].agentDir`` override is scanned too — otherwise an
    agent configured with a non-default working directory is invisible
    to the scrub entirely, and its cached real key survives silently.
    """
    events: list[OpenclawIntegrationEvent] = []
    state_dir = _openclaw_state_dir(home_dir)
    agent_dirs = _agent_auth_store_dirs(state_dir, config)

    seed_vars: dict[str, str] = {}
    for provider, alias, shard_a_str in planned_updates:
        var_name = env_var_by_alias.get(alias)
        if not var_name or not _ENV_SECRET_REF_ID_RE.match(var_name):
            # WOR-796: a present-but-non-uppercase var name is the leak-risk case
            # — a lowercase ``${var}`` is not a valid SecretRef, so we (correctly)
            # refuse to write it, but that means this provider's cached real key
            # is NOT scrubbed while openclaw.json still reads "locked". Emit a loud
            # event so protection can't silently degrade (scrub-correctness gap #1).
            # A wholly-missing var name (nothing to point a ref at) stays silent.
            if var_name:
                events.append(
                    OpenclawIntegrationEvent(
                        # warn-level, NOT error: worthless already only warns on a
                        # non-uppercase key var for .env locking (CANONICAL_KEY_VAR_RE),
                        # so failing the whole lock here (has_failure → exit 73) would be
                        # inconsistent. The loud [WARN] in lock's output is what closes the
                        # silent-degradation gap.
                        code=OpenclawErrorCode.AGENT_AUTH_STORE_SCRUB_SKIPPED,
                        level="warn",
                        detail=(
                            f"did NOT scrub {provider!r}'s cached real key — its key "
                            f"variable {var_name!r} is not an uppercase SecretRef id "
                            "([A-Z][A-Z0-9_]*). Rename it uppercase in your .env and "
                            "re-lock; the real key is still live in OpenClaw's agent cache."
                        ),
                        extra={"provider": provider, "var_name": var_name},
                    )
                )
            continue
        secret_ref = f"${{{var_name}}}"
        scrubbed_any = False
        for agent_dir in agent_dirs:
            if _scrub_models_json(agent_dir / "models.json", provider, secret_ref):
                scrubbed_any = True
            if _scrub_auth_profiles_json(agent_dir / "auth-profiles.json", provider, secret_ref):
                scrubbed_any = True
        if scrubbed_any:
            seed_vars[var_name] = shard_a_str
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.AGENT_AUTH_STORE_SCRUBBED,
                    level="info",
                    detail=(
                        f"scrubbed cached real key for {provider!r} from agent auth "
                        "stores (auth-profiles.json / models.json)"
                    ),
                    extra={"provider": provider},
                )
            )

    if seed_vars:
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key
        from worthless.cli.errors import UnsafeRewriteRefused

        for var_name, shard_a_str in seed_vars.items():
            try:
                add_or_rewrite_env_key(state_dir / ".env", var_name, shard_a_str)
            except (OSError, ValueError, UnsafeRewriteRefused):
                # Best-effort (L1/L2): the JSON scrub already happened; a
                # failure to seed OpenClaw's own .env fails closed (the ref
                # resolves empty on reload) rather than leaking anything.
                pass

    return events


def _restore_models_json(path: Path, provider: str, secret_ref: str, plaintext: str) -> bool:
    """Undo :func:`_scrub_models_json`: swap the EXACT *secret_ref* back to
    *plaintext*. Matching the exact ref (not "any env ref") avoids
    clobbering some other SecretRef the user configured independently.
    Same best-effort contract + flock + symlink refusal (F-CFG-15) as the
    scrub side — never raises.
    """
    try:
        with _config_mod._file_lock(path):
            _config_mod._refuse_if_symlink(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            providers = data.get("providers")
            if not isinstance(providers, dict):
                return False
            entry = providers.get(provider)
            if not isinstance(entry, dict) or entry.get("apiKey") != secret_ref:
                return False
            entry["apiKey"] = plaintext
            _config_mod._atomic_write_json(path, data)
            return True
    except (OSError, ValueError, OpenclawConfigError):
        return False


def _restore_auth_profiles_json(path: Path, provider: str, secret_ref: str, plaintext: str) -> bool:
    """Undo :func:`_scrub_auth_profiles_json`, same exact-ref matching,
    best-effort contract, and flock + symlink refusal.
    """
    try:
        with _config_mod._file_lock(path):
            _config_mod._refuse_if_symlink(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            profiles = data.get("profiles")
            if not isinstance(profiles, dict):
                return False
            changed = False
            for cred in profiles.values():
                if not isinstance(cred, dict) or cred.get("provider") != provider:
                    continue
                if cred.get("key") == secret_ref:
                    cred["key"] = plaintext
                    changed = True
            if changed:
                _config_mod._atomic_write_json(path, data)
            return changed
    except (OSError, ValueError, OpenclawConfigError):
        return False


def restore_agent_auth_stores(
    home_dir: Path,
    provider: str,
    var_name: str,
    plaintext: str,
    config: dict | None = None,
) -> bool:
    """Undo :func:`scrub_agent_auth_stores` for one provider: swap the
    exact ``${var_name}`` ref this tool wrote back to *plaintext*.
    Best-effort: never raises. *config* is threaded to
    :func:`_agent_auth_store_dirs` for the same ``agentDir``-override
    reason as the scrub side — see :func:`_agent_dir_overrides`.
    """
    state_dir = _openclaw_state_dir(home_dir)
    secret_ref = f"${{{var_name}}}"
    changed = False
    for agent_dir in _agent_auth_store_dirs(state_dir, config):
        if _restore_models_json(agent_dir / "models.json", provider, secret_ref, plaintext):
            changed = True
        if _restore_auth_profiles_json(
            agent_dir / "auth-profiles.json", provider, secret_ref, plaintext
        ):
            changed = True
    return changed


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


def preview_unrecognized(
    planned_updates: list[tuple[str, str, str]],
    *,
    proxy_base_url: str,
    managed_aliases: set[str] | None,
) -> list[str]:
    """Provider names whose existing OpenClaw entry would be adopted-or-skipped.

    WOR-650: the CLI calls this BEFORE any write so it can prompt the human
    once for the unrecognized proxy-shaped entries (a synced config, reinstall,
    or something else). Read-only — it classifies each planned provider via the
    same read + :func:`_classify_adoption` path the real write uses, with a
    no-consent probe policy, and returns the providers that produced an
    adoption event. The binding decision is still re-made at write time off its
    own read inside :func:`apply_lock` (TOCTOU-safe).
    """
    state = detect()
    if not state.present:
        return []
    config_path = _resolve_active_config_path(state, state.home_dir)
    probe = AdoptionPolicy(managed_aliases=managed_aliases, adopt_unrecognized=False)
    unrecognized: list[str] = []
    for provider, _alias, _shard in planned_updates:
        existing, read_err = _get_provider_for_lock(config_path, provider)
        if read_err is not None:
            continue
        _skip, event = _classify_adoption(
            existing,
            provider=provider,
            resolved_proxy_base_url=proxy_base_url,
            policy=probe,
        )
        if event is not None:
            unrecognized.append(provider)
    return unrecognized


def _apply_lock_scrub_agent_stores(
    state: IntegrationState,
    planned_updates: list[tuple[str, str, str]],
    providers_set: list[str],
    env_var_by_alias: dict[str, str] | None,
    original_config: dict | None,
) -> list[OpenclawIntegrationEvent]:
    """Stage A2 of apply_lock: scrub agent auth stores for cleanly-written
    providers. WOR-796. Only providers whose openclaw.json write actually
    succeeded (survived any Stage A rollback) — a provider we didn't
    cleanly write there shouldn't have its separate agent-cache entry
    touched either. Extracted to keep apply_lock within xenon's budget.

    *original_config* is the already-read pre-write openclaw.json snapshot
    (read for the Stage A rollback path) — reused here so
    ``agents.list[].agentDir`` overrides are discovered without a second
    read of the same file.
    """
    if not env_var_by_alias or state.home_dir is None:
        return []
    written_updates = [
        (provider, alias, shard_a)
        for provider, alias, shard_a in planned_updates
        if provider in providers_set
    ]
    if not written_updates:
        return []
    return scrub_agent_auth_stores(
        state.home_dir, written_updates, env_var_by_alias, original_config
    )


def _repoint_primary_off_decoy(config_path: Path, provider: str, decoy_name: str) -> None:
    """Repoint the default model off a just-removed decoy.

    ``agents.defaults.model.primary`` of ``worthless-openai/gpt-4o`` becomes
    ``openai/gpt-4o``. Only fires on an exact ``worthless-<provider>/`` prefix;
    a primary already pointing at the real provider (or anything else) is left
    untouched.
    """
    data = _config_mod.read_config(config_path)
    if not isinstance(data, dict):
        return
    agents = data.get("agents")
    defaults = agents.get("defaults") if isinstance(agents, dict) else None
    model = defaults.get("model") if isinstance(defaults, dict) else None
    primary = model.get("primary") if isinstance(model, dict) else None
    prefix = f"{decoy_name}/"
    if isinstance(primary, str) and primary.startswith(prefix):
        _config_mod.repoint_model_primary(
            config_path, old_ref=primary, new_ref=f"{provider}/{primary[len(prefix) :]}"
        )


def _apply_lock_migrate_legacy_decoy(
    config_path: Path,
    resolved_proxy_base_url: str,
    planned_updates: list[tuple[str, str, str]],
    events: list[OpenclawIntegrationEvent],
) -> bool:
    """Heal a legacy decoy-layout install in place (WOR-656 F6).

    Old worthless installs wrote a separate proxy-shaped
    ``models.providers.worthless-<p>`` decoy beside the UNTOUCHED original
    ``<p>``. The current design rewrites the original in place (Stage A), so on
    the next lock we first delete the stale decoy and, when the default model
    still points at it, repoint ``agents.defaults.model.primary`` back to the
    real provider.

    Only providers actually being locked this run (``planned_updates``) are
    considered, and only when the sibling ``worthless-<p>`` entry is one we
    recognize as OUR proxy decoy (``_is_proxy_url``) — never a user's own
    ``worthless-``-named provider pointing elsewhere.

    Returns ``True`` when a write failed and the whole transaction must roll
    back (the caller restores the pre-lock config byte-identically and skips
    Stage A); ``False`` on success or a clean no-op. NEVER logs the decoy's
    apiKey (its shard-A half) — SR-04.
    """
    for provider, alias, _shard_a in planned_updates:
        decoy_name = f"worthless-{provider}"
        try:
            decoy = _config_mod.get_provider(config_path, decoy_name)
        except (OSError, OpenclawConfigError):
            # Can't read the config to look for a decoy. Skip migration and let
            # Stage A handle it: Stage A surfaces CONFIG_UNREADABLE and aborts
            # the write byte-identically (WOR-516). Returning rollback here would
            # SKIP Stage A and swallow that event — re-opening the WOR-516 bug
            # where an unreadable config could be deleted by a {}-snapshot rollback.
            return False
        if not isinstance(decoy, dict):
            continue  # no decoy for this provider — new-design layout, nothing to heal
        decoy_base = decoy.get("baseUrl")
        if not isinstance(decoy_base, str) or not _is_proxy_url(
            decoy_base, resolved_proxy_base_url
        ):
            continue  # a user's own ``worthless-``-named provider, not our decoy — leave it
        try:
            # Repoint BEFORE deleting the decoy: a hard crash between the two
            # writes then leaves an idempotently-recoverable state (decoy still
            # present → next lock re-heals) rather than a dangling model.primary
            # pointing at a removed provider that no tooling self-heals.
            _repoint_primary_off_decoy(config_path, provider, decoy_name)
            _config_mod.unset_provider(config_path, decoy_name)
        except (OSError, OpenclawConfigError) as exc:
            events.append(
                OpenclawIntegrationEvent(
                    code=OpenclawErrorCode.WRITE_FAILED,
                    level="error",
                    detail=(
                        f"failed to migrate the legacy '{decoy_name}' decoy — rolling back; "
                        f"fix the cause and re-run worthless lock ({type(exc).__name__})"
                    ),
                    extra={"provider": provider},
                )
            )
            return True
        events.append(
            OpenclawIntegrationEvent(
                code=OpenclawErrorCode.LEGACY_DECOY_MIGRATED,
                level="info",
                detail=(
                    f"healed legacy decoy layout: removed '{decoy_name}'; '{provider}' now "
                    f"routes through the proxy (alias {_sanitize_alias_for_log(alias)})"
                ),
                extra={
                    "provider": provider,
                    "alias": _sanitize_alias_for_log(_alias_from_base_url(decoy_base) or ""),
                },
            )
        )
    return False


def apply_lock(
    planned_updates: list[tuple[str, str, str]],
    *,
    proxy_base_url: str | None = None,
    adoption_policy: AdoptionPolicy | None = None,
    env_var_by_alias: dict[str, str] | None = None,
) -> OpenclawApplyResult:
    """Wire OpenClaw to route through worthless. Idempotent. Best-effort.

    Stage 3 of ``worthless lock``. Runs AFTER .env + DB are committed.
    Per L1/L2: failures here NEVER roll back lock-core. They surface as
    structured events in the returned :class:`OpenclawApplyResult`.

    Args:
        planned_updates: list of ``(provider, alias, shard_a)`` triples for
            keys that were just locked.  ``shard_a`` is that alias's shard-A
            — the same format-preserving half written to ``.env`` — written
            PER-ALIAS (each alias gets its own; they do NOT share one token).
            Safe to sit in the config only insofar as it cannot be logged to
            a leak (SR-04) and cannot reconstruct the key without shard-B; it
            remains a LIVE replay credential until the key is retired (see the
            retired-key tripwire in ``proxy/app.py``).
        proxy_base_url: override for the proxy host. Defaults to
            ``http://127.0.0.1:8787`` (the canonical worthless port).
        env_var_by_alias: WOR-796 — maps each alias to the ``*_API_KEY``
            env var holding shard-A in the project ``.env``. Used by
            :func:`scrub_agent_auth_stores` to build the ``${VAR}`` ref
            written into agent auth stores. ``None``/missing entries skip
            the scrub for that alias (best-effort, never blocks lock-core).

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

    # ---- Stage A(pre): heal legacy decoy layout (WOR-656 F6) -------------
    # Old installs wrote a separate ``worthless-<p>`` decoy beside the
    # untouched original ``<p>``. Delete our stale decoy (and repoint a
    # decoy-pointing default model) BEFORE Stage A rewrites the original in
    # place. Runs under apply_lock's existing ``original_config`` rollback
    # umbrella, so a mid-migration write failure restores byte-identically and
    # Stage A is skipped.
    rollback_needed = _apply_lock_migrate_legacy_decoy(
        config_path,
        resolved_proxy_base_url,
        planned_updates,
        events,
    )

    # ---- Stage A: write providers ----------------------------------------
    # F-CFG-13 / DV-01/DV-02 handling is inside _apply_lock_write_providers.
    # Extracted to keep apply_lock within xenon's complexity budget (rank C).
    if not rollback_needed:
        rollback_needed = _apply_lock_write_providers(
            config_path,
            resolved_proxy_base_url,
            planned_updates,
            events,
            providers_set,
            providers_skipped,
            adoption_policy,
        )

    # ---- Transactional rollback on write failure -------------------------
    if rollback_needed:
        _apply_lock_rollback(config_path, original_config, events, providers_set, providers_skipped)

    # ---- Stage A.5: neutralize stale agent models.json projections -------
    # WOR-777 Layer 2: the provider write above rotated openclaw.json, but
    # OpenClaw's per-agent models.json cache would merge-preserve the OLD
    # shard-A. Remove our stale entry so the next agent turn regenerates it
    # with the new key. Operates only on what Stage A actually wrote
    # (providers_set is empty after a rollback, so this no-ops).
    #
    # Runs BEFORE Stage A2 (WOR-796) deliberately: on a re-lock, the ONLY
    # overlap between the two is a stale entry whose baseUrl already points
    # at our proxy (this neutralize's own trigger) AND whose OLD shard-A
    # apiKey happens to still look key-shaped (format-preserving split —
    # WOR-796's trigger). Deleting it here first means WOR-796's scrub finds
    # nothing left to touch for that entry (no-op, not a mismatch) instead
    # of scrubbing a value that then gets deleted anyway. A first-ever lock
    # (agent cache baseUrl = the REAL upstream, never touched this proxy
    # before) never matches this neutralize's baseUrl check at all — that
    # case is WOR-796's alone to handle.
    _apply_lock_neutralize_models_json(config_path, resolved_proxy_base_url, providers_set, events)

    # ---- Stage A2: scrub the real key cached in agent auth stores --------
    # WOR-796. Extracted to keep apply_lock within xenon's complexity budget.
    events.extend(
        _apply_lock_scrub_agent_stores(
            state, planned_updates, providers_set, env_var_by_alias, original_config
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
        original_config_snapshot=original_config,
    )


def _apply_unlock_stage_a(
    config_path: Path,
    restores: list[OcRestore],
    events: list[OpenclawIntegrationEvent],
    providers_restored: list[str],
    providers_skipped: list[tuple[str, str]],
    agent_cache_blocked: set[str],
) -> bool:
    """Stage A of apply_unlock: restore each provider's ORIGINAL entry.

    WOR-621 F2. F1 made ``lock`` rewrite the original entry (proxy +
    shard-A), so the undo is no longer "remove a ``worthless-*`` decoy" — it
    RESTORES the original entry verbatim from the key-redacted rollback
    record (:func:`build_oc_rollback_entry_record`), offline.

    Fail-CLOSED (decision 3): a corrupt/missing record, or a plaintext
    restore with no reconstructed key, leaves the provider on the proxy and
    is surfaced as a skip — never a silent pass, never a bad/plaintext
    write.

    Returns ``True`` if a write failure occurred and rollback is required.
    Mutates providers_restored / providers_skipped / events in place.

    Deliberately does NOT touch the WOR-796 agent-cache surface, and does
    NOT zero ``restore.plaintext_key`` — the caller (:func:`apply_unlock`)
    needs it intact afterward for :func:`_restore_agent_auth_stores_after_unlock`,
    which must run only once this whole stage's rollback outcome is known
    (a mid-stage rollback here reverts EVERY provider processed so far —
    restoring an earlier provider's agent cache to plaintext before that is
    decided would leave it exposed under a later provider's failure).

    *agent_cache_blocked* is mutated with any provider whose openclaw.json
    restore hit a REAL problem (tamper, unreadable config, corrupt key) —
    restoring ITS agent cache to plaintext would leave it mismatched
    against an openclaw.json entry that's still on the proxy. The benign
    "no original entry existed" no-op (``record is None`` with no MAC) is
    deliberately NOT added here — that provider's agent cache is still
    safe and expected to restore, even though it never touches
    ``providers_restored`` (there's nothing for THIS function to do in
    openclaw.json for it either way).
    """
    for restore in restores:
        provider = restore.provider
        plaintext_key = restore.plaintext_key
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
            agent_cache_blocked.add(provider)
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
                agent_cache_blocked.add(provider)
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
                agent_cache_blocked.add(provider)
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
            agent_cache_blocked.add(provider)
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
    return False


def _agent_cache_eligible_providers(
    restores: list[OcRestore],
    config_missing: bool,
    rollback_needed: bool,
    agent_cache_blocked: set[str],
) -> set[str] | None:
    """Which providers' agent caches are safe to restore. Extracted to
    keep :func:`apply_unlock` under xenon's budget.

    - ``config_missing``: Stage A never ran at all — nothing to roll back,
      restore unconditionally (``None``).
    - ``rollback_needed``: a write failure rolled openclaw.json back to its
      pre-unlock snapshot for EVERY provider processed this stage — block
      everyone rather than risk a plaintext cache next to a locked entry.
    - otherwise: every provider except the ones Stage A specifically
      flagged as a real problem (tamper/unreadable/corrupt) is eligible —
      includes providers with no original openclaw.json entry at all (a
      benign no-op for Stage A, never added to ``providers_restored``, but
      still fully safe to restore in the agent cache).
    """
    if config_missing:
        return None
    if rollback_needed:
        return set()
    return {r.provider for r in restores} - agent_cache_blocked


def _restore_agent_auth_stores_after_unlock(
    restores: list[OcRestore],
    home_dir: Path | None,
    config: dict | None,
    eligible: set[str] | None,
) -> None:
    """WOR-796: restore the agent-cache surface for each eligible provider,
    then zero every restore's plaintext_key — the single point where all
    restores are known final, deliberately called only AFTER Stage A's
    rollback outcome (if any) is resolved.

    *eligible* is ``None`` to restore unconditionally for every restore —
    Stage A never ran this pass (openclaw.json missing/unreadable/symlinked),
    so there is nothing there to roll back and the agent cache is a fully
    separate surface. Otherwise *eligible* is the set of providers whose
    openclaw.json restore is FINAL (Stage A completed with no rollback) —
    ``rollback_config`` reverts the WHOLE file to its pre-unlock snapshot,
    so restoring an earlier provider's cache to plaintext before knowing
    the stage won't roll back would leave that cache exposed while
    openclaw.json reverts to its locked shape for every provider (Bugbot
    HIGH finding).
    """
    try:
        if home_dir is None:
            return
        for restore in restores:
            if eligible is not None and restore.provider not in eligible:
                continue
            plaintext_key = restore.plaintext_key
            if not restore.var_name or plaintext_key is None:
                continue
            try:
                restore_agent_auth_stores(
                    home_dir,
                    restore.provider,
                    restore.var_name,
                    plaintext_key.decode("utf-8"),
                    config,
                )
            except UnicodeDecodeError:
                pass
    finally:
        for restore in restores:
            if restore.plaintext_key is not None:
                zero_buf(restore.plaintext_key)


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
    original_config_snapshot: dict | None = None
    agent_cache_blocked: set[str] = set()
    rollback_needed = False
    if not config_missing:
        try:
            original_config_snapshot = _config_mod.read_config(config_path)
        except (OpenclawConfigError, OSError):
            original_config_snapshot = None
        rollback_needed = _apply_unlock_stage_a(
            config_path,
            restores,
            events,
            providers_restored,
            providers_skipped,
            agent_cache_blocked,
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

    # WOR-796 (Bugbot fixes): restore the agent-cache surface now that
    # Stage A's rollback outcome (if any) is fully resolved — see
    # _restore_agent_auth_stores_after_unlock's docstring for why this must
    # run AFTER, never during/before, Stage A's per-provider loop.
    _restore_agent_auth_stores_after_unlock(
        restores,
        state.home_dir,
        original_config_snapshot,
        eligible=_agent_cache_eligible_providers(
            restores, config_missing, rollback_needed, agent_cache_blocked
        ),
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
    compares each provider's entry ``baseUrl`` against the expected URL for
    the current proxy host. (WOR-621 F1: the entry is the bare provider name,
    e.g. ``openai`` — not a ``worthless-<provider>`` decoy.)

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

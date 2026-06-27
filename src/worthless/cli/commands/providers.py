"""``worthless providers`` subcommands (worthless-8rqs Phase 2).

Two operations:

- ``providers list`` — print the merged registry (bundled + user override).
  Plain text by default; ``-j`` / ``--json`` emits machine-readable output.
- ``providers register`` — append a custom provider to ``~/.worthless/providers.toml``.
  Refuses bundled name conflicts (suggest a different name); refuses bundled
  URL conflicts unless ``--force``; validates URL scheme + netloc and
  protocol enum.

Implementation notes
- The user file is plain data, not a secret — written with mode 0644.
- Atomic write: stage to ``.tmp`` and ``rename`` on success.
- We hand-build the TOML for the new entry; ``tomllib`` is read-only and we
  don't want to take on ``tomli_w`` as a dep just for one stanza.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import typer

from worthless.cli.console import get_console
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.providers import (
    ProviderEntry,
    bundled_names,
    load_bundled,
    load_user,
    lookup_by_url,
    user_names,
    user_registry_path,
)

_ALLOWED_PROTOCOLS = ("openai", "anthropic")
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def _validate_name(name: str) -> str:
    if not _NAME_RE.match(name):
        raise WorthlessError(
            ErrorCode.INVALID_INPUT,
            f"provider name {name!r} must be alphanumeric with optional - or _",
        )
    return name


def _validate_url(url: str) -> str:
    """Accept http(s) URLs with non-empty hostname; reject everything else."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise WorthlessError(ErrorCode.INVALID_INPUT, f"invalid URL: {exc}") from exc
    if parsed.scheme not in ("http", "https"):
        raise WorthlessError(
            ErrorCode.INVALID_INPUT,
            f"URL scheme must be http or https, got {parsed.scheme!r}",
        )
    if not parsed.netloc:
        raise WorthlessError(ErrorCode.INVALID_INPUT, "URL has empty host (netloc)")
    return url


def _refuse_name_collision(name: str, taken: set[str], suffix_hint: str) -> None:
    """Raise INVALID_INPUT if ``name`` is in ``taken``. Used by ``register``
    to refuse both bundled-name conflicts and user-name re-registrations
    with the same error shape and the same call shape — keeps the error
    format from drifting between the two checks (and makes ``--json``
    error rendering consistent across the two paths)."""
    if name in taken:
        raise WorthlessError(
            ErrorCode.INVALID_INPUT,
            f"name {name!r} {suffix_hint}",
        )


def _validate_protocol(protocol: str) -> str:
    if protocol not in _ALLOWED_PROTOCOLS:
        raise WorthlessError(
            ErrorCode.INVALID_INPUT,
            f"protocol must be one of {_ALLOWED_PROTOCOLS}, got {protocol!r}",
        )
    return protocol


def _atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """Write ``content`` to ``path`` atomically. Mode 0644 is fine for the
    registry — it's public data, not a secret.

    UTF-8 explicit (TOML spec mandates UTF-8). Without ``encoding=``,
    ``write_text`` falls back to the platform locale — cp1252 on a
    fresh Windows install — which would silently corrupt non-ASCII
    provider names / URLs. Same reasoning the loader uses on read.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.chmod(mode)
    tmp.replace(path)


def _append_provider_block(name: str, url: str, protocol: str) -> str:
    """Build the TOML stanza for one provider entry. URL contains no quotes
    in any reasonable case (validated above), but escape defensively."""
    safe_url = url.replace("\\", "\\\\").replace('"', '\\"')
    return f'\n[provider.{name}]\nurl = "{safe_url}"\nprotocol = "{protocol}"\n'


def _format_entry_for_list(entry: ProviderEntry, source: str) -> dict[str, str]:
    return {
        "name": entry.name,
        "url": entry.url,
        "protocol": entry.protocol,
        "source": source,
    }


def register_providers_commands(app: typer.Typer) -> None:
    """Register the ``providers`` subcommand group on the Typer app."""
    providers_group = typer.Typer(
        help="Manage the LLM-provider registry (URL → wire-protocol mapping).",
        no_args_is_help=True,
    )
    app.add_typer(providers_group, name="providers")

    @providers_group.command("list")
    @error_boundary
    def list_providers() -> None:
        """Print the merged registry (bundled + ~/.worthless/providers.toml)."""
        console = get_console()
        bundled = load_bundled()
        user = load_user()

        rows: list[dict[str, str]] = []
        for entry in bundled.values():
            # If user has same URL, the user entry will replace this one below.
            if entry.url not in user:
                rows.append(_format_entry_for_list(entry, "bundled"))
        for entry in user.values():
            rows.append(_format_entry_for_list(entry, "user"))

        # Stable order: bundled first, then user, alphabetical by name within each group.
        rows.sort(key=lambda r: (r["source"] != "bundled", r["name"]))

        if console.json_mode:
            sys.stdout.write(json.dumps(rows, indent=2) + "\n")
            return

        # Human-readable table.
        name_w = max((len(r["name"]) for r in rows), default=8) + 2
        proto_w = max((len(r["protocol"]) for r in rows), default=8) + 2
        src_w = 8
        sys.stdout.write(f"{'NAME':<{name_w}}{'PROTOCOL':<{proto_w}}{'SOURCE':<{src_w}}URL\n")
        for r in rows:
            sys.stdout.write(
                f"{r['name']:<{name_w}}{r['protocol']:<{proto_w}}{r['source']:<{src_w}}{r['url']}\n"
            )

    @providers_group.command("register")
    @error_boundary
    def register_provider(
        name: str = typer.Option(..., "--name", help="Provider name (alphanumeric, - and _ ok)"),
        url: str = typer.Option(..., "--url", help="Upstream URL (http/https)"),
        protocol: str = typer.Option(..., "--protocol", help="Wire protocol: openai or anthropic"),
        force: bool = typer.Option(
            False, "--force", help="Override a bundled URL (otherwise refused)"
        ),
    ) -> None:
        """Append a provider to ``~/.worthless/providers.toml``."""
        _validate_name(name)
        _validate_url(url)
        _validate_protocol(protocol)

        # Two name-collision sources, same shape: refuse and suggest a
        # qualified alternative. Bundled names (``openai``, ``anthropic``,
        # …) are reserved. User names are refused too — otherwise this
        # command silently appends a duplicate ``[provider.<name>]`` table
        # to the user TOML, which TOML forbids; the next ``load_user()``
        # would raise and break every providers/lock flow until the user
        # hand-edits ``~/.worthless/providers.toml``.
        _refuse_name_collision(
            name,
            bundled_names(),
            f"conflicts with a bundled provider; pick a different name (e.g., {name}-staging)",
        )
        _refuse_name_collision(
            name,
            user_names(),
            f"is already registered in {user_registry_path()}; "
            f"remove it from that file first, or pick a different name "
            f"(e.g., {name}-v2)",
        )
        # CodeRabbit catch on M14 review: use lookup_by_url (which
        # normalises trailing slash) instead of `url in bundled` (which
        # is exact-string against the already-normalised bundled keys).
        # Without this, a user passing `--url https://api.openai.com/v1/`
        # (extra slash) would bypass the bundled-URL collision check
        # because bundled stores the URL without trailing slash. The new
        # entry then normalises on load and silently overrides the
        # bundled `openai` entry — including swapping its protocol,
        # which would misroute adapter dispatch. lookup_by_url applies
        # the same normalisation to the candidate URL and to the
        # registry, so the comparison is symmetric.
        existing = lookup_by_url(url)
        if existing is not None and existing.name in bundled_names() and not force:
            raise WorthlessError(
                ErrorCode.INVALID_INPUT,
                f"URL {url!r} is already bundled (under name "
                f"{existing.name!r}); pass --force to override locally",
            )

        path = user_registry_path()
        # UTF-8 explicit; default would use platform locale and corrupt
        # any non-ASCII content already in the user's providers.toml.
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        new_block = _append_provider_block(name, url, protocol)
        _atomic_write_text(path, existing + new_block)

        console = get_console()
        if console.json_mode:
            sys.stdout.write(
                json.dumps({"name": name, "url": url, "protocol": protocol, "path": str(path)})
                + "\n"
            )
        else:
            sys.stdout.write(f"Registered provider {name!r} at {path}\n")

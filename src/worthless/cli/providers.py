"""Provider URL → protocol registry loader (worthless-8rqs).

The registry maps known LLM-provider upstream URLs (e.g.,
``https://api.openai.com/v1``) to a wire protocol (``openai`` /
``anthropic``). ``worthless lock`` consults it when scanning ``.env``
files, so the user doesn't have to specify ``--protocol`` for the common
case.

Two sources, merged at load time:

1. **Bundled** — ``src/worthless/providers.toml`` ships with the package.
   Source of truth for upstream-blessed providers.
2. **User override** — ``~/.worthless/providers.toml`` (optional). Allows
   users to register internal LLM gateways or staging endpoints without
   modifying the package.

On URL conflict, the user entry wins. A malformed user file is skipped
with a logged warning (the bundled registry alone is enough to keep
``worthless lock`` working).
"""

from __future__ import annotations

import logging
import sys

# Project requires Python >=3.10 (pyproject.toml). The resources.files()
# API we use was added in 3.9. Semgrep's python37 compatibility rule
# fires on importlib.resources regardless — suppress the false positive.
# nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from importlib import resources
from pathlib import Path
from typing import NamedTuple

# Python 3.10 ships without ``tomllib``; ``tomli`` is the canonical backport
# and is already a conditional dependency in ``pyproject.toml``.
if sys.version_info >= (3, 11):  # pragma: no cover — version branch
    import tomllib
else:  # pragma: no cover — version branch
    import tomli as tomllib

logger = logging.getLogger(__name__)


class ProviderEntry(NamedTuple):
    """One row in the provider registry."""

    name: str
    url: str
    protocol: str  # "openai" | "anthropic"


def _user_registry_path() -> Path:
    """Return the user-override path. Reads ``HOME`` so tests can redirect."""
    return Path.home() / ".worthless" / "providers.toml"


def _strip_trailing_slash(url: str) -> str:
    """Drop a single trailing slash so ``…/v1`` and ``…/v1/`` are the same key.

    Registry lookups are exact-string keyed. Without this, a user whose
    ``.env`` has ``OPENAI_BASE_URL=https://api.openai.com/v1/`` (extra
    slash) would fail M3's lock-time registry membership check even
    though the URL is the bundled OpenAI endpoint.

    Scope: trailing slash only. Scheme/host case folding and explicit
    default-port stripping (``:443`` on https) are NOT handled here —
    file as a follow-up if real users hit those forms. Keeping the name
    honest about what this function does.
    """
    if url.endswith("/") and not url.endswith("://"):
        return url[:-1]
    return url


def _parse_toml_to_entries(raw: dict) -> dict[str, ProviderEntry]:
    """Convert a parsed-TOML dict into a URL-keyed entry map.

    Expected structure:
        [provider.<name>]
        url = "..."
        protocol = "..."

    Defensive against malformed input: if ``provider`` is something
    other than a table (e.g. a stray ``provider = "string"`` line at
    file root), return ``{}`` and log a warning. ``load_user``'s
    docstring promises ``{}`` on any failure mode — this guard makes
    that promise true for the "section is wrong shape" case too.
    """
    out: dict[str, ProviderEntry] = {}
    providers = raw.get("provider", {})
    if not isinstance(providers, dict):
        logger.warning(
            "provider section has invalid shape (%s); falling back to "
            "empty registry. Expected [provider.<name>] tables.",
            type(providers).__name__,
        )
        return out
    for name, body in providers.items():
        if not isinstance(body, dict):
            continue
        url = body.get("url")
        protocol = body.get("protocol")
        if not isinstance(url, str) or not isinstance(protocol, str):
            logger.warning("provider %r has missing url or protocol; skipping", name)
            continue
        normalized = _strip_trailing_slash(url)
        out[normalized] = ProviderEntry(name=name, url=normalized, protocol=protocol)
    return out


def load_bundled() -> dict[str, ProviderEntry]:
    """Load ``src/worthless/providers.toml`` shipped with the package.

    UTF-8 is explicit (TOML spec mandates it). Without ``encoding=``,
    ``read_text()`` falls back to the platform locale — cp1252 on a
    fresh Windows install — which would fail on any non-ASCII character
    in the bundled file. Same reasoning applies to ``load_user()``.
    """
    bundle_text = (
        resources.files("worthless").joinpath("providers.toml").read_text(encoding="utf-8")
    )
    parsed = tomllib.loads(bundle_text)
    return _parse_toml_to_entries(parsed)


def load_user() -> dict[str, ProviderEntry]:
    """Load the optional user override, returning {} on any failure mode."""
    path = _user_registry_path()
    if not path.is_file():
        return {}
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning(
            "could not parse user providers.toml at %s — falling back to bundled registry only: %s",
            path,
            exc,
        )
        return {}
    return _parse_toml_to_entries(parsed)


def load_registry() -> dict[str, ProviderEntry]:
    """Return the merged registry: bundled with user-override layered on top."""
    return {**load_bundled(), **load_user()}


def lookup_by_url(url: str) -> ProviderEntry | None:
    """Return the entry for a given URL, or ``None`` if unknown.

    Strips a trailing slash on the input the same way registry entries
    have it stripped at load time, so callers passing ``https://x.com/v1/``
    match an entry stored as ``https://x.com/v1``.
    """
    return load_registry().get(_strip_trailing_slash(url))


def bundled_names() -> set[str]:
    """Return the set of names registered in the bundled file (used to refuse
    name collisions when registering a user provider)."""
    return {e.name for e in load_bundled().values()}


def user_names() -> set[str]:
    """Return the set of names already registered in the user file (used to
    refuse re-registering an existing user provider — see CodeRabbit #7
    on PR #127). Symmetric with ``bundled_names``."""
    return {e.name for e in load_user().values()}


def user_registry_path() -> Path:
    """Public accessor for ``~/.worthless/providers.toml``."""
    return _user_registry_path()


def lookup_by_name(name: str) -> ProviderEntry | None:
    """Return the entry for a given provider name, or ``None`` if unknown.
    Used by ``worthless lock`` to fall back to the canonical URL when the
    user's ``.env`` has an API key but no ``*_BASE_URL`` companion."""
    for entry in load_registry().values():
        if entry.name == name:
            return entry
    return None

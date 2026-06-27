"""Worthless integration with OpenClaw.

Canonical home for the openclaw.json reader/writer (Phase 1) plus the
detect/install plumbing (Phase 2.a) that ``worthless lock``/``unlock``/
``doctor`` will silently invoke (Phases 2.b–2.d). Per locked decision
L6 there is no ``worthless openclaw`` namespace — integration is
plumbing inside existing commands, not a new user-facing surface.
"""

from worthless.openclaw.config import (
    OpenclawConfigError,
    get_provider,
    locate_config_path,
    read_config,
    set_provider,
    unset_provider,
)

__all__ = [
    "OpenclawConfigError",
    "get_provider",
    "locate_config_path",
    "read_config",
    "set_provider",
    "unset_provider",
]

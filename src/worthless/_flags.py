"""Cross-cutting feature flags read by both CLI and proxy layers.

Lives at the package root because the same env vars are read from both
``worthless.cli`` and ``worthless.proxy``; putting them in either subtree
would create a one-direction dependency that does not match the runtime
relationship between the two.

The flag readers DO strip whitespace — a value like ``"1 "`` from a copy-
pasted operator manifest MUST turn a fail-secure-on flag on, not silently
leave it off. That asymmetry vs ``worthless.proxy.config._env_bool``
(which deliberately does NOT strip, because ``WORTHLESS_ALLOW_INSECURE``'s
fail-secure direction is the opposite) is intentional — see that helper's
docstring for the rationale.
"""

from __future__ import annotations

import os
import sys

#: Env var that gates routing of every Fernet crypto operation through
#: the sidecar. Set by the proxy container's entrypoint; never set on
#: bare metal. See WOR-465.
WORTHLESS_FERNET_IPC_ONLY_ENV = "WORTHLESS_FERNET_IPC_ONLY"

#: Env var for the sidecar's AF_UNIX socket path. Defaults handled by
#: ``proxy.config.DEFAULT_SIDECAR_SOCKET_PATH`` at the call site.
WORTHLESS_SIDECAR_SOCKET_ENV = "WORTHLESS_SIDECAR_SOCKET"


def ipc_mode_active() -> bool:
    """True when this process should route Fernet operations via the sidecar IPC.

    Single source of truth for the three-way guard used in ``ensure_home``,
    ``open_repo``, and ``doctor``: flag enabled + not Windows + non-root.

    Root (uid 0) reads ``fernet.key`` directly — it bypasses DAC on Linux
    and covers entrypoint bootstrap and operator ``docker exec`` sessions.
    Windows has no Docker sidecar topology.
    """
    if sys.platform == "win32":
        return False
    return fernet_ipc_only_enabled() and os.geteuid() != 0


def fernet_ipc_only_enabled() -> bool:
    """``True`` when ``WORTHLESS_FERNET_IPC_ONLY`` is a truthy string.

    Strips whitespace so ``"1 "`` (trailing space from copy-paste) is
    treated the same as ``"1"`` — silently flipping a security flag OFF
    on a typo is the wrong default direction.
    """
    return os.environ.get(WORTHLESS_FERNET_IPC_ONLY_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

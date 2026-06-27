# ruff: noqa: S108
"""Static (no-Docker) assertions about deploy/entrypoint.sh (WOR-465 A4).

These checks run on every CI pass, not just the Docker-marked lane, because
they are file-content assertions that catch regressions even without a
running Docker daemon.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_fernet_fd_not_in_entrypoint() -> None:
    """WOR-465 A4: entrypoint.sh must not open or export WORTHLESS_FERNET_FD.

    Adversarial review identified this as the BLOCKER: even without the
    export, 'exec 3< fernet.key' leaves an open fd that uvicorn inherits
    (POSIX exec preserves fds without O_CLOEXEC). A proxy-RCE attacker
    can enumerate /proc/self/fd/ and read fd 3 regardless of file
    permissions. Both lines must be absent from the shipped entrypoint.

    RED before A4: entrypoint.sh still has both lines.
    GREEN after A4: both lines are removed.
    """
    entrypoint = REPO_ROOT / "deploy" / "entrypoint.sh"
    text = entrypoint.read_text()

    assert not re.search(r"\bexec\s+3<", text), (
        "WOR-465 A4: 'exec 3< fernet.key' (any whitespace variant) must be removed "
        "from entrypoint.sh. Without removal, fd 3 is inherited by uvicorn (POSIX "
        "exec does not close fds without O_CLOEXEC) and readable by a proxy-RCE "
        "attacker via /proc/self/fd/3, bypassing the worthless-crypto:worthless-crypto "
        "0400 permission entirely."
    )
    assert "WORTHLESS_FERNET_FD" not in text, (
        "WOR-465 A4: 'WORTHLESS_FERNET_FD' export must be removed from "
        "entrypoint.sh. The proxy no longer reads fernet.key directly; "
        "the sidecar holds it and the proxy uses IPC verbs."
    )

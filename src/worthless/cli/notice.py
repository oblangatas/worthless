"""One-time AS-IS / no-warranty notice (WOR-488).

AGPL-3.0 sections 15-16 and the LICENSE file disclaim all warranty, but users
do not read licenses. Surfacing the disclaimer once in the tool itself means a
user cannot say "I never saw any warning." Shown once per install, on stderr,
and never in ``--json`` mode so machine output stays clean.
"""

from __future__ import annotations

import os
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.console import WorthlessConsole

AS_IS_NOTICE = (
    "Worthless is free software provided AS IS, WITHOUT WARRANTY OF ANY KIND, "
    "to the fullest extent permitted by law (AGPL-3.0 sections 15-16). "
    "You run it at your own risk. See the LICENSE file for full terms. "
    "(Shown once.)"
)


def maybe_show_as_is_notice(console: WorthlessConsole) -> bool:
    """Show the AS-IS notice once per install. Returns ``True`` if shown.

    Skipped entirely in ``--json`` mode (machine output) so a human still sees
    it on a later interactive run. Best-effort: a non-writable home never
    raises, so this can never break a command.
    """
    if console.json_mode:
        return False
    try:
        # Resolve the home path WITHOUT side effects. get_home() would call
        # ensure_home(), which re-creates a wiped SQLite DB — a legal notice
        # must never touch the keystore/DB lifecycle. Constructing
        # WorthlessHome is pure (no I/O until we touch the marker below).
        env_home = os.environ.get("WORTHLESS_HOME")
        home = WorthlessHome(base_dir=Path(env_home)) if env_home else WorthlessHome()
        marker = home.warranty_notice_marker
        if marker.exists():
            return False
    except Exception:
        return False

    console.print_notice(AS_IS_NOTICE)

    try:
        # Never CREATE the home dir from a legal notice: doing so would flip
        # the `base_dir.exists()` first-run heuristic other commands rely on
        # (e.g. status provisions a keystore only if the home already exists).
        # Persist the marker only once the home exists; until then the notice
        # may show again, which is legally harmless ("shown at least once").
        if marker.parent.exists():
            marker.touch(mode=0o600, exist_ok=True)
    except OSError:
        # Showing the notice is what matters; persisting it is best-effort.
        pass
    return True

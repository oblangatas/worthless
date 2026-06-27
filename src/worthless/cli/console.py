"""WorthlessConsole — TTY/plain/json output routing singleton."""

from __future__ import annotations

import json
import os
import sys
from contextlib import nullcontext
from typing import Any

from rich.console import Console
from rich.markup import escape as _rich_escape

from worthless.cli.errors import WorthlessError

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_console: WorthlessConsole | None = None


def get_console() -> WorthlessConsole:
    """Return the current console (creates a default if none set)."""
    global _console  # noqa: PLW0603
    if _console is None:
        _console = WorthlessConsole()
    return _console


def set_console(console: WorthlessConsole) -> None:
    """Install *console* as the module-level singleton."""
    global _console  # noqa: PLW0603
    _console = console


# ---------------------------------------------------------------------------
# Console class
# ---------------------------------------------------------------------------


class WorthlessConsole:
    """Routes output to stderr (spinners/status) vs stdout (data).

    Respects ``--quiet``, ``--json``, and ``NO_COLOR``.
    """

    def __init__(self, quiet: bool = False, json_mode: bool = False) -> None:
        self.quiet = quiet
        self.json_mode = json_mode
        no_color = self._no_color
        self._err = Console(stderr=True, no_color=no_color)
        self._out = Console(no_color=no_color)

    # ------------------------------------------------------------------
    # Colour helpers
    # ------------------------------------------------------------------

    @property
    def _no_color(self) -> bool:
        if os.environ.get("FORCE_COLOR"):
            return False
        return bool(os.environ.get("NO_COLOR"))

    # ------------------------------------------------------------------
    # Output methods
    # ------------------------------------------------------------------

    def status(self, message: str) -> Any:
        """Return a Rich spinner context manager on stderr, or a no-op."""
        if self.quiet:
            return nullcontext()
        return self._err.status(message)

    def print_result(self, data: dict[str, Any]) -> None:
        """Print structured data — JSON to stdout in json_mode, Rich otherwise."""
        if self.json_mode:
            sys.stdout.write(json.dumps(data, default=str) + "\n")
            sys.stdout.flush()
        else:
            self._out.print(data)

    def print_success(self, message: str) -> None:
        """Green text to stderr (suppressed in quiet mode).

        worthless-k82c: ``_rich_escape`` on the inner content so any
        bracketed token in the user message (e.g. ``[truncated]``) survives
        literally — rich would otherwise silently drop it as unrecognized
        markup. The surrounding ``[green]...[/green]`` style wrapper still
        renders correctly.
        """
        if not self.quiet:
            self._err.print(f"[green]{_rich_escape(message)}[/green]")

    def print_error(self, error: WorthlessError) -> None:
        """Red WRTLS-NNN to stderr (always shown).

        worthless-k82c: escape bracketed tokens in the error body. Error
        messages routinely contain file paths and ``[reason]`` tokens
        (see ``_lock_keys`` skip-block in lock.py) that rich would
        otherwise eat as unrecognized style tags.
        """
        self._err.print(f"[bold red]{_rich_escape(str(error))}[/bold red]")

    def print_hint(self, message: str) -> None:
        """Dim hint text to stderr (suppressed in quiet and json modes).

        worthless-k82c: see :meth:`print_error`. Hints may include file
        paths or commands with bracketed tokens.
        """
        if not self.quiet and not self.json_mode:
            self._err.print(f"[dim]{_rich_escape(message)}[/dim]")

    def print_warning(self, message: str) -> None:
        """Yellow text to stderr (suppressed in quiet mode).

        worthless-k82c: escape bracketed tokens in the inner message —
        warnings frequently carry the same kind of free-form content as
        errors (paths, reasons, findings).
        """
        if not self.quiet:
            self._err.print(f"[yellow]{_rich_escape(message)}[/yellow]")

    def print_notice(self, message: str) -> None:
        """One-time informational notice to stderr (the AS-IS warranty
        notice, WOR-488).

        Shown unless ``--json`` (machine output). NOT suppressed by ``--quiet``:
        a legal notice must be seen at least once, even by a quiet first run.
        """
        if not self.json_mode:
            self._err.print(f"[yellow]{_rich_escape(message)}[/yellow]")

    def print_failure(self, message: str) -> None:
        """Red text to stderr for [FAIL] blocks (always shown — even in quiet).

        Distinct from :meth:`print_error` which formats a structured
        :class:`WorthlessError`. This prints a free-form failure line and is
        used for the trust-fix [FAIL] block on partial OpenClaw failure
        (per spec § L2 revised 2026-05-08). Always shown — quiet does not
        suppress trust-failure messages, by design: the user MUST learn
        about partial failures even with -q.

        worthless-k82c: escape bracketed tokens in the inner message so
        ``[FAIL]`` prefixes and ``[reason]`` suffixes survive intact.
        """
        self._err.print(f"[bold red]{_rich_escape(message)}[/bold red]")

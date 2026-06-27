"""Restore command — thin wrapper around ``safe_restore``."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary
from worthless.cli.safe_rewrite import _MAX_BYTES, safe_restore


def register_restore_commands(app: typer.Typer) -> None:
    """Register the ``restore`` command on *app*."""

    @app.command()
    @error_boundary
    def restore(
        target: Path = typer.Argument(..., help="Path to the .env file to restore."),
    ) -> None:
        """Restore a ``.env`` from stdin bytes (bypasses DELTA gate only)."""
        # Bounded read so a runaway pipe cannot stream GBs before the SIZE gate.
        new_content = sys.stdin.buffer.read(_MAX_BYTES + 1)
        if not new_content:
            raise WorthlessError(
                ErrorCode.UNSAFE_REWRITE_REFUSED,
                "refusing to restore with empty stdin — pipe replacement bytes in",
            )
        if len(new_content) > _MAX_BYTES:
            raise WorthlessError(
                ErrorCode.UNSAFE_REWRITE_REFUSED,
                f"stdin payload exceeds {_MAX_BYTES}-byte .env limit",
            )
        safe_restore(
            target,
            new_content,
            original_user_arg=target,
            repo_root=target.parent,
            allow_outside_repo=True,
        )

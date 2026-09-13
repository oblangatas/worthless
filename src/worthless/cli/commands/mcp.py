"""mcp command — start the Worthless MCP server over stdio."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

import typer

from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary


def _installed_mcp() -> str:
    try:
        return f"mcp {version('mcp')}"
    except PackageNotFoundError:
        return "no mcp"


def register_mcp_commands(app: typer.Typer) -> None:
    """Register the ``mcp`` command on the Typer app."""

    @app.command()
    @error_boundary
    def mcp() -> None:
        """Start the MCP server (stdio transport)."""
        try:
            from worthless.mcp.server import main
        except ImportError as exc:
            # Only the SDK itself: a broken worthless import must not be
            # disguised as a missing extra.
            if (exc.name or "").split(".")[0] != "mcp":
                raise
            # `pip install -U worthless` without the extra keeps mcp 1.x (or
            # none). Naming what IS installed keeps a future broken 2.x minor
            # from reading as "you don't have 2.x" (WOR-929).
            raise WorthlessError(
                ErrorCode.BOOTSTRAP_FAILED,
                f"`worthless mcp` could not load the MCP SDK (found {_installed_mcp()}). "
                "Reinstall with the extra, which pins a compatible mcp: "
                "pip install -U 'worthless[mcp]'",
            ) from exc

        main()

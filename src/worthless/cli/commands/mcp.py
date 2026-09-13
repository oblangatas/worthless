"""mcp command — start the Worthless MCP server over stdio."""

from __future__ import annotations

import typer

from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary


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
            # none), which lacks mcp.server.mcpserver (WOR-929).
            raise WorthlessError(
                ErrorCode.BOOTSTRAP_FAILED,
                "`worthless mcp` needs the MCP SDK 2.x (mcp>=2.1,<3), which this "
                "environment does not have. Reinstall with the extra: "
                "pip install -U 'worthless[mcp]'",
            ) from exc

        main()

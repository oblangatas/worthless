"""Worthless CLI — enrollment and key management.

This package intentionally does NOT re-export ``worthless.cli.app:app``.
The proxy import path goes through ``worthless.cli.keystore``
(``worthless.proxy.config:9 → from worthless.cli.keystore import …``),
and Python loads the parent package ``worthless.cli`` before any
submodule. Re-exporting the typer app here would cascade through every
CLI command at proxy boot — pulling in ``cryptography.fernet``,
``worthless.crypto.splitter``, and the entire CLI tree.

Console entry point at ``worthless.cli.app:app`` imports the submodule
directly (see ``[project.scripts]`` in pyproject.toml), so dropping the
re-export does not break ``worthless`` invocations. The runtime
import-snapshot test at ``tests/ipc/test_proxy_client_unit.py`` guards
against this regressing.
"""

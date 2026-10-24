"""``python -m worthless`` — the same CLI as the ``worthless`` command.

The default command spawns its proxy this way so it always runs *this*
install, never whichever ``worthless`` is first on PATH (worthless-l0s1).
"""

from worthless.cli.app import app

app(prog_name="worthless")

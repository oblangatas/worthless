"""WOR-464: stable JSON schema version for ``worthless doctor --json``.

Bumped only on breaking output shape changes. New optional fields, new
``check_id`` values, or new findings inside an existing check do NOT bump
the version — those are additive. Renames, removed fields, or changed
value types DO bump.
"""

from __future__ import annotations

SCHEMA_VERSION = "1"

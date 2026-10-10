"""Orphan-state predicate + plain-English wording (HF7 / worthless-3907).

An *orphan* enrollment is a DB row whose ``env_path`` points to a file
where the matching ``var_name`` line is absent — usually because the
user manually deleted it from ``.env`` between locking and unlocking.

User-facing phrases live here, not the technical term: a real user does
NOT think "I have an orphan", they think "my key is broken". The shared
phrase tokens ``can't restore`` (problem) + ``worthless doctor --fix``
(solution) are AND-bound by tests so reword in one place.

The predicate is shared with ``unlock``, ``doctor``, and (future HF5)
``status`` + ``scan`` so detection logic doesn't drift.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values

from worthless.storage.repository import EnrollmentRecord

# User-facing phrase tokens. Plain English, no engineer jargon. Tests
# AND-bind via ``_has_all_tokens``. Reword here only — five files
# follow.
PROBLEM_PHRASE = "can't restore"
FIX_PHRASE = "worthless doctor --fix"


def is_orphan(enrollment: EnrollmentRecord) -> bool:
    """An enrollment is orphan iff its ``env_path`` is set but the matching
    ``var_name`` line is missing from that file (or the file no longer
    exists). ``env_path is None`` means a direct enrollment with no
    ``.env`` binding — not an orphan, just unbound.
    """
    if not enrollment.env_path:
        return False
    env_path = Path(enrollment.env_path)
    if not env_path.exists():
        return True
    return enrollment.var_name not in dotenv_values(env_path)


def env_file_missing(enrollment: EnrollmentRecord) -> bool:
    """True when the enrollment's ``.env`` file no longer exists at its path.

    A missing *file* is not a dead key. It usually means the project moved
    — a removed git worktree, a renamed folder — and Shard A is still on
    disk somewhere. Such a key is recoverable and must never be purged.
    Only a deleted *line* in a file that still exists is a dead key.

    Detection is unchanged: ``is_orphan`` still flags a missing file, so
    ``status`` and ``scan`` keep warning about it. This only separates
    "warn about it" from "safe to destroy".
    """
    return bool(enrollment.env_path) and not Path(enrollment.env_path).exists()


def find_orphans(enrollments: list[EnrollmentRecord]) -> list[EnrollmentRecord]:
    """Filter a list of enrollments to the orphans, parsing each unique
    ``env_path`` only once. With N orphans sharing one ``.env`` (common —
    many aliases bound to the same project file), naive per-orphan
    ``dotenv_values`` calls re-parse N times.
    """
    parsed_cache: dict[str, dict[str, str | None]] = {}
    orphans: list[EnrollmentRecord] = []
    for e in enrollments:
        if not e.env_path:
            continue
        env_path = Path(e.env_path)
        if not env_path.exists():
            orphans.append(e)
            continue
        if e.env_path not in parsed_cache:
            parsed_cache[e.env_path] = dotenv_values(env_path)
        if e.var_name not in parsed_cache[e.env_path]:
            orphans.append(e)
    return orphans


def format_orphan_error(enrollment: EnrollmentRecord) -> str:
    """User-facing error string for the orphan condition. Plain English up
    front so Rich's 80-column wrap can't split phrase tokens across a
    newline at the long ``env_path``.
    """
    return (
        f"{PROBLEM_PHRASE} {enrollment.key_alias}: its .env line was deleted. "
        f"Run `{FIX_PHRASE}` to clean up. "
        f"(Variable {enrollment.var_name} not found in {enrollment.env_path}.)"
    )

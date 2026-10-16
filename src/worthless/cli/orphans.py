"""Orphan-state predicate + plain-English wording (HF7 / worthless-3907).

An *orphan* enrollment is a DB row whose ``env_path`` points to a file
where the matching ``var_name`` line is absent — the user deleted the
line — or whose ``.env`` is no longer there at all, because the project
moved or was deleted. Doctor only ever destroys the first (see
``env_file_missing``).

User-facing phrases live here, not the technical term: a real user does
NOT think "I have an orphan", they think "my key is broken". The shared
phrase tokens ``can't restore`` (problem) + ``worthless doctor --fix``
(solution) are AND-bound by tests so reword in one place.

The predicate is shared with ``unlock``, ``doctor``, and (future HF5)
``status`` + ``scan`` so detection logic doesn't drift.
"""

from __future__ import annotations

import hmac
from pathlib import Path

from dotenv import dotenv_values

from worthless.storage.repository import EnrollmentRecord, ShardRepository

# User-facing phrase tokens. Plain English, no engineer jargon. Tests
# AND-bind via ``_has_all_tokens``. Reword here only — five files
# follow.
PROBLEM_PHRASE = "can't restore"
FIX_PHRASE = "worthless doctor --fix"

# Advice for a key whose ``.env`` is missing. Never call it "safe": removing a
# git worktree deletes its gitignored ``.env``, and Shard A with it. Never send
# the user to ``uninstall``: it wipes every key it can't restore, not just this
# one. And ``revoke --alias`` is not "just this one" either: the same key locked
# in two projects (a worktree's copy of the main repo's ``.env``) shares one
# alias, and revoke deletes it in both. See ``removed_project_advice``.
MOVED_FIX_PHRASE = "Moved it? Put the project back at the path shown, then run `worthless unlock`"
DELETED_FIX_PHRASE = (
    "Removed it (`git worktree remove` takes its `.env` with it)? Then that key is "
    "gone, and `worthless revoke --alias {alias}` removes it"
)
SHARED_KEY_PHRASE = (
    "Removed it? Leave this record: the same key is also locked at {other}, and "
    "removing the key by its alias would break that copy too"
)


def is_orphan(enrollment: EnrollmentRecord) -> bool:
    """An enrollment is orphan iff its ``env_path`` is set but the matching
    ``var_name`` line is missing from that file (or the file no longer
    exists). ``env_path is None`` means a direct enrollment with no
    ``.env`` binding — not an orphan, just unbound.
    """
    if not enrollment.env_path:
        return False
    env_path = Path(enrollment.env_path)
    try:
        if not env_path.exists():
            return True
        return enrollment.var_name not in dotenv_values(env_path)
    except (OSError, UnicodeDecodeError):
        # Can't look (folder not searchable) or can't read it: never call it
        # an orphan — doctor --fix purges orphans.
        return False


def env_file_missing(enrollment: EnrollmentRecord) -> bool:
    """True when the enrollment's ``.env`` is not a regular file at its path.

    Missing, a dangling symlink, or a directory in its place (Docker creates
    one for a missing bind-mount) all count: python-dotenv reads any of them
    as empty, which would otherwise look like a deleted line.

    A missing *file* is not proof of a dead key. A moved or renamed folder, or
    an unmounted drive, leaves Shard A intact somewhere else, so the key may be
    recoverable and is never purged. A deleted project — ``git worktree
    remove`` included, since it deletes the gitignored ``.env`` — took Shard A
    with it. Doctor can't tell the two apart, so it keeps the record and says
    how to remove it (``revoke``).

    A deleted *line* in a file that still exists is treated as a dead key. That
    is still a guess: a renamed variable or a commented-out line looks the same
    (WOR-938).

    Detection is unchanged: ``is_orphan`` still flags a missing file, so
    ``status`` and ``scan`` keep warning about it. This only separates
    "warn about it" from "safe to destroy".
    """
    return bool(enrollment.env_path) and not Path(enrollment.env_path).is_file()


def removed_project_advice(
    orphan: EnrollmentRecord, all_enrollments: list[EnrollmentRecord]
) -> str:
    """What to do if *orphan*'s project was deleted rather than moved.

    ``revoke --alias`` removes the key from every place it is locked, so it is
    offered only when *orphan* is the key's only record. Any other record —
    live, moved, another variable, or a direct enrollment — may be a working or
    recoverable copy, so the advice names it instead.
    """
    other = next(
        (
            e
            for e in all_enrollments
            if e.key_alias == orphan.key_alias
            and (e.var_name, e.env_path) != (orphan.var_name, orphan.env_path)
        ),
        None,
    )
    if other is None:
        return DELETED_FIX_PHRASE.format(alias=orphan.key_alias)
    return SHARED_KEY_PHRASE.format(other=other.env_path or "a direct enrollment with no .env")


def find_orphans(enrollments: list[EnrollmentRecord]) -> list[EnrollmentRecord]:
    """Filter a list of enrollments to the orphans, parsing each unique
    ``env_path`` only once. With N orphans sharing one ``.env`` (common —
    many aliases bound to the same project file), naive per-orphan
    ``dotenv_values`` calls re-parse N times.
    """
    parsed_cache: dict[str, dict[str, str | None] | None] = {}
    orphans: list[EnrollmentRecord] = []
    for e in enrollments:
        if not e.env_path:
            continue
        env_path = Path(e.env_path)
        try:
            missing = not env_path.exists()
        except OSError:
            continue  # folder not searchable: never an orphan
        if missing:
            orphans.append(e)
            continue
        if e.env_path not in parsed_cache:
            try:
                parsed_cache[e.env_path] = dotenv_values(env_path)
            except (OSError, UnicodeDecodeError):
                parsed_cache[e.env_path] = None  # unreadable: never an orphan
        parsed = parsed_cache[e.env_path]
        if parsed is not None and e.var_name not in parsed:
            orphans.append(e)
    return orphans


# WOR-958: what lock still has to do for a key left this way.
UNLOCKED_FIX_PHRASE = "worthless lock"


async def find_unlocked(
    repo: ShardRepository, enrollments: list[EnrollmentRecord]
) -> list[EnrollmentRecord]:
    """Enrollments whose ``.env`` still holds the original key (WOR-958).

    ``lock`` commits the DB, then rewrites ``.env``. A ``kill -9`` between
    the two leaves the DB saying "locked" over a real key. The stored
    commitment is HMAC(nonce, original key), kept unencrypted, so this needs
    no decrypt and no keychain. A real shard A matches only by an HMAC
    collision, so a healthy key is never reported here.
    """
    parsed_cache: dict[str, dict[str, str | None]] = {}
    unlocked: list[EnrollmentRecord] = []
    for e in enrollments:
        try:
            if not e.env_path or not Path(e.env_path).is_file():
                continue
        except OSError:
            continue  # folder not searchable: skip, like an unreadable file
        if e.env_path not in parsed_cache:
            # Unreadable or not UTF-8: skip it. One bad file must never blind
            # status, scan and doctor to every other key.
            try:
                parsed_cache[e.env_path] = dotenv_values(e.env_path)
            except (OSError, UnicodeDecodeError):
                parsed_cache[e.env_path] = {}
        value = parsed_cache[e.env_path].get(e.var_name)
        if not value:
            continue
        shard = await repo.fetch_encrypted(e.key_alias)
        if shard is None:
            continue
        candidate = bytearray(value.encode("utf-8"))
        try:
            digest = hmac.new(shard.nonce, candidate, "sha256").digest()
        finally:
            candidate[:] = b"\0" * len(candidate)
        if hmac.compare_digest(digest, shard.commitment):
            unlocked.append(e)
    return unlocked


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

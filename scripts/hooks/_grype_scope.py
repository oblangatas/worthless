#!/usr/bin/env python3
"""What a `.grype.yaml` ignore rule scopes to — defined once, for both hooks.

Two hooks read these rules and they MUST agree on what a scope means:

  check_grype_ignore_expiry.py      validates the rule's shape (is it scoped at
                                    all? is a type-only scope bounded?)
  check_grype_unmapped_findings.py  decides whether a rule covers a finding

When they disagreed, a waiver silently excused findings nobody argued about.
That is not hypothetical: the matcher read `name` and `type` only while the
validator happily blessed rules carrying a `version`, so a version pin added to
bound a waiver bound nothing on the gate that actually blocks — and the waiver
would have kept suppressing after Debian shipped a fix. Keeping SCOPE_KEYS and
the matching rule in one place is what stops the next added key repeating it.

Imported as a bare module name: pre-commit runs these hooks as
`uv run python scripts/hooks/<hook>.py`, so sys.path[0] is scripts/hooks.
"""

from __future__ import annotations

# Every field a scope may constrain. Adding one here teaches BOTH hooks at once,
# which is the entire point of this module.
SCOPE_KEYS = ("name", "type", "version")

# Qualifiers grype itself honours that this gate does NOT evaluate. Grype 0.114.0
# also constrains `language`, `location` and `upstream-name`. Dropping them
# silently would make a waiver LOOSER here than in grype — a rule meant to excuse
# one npm package at one path would, to this gate, excuse that package anywhere,
# so we would wave through findings grype still reports. That is the fail-open
# direction, and it is the same drift this module exists to prevent, one level up.
#
# They are refused rather than implemented on purpose: matching a location or a
# language means inventing an answer for artifacts whose records carry no such
# field, and a gate that guesses is worse than one that says it cannot tell.
# Teaching it to evaluate them is a real option later — then move the key from
# here into SCOPE_KEYS and the refusal disappears on its own.
UNEVALUABLE_KEYS = ("language", "location", "upstream-name")


def scope_of(rule: dict) -> dict[str, str]:
    """The scope a rule constrains, as a plain dict. Empty dict = unscoped.

    Tolerates the malformed shapes a hand-edited YAML file produces: `package`
    absent, null, a list, or carrying empty-string values. All of them collapse
    to "unscoped", which callers must treat as the dangerous case rather than
    the permissive one.
    """
    pkg = rule.get("package")
    if not isinstance(pkg, dict):
        return {}
    return {k: str(pkg[k]) for k in SCOPE_KEYS if pkg.get(k)}


def unevaluable_qualifiers(rule: dict) -> list[str]:
    """Qualifiers this rule uses that the matcher cannot honour, sorted.

    Empty list = every constraint the rule expresses is one `covers()` actually
    enforces. Anything returned here means the rule promises grype a narrowing
    this gate would ignore, so the caller must refuse it rather than quietly
    matching wider than the author asked for.
    """
    pkg = rule.get("package")
    if not isinstance(pkg, dict):
        return []
    return sorted(k for k in UNEVALUABLE_KEYS if pkg.get(k))


def is_bounded(scope: dict[str, str]) -> bool:
    """Is this scope narrow enough to be worth calling a scope at all?

    A literal `name` is the narrowest form and needs nothing else. A `type`
    alone is not a scope — `type: deb` is every Debian package in the image —
    so it counts only when a `version` bounds it. The type escape hatch exists
    for names grype would compile as a regex, and it is only defensible bounded.
    """
    if scope.get("name"):
        return True
    return bool(scope.get("type") and scope.get("version"))


def covers(scope: dict[str, str], artifact: dict) -> bool:
    """Does this scope cover this artifact?

    An EMPTY scope covers nothing. That is deliberate and it is a reversal: this
    used to return True for an empty scope ("rule named no package: covers
    everything"), which made the gate fail OPEN on exactly the malformed or
    unscoped rules it should be most suspicious of — and contradicted its own
    contract of only ever narrowing what is excused. Unscoped rules are now
    rejected outright by the expiry hook, so nothing legitimate relies on the
    old behaviour; failing closed means a rule that slips past that hook still
    does not silence a finding here.

    Plain equality, not grype's regex matching. Being stricter than grype is the
    safe direction: a scope we fail to match keeps gating rather than slipping
    past.
    """
    if not scope:
        return False
    return all(scope[key] == str(artifact.get(key) or "") for key in scope)

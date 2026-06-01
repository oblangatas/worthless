# F-15 Implementation Ticket — R-21 canary tests wrong ruleset

> "If the canary push asks `branch-protection` to bounce it, learning the answer tells you nothing about whether `v-tags-signed` is still on duty."

## 1. Problem

**ELI5.** The release script needs to prove a specific GitHub ruleset (`v-tags-signed`, which only guards real `refs/tags/v*` tag pushes) is actually live, because the API might be lying. Today we prove it by trying to push something to `refs/canary/ruleset-probe-$$`. But `v-tags-signed` doesn't watch that namespace at all — push-protection or branch-protection bounces the canary instead. We then see "rejected" and high-five ourselves. An attacker who silently switches off only `v-tags-signed` keeps every other ruleset on, the canary still gets rejected, the script still declares green, and the next real signed tag push goes out under no signature enforcement.

**Technical.** GitHub repository rulesets are scoped by `target` + ref-name pattern. `v-tags-signed` targets `refs/tags/v*`. A `git push origin :refs/canary/ruleset-probe-<ts>` either matches a different ruleset (false-positive rejection) or — if no ruleset covers that pattern — succeeds as a no-op delete of a nonexistent ref (false-negative). Neither outcome is evidence about `v-tags-signed`. The correct canary must (a) target a ref the ruleset is scoped to, (b) violate the rule it enforces (`required_signatures`), and (c) be confirmed rejected *by name*.

## 2. Current spec text being replaced

**`SPEC.md` §5 R6 bash block:**

```bash
# R-21 (F-3): second-channel canary — API answer alone is not proof
git push origin :refs/canary/ruleset-probe-$$ 2>&1 | grep -q "rejected.*v-tags-signed" \
  || die "ruleset second-channel probe failed: API says active, push was not rejected"
```

**`security-engineer.md` R-21 row:** existing single-row entry.

## 3. Proposed fix — verbatim hunks

### Replace R-21 hunk in `SPEC.md` §5 R6:

```bash
# R-21 (F-3, F-15): second-channel canary — must target refs/tags/v* AND
# the rejection must name v-tags-signed. A no-op canary on refs/canary/*
# would be bounced by an UNRELATED ruleset, false-greening the probe.
CANARY_TAG="v0.0.0-canary-$$-$(date +%s)"           # guaranteed-unique, matches refs/tags/v*
git tag -d "$CANARY_TAG" 2>/dev/null || true
git tag "$CANARY_TAG" HEAD                          # LIGHTWEIGHT (unsigned) → trips required_signatures
# Trap cleans up the local + remote canary tag regardless of probe outcome
cleanup_canary() {
    git tag -d "$CANARY_TAG" 2>/dev/null || true
    git push origin --delete "refs/tags/$CANARY_TAG" 2>/dev/null || true
}
trap 'cleanup_canary' RETURN
CANARY_OUT=$(git push origin "refs/tags/$CANARY_TAG" 2>&1) ; CANARY_RC=$?
if [ $CANARY_RC -eq 0 ]; then
    cleanup_canary
    die "R-21: canary tag $CANARY_TAG pushed SUCCESSFULLY — v-tags-signed is OFF (API lied about 'active')"
fi
if ! printf '%s\n' "$CANARY_OUT" | grep -Eq 'rejected.*(v-tags-signed|Required signatures|ruleset[[:space:]]+["'\''[:alnum:]_-]*v-tags-signed)'; then
    cleanup_canary
    die "R-21: canary rejected but NOT by v-tags-signed — different ruleset caught it (output: $(printf '%s' "$CANARY_OUT" | tr '\n' '|' | head -c 400)). Treat as v-tags-signed DISABLED."
fi
cleanup_canary
```

### Replace R-21 row in `security-engineer.md`:

```
| R-21 | P9 + R-4 do NOT trust `gh api` responses alone — second-channel attestation MUST push an UNSIGNED lightweight tag matching the ruleset's scope: `git tag v0.0.0-canary-$$-<ts> HEAD && git push origin refs/tags/v0.0.0-canary-$$-<ts>`. Push MUST be rejected AND the stderr MUST name `v-tags-signed` (or `Required signatures` attributable to that ruleset by GitHub's enforcement-message contract). Rejection by any other ruleset name ⇒ treat `v-tags-signed` as DISABLED. Push SUCCESS ⇒ same. Local + remote canary tag MUST be cleaned up via `RETURN`-trap regardless of outcome. TLS SPKI for `api.github.com` additionally pinned in SR-10. | MITM/proxy forging `enforcement: active` JSON while upstream is actually disabled (F-3); canary probing wrong ruleset namespace (F-15) |
```

## 4. TDD §8 row update — replaces existing F-3 row

```
| Negative (F-3 / F-15) | MITM `gh api /rulesets` returns `enforcement: active` while upstream is disabled — three sub-scenarios: (a) `v-tags-signed` OFF, no other tag-ruleset → canary tag push succeeds; (b) `v-tags-signed` OFF, `branch-protection` rejects with non-matching name; (c) `v-tags-signed` ON → push rejected with `v-tags-signed` named in stderr | P9 + R-4 doctor MUST: (a) die `"canary tag pushed SUCCESSFULLY — v-tags-signed is OFF"`; (b) die `"rejected but NOT by v-tags-signed"`; (c) pass. All three MUST leave zero canary tags locally or on remote (`git tag --list 'v0.0.0-canary-*'` empty, `git ls-remote origin 'refs/tags/v0.0.0-canary-*'` empty). |
```

## 5. Risks / open questions

1. **Bypass-list.** If `v-tags-signed` has a `bypass_actors` entry that includes the maintainer (common after debugging sessions), the canary push *succeeds* — current spec text reads that as "ruleset OFF" and dies. That's a true-positive ("you can push unsigned tags right now") but the death message is misleading. R-4 doctor should also assert `bypass_actors == []` via API before trusting the canary semantics.
2. **Enforcement-message contract.** GitHub does not formally guarantee that the ruleset name appears in the push rejection stderr. Current regex matches `v-tags-signed` literal OR `Required signatures` (the human message for that rule type). Both have been observed in 2025-2026 stderr but a GitHub UI revision could break the parse. Mitigation: also assert via API that `v-tags-signed` is the *only* tag-scoped ruleset with `required_signatures` enabled, so "Required signatures" rejection is unambiguous.
3. **Tag-namespace pollution.** Canary tag name `v0.0.0-canary-$$-<ts>` is well below any real semver. `git tag --list` filters and the GitHub Releases page show only annotated/published tags by default, so a 200ms-lived lightweight tag should not visibly pollute. Worst case if cleanup fails: stray `v0.0.0-canary-*` tag, easily mass-deleted with `git push origin --delete $(git ls-remote --tags origin 'v0.0.0-canary-*' | awk '{print $2}')`.
4. **Collision.** `$$` (PID) + `date +%s` (epoch seconds) guarantees uniqueness within a single host-second. Two parallel `release-recover.sh` runs on the same machine within same second would collide on PID — impossible (PID unique per live process). Two runs on different machines could share PID+epoch; vanishingly unlikely but addable: append `$(openssl rand -hex 4)` if paranoid.
5. **Race with cleanup.** `RETURN` trap (bash function-scope) fires when the R6 step's function returns. If R6 is inlined (not a function), use `EXIT` instead — but we already have an `EXIT` trap for `re_enable_from_snapshot`. Solution: wrap canary block in one-shot subshell or inline function so `RETURN` is unambiguous.
6. **Rate limit / ref-update push protection.** GitHub may rate-limit rapid create+delete cycles on `refs/tags/*` from the same actor; canary plus cleanup is two ref updates per recovery. R-24 already does 3 API polls; adding 2 push round-trips is fine but worth noting in runbook.

## 6. Estimated lines changed

- `SPEC.md` §5 R6 hunk: -3 / +21 lines (net +18)
- `SPEC.md` §8 row: -1 / +1 lines (rewritten cell)
- `security-engineer.md` R-21 row: -1 / +1 lines (rewritten cell)

**Total: ~20 line delta across 2 files.**

## 7. Implementation order

1. **`SPEC.md` §5 R6 first** — implementation contract. Get the bash hunk exactly right.
2. **`security-engineer.md` R-21 row second** — mirror the SPEC §5 contract; add F-15 to the threat column.
3. **`SPEC.md` §8 negative-test row third** — derive three sub-scenarios (a/b/c) from R6 hunk's three failure paths.

Reason for order: §5 defines behavior; §6 (R-21 row) and §8 (test row) are reflections. Editing reflections first invites drift.

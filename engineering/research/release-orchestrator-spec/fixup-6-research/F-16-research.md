# F-16 Implementation Ticket — Audit log JSONL schema + replay-day forensic command (R-26)

## 1. Problem (ELI5 + technical)

**ELI5:** When the recovery flow opens the 120-second ruleset window, today's log just says "we disabled it, then signed, then re-enabled." If something goes wrong (or someone tampers with the runner mid-window), the on-call has nothing to reconstruct *which binary actually ran*, *which agent socket signed*, or *what token scope was live*. It's like a flight recorder that only logs "took off / landed" — useless when the wing falls off.

**Technical:** R-15 mandates an append-only GPG-signed log but leaves line format unspecified. IR analysis identified 8 missing witness fields whose absence makes post-breach forensics impossible: resolved tool paths + SHA256 per call (binary swappable between P11 preflight one-shot and step 4.2b execution), `gpgconf --list-dirs agent-socket` per sign (detects socket-hijack), live `GH_TOKEN` scope per `gh api` (detects scope-elevation mid-window), `gh api` response body hashes (proves ruleset state transitions are what we think they are), watchdog/heartbeat PID + `kill -0` poll timestamps (proves the watchdog was actually alive when we trusted it), `umask`/RUID/login-session/tty (detects sudo-impersonation), `git rev-parse HEAD` of release.sh repo (detects the script being swapped under us), R-13-redacted env snapshot keys (detects injected `LD_PRELOAD`/`PYTHONPATH`/`PATH` prepends).

## 2. Current text being amended

**SPEC.md §5:** `Append-only audit log .release-audit/YYYY-MM-DD.log written for every disable/enable/sign/push, sealed with GPG-detached signature .log.asc at script exit (R-15, F-14).`

**security-engineer.md R-15 row:** existing single-row entry.

## 3. Proposed R-26 + R-15 update

### R-15 (amended — replace existing row)

> R-15 | Audit log `.release-audit/YYYY-MM-DD.log` is **JSONL** (one well-formed JSON object per `\n`-terminated line, schema defined in R-26) written append-only for every `disable | enable | sign | push | recovery-window-open | recovery-window-close` event. At first-write of each day's file: `chflags uappnd` (mac) / `chattr +a` (Linux) — append-only FS flag is set BEFORE the second line is written. Each line written via single `printf '%s\n' "$json"` to a `flock`-held FD; no rewrites, no in-place edits. At end of every run, sign the day's log with `gpg --detach-sign --armor` → `.release-audit/YYYY-MM-DD.log.asc` (uses R-7's pinned agent). `release-doctor.sh --verify-audit-log` verifies every `.asc` against `$MAINTAINER_GPG_FINGERPRINT` AND validates every line against R-26 JSON Schema; refuses on any mismatch, missing signature, schema violation, or missing required field. | Forensics integrity; F-14 tamper; F-16 witness-field gaps.

### R-26 (NEW — insert after R-25)

> R-26 | Every audit-log line conforms to the R-26 JSON Schema (Draft 2020-12, embedded in `scripts/release/audit-schema.json`, SHA256 pinned in `lib/tool-trust.sh`). Mandatory fields appear on EVERY event; per-event-type variants add discriminated additional fields. Tool resolution + SHA256 captured **at each call site**, not cached from P11 (P11 records preflight baseline; each subsequent call records "current" — `release-doctor.sh --replay-day` diffs and refuses if any tool SHA changed mid-window). `gh api` response bodies stored as SHA256 hashes (privacy + size), with first 256 bytes raw only for `4xx/5xx` (debuggability). Env-var snapshot filtered through R-13 redactor and stored as **sorted key-list only** (values never logged; presence-witness only). | Post-breach forensic reconstruction (F-16); detects mid-window binary swap, agent-socket hijack, token-scope elevation, ruleset-state lying, watchdog liveness fraud, sudo impersonation, release.sh swap, env-injection.

### R-26 JSON Schema (paste into `scripts/release/audit-schema.json`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://worthless.tools/release/audit-schema/v1.json",
  "title": "Worthless release audit log line (R-26)",
  "type": "object",
  "required": [
    "schema_version", "ts", "event", "script", "script_git_sha",
    "pid", "ppid", "ruid", "euid", "login_session", "tty",
    "umask", "cwd", "hostname",
    "tool_witness", "gpg_agent_socket",
    "watchdog", "env_keys", "marker"
  ],
  "properties": {
    "schema_version": { "const": "r26.v1" },
    "ts":   { "type": "string", "format": "date-time", "description": "RFC3339 UTC, ns precision" },
    "event": { "enum": ["disable", "enable", "sign", "push", "recovery-window-open", "recovery-window-close"] },
    "script": { "enum": ["release.sh", "release-recover.sh", "release-doctor.sh"] },
    "script_git_sha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
    "pid":  { "type": "integer", "minimum": 1 },
    "ppid": { "type": "integer", "minimum": 1 },
    "ruid": { "type": "integer", "minimum": 0 },
    "euid": { "type": "integer", "minimum": 0 },
    "login_session": { "type": "string" },
    "tty": { "type": "string" },
    "umask": { "type": "string", "pattern": "^0[0-7]{3}$" },
    "cwd":  { "type": "string" },
    "hostname": { "type": "string" },
    "tool_witness": {
      "type": "object",
      "patternProperties": {
        "^(gh|gpg|git|docker|pip|awk|sed|jq|flock)$": {
          "type": "object",
          "required": ["path", "sha256"],
          "properties": {
            "path":   { "type": "string" },
            "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
            "version": { "type": "string" }
          },
          "additionalProperties": false
        }
      },
      "minProperties": 1,
      "additionalProperties": false
    },
    "gpg_agent_socket": { "type": "string" },
    "watchdog": {
      "type": "object",
      "required": ["pid", "alive", "heartbeat_pid", "heartbeat_alive", "polled_at"],
      "properties": {
        "pid":             { "type": "integer", "minimum": 0 },
        "alive":           { "type": "boolean" },
        "heartbeat_pid":   { "type": "integer", "minimum": 0 },
        "heartbeat_alive": { "type": "boolean" },
        "polled_at":       { "type": "string", "format": "date-time" }
      },
      "additionalProperties": false
    },
    "env_keys": {
      "type": "array",
      "items": { "type": "string" },
      "uniqueItems": true
    },
    "marker": { "type": "string" }
  },
  "oneOf": [
    {
      "properties": {
        "event": { "const": "disable" },
        "ruleset_id":  { "type": "string" },
        "gh_token_scopes": { "type": "array", "items": { "type": "string" } },
        "gh_api_request":  { "type": "object", "required": ["method","path"] },
        "gh_api_response": { "type": "object", "required": ["status","body_sha256"] },
        "prior_ruleset_state_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      },
      "required": ["ruleset_id","gh_token_scopes","gh_api_request","gh_api_response","prior_ruleset_state_sha256"]
    },
    {
      "properties": {
        "event": { "const": "enable" },
        "ruleset_id":  { "type": "string" },
        "gh_token_scopes": { "type": "array", "items": { "type": "string" } },
        "gh_api_request":  { "type": "object" },
        "gh_api_response": { "type": "object", "required": ["status","body_sha256"] },
        "restored_ruleset_state_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      },
      "required": ["ruleset_id","gh_token_scopes","gh_api_request","gh_api_response","restored_ruleset_state_sha256"]
    },
    {
      "properties": {
        "event": { "const": "sign" },
        "tag":            { "type": "string", "pattern": "^v\\d+\\.\\d+\\.\\d+(-\\w+)?$" },
        "tag_object_sha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
        "signer_fpr":     { "type": "string", "pattern": "^[0-9A-F]{40}$" },
        "gpg_exit":       { "type": "integer" }
      },
      "required": ["tag","tag_object_sha","signer_fpr","gpg_exit"]
    },
    {
      "properties": {
        "event": { "const": "push" },
        "ref":              { "type": "string" },
        "remote":           { "type": "string" },
        "remote_url_redacted": { "type": "string" },
        "gh_token_scopes":  { "type": "array", "items": { "type": "string" } },
        "push_exit":        { "type": "integer" },
        "pushed_object_sha":{ "type": "string", "pattern": "^[0-9a-f]{40}$" }
      },
      "required": ["ref","remote","push_exit","pushed_object_sha"]
    },
    {
      "properties": {
        "event": { "const": "recovery-window-open" },
        "window_deadline_ts": { "type": "string", "format": "date-time" },
        "window_max_seconds": { "type": "integer", "const": 120 }
      },
      "required": ["window_deadline_ts","window_max_seconds"]
    },
    {
      "properties": {
        "event": { "const": "recovery-window-close" },
        "open_marker_correlation_id": { "type": "string" },
        "actual_window_seconds":      { "type": "number" },
        "close_reason":               { "enum": ["normal","trap","watchdog-timeout","doctor-fail"] }
      },
      "required": ["open_marker_correlation_id","actual_window_seconds","close_reason"]
    }
  ],
  "unevaluatedProperties": false
}
```

## 4. `release-doctor.sh --replay-day YYYY-MM-DD` spec

**Parses:** every line of `.release-audit/YYYY-MM-DD.log`; loads `.release-audit/YYYY-MM-DD.log.asc`.

**Verifies (fail-closed on any):**
1. GPG signature valid against `$MAINTAINER_GPG_FINGERPRINT`.
2. Every line parses as JSON + validates against R-26 schema.
3. Tool SHA invariant: identical across ALL lines within same `marker` correlation group.
4. `gpg_agent_socket` identical across all `sign` events in one marker group.
5. `gh_token_scopes` never gains a scope between open/close events of same marker.
6. Ruleset restore: every `disable` has matching `enable` whose `restored_ruleset_state_sha256 == disable.prior_ruleset_state_sha256`.
7. Window pairing: every open has matching close; `actual_window_seconds <= 120`.
8. Watchdog liveness: every event during open window has `watchdog.alive == true && heartbeat_alive == true`.
9. `script_git_sha` constant within marker group.
10. RUID/EUID/login_session constant within marker group.
11. `env_keys` diff between open/close: WARN if injection-relevant keys appear (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`).

**Surfaces:** human-readable table; `--json` flag for IR sidecar. Exit non-zero on any FAIL.

## 5. TDD §8 rows

```
| Negative (F-16) | hand-craft log line omitting required R-26 field; re-sign with valid GPG | doctor --verify-audit-log AND --replay-day MUST refuse "schema-violation: missing required property" exit 1 |
| Negative (F-16b) | inject second `sign` line with different tool_witness.gpg.sha256 | --replay-day MUST refuse "tool-swap-detected: gpg sha256 changed mid-window-marker" exit 1 |
| Negative (F-16c) | `disable.prior_ruleset_state_sha256` ≠ matching `enable.restored_ruleset_state_sha256` | --replay-day MUST refuse "ruleset-restore-mismatch: marker <id>" exit 1 |
```

## 6. Risks / open questions

1. **`gh api` body size.** Hash-only for 2xx; first 256 bytes for 4xx/5xx. Optional CAS layout `.release-audit/<date>/bodies/<sha256>.json` for full bodies if line schema insufficient.
2. **Day boundary during long recovery.** Marker correlation ID is global (UUIDv7 with ISO prefix). `--replay-day --span N` loads adjacent days. Close-without-open after 1-day walkback ⇒ refuse.
3. **R-15 append-only vs JSON.** JSONL is line-oriented; single `printf '%s\n'` under `flock` preserves append-only. Never `jq -i`. FS flag enforces; schema check is fallback.
4. **Performance.** SHA256 per call ~5-20 ms; ~30 events per release ⇒ <1s overhead. If issue: cache + emit first/current witness.
5. **`script_git_sha` outside git.** Symlink resolution via `git -C "$(dirname "$(readlink -f "$0")")" rev-parse HEAD`. If non-git: `"script_git_sha": "not-from-git"` and doctor refuses unconditionally.

## 7. Estimated lines changed

| File | Lines |
|---|---|
| `SPEC.md` §5 + §8 | +35 |
| `security-engineer.md` (R-15 update + R-26 new) | +6 / -2 |
| `scripts/release/audit-schema.json` (NEW) | +145 |
| `lib/release/audit.sh` (NEW) | ~80 |
| `scripts/release-doctor.sh --replay-day` | ~120 |
| `tests/release/test-audit-schema.bats` | ~60 |
| `tests/release/test-replay-day.bats` | ~80 |
| `lib/tool-trust.sh` SHA pin | +2 |
| **Total** | **~530** |

## 8. Implementation order

1. Land `audit-schema.json` + pin SHA in `lib/tool-trust.sh` (immutable contract first).
2. Write `lib/release/audit.sh::emit_audit_event` — single fn, all required fields, R-13 redactor on env, `flock` + `printf`.
3. Write schema validation tests against fixture lines — RED.
4. Replace existing `echo >> .release-audit/...` call sites with `emit_audit_event` — GREEN.
5. Update R-15 + add R-26 in `security-engineer.md`; amend SPEC §5; add F-16 negative tests to §8.
6. Implement `release-doctor.sh --replay-day` (cross-line invariants 1-11).
7. Write replay tests (F-16, F-16b, F-16c).
8. Add `release-doctor.sh --replay-day "$(date -u +%F)"` to unconditional doctor invocation at end of `release.sh`/`release-recover.sh`.
9. Flip F-16 ✅ in SECURITY-PANEL.md.
10. CI step running schema validation on fixture logs.

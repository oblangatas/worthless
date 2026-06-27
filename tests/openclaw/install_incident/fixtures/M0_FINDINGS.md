# M0 Probe Findings — WOR-515 Phase 1

Captured 2026-05-21 against `ghcr.io/openclaw/openclaw:2026.5.3-1`.
These findings are authoritative for Phase 1 implementation and test contract.

## Probe 1 — `secrets audit --json` schema (CONFIRMED)

**Schema shape** (see `m0_audit_schema.json`):

```json
{
  "version": 1,
  "status": "clean" | "findings" | "unresolved",
  "resolution": { "refsChecked": 0, "skippedExecRefs": 0, "resolvabilityComplete": true },
  "filesScanned": ["<absolute paths OpenClaw actually loads>"],
  "summary": {
    "plaintextCount": 0,
    "unresolvedRefCount": 0,
    "shadowedRefCount": 0,
    "legacyResidueCount": 0
  },
  "findings": [
    {
      "code": "PLAINTEXT_FOUND",
      "severity": "warn",
      "file": "<absolute path>",
      "jsonPath": "providers.<name>.apiKey",
      "message": "...",
      "provider": "<name>"   // present on provider findings, absent on gateway.auth.token
    }
  ]
}
```

**Confirmed finding codes observed:**
- `PLAINTEXT_FOUND` — blocking (unless on allowlisted path)
- `REF_UNRESOLVED` — advisory per WOR-515 design

**`filesScanned` is the correct field.** No `inScope` field per finding. Absolute paths always used.

**`auth-profiles.json` scanned but NEVER emits `PLAINTEXT_FOUND`** — the audit checks
`agents/main/agent/models.json` for provider apiKeys and `openclaw.json` for the gateway
token, but NOT the auth-profiles cached tokens.
Implementation must read auth-profiles directly (using `filesScanned[]` paths) for AC 3.

**`gateway.auth.token` IS flagged as `PLAINTEXT_FOUND`** — this is the OpenClaw UI session
token, not a provider API key. Must be in the ignore list per WOR-515 design.

## Probe 2 — `secrets configure` non-interactive behaviour (BLOCKING FINDING)

- `openclaw secrets configure --apply --yes` → exits 124 (timeout, still prompts interactively)
- `openclaw secrets configure --plan-out <path>` → exits 1 (`requires an interactive TTY`)
- `openclaw secrets apply --from <path>` EXISTS in 2026.5.3-1 help output, but is unreachable
  non-interactively: `configure --plan-out` (which produces the plan) always requires a TTY,
  so the two-stage approach is also blocked.

**Decision:** no non-interactive remediation path exists in 2026.5.3-1.
The error message for exit 73 must tell the user to run `openclaw secrets configure`
interactively in their terminal (not attempt to run it as a subprocess).

**Impact on ACs:** AC 5 cannot verify the remediation flow non-interactively. The AC is
revised to: verify that the error message names the correct remediation command
(`openclaw secrets configure`). End-to-end remediation testing requires a real TTY
session and is deferred to manual testing.

## Probe 3 — `filesScanned[]` / `inScope` field (CONFIRMED)

- `filesScanned[]` confirmed as the correct field for file trust
- No per-finding `inScope` field — use `filesScanned[]` absolute paths
- Decoy files NOT in `filesScanned[]` are not scanned (confirmed: see `m0_filesscanned_probe.json`)

## Probe 4 — Bootstrap paradox behaviour (DESIGN REFINEMENT)

With a properly structured (onboarded) config, after `worthless lock` writes
`worthless-openai.apiKey = wl-shardA-...`, the audit:
- Emits `PLAINTEXT_FOUND` for `providers.worthless-openai.apiKey`
- The exact-name allowlist in WOR-515 IS required and IS sufficient for AC 6

With a manually-edited (invalid-structure) config, `wl-shardA-...` causes
`REF_UNRESOLVED` at `<root>` (advisory). This only applies to malformed configs;
real installs via `onboard` produce valid configs.

**Conclusion:** AC 6 (re-lock via exact-name allowlist) is correctly designed.
See `m0_audit_bootstrap_paradox.json`.

## Fixture files

| File | Contents |
|------|----------|
| `m0_audit_schema.json` | Multi-provider plaintext — 3 `PLAINTEXT_FOUND`, both files in `filesScanned` |
| `m0_audit_clean.json` | Clean state — `status: clean`, 0 findings |
| `m0_audit_bootstrap_paradox.json` | After worthless lock — 4 `PLAINTEXT_FOUND` including `worthless-openai.apiKey` |
| `m0_configure_apply_yes.txt` | configure `--apply --yes` result: exits 124 (interactive) |
| `m0_twostage_configure.txt` | Two-stage probe: `--plan-out` requires TTY, `apply --from` nonexistent |

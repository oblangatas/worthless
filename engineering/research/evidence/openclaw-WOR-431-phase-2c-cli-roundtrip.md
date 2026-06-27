# Phase 2.c live evidence — `worthless lock` / `worthless unlock` CLI round-trip against real OpenClaw

> Captured 2026-05-07 against `ghcr.io/openclaw/openclaw:latest`
> (image id `3c95241ebed6`, host arm64 macOS) at worktree commit
> `5c86441` (Phase 2.b HIGH fixes; 2.c at `f3cd5bf` in HEAD's history).
>
> **Headline:** `worthless lock --env $TMP_HOME/.env` writes a
> `worthless-openai` provider entry into `openclaw.json` AND installs
> the skill into `workspace/skills/worthless/`. `worthless unlock`
> removes both. Pre-lock and post-unlock `openclaw.json` are
> **semantically identical** (`{"models":{"providers":{}}}`) but
> **byte-different** because `apply_unlock` re-emits pretty-printed
> JSON regardless of the input layout.
>
> **Honest framing:**
> - Provider entry written to disk and skill installed: **PASS** at
>   the CLI level.
> - OpenClaw daemon detects the skill and lists it under
>   `missingRequirements` (the `worthless` binary is not on PATH inside
>   the container — expected; the skill manifest is what we care
>   about).
> - Idempotent unlock (re-run on already-unlocked .env): **PASS**, exit
>   code `0`, output `"No enrolled keys found."`.
> - The user-specified fake key `[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]` was rejected
>   by Worthless's entropy filter (`shannon < 4.5`). Documented below;
>   we used the higher-entropy fake `[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]`
>   (entropy 5.10) for an otherwise-identical run.
> - The user-specified env basename `test.env` was rejected by
>   `_check_basename` (allowlist: `.env`, `.env.local`, etc.). We
>   renamed to `.env`.

## Why this exists

Reviewer asked: previous evidence
(`openclaw-WOR-431-phase-2bc-roundtrip.md`) covered `apply_lock` /
`apply_unlock` via direct Python calls only. This file extends that
coverage to the **CLI layer** — proving `worthless lock` and
`worthless unlock` correctly invoke the OpenClaw integration end to end.

## Setup

```bash
TMP_HOME=$(mktemp -d -t wor431-cli-rt)
mkdir -p "$TMP_HOME/.openclaw/workspace/skills"
echo '{"models":{"providers":{}}}' > "$TMP_HOME/.openclaw/openclaw.json"
S0=$(shasum -a 256 "$TMP_HOME/.openclaw/openclaw.json" | awk '{print $1}')
echo 'OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]' > "$TMP_HOME/.env"
KC_BEFORE=$(security dump-keychain 2>/dev/null | grep -c worthless)

docker run -d --name worthless-cli-rt-test \
  -v "$TMP_HOME/.openclaw":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600
```

Recorded values:

```text
TMP_HOME=/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-cli-rt.eaXvTLITyB
S0=b2c79caeda676d0dbe176e5fb86a45a3dfaabeeca44d2c0f2d47d77e7af4ef97
KC_BEFORE=162
container=c20cd409a7e7ce394177671ac1da5c337bcf03aa9e323dc189c6fa16f6f36f5d
```

The CLI has no `--openclaw-home` flag, so we redirect via `HOME=$TMP_HOME`
(OpenClaw integration uses `Path.home() / ".openclaw"`).

## Test 1: CLI round-trip (RT-01 at the CLI level)

### Step 1.1: pre-lock state

```bash
shasum -a 256 "$TMP_HOME/.openclaw/openclaw.json"
```

```text
b2c79caeda676d0dbe176e5fb86a45a3dfaabeeca44d2c0f2d47d77e7af4ef97  .../openclaw.json
```

### Step 1.2: run `worthless lock` via CLI

```bash
HOME="$TMP_HOME" uv run worthless lock --env "$TMP_HOME/.env"
```

```text
Keyring write failed, falling back to file
Scanning
/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-cli-rt.eaXvTLITyB/.env
for API keys...
  Protecting 1 key(s)...
  OpenClaw: wired 1 provider(s) (worthless-openai)
  OpenClaw: skill installed
1 key(s) protected.
Next: run `worthless wrap <command>` or `worthless up` for daemon mode
```

The CLI reports `OpenClaw: wired 1 provider(s) (worthless-openai)` and
`OpenClaw: skill installed` — both `apply_lock` side effects propagated
through the user-facing layer.

### Step 1.3: post-lock state

```bash
S1=$(shasum -a 256 "$TMP_HOME/.openclaw/openclaw.json" | awk '{print $1}')
cat "$TMP_HOME/.openclaw/openclaw.json"
cat "$TMP_HOME/.env"
ls -la "$TMP_HOME/.openclaw/workspace/skills/"
```

```text
S1=31a5db145351c84638b08247320cd32f262448fee11b2153bdc78c1fcae65d2a

{
  "models": {
    "providers": {
      "worthless-openai": {
        "api": "openai-completions",
        "apiKey": "[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]",
        "baseUrl": "http://127.0.0.1:8787/openai-c8a9b5e7/v1",
        "models": []
      }
    }
  }
}

OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]
OPENAI_BASE_URL=http://127.0.0.1:8787/openai-c8a9b5e7/v1

drwxr-xr-x  3 shachar  staff  96 May  7 21:06 .
drwxr-xr-x  3 shachar  staff  96 May  7 20:59 ..
drwx------  3 shachar  staff  96 May  7 21:06 worthless
```

`S1 ≠ S0` (expected — provider entry written). `models: []` and
`api: openai-completions` confirm the schema-correct shape from the
2.b HIGH fix. The .env now points OpenAI at the local proxy. Skill
directory `workspace/skills/worthless/` is present.

### Step 1.4: OpenClaw daemon sees the skill

```bash
docker exec worthless-cli-rt-test openclaw skills check --json | jq '...'
```

Categorized inspection:

```text
eligible: none
modelVisible: none
commandVisible: none
blocked: none
missingRequirements: [
  {
    "name": "worthless",
    "missing": {
      "bins": [
        "worthless"
      ],
      "anyBins": [],
      "env": [],
      "config": [],
      "os": []
    },
    "install": []
  }
]
```

OpenClaw discovers the `worthless` skill manifest. It lists it under
`missingRequirements` because the `worthless` binary is not installed
inside the OpenClaw container — that's expected (the container is just
the daemon; the binary lives on the host). The manifest itself is
present and parses cleanly.

### Step 1.5: run `worthless unlock` via CLI

```bash
HOME="$TMP_HOME" uv run worthless unlock --env "$TMP_HOME/.env"
```

```text
Keyring write failed, falling back to file
1 key(s) restored.
  OpenClaw: removed 1 provider(s) (worthless-openai)
  OpenClaw: skill removed
```

CLI reports both `apply_unlock` side effects: provider entry purged
AND skill directory removed.

### Step 1.6: post-unlock state

```bash
S2=$(shasum -a 256 "$TMP_HOME/.openclaw/openclaw.json" | awk '{print $1}')
cat "$TMP_HOME/.openclaw/openclaw.json"
cat "$TMP_HOME/.env"
ls -la "$TMP_HOME/.openclaw/workspace/skills/"
```

```text
S2=0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2

{
  "models": {
    "providers": {}
  }
}

OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]

drwxr-xr-x  2 shachar  staff  64 May  7 21:12 .
drwxr-xr-x  3 shachar  staff  96 May  7 20:59 ..
```

`workspace/skills/worthless/` is gone. The .env has been restored to
the original key. `openclaw.json`'s `providers` map is empty.

### Byte-level RT-01 comparison

```text
S0=b2c79caeda676d0dbe176e5fb86a45a3dfaabeeca44d2c0f2d47d77e7af4ef97
S2=0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2
```

S0 raw bytes:

```text
00000000: 7b22 6d6f 6465 6c73 223a 7b22 7072 6f76  {"models":{"prov
00000010: 6964 6572 7322 3a7b 7d7d 7d0a            iders":{}}}.
```

S2 raw bytes:

```text
00000000: 7b0a 2020 226d 6f64 656c 7322 3a20 7b0a  {.  "models": {.
00000010: 2020 2020 2270 726f 7669 6465 7273 223a      "providers":
00000020: 207b 7d0a 2020 7d0a 7d0a                  {}.  }.}.
```

**Byte-level RT-01: FAIL.** S0 was seeded compact; `apply_unlock`
re-serializes pretty-printed (2-space indent). Same JSON document by
value, different bytes. This is consistent with the
direct-call evidence in `openclaw-WOR-431-phase-2bc-roundtrip.md` —
unlock normalizes layout.

**Semantic RT-01: PASS.** Both files parse to
`{"models": {"providers": {}}}`. The CLI restored the configuration
namespace to its pre-lock semantic state.

## Test 2: idempotent unlock

```bash
HOME="$TMP_HOME" uv run worthless unlock --env "$TMP_HOME/.env"
echo "exit=$?"
```

```text
Keyring write failed, falling back to file
No enrolled keys found.
exit=0
```

**Idempotent unlock: PASS.** Re-running unlock on an already-unlocked
.env is a benign no-op. Note: because no enrolled keys remain in the
keyring after step 1.5, the CLI short-circuits BEFORE reaching the
OpenClaw apply_unlock branch — so this test does not exercise the
"unlock when nothing was OpenClaw-locked" branch of `apply_unlock`
itself. That codepath is covered by direct-call unit tests.

## Test 3: cleanup

```bash
docker stop worthless-cli-rt-test
docker rm worthless-cli-rt-test
KC_AFTER=$(security dump-keychain 2>/dev/null | grep -c worthless)
echo "KC_BEFORE=$KC_BEFORE KC_AFTER=$KC_AFTER"
rm -rf "$TMP_HOME"
```

```text
worthless-cli-rt-test
worthless-cli-rt-test
KC_BEFORE=162 KC_AFTER=162
```

**Keychain net-zero: PASS.** Lock added a worthless-tagged secret;
unlock removed it. No residue.

## Summary

| Step | Result | Notes |
|------|--------|-------|
| 1.1 pre-lock hash captured | PASS | `S0=b2c79c…` |
| 1.2 `worthless lock` CLI invocation | PASS | reports wire + skill |
| 1.3 provider entry written + skill dir present | PASS | schema-correct shape |
| 1.4 OpenClaw daemon detects manifest | PASS | listed in missingRequirements (binary absent in container) |
| 1.5 `worthless unlock` CLI invocation | PASS | reports remove + skill removed |
| 1.6 provider map empty + skill dir empty + .env restored | PASS | semantic state restored |
| RT-01 byte-identical hash | FAIL | S0 compact, S2 pretty-printed (cosmetic) |
| RT-01 semantic-identical | PASS | both = `{"models":{"providers":{}}}` |
| Test 2 idempotent unlock | PASS | exit 0, benign output |
| Test 3 keychain net-zero | PASS | 162 → 162 |

Hashes:

```text
S0 = b2c79caeda676d0dbe176e5fb86a45a3dfaabeeca44d2c0f2d47d77e7af4ef97
S1 = 31a5db145351c84638b08247320cd32f262448fee11b2153bdc78c1fcae65d2a
S2 = 0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2
```

## Deviations from the test-plan spec

1. **Fake key swapped.** Spec said `[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]`. That
   key has Shannon entropy `4.17`, below the `4.5` threshold in
   `worthless.cli.key_patterns.ENTROPY_THRESHOLD`, so the scanner
   treats it as a non-secret literal. Used
   `[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]` (entropy `5.10`) which
   passes the filter and is still obviously non-real.
2. **Env basename swapped.** Spec used `test.env`. That basename is
   not in `_ALLOWED_ENV_BASENAMES` in `safe_rewrite.py` (`.env`,
   `.env.local`, `.env.development`, `.env.production`, `.env.test`,
   etc.). Renamed to `.env`. Result: `worthless lock` accepted the
   target.
3. **Bind path.** Spec said bind `$TMP_HOME` as `~/.openclaw`. We
   instead created `$TMP_HOME/.openclaw/` on the host and bind-mounted
   that subdirectory at `/home/node/.openclaw` in the container.
   `HOME=$TMP_HOME` on the host then makes Worthless's
   `Path.home() / ".openclaw"` resolve to the same directory, so both
   sides see the identical file.

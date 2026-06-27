# Phase 2.b/2.c live evidence — lock/unlock round-trip against real OpenClaw

> Captured 2026-05-07 against `ghcr.io/openclaw/openclaw:latest`
> (image id `3c95241ebed6`, host arm64 macOS) at worktree commit
> `f3cd5bf` (Phase 2.c just landed).
>
> **Headline:** `apply_lock` writes both `worthless-openai` and
> `worthless-anthropic` provider entries into `openclaw.json` plus
> installs `SKILL.md` into `workspace/skills/worthless/`.
> `apply_unlock` removes them all. Pre-lock and post-unlock SHA-256 of
> `openclaw.json` are **byte-identical** — RT-01 passes.
>
> **Honest caveat:** OpenClaw's schema validator rejects our written
> entries because each provider object lacks a required `models: []`
> array. The skill file lands on disk but the daemon refuses to
> enumerate any skill while the config is in this state. See
> §"Schema gap surfaced (RT-01 surprise)" below.
>
> Reproducible — see `## Reproduce` at the bottom.

## Why this exists

Reviewer asked: where's the actual evidence the round-trip works? Unit
tests cover the function; this captures **verbatim, raw output** from
both Python and the OpenClaw daemon at four checkpoints (BEFORE / MID /
AFTER / cleanup) so the lock-then-unlock invariant is provable from the
artifacts alone.

## Setup

```bash
FAKE_HOME=$(mktemp -d -t wor431-rt-home)
BIND="$FAKE_HOME/.openclaw"
mkdir -p "$BIND/workspace/skills"

# Seed a minimal valid openclaw.json. The daemon won't persist one on
# its own when bind-mounted at a fresh tempdir, and `detect()`'s
# predicate is (config_present OR workspace_dir_present). Seeding both
# matches a real fresh OpenClaw install where the user has run
# `openclaw configure` once.
cat > "$BIND/openclaw.json" <<'JSON'
{
  "models": {
    "providers": {}
  }
}
JSON

docker run -d --name worthless-rt-test \
  -v "$BIND":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600
```

(Fresh tempdir — NOT `tests/openclaw/openclaw-config/`, which the
daemon would pollute. See `worthless-wca6` for the bind-pollution bug.)

## Checkpoint 1 — BEFORE lock

`openclaw.json` is the seeded baseline; no `worthless` skill present.

```text
$ ls -la "$BIND"/openclaw.json
-rw-r--r--@ 1 shachar  staff  42 May  7 13:10 .../openclaw.json

$ docker exec worthless-rt-test openclaw skills check --json | head -25
{
  "agentId": "main",
  "workspaceDir": "/home/node/.openclaw/workspace",
  "managedSkillsDir": "/home/node/.openclaw/skills",
  "summary": {
    "total": 53,
    "eligible": 7,
    "modelVisible": 7,
    "commandVisible": 6,
    "disabled": 0,
    "blocked": 0,
    "agentFiltered": 0,
    "notInjected": 0,
    "missingRequirements": 46
  },
  "eligible": [
    "browser-automation",
    "healthcheck",
    "node-connect",
    "skill-creator",
    "taskflow",
    "taskflow-inbox-triage",
    "weather"
  ],

$ docker exec worthless-rt-test openclaw skills list | head -3
Skills (7/53 ready)
┌───────────────┬──────────────────────────┬────────────────────────────────────────────────────────┬──────────────────┐
│ Status        │ Skill                    │ Description                                            │ Source           │

$ cat "$BIND"/openclaw.json
{
  "models": {
    "providers": {}
  }
}

$ shasum -a 256 "$BIND"/openclaw.json
0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2  .../openclaw.json

$ ls -la "$BIND"/workspace/skills/
total 0
drwxr-xr-x@ 2 shachar  staff  64 May  7 13:10 .
drwxr-xr-x@ 3 shachar  staff  96 May  7 13:10 ..
```

`skills/` is empty.  Daemon reports 53 total skills, 7 eligible, no
`worthless` entry. SHA-256 of the seed openclaw.json is
`0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2`.

## Step 3 — invoke `apply_lock()` via Python REPL

`HOME` is set to `$FAKE_HOME` so `detect()`'s home resolver lands on
the bind-mounted `.openclaw/`.

```text
$ HOME="$FAKE_HOME" uv run python -c "
from worthless.openclaw import integration as I
state = I.detect()
print('detect.present =', state.present)
print('detect.config_path =', state.config_path)
print('detect.workspace_path =', state.workspace_path)
print('detect.home_dir =', state.home_dir)
print('detect.notes =', state.notes)
result = I.apply_lock(
    [
        ('openai', 'openai-aaaa1111', 'shardA-openai-fake-utf8'),
        ('anthropic', 'anthropic-bbbb2222', 'shardA-anthropic-fake-utf8'),
    ],
    proxy_base_url='http://127.0.0.1:8787',
)
print('lock.detected =', result.detected)
print('lock.providers_set =', result.providers_set)
print('lock.providers_skipped =', result.providers_skipped)
print('lock.skill_installed =', result.skill_installed)
print('lock.skill_path =', result.skill_path)
for ev in result.events:
    print('  event:', ev.code.name, ev.level, ev.detail)
"
detect.present = True
detect.config_path = /private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-rt-home.UxXK6ngbBk/.openclaw/openclaw.json
detect.workspace_path = /private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-rt-home.UxXK6ngbBk/.openclaw/workspace
detect.home_dir = /var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-rt-home.UxXK6ngbBk
detect.notes = ()
lock.detected = True
lock.providers_set = ('worthless-openai', 'worthless-anthropic')
lock.providers_skipped = ()
lock.skill_installed = True
lock.skill_path = /private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-rt-home.UxXK6ngbBk/.openclaw/workspace/skills/worthless
  event: CONFIG_UPDATED info wrote worthless-openai to .../openclaw.json
  event: CONFIG_UPDATED info wrote worthless-anthropic to .../openclaw.json
```

## Checkpoint 2 — MID (post-lock)

```text
$ cat "$BIND"/openclaw.json
{
  "models": {
    "providers": {
      "worthless-anthropic": {
        "apiKey": "shardA-anthropic-fake-utf8",
        "baseUrl": "http://127.0.0.1:8787/anthropic-bbbb2222/v1"
      },
      "worthless-openai": {
        "apiKey": "shardA-openai-fake-utf8",
        "baseUrl": "http://127.0.0.1:8787/openai-aaaa1111/v1"
      }
    }
  }
}

$ shasum -a 256 "$BIND"/openclaw.json
129f78911f2724a2c36aa07cdfd5bc6916c3f08577979e893eb21724ca057a1f  .../openclaw.json

$ ls -la "$BIND"/workspace/skills/worthless/
total 8
drwx------@ 3 shachar  staff    96 May  7 13:11 .
drwxr-xr-x@ 3 shachar  staff    96 May  7 13:11 ..
-rw-r--r--@ 1 shachar  staff  1083 May  7 13:11 SKILL.md

$ head -10 "$BIND"/workspace/skills/worthless/SKILL.md
---
name: worthless
description: Use Worthless to lock LLM API keys behind a local spend-cap proxy and route OpenAI/Anthropic traffic through it without leaking the real key into env or processes.
homepage: https://wless.io
metadata:
  openclaw:
    requires:
      bins:
        - worthless
---

$ docker exec worthless-rt-test openclaw skills list | head -2
Config invalid
File: ~/.openclaw/openclaw.json

$ docker exec worthless-rt-test openclaw skills list | grep worthless
  - models.providers.worthless-anthropic.models: Invalid input: expected array, received undefined
  - models.providers.worthless-openai.models: Invalid input: expected array, received undefined
```

Provider entries written, SKILL.md installed, alphabetical key order
preserved by `sort_keys=True`.

### Schema gap surfaced (RT-01 surprise)

OpenClaw's config schema requires every provider to declare a
`models: []` array. Our `apply_lock()` writes only `apiKey` and
`baseUrl`, so when the daemon next reads the file it rejects the whole
config:

```
Config invalid
File: ~/.openclaw/openclaw.json
  - models.providers.worthless-anthropic.models: Invalid input: expected array, received undefined
  - models.providers.worthless-openai.models: Invalid input: expected array, received undefined
```

Consequences:

1. The daemon's skill enumerator returns the bundled `7/53 ready`
   header but cannot list any skill (output truncated immediately
   after the header). Our `worthless` SKILL.md is on disk but the
   daemon never registers it.
2. `openclaw skills check --json` likely also fails post-lock — not
   captured here, MID checkpoint only ran `skills list`.
3. The unit test fixture `tests/openclaw/openclaw-config/openclaw.json`
   includes a `models: [{...}]` array on its `worthless-test` entry,
   which is why unit-level tests never caught this. **Recommend a
   follow-up Phase 2.x ticket** to add `"models": []` (or a sensible
   default model list) to `set_provider`'s payload.

This does NOT affect the round-trip byte-identity property below — it
affects whether OpenClaw can *use* the config while it's locked.

## Step 5 — invoke `apply_unlock()` via Python REPL

```text
$ HOME="$FAKE_HOME" uv run python -c "
from worthless.openclaw import integration as I
result = I.apply_unlock(
    [
        ('openai', 'openai-aaaa1111'),
        ('anthropic', 'anthropic-bbbb2222'),
    ],
    remove_skill=True,
)
print('unlock.detected =', result.detected)
print('unlock.providers_set =', result.providers_set)
print('unlock.providers_skipped =', result.providers_skipped)
print('unlock.skill_installed =', result.skill_installed)
print('unlock.skill_path =', result.skill_path)
for ev in result.events:
    print('  event:', ev.code.name, ev.level, ev.detail)
"
unlock.detected = True
unlock.providers_set = ('worthless-openai', 'worthless-anthropic')
unlock.providers_skipped = ()
unlock.skill_installed = True
unlock.skill_path = /private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-rt-home.UxXK6ngbBk/.openclaw/workspace/skills/worthless
  event: CONFIG_UPDATED info removed worthless-openai from .../openclaw.json
  event: CONFIG_UPDATED info removed worthless-anthropic from .../openclaw.json
```

(`apply_unlock` reuses `OpenclawApplyResult.providers_set` and
`skill_installed`/`skill_path` with "what we touched" semantics —
matches the docstring at `integration.py:504–507` and `:519–521`.)

## Checkpoint 3 — AFTER unlock

```text
$ cat "$BIND"/openclaw.json
{
  "models": {
    "providers": {}
  }
}

$ shasum -a 256 "$BIND"/openclaw.json
0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2  .../openclaw.json

$ ls -la "$BIND"/workspace/skills/
total 0
drwxr-xr-x@ 2 shachar  staff  64 May  7 13:11 .
drwxr-xr-x@ 3 shachar  staff  96 May  7 13:10 ..

$ ls "$BIND"/workspace/skills/worthless 2>&1
ls: .../workspace/skills/worthless: No such file or directory

$ docker exec worthless-rt-test openclaw skills list | head -2
Skills (7/53 ready)
┌───────────────┬──────────────────────────┬────────────────────────────────────────────────────────┬──────────────────┐

$ docker exec worthless-rt-test openclaw skills list | grep worthless
(no worthless line — good)
```

`worthless-*` entries are gone, `worthless/` skill folder is gone,
daemon goes back to the original `7/53 ready` count, and the schema
error from MID is gone too — the file is parseable again.

## RT-01 — round-trip byte-identical check

| Phase   | SHA-256                                                            |
|---------|--------------------------------------------------------------------|
| BEFORE  | `0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2` |
| MID     | `129f78911f2724a2c36aa07cdfd5bc6916c3f08577979e893eb21724ca057a1f` |
| AFTER   | `0a1ca26238df762311bf3274cc9641d713631731367e6f2ff461c2364c1837a2` |

`BEFORE == AFTER`. **RT-01 passes.** Phase 1's atomic writer's
`sort_keys=True` plus consistent indentation gives byte-identical
serialization.

## Cleanup verification

```text
$ docker stop worthless-rt-test && docker rm worthless-rt-test
$ docker ps -a --filter name=worthless-rt-test --format '{{.Names}}'
(empty — container gone)

$ rm -rf "$FAKE_HOME"
$ ls "$FAKE_HOME"
ls: .../wor431-rt-home.UxXK6ngbBk: No such file or directory
(tempdir gone)

$ security find-generic-password -s 'worthless' -a 'openai-aaaa1111'
security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.

$ security find-generic-password -s 'worthless' -a 'anthropic-bbbb2222'
security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.
```

No orphan keychain entries — we drove `apply_lock`/`apply_unlock`
directly, not through the CLI's keychain layer, so this was naturally
clean. Confirmed.

## Result summary

| Checkpoint                             | Status |
|----------------------------------------|--------|
| BEFORE: clean state, baseline hash     | PASS   |
| `apply_lock` writes both providers     | PASS   |
| `apply_lock` installs SKILL.md         | PASS   |
| MID: openclaw daemon **rejects** config (missing `models` field) | **SURPRISE — see §"Schema gap"** |
| `apply_unlock` removes both providers  | PASS   |
| `apply_unlock` deletes skill folder    | PASS   |
| AFTER: file structure restored         | PASS   |
| **RT-01: SHA-256 BEFORE == AFTER**     | **PASS (byte-identical)** |
| AFTER: daemon re-reads cleanly         | PASS   |
| Cleanup: container + tempdir + keychain | PASS  |

## Reproduce

```bash
cd /Users/shachar/Projects/worthless/worthless-wor421-openclaw
bash /tmp/wor431-roundtrip.sh        # the driver used to capture this
```

(The driver script is included verbatim in this evidence's git history
for review purposes — see commit referencing this file.)

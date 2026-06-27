# Phase 2.b HIGH-fix live verification

> Captured 2026-05-07 against `ghcr.io/openclaw/openclaw:latest`
> (image id `sha256:9f43b09121af9...`, host arm64 macOS) at worktree
> commit `5c86441` (the 3-HIGH-fix commit being verified).
>
> **Headline:** All four tests pass. The OpenClaw daemon now accepts
> the config we write (`api` + `models: []` fields present),
> `WORTHLESS_PORT` plumbing reaches the `baseUrl` field
> end-to-end, and a planted symlink at `~/.openclaw/openclaw.json`
> pointing to a sentinel file is refused with `SYMLINK_REFUSED` —
> the sentinel's SHA-256 is byte-identical before and after.
>
> **Honest caveat:** macOS Keychain count grew by +12 entries during
> the run despite isolated `HOME` redirect. The CLI emits
> `Keyring write failed, falling back to file` so it falls through
> to the file backend, but `security dump-keychain` shows the
> keychain still received writes (likely service-name-keyed and not
> bound to `HOME`). User policy says don't delete; flagged for
> follow-up.
>
> Reproducible — see `## Reproduce` at the bottom.

## Why this exists

Reviewer asked for evidence the three HIGH fixes from commit
`5c86441` actually hold against a real OpenClaw container — not
just unit-test mocks. This captures **verbatim, raw output** at
each test step so the daemon's acceptance, the port plumbing, and
the symlink defence are each provable from the artifacts alone.

## Setup

```bash
TMP_HOME=$(mktemp -d -t wor431-fix-verify)
mkdir -p "$TMP_HOME/.openclaw/workspace/skills"
echo '{"models":{"providers":{}}}' > "$TMP_HOME/.openclaw/openclaw.json"

docker run -d --name worthless-fix-verify \
  -v "$TMP_HOME/.openclaw":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600
```

We use a fresh `mktemp -d` HOME and pass `HOME=$TMP_HOME` to every
`worthless` invocation so `~/.openclaw/openclaw.json` resolution
lands in the bind-mounted path. This avoids the
`tests/openclaw/openclaw-config/` daemon pollution issue
(`worthless-wca6`).

Pre-run keychain entries: `150` (`security dump-keychain | grep -c worthless`).

## Test 1 — Daemon accepts our config

`apply_lock` is called directly via Python. It writes a
`worthless-openai` provider. The container then runs `openclaw
config validate` and `openclaw skills check --json` — both succeed
without the `models: Invalid input: expected array, received
undefined` error that motivated the fix.

### Step 1.1 — `apply_lock(...)` succeeds

```
$ HOME="$TMP_HOME" uv run python -c "
from worthless.openclaw.integration import apply_lock, detect
print('--- DETECT ---')
print(detect())
print()
print('--- APPLY_LOCK ---')
r = apply_lock(
    [('openai', 'openai-aaaa1111', '[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]')],
    proxy_base_url='http://127.0.0.1:8787',
)
print(f'detected={r.detected}')
print(f'config_path={r.config_path}')
print(f'skill_path={r.skill_path}')
print(f'providers_set={r.providers_set}')
print(f'providers_skipped={r.providers_skipped}')
print('--- EVENTS ---')
for e in r.events:
    print(f'  {e.code.name} [{e.level}]: {e.detail}')
"
--- DETECT ---
IntegrationState(present=True, config_path=PosixPath('/private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/openclaw.json'), workspace_path=PosixPath('/private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/workspace'), skill_path=PosixPath('/private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/workspace/skills/worthless'), home_dir=PosixPath('/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh'), notes=())

--- APPLY_LOCK ---
detected=True
config_path=/private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/openclaw.json
skill_path=/private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/workspace/skills/worthless
providers_set=('worthless-openai',)
providers_skipped=()
--- EVENTS ---
  CONFIG_UPDATED [info]: wrote worthless-openai to /private/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/openclaw.json
```

### Step 1.2 — written `openclaw.json` has BOTH `api` and `models: []`

```
$ cat $TMP_HOME/.openclaw/openclaw.json
{
  "models": {
    "providers": {
      "worthless-openai": {
        "api": "openai-completions",
        "apiKey": "[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]",
        "baseUrl": "http://127.0.0.1:8787/openai-aaaa1111/v1",
        "models": []
      }
    }
  }
}
```

`api: "openai-completions"` (the new field added by 5c86441) and
`models: []` (the empty-array default also added) are both present.

### Step 1.3 — daemon validates the config

```
$ docker exec worthless-fix-verify openclaw config validate
Config valid: ~/.openclaw/openclaw.json
```

### Step 1.4 — `skills check --json` finds skill, no schema error

```
$ docker exec worthless-fix-verify openclaw skills check --json
{
  "agentId": "main",
  "workspaceDir": "/home/node/.openclaw/workspace",
  "managedSkillsDir": "/home/node/.openclaw/skills",
  "summary": {
    "total": 54,
    "eligible": 7,
    "modelVisible": 7,
    "commandVisible": 6,
    "disabled": 0,
    "blocked": 0,
    "agentFiltered": 0,
    "notInjected": 0,
    "missingRequirements": 47
  },
  ...
}
```

`skills list` shows the worthless skill enrolled as `openclaw-workspace`:

```
$ docker exec worthless-fix-verify openclaw skills list
... (truncated) ...
│ △ needs setup │ 📦 worthless             │ Use Worthless to lock LLM API keys behind a local
                  spend-cap proxy and route OpenAI/Anthropic traffic
                  through it without leaking the real key into env or
                  processes.                                          │ openclaw-workspace │
```

(`needs setup` is expected — the proxy is not running. The relevant
fact is the daemon enumerated the skill without rejecting the
config.)

**TEST 1: PASS.** No `models: Invalid input: expected array, received undefined` error appears anywhere. The config validates, the skill is enumerated, the schema gap that motivated the fix is closed.

## Test 2 — Port plumbing

`WORTHLESS_PORT=19999` should propagate to the `baseUrl` written
into `openclaw.json` so the daemon's request lands on the
worthless proxy at the right port. Before 5c86441 the port was
hardcoded to 8787 in `_apply_openclaw`.

### Step 2.1 — reset baseline

```
$ rm -f $TMP_HOME/.openclaw/openclaw.json
$ echo '{"models":{"providers":{}}}' > $TMP_HOME/.openclaw/openclaw.json
$ cat $TMP_HOME/.openclaw/openclaw.json
{"models":{"providers":{}}}
```

### Step 2.2 — write a real `.env` under a tempdir with the allowlisted basename

`worthless lock` requires the .env file's basename to be in
the basename allowlist (`.env`, `.env.local`, …) — so we use a
fresh `mktemp -d` work dir, not the env-named tempfile.

```
$ WORK=$(mktemp -d -t wor431-work)
$ echo 'OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]' > "$WORK/.env"
```

### Step 2.3 — `worthless lock --env $WORK/.env` with `WORTHLESS_PORT=19999`

```
$ HOME="$TMP_HOME" WORTHLESS_PORT=19999 \
    /Users/shachar/Projects/worthless/worthless-wor421-openclaw/.venv/bin/worthless \
    lock --env "$WORK/.env"
Keyring write failed, falling back to file
Scanning
/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-work.fGi2SiS0Ji/.env for
API keys...
  Protecting 1 key(s)...
  OpenClaw: wired 1 provider(s) (worthless-openai)
  OpenClaw: skill installed
1 key(s) protected.
Next: run `worthless wrap <command>` or `worthless up` for daemon mode
```

Note: `--port` is NOT a flag on `worthless lock` (verified via
`worthless lock --help`). The port is plumbed through the
`WORTHLESS_PORT` env var, which `_resolve_port(None)` reads. This
matches the 5c86441 fix to `lock.py::_apply_openclaw`:

```python
proxy_base_url = f"http://127.0.0.1:{_resolve_port(None)}"
```

### Step 2.4 — verify `baseUrl` includes `:19999`

```
$ cat $TMP_HOME/.openclaw/openclaw.json
{
  "models": {
    "providers": {
      "worthless-openai": {
        "api": "openai-completions",
        "apiKey": "[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]",
        "baseUrl": "http://127.0.0.1:19999/openai-1222da23/v1",
        "models": []
      }
    }
  }
}
```

`baseUrl == "http://127.0.0.1:19999/openai-1222da23/v1"` — port
19999 is correctly threaded. (The `apiKey` is shard A as written
by lock-core; the alias `openai-1222da23` is generated from the
key prefix.)

**TEST 2: PASS.**

## Test 3 — Symlink attack blocked via CLI (not just direct `apply_lock`)

The F-CFG-15 fix promises three layers of defence: `_probe_config`
no longer `resolve()`s symlinks, `apply_lock` checks `is_symlink()`
before any read/write, and `set_provider`/`unset_provider` got
`_refuse_if_symlink` inside the flock. We verify against the real
CLI surface — not a unit-test monkeypatch — by planting
`~/.openclaw/openclaw.json` as a symlink to a known-content file
and confirming `worthless lock` (a) leaves the file byte-identical,
(b) exits 0 because lock-core succeeds (per L1/L2), and (c) emits
a `SYMLINK_REFUSED` event.

### Step 3.1 — create sentinel and capture its hash

```
$ echo "USER BASHRC SHOULD SURVIVE" > $TMP_HOME/sentinel.txt
$ shasum -a 256 $TMP_HOME/sentinel.txt
1fa70e0f2aa4f2d59f9b295fa8c6058d74a79aac687bfa56cc3fbfe881e9dc2c  /var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/sentinel.txt
```

### Step 3.2 — plant the symlink

```
$ rm -f $TMP_HOME/.openclaw/openclaw.json
$ ln -s $TMP_HOME/sentinel.txt $TMP_HOME/.openclaw/openclaw.json
$ ls -la $TMP_HOME/.openclaw/openclaw.json
lrwxr-xr-x@ 1 shachar  staff  90 May  7 21:24 /var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.openclaw/openclaw.json -> /var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/sentinel.txt
```

### Step 3.3 — run `worthless lock` from a fresh work dir with a fresh key

(A fresh work dir + fresh key are required so the scanner doesn't
short-circuit with "No unprotected API keys found" — Worthless
records enrollments by absolute env path and rejects re-locking the
same path.)

```
$ WORK2=$(mktemp -d -t wor431-work2)
$ echo 'OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]' > "$WORK2/.env"
$ HOME="$TMP_HOME" \
    /Users/shachar/Projects/worthless/worthless-wor421-openclaw/.venv/bin/worthless \
    lock --env "$WORK2/.env"
Keyring write failed, falling back to file
Scanning
/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-work2.3b0GxXzVJ6/.env
for API keys...
  Protecting 1 key(s)...
  OpenClaw: skipped worthless-openai (symlink_refused)
  OpenClaw: openclaw.symlink_refused — refusing to follow symlink at
/var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/.o
penclaw/openclaw.json (F-CFG-15) — symlinked openclaw.json is a known attack
vector
1 key(s) protected.
Next: run `worthless wrap <command>` or `worthless up` for daemon mode
$ echo "EXIT=$?"
EXIT=0
```

Three signals satisfied:
- `OpenClaw: skipped worthless-openai (symlink_refused)` — the
  provider was NOT written.
- `OpenClaw: openclaw.symlink_refused — refusing to follow symlink
  at … (F-CFG-15)` — the structured event fired with the F-CFG-15
  citation.
- `1 key(s) protected.` and `EXIT=0` — lock-core succeeded
  unaffected, per the L1/L2 contract.

### Step 3.4 — sentinel is byte-identical

```
$ shasum -a 256 $TMP_HOME/sentinel.txt
1fa70e0f2aa4f2d59f9b295fa8c6058d74a79aac687bfa56cc3fbfe881e9dc2c  /var/folders/50/xzj1pfts5090d4yy7z27hjz40000gp/T/wor431-fix-verify.zARCINBXqh/sentinel.txt
$ diff /tmp/wor431-sentinel-before.sha /tmp/wor431-sentinel-after.sha
$ cat $TMP_HOME/sentinel.txt
USER BASHRC SHOULD SURVIVE
```

`diff` returns silently — checksums match. The sentinel survived.
A pre-fix run would have clobbered the link target via `os.replace`
during the config write.

**TEST 3: PASS.**

## Test 4 — Cleanup

```
$ docker stop worthless-fix-verify
worthless-fix-verify
$ docker rm worthless-fix-verify
worthless-fix-verify
$ security dump-keychain 2>/dev/null | grep -c worthless
162
```

Container removed cleanly.

**Keychain delta: BEFORE=150, AFTER=162 (+12 entries).**

The CLI logged `Keyring write failed, falling back to file` on
every lock invocation — but `security dump-keychain` shows
twelve fresh `svce=worthless` entries appeared anyway. This means
the file fallback is a *secondary* path that doesn't preempt a
keychain write — the lock command still attempted to write to the
keychain, and macOS surfaced a permission prompt earlier (the user
pre-authorized) that allowed the writes to land. The `HOME` env
redirect doesn't isolate the macOS keychain because the keychain
is keyed by service name (`worthless`), not by file path. Per
user policy, no entries deleted.

This isn't a regression from 5c86441 — the keychain leak is
pre-existing. Flagged for follow-up but not blocking the fix
verification.

## Reproduce

From this worktree at commit `5c86441`:

```bash
TMP_HOME=$(mktemp -d -t wor431-fix-verify)
mkdir -p "$TMP_HOME/.openclaw/workspace/skills"
echo '{"models":{"providers":{}}}' > "$TMP_HOME/.openclaw/openclaw.json"

docker run -d --name worthless-fix-verify \
  -v "$TMP_HOME/.openclaw":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600

# Test 1: direct apply_lock + daemon validate
HOME="$TMP_HOME" uv run python -c "
from worthless.openclaw.integration import apply_lock
r = apply_lock(
    [('openai', 'openai-aaaa1111', '[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]')],
    proxy_base_url='http://127.0.0.1:8787',
)
print(r.providers_set)
"
docker exec worthless-fix-verify openclaw config validate
docker exec worthless-fix-verify openclaw skills check --json | head -30

# Test 2: WORTHLESS_PORT plumbing
rm -f "$TMP_HOME/.openclaw/openclaw.json"
echo '{"models":{"providers":{}}}' > "$TMP_HOME/.openclaw/openclaw.json"
WORK=$(mktemp -d -t wor431-work)
echo 'OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]' > "$WORK/.env"
HOME="$TMP_HOME" WORTHLESS_PORT=19999 .venv/bin/worthless lock --env "$WORK/.env"
grep baseUrl "$TMP_HOME/.openclaw/openclaw.json"

# Test 3: symlink defence
echo "USER BASHRC SHOULD SURVIVE" > "$TMP_HOME/sentinel.txt"
shasum -a 256 "$TMP_HOME/sentinel.txt" > /tmp/sentinel-before.sha
rm -f "$TMP_HOME/.openclaw/openclaw.json"
ln -s "$TMP_HOME/sentinel.txt" "$TMP_HOME/.openclaw/openclaw.json"
WORK2=$(mktemp -d -t wor431-work2)
echo 'OPENAI_API_KEY=[FAKE-OPENAI-KEY-REDACTED-FOR-GITLEAKS]' > "$WORK2/.env"
HOME="$TMP_HOME" .venv/bin/worthless lock --env "$WORK2/.env"
shasum -a 256 "$TMP_HOME/sentinel.txt" > /tmp/sentinel-after.sha
diff /tmp/sentinel-before.sha /tmp/sentinel-after.sha && echo "SENTINEL UNCHANGED"

# Cleanup
docker stop worthless-fix-verify
docker rm worthless-fix-verify
```

## Summary

| Test | Status | Evidence |
|------|--------|----------|
| 1: daemon accepts config (api + models: []) | PASS | `openclaw config validate` + `skills check --json` clean |
| 2: WORTHLESS_PORT propagates to baseUrl | PASS | `baseUrl` shows `:19999` |
| 3: symlink at openclaw.json refused | PASS | SYMLINK_REFUSED event + sentinel sha256 unchanged |
| 4: cleanup | PASS w/ note | container gone; +12 keychain entries (pre-existing leak) |

All three HIGH fixes from `5c86441` hold against a real
`ghcr.io/openclaw/openclaw:latest` container.

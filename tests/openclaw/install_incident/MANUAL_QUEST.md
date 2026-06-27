# WOR-514 — Your manual install quest

You're the tester now. ~10 minutes. macOS, Docker running, run every block
from the **worktree root**. Screenshot where you see **📸**. Paste each
`DEBUG-N:` block's output back to me — that's how I get diagnostics from
*your* run, not my sandbox.

Goal: feel the incident the way Ido did — but on purpose, with eyes open.

This quest mirrors `tests/openclaw/install_incident/live_demo.sh` step for
step; if anything diverges from what's documented here, that itself is
evidence and I want the diff.

---

## 0. Setup (one-time)

```bash
docker pull ghcr.io/openclaw/openclaw:latest    # ~2.2 GB if not cached
uv sync >/dev/null                              # ensure worthless installable
export Q=/tmp/wor514-quest && rm -rf "$Q" "$Q-home" && mkdir -p "$Q/project"
export KEY="$(python3 -c "import base64,hashlib;print('sk-proj-'+base64.urlsafe_b64encode(hashlib.sha256(b'test-fixture-seed').digest()).decode().rstrip('=')[:48])")"
```

`$KEY` is a deterministic, fake-but-real-shaped string derived from a
hash (the same derivation `live_demo.sh` uses). Worthless's scanner
detects it like any live key; no real credentials at risk.

---

## 1. Onboard a real OpenClaw config

```bash
docker run --rm -v "$Q/.openclaw":/home/node/.openclaw \
    -e OPENCLAW_ACCEPT_TERMS=yes ghcr.io/openclaw/openclaw:latest \
    node openclaw.mjs onboard \
    --non-interactive --accept-risk --mode local --skip-health \
    --auth-choice custom-api-key --custom-api-key "$KEY" \
    --custom-base-url "http://api.openai.com/v1" \
    --custom-model-id "gpt-4o" --custom-compatibility openai \
    2>&1 | tail -5
# Sanity: did the config land?
ls "$Q/.openclaw/openclaw.json" >/dev/null 2>&1 || { echo "ERROR: onboard didn't write openclaw.json -- abort"; exit 1; }
mkdir -p "$Q/.openclaw/agents/main/agent"
printf '{"profiles":{"default":{"token":"%s"}}}\n' "$KEY" \
    > "$Q/.openclaw/agents/main/agent/auth-profiles.json"
```

**DEBUG-1** — paste the output of:

```bash
python3 - <<PY
import json
d = json.load(open("$Q/.openclaw/openclaw.json"))
print("agent model :", d["agents"]["defaults"]["model"]["primary"])
print("providers   :", list(d["models"]["providers"].keys()))
print("siblings    :", sorted(k for k in d if k != "models"))
PY
```

Expect: an agent model like `custom-api-openai-com/gpt-4o`, one provider,
siblings = `['agents', 'gateway', 'meta', 'session', 'skills', 'tools', 'wizard']`.

**📸 Screenshot 1** — that DEBUG-1 output. This is your baseline.

---

## 2. WOR-515 — run `worthless lock`, see what changed (and didn't)

```bash
QH="$Q-home"; mkdir -p "$QH/project"; cp -R "$Q/.openclaw" "$QH/.openclaw"
echo "OPENAI_API_KEY=$KEY" > "$QH/project/.env"
HOME="$QH" USERPROFILE="$QH" WORTHLESS_HOME="$QH/whome" \
    uv run worthless lock --env "$QH/project/.env"
echo "exit=$?"
```

**📸 Screenshot 2** — the full `lock` output, including the `[OK]` line
and the `OpenClaw integration` section. Note that `lock` reports success.

**DEBUG-2** — paste:

```bash
python3 - <<PY
import json
d = json.load(open("$QH/.openclaw/openclaw.json"))
print("agent model AFTER:", d["agents"]["defaults"]["model"]["primary"])
print("providers AFTER  :", list(d["models"]["providers"].keys()))
print("siblings AFTER   :", sorted(k for k in d if k != "models"))
PY
echo "---auth-profiles.json after lock---"
head -c 200 "$QH/.openclaw/agents/main/agent/auth-profiles.json"; echo
```

**PASS for WOR-515 (this is the bug, not a regression):**
- `agent model AFTER` is **unchanged** — still the original provider.
- `providers AFTER` contains **both** the original and `worthless-openai`.
- `auth-profiles.json` is **byte-identical** to step 1 — real `$KEY` still on disk.

→ `lock` said success. The agent will still use the real provider. The
cached token is still live. The proxy is never in the request path.

---

## 3. WOR-516 — `lock` against an unreadable config

OpenClaw writes `openclaw.json` 0600 owner-only. When the `worthless`
process is a different uid (container deploys, some host installs), it
can't read the file. Here's what `lock` does then.

```bash
chmod 000 "$QH/.openclaw/openclaw.json"
HOME="$QH" USERPROFILE="$QH" WORTHLESS_HOME="$QH/whome" \
    uv run worthless lock --env "$QH/project/.env"
echo "exit=$?"
chmod 600 "$QH/.openclaw/openclaw.json"
```

**📸 Screenshot 3** — the `lock` output. It will print `[OK]`. That's
the bug.

**DEBUG-3** — paste:

```bash
python3 -c "import json; d=json.load(open('$QH/.openclaw/openclaw.json')); print('siblings AFTER:', sorted(k for k in d if k!='models')); print('providers:', list(d['models']['providers'].keys()))"
ls "$QH/.openclaw/"*.bak 2>/dev/null || echo "NO BACKUP FILE"
```

**PASS for WOR-516:**
- `siblings AFTER: []` — gateway auth, agent's model, channels, tools,
  skills, wizard, meta **all gone**.
- `NO BACKUP FILE` — no recovery path.

---

## 4. Boot OpenClaw on the wiped config → exit 78

```bash
docker run --rm -v "$QH/.openclaw":/home/node/.openclaw \
    -e OPENCLAW_ACCEPT_TERMS=yes ghcr.io/openclaw/openclaw:latest \
    2>&1 | tail -3
echo "container exit=$?"
```

**📸 Screenshot 4** — the `Gateway start blocked: existing config is
missing gateway.mode. Treat this as suspicious or clobbered config.` line
and the `container exit=78`.

→ `worthless lock` reported success, destroyed the user's OpenClaw
configuration, and wrote no backup. OpenClaw now refuses to start.
Recovery requires a backup file — exactly what Ido fell back on.

---

## Cleanup

```bash
rm -rf "$Q" "$Q-home"
docker rm -f $(docker ps -aq -f ancestor=ghcr.io/openclaw/openclaw:latest) 2>/dev/null
```

---

## What to report back

1. **📸 Screenshots 1–4.**
2. **DEBUG-1, DEBUG-2, DEBUG-3 outputs**, pasted verbatim.
3. Any step where the output diverges from what's documented above — that's
   environmental data I want.

Once that's in I'll confirm we match `live_demo.sh` byte-for-byte and we
move to Phase 1 — the credential-cache registry, which is where your
OpenClaw key-management review feeds in.

---

## Bonus — attacks the same harness can drive (later, your other ask)

- **F-CFG-15 symlink redirect.** Point `~/.openclaw/openclaw.json` at
  `~/.bashrc` before `lock`. Worthless refuses the transaction (verified
  in code) — proves the existing defense.
- **Malicious pre-existing provider** with a credible name but a
  `baseUrl` pointing at attacker.example. `lock` skips it (F-CFG-13
  `PROVIDER_CONFLICT`) — does scan still flag it as a finding?
- **Hostile cached credential** — keyring/keychain entry holding a key
  the user thinks is rotated. The whole point of Phase 1's registry.

These slot naturally into the published-artifact test tier (F5).

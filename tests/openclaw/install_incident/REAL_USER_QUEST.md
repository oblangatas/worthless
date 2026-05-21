# WOR-514 — Real-user install quest

> You're following the published `docs.wless.io/install/openclaw` flow on your
> own `~/.openclaw`. Most faithful reproduction of Ido's incident — your real
> OpenClaw config WILL get touched. You back it up first. Worthless does not.

~15 minutes. macOS. Run every block from any shell. Don't run inside the
worktree — we want the *published* `worthless` from `curl https://wless.io/install.sh | sh`,
not the development build. **Paste back** each `DEBUG-N` block and the 📸
screenshots.

---

## 0. Back up your real OpenClaw config

Worthless writes no backup (this is exactly WOR-516 — the missing-feature
evidence). You do it yourself. If you skip this step and the quest goes
wrong, you lose your channels, sessions, and gateway auth.

```bash
BK=~/.openclaw.backup.$(date +%Y%m%d-%H%M%S)
cp -R ~/.openclaw "$BK"
echo "Backup: $BK"
```

---

## 1. Baseline — what does your OpenClaw look like before?

```bash
python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path.home() / ".openclaw" / "openclaw.json"
d = json.load(open(p))
print("agent model :", d.get("agents",{}).get("defaults",{}).get("model",{}).get("primary"))
print("providers   :", list(d.get("models",{}).get("providers",{}).keys()))
print("siblings    :", sorted(k for k in d if k != "models"))
ap = pathlib.Path.home() / ".openclaw" / "agents" / "main" / "agent" / "auth-profiles.json"
print("auth-profiles.json :", "PRESENT" if ap.exists() else "absent")
PY
```

**📸 Screenshot 1** + **DEBUG-1: paste the output above.**

---

## 2. Install Worthless the documented way

```bash
curl -sSL https://wless.io/install.sh | sh
hash -r          # refresh PATH cache
which worthless
worthless --version
```

**📸 Screenshot 2** — `worthless --version` (the published version, not the
worktree's). If `which worthless` points anywhere inside `.claude/worktrees/`,
your `uv`-installed worthless is shadowing the published one; prepend
`~/.local/bin` to PATH and re-`hash -r`.

---

## 3. Run `worthless lock` — the one-line documented user flow

The docs say: *"Lock your key — OpenClaw config updated automatically."*

```bash
mkdir -p /tmp/wor514 && cd /tmp/wor514
# fake-but-real-shaped key; no real credential at risk
KEY="$(python3 -c "import base64,hashlib;print('sk-proj-'+base64.urlsafe_b64encode(hashlib.sha256(b'quest-seed').digest()).decode().rstrip('=')[:48])")"
echo "OPENAI_API_KEY=$KEY" > .env

worthless lock
echo "exit=$?"
```

**📸 Screenshot 3** — the full `lock` output. Look for `[OK]` and the
`OpenClaw integration` section. lock will tell you it succeeded.

---

## 4. Inspect what `lock` did — the WOR-515 evidence

```bash
python3 - <<'PY'
import json, pathlib
p = pathlib.Path.home() / ".openclaw" / "openclaw.json"
d = json.load(open(p))
print("agent model AFTER:", d.get("agents",{}).get("defaults",{}).get("model",{}).get("primary"))
print("providers AFTER  :", list(d.get("models",{}).get("providers",{}).keys()))
print("siblings AFTER   :", sorted(k for k in d if k != "models"))
PY
echo "---auth-profiles comparison---"
if cmp -s "$BK/agents/main/agent/auth-profiles.json" \
         ~/.openclaw/agents/main/agent/auth-profiles.json; then
  echo "auth-profiles: UNCHANGED (real token still on disk)"
else
  echo "auth-profiles: CHANGED"
fi
```

**DEBUG-2: paste the output above.** Do not paste raw
`auth-profiles.json` contents.

**PASS for WOR-515** (these mean the bypass is live on your machine):
- `agent model AFTER` is **unchanged** from Step 1
- `providers AFTER` includes both your original provider **and** `worthless-<x>`
- `auth-profiles.json: UNCHANGED` — real token still cached on disk
- `siblings AFTER` is still the full set (no corruption — your host install
  is readable to lock, so WOR-516's destructive path doesn't trigger)

→ `lock` said success. If you restarted OpenClaw and used it right now, it
would still talk to your real provider directly. The Worthless proxy would
never see the request.

---

## 5. Restore — your real OpenClaw back to normal

```bash
# remove the worthless-* provider entry + the skill folder
worthless unlock 2>&1 | tail -5

# belt-and-braces: restore from backup (in case unlock missed anything)
rm -rf ~/.openclaw
mv "$BK" ~/.openclaw
echo "Restored from $BK"
```

Verify your OpenClaw still works the way it did before. If not, the backup
is what got Ido out of this in his real incident.

---

## (Optional) WOR-516 addendum — the foreign-uid corruption path

Skip if you're done. Doesn't reproduce naturally on your host install
(your uid owns the config, so lock can read it). To see it, you simulate
the container/foreign-uid scenario:

```bash
BK2=~/.openclaw.backup.$(date +%Y%m%d-%H%M%S)
cp -R ~/.openclaw "$BK2"

chmod 000 ~/.openclaw/openclaw.json
cd /tmp/wor514
worthless lock; echo "exit=$?"
chmod 600 ~/.openclaw/openclaw.json

python3 -c "import json, pathlib; d=json.load(open(pathlib.Path.home()/'.openclaw'/'openclaw.json')); print('siblings AFTER chmod-000 lock:', sorted(k for k in d if k!='models'))"
ls ~/.openclaw/*.bak 2>/dev/null || echo "NO BACKUP FILE"
```

**📸 Screenshot 4** + **DEBUG-3: paste the output above.**

**PASS for WOR-516:**
- `siblings AFTER chmod-000 lock: []` — entire config wiped
- `NO BACKUP FILE` — worthless wrote nothing

Now restore (do not skip this):

```bash
rm -rf ~/.openclaw && mv "$BK2" ~/.openclaw
echo "Restored."
```

---

## What to paste back

- **📸 Screenshots 1–3** (4 if you did the WOR-516 addendum)
- **DEBUG-1** (baseline)
- **DEBUG-2** (post-lock WOR-515 evidence)
- **DEBUG-3** (post-chmod-000-lock WOR-516 evidence, if you did it)

Any step where the output diverges from documented — that diff is data.

Once that's in, I confirm the bypass matches `live_demo.sh`, we move to
**Phase 1** (credential-cache registry / `lock` fail-loud). Your OpenClaw
key-management review feeds straight into Phase 1's registry design —
share it whenever.

# WOR-514 — Real user journey: "I want to protect my OpenClaw keys"

> You're an OpenClaw user. Your job is to protect your API keys. Discover
> the options the same way a real user would: in the UI, by asking the AI,
> by searching skills. Then follow whatever the system tells you. We watch
> where worthless does — and doesn't — show up.

~20 minutes. All Docker, host stays clean. Browser required (localhost:18789).
Real provider key **optional** — needed only for live chat in step 5. Without
one you still get Steps 1–4 (discovery + UI install attempt + manual fallback);
the discoverability evidence is the most useful part.

---

## 0. Setup

```bash
docker compose -p wor514 down -v --remove-orphans 2>/dev/null
cd "$(git rev-parse --show-toplevel)/deploy"
cp -f docker-compose.env.example docker-compose.env
# Fake-but-real-shaped key for the manual fallback step. Replace with your real
# key in Step 5 only if you want chat to actually complete.
KEY="$(python3 -c "import base64,hashlib;print('sk-proj-'+base64.urlsafe_b64encode(hashlib.sha256(b'quest-seed').digest()).decode().rstrip('=')[:48])")"
```

---

## 1. Start OpenClaw — fresh user, no worthless yet

```bash
docker compose -p wor514 --profile openclaw up -d openclaw
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Status}}' wor514-openclaw-1 2>/dev/null)" = "running" ] && break
  sleep 1
done
docker compose -p wor514 ps openclaw
docker compose -p wor514 logs --tail=10 openclaw
```

**📸 Screenshot 1** — OpenClaw container `running`. If it's `exited 78`, paste
the log lines back — that's an immediate published-flow gap before we even
start.

Open in your browser: **http://localhost:18789**

**📸 Screenshot 2** — the OpenClaw web UI landing page.

---

## 2. Discoverability — does OpenClaw know about worthless?

In the OpenClaw UI:

1. Find the **Skills** section (sidebar or menu).
2. **Search** for `worthless`.
3. **📸 Screenshot 3** — the search results (likely empty: skill not yet on ClawHub).
4. Also try: search for `protect api keys`, `key protection`, `secrets`. **📸 Screenshot 4** — whatever shows up. Note whether OpenClaw's native `secrets-management` skill appears here (it might).

Now try the **chat**:

1. Open a chat.
2. Send: `"I want to protect my OpenAI API key. What are my options?"`
3. **📸 Screenshot 5** — the AI's response. (May fail if no real API key is configured — that's also a useful signal; capture the error.)
4. Send: `"Install the worthless skill"`
5. **📸 Screenshot 6** — the response.

**Why we're doing this:** if "worthless" doesn't surface in any of those
paths, that's its own integration-gap finding (separate from WOR-515/516).
This is what every real OpenClaw user does before they ever read your docs.

---

## 3. Fall back to docs.wless.io — find the install instructions

A user who didn't find worthless natively might Google. Imagine you landed
on **docs.wless.io/install/openclaw**. The "All-container setup" section
tells you to:

```bash
docker compose -p wor514 up -d proxy
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' wor514-proxy-1 2>/dev/null)" = "healthy" ] && break
  sleep 1
done
docker compose -p wor514 ps proxy
```

**📸 Screenshot 7** — proxy `healthy`.

Per docs.wless.io:

```bash
printf 'OPENAI_API_KEY=%s\n' "$KEY" | \
  docker compose -p wor514 exec -T proxy sh -c 'cat > /tmp/.env'
docker compose -p wor514 exec proxy worthless lock --env /tmp/.env
echo "lock exit=$?"
```

**📸 Screenshot 8** — `lock` output. You'll see `[OK]`.

Per docs.wless.io, restart OpenClaw to pick up the new provider:

```bash
docker compose -p wor514 restart openclaw
sleep 5
docker compose -p wor514 ps openclaw
docker compose -p wor514 logs --tail=15 openclaw
```

**📸 Screenshot 9** — OpenClaw status + logs after restart.

---

## 4. Return to the UI — is anything different?

Reload **http://localhost:18789**.

1. Check **Skills** — is there a worthless skill listed now? (The `lock`
   command installs a `worthless` skill folder.) **📸 Screenshot 10**.
2. Check the chat. Send: `"Are my API keys protected now?"`
3. **📸 Screenshot 11** — the response.

**DEBUG-1** — paste:

```bash
docker compose -p wor514 exec proxy sh -c '
  echo "--- openclaw.json ---"; cat /data/.openclaw/openclaw.json
  echo; echo "--- skills/ ---"; ls -la /data/.openclaw/workspace/skills/ 2>/dev/null
  echo; echo "--- *.bak ---"; ls /data/.openclaw/*.bak 2>/dev/null || echo NO_BACKUP
'
```

What we're looking for: did `lock` write a `worthless-openai` provider? Did
it install the skill folder? Are there siblings missing? Any backup?

---

## 5. (Optional) Live chat with a real key — does the proxy see the request?

Skip if you don't want to use a real key. This step proves whether the proxy
is actually in the request path.

Re-onboard OpenClaw with **your real key** (replace `$KEY`):

```bash
# Use a real OPENAI_API_KEY
REAL_KEY="<paste-your-real-sk-key-here>"
printf 'OPENAI_API_KEY=%s\n' "$REAL_KEY" | \
  docker compose -p wor514 exec -T proxy sh -c 'cat > /tmp/.env'
docker compose -p wor514 exec proxy worthless lock --env /tmp/.env
docker compose -p wor514 restart openclaw
```

In the UI, send a chat message. Then check the proxy:

```bash
docker compose -p wor514 exec proxy curl -s http://localhost:8787/healthz | \
  python3 -c "import sys,json;print('requests_proxied:', json.load(sys.stdin).get('requests_proxied'))"
docker compose -p wor514 logs --tail=20 proxy | grep -i 'proxied\|upstream\|forward'
```

**DEBUG-2** — paste the output above + **📸 Screenshot 12** of the chat
response.

**PASS for WOR-515 (or its absence):**
- `requests_proxied > 0` and proxy logs show the upstream call → the proxy
  is in the path; the all-container deployment **does** protect.
- `requests_proxied == 0` → bypass confirmed in the all-container flow,
  same as the host-install bug.

---

## 6. Cleanup

```bash
docker compose -p wor514 down -v --remove-orphans
echo "Cleaned. Host untouched."
```

---

## What to paste back

- **📸 Screenshots 1–11** (12 if you ran Step 5)
- **DEBUG-1** (post-`lock` openclaw.json, skills, backup check)
- **DEBUG-2** (proxy counter + logs, if you ran Step 5)
- One sentence per step on what felt natural and what felt broken — the UX
  evidence is the point of this quest.

I'll cross-check against `live_demo.sh`'s deterministic findings. The
discoverability data (Steps 2 + 4) is its own evidence — feeds straight
into the WOR-433 publish ticket and Phase 1's credential-cache registry.

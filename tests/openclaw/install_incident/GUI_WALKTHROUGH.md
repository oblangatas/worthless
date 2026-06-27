# WOR-514 — OpenClaw GUI walkthrough (Phase 0 reproduction, UI edition)

> Prerequisite: the wor514 docker stack is up, openclaw published on
> `http://localhost:18789/`. If not, see `DOCKER_QUEST.md` Step 1 + the
> workaround for WOR-546 (openclaw must be on `wor514_frontend`, not only
> `wor514_openclaw-net`).

You're walking through OpenClaw the way a real user would. Goal: capture
three pieces of evidence — discoverability gap, bypass after lock, what
OpenClaw's own audit says — by clicking, screenshotting, and pasting back.

~10 minutes. 6 steps, 1 screenshot per step minimum.

---

## What we're proving

1. **Discoverability gap.** A real OpenClaw user searching for "protect my keys" via the UI doesn't find worthless — it isn't on ClawHub yet (WOR-433). They have to discover `docs.wless.io` independently.
2. **Bypass after lock (WOR-515).** Even after `worthless lock`, OpenClaw's agent default model is unchanged — the proxy is never in the request path.
3. **OpenClaw's own audit reports plaintext.** `openclaw secrets audit` flags `auth-profiles.json` cached tokens + the original `openclaw.json` provider's apiKey. That's the signal Phase 1's audit-gate keys off.

---

## Step 0 — Grab the gateway auth token

OpenClaw auto-generates a `gateway.auth.token` on first boot and the
Control UI requires it. Plain `http://localhost:18789/` will fail with
"unauthorized: gateway token missing." Extract the token first:

```bash
docker exec wor514-openclaw-1 cat /home/node/.openclaw/openclaw.json \
  | python3 -c "import sys, json; t=json.load(sys.stdin)['gateway']['auth']['token']; print(f'http://localhost:18789/#token={t}')"
```

Open the printed URL. The SPA consumes the `#token=...` fragment (not
sent to server logs) and stores it in localStorage; subsequent visits to
plain `http://localhost:18789/` work.

## Step 1 — Landing page

Open the URL from Step 0.

**📸 Screenshot 1** — the landing page. Look for: sidebar/menu (Skills? Providers? Secrets? Settings?), chat area, any onboarding wizard.

If a setup wizard appears: **don't complete it yet** — screenshot and paste back. We'll decide together.

---

## Step 2 — Skills, search `worthless`

Find **Skills** in the sidebar / menu. Search for `worthless`.

**📸 Screenshot 2** — the (likely empty) result. This is the discoverability gap.

---

## Step 3 — Skills, broader searches

Same Skills section. Try in order:

- Search `protect api keys`
- Search `secrets`

**📸 Screenshot 3 + 4** — one per search. Note whether OpenClaw's native `secrets-management` skill or anything related appears.

---

## Step 4 — Chat: "How do I protect my key?"

Open a chat. Send verbatim:

> `I want to protect my OpenAI API key. What are my options?`

**📸 Screenshot 5** — the AI's response.

If chat fails (no provider configured, no key, etc.) — also valuable. Screenshot the error.

---

## Step 5 — Chat: "Install worthless"

Same chat. Send verbatim:

> `Install the worthless skill`

**📸 Screenshot 6** — the response.

---

## Step 6 — Settings / Providers / Secrets

Click through the sidebar's other sections. Find Providers and Secrets.

**📸 Screenshots 7 + 8** — one for each section.

Note especially: does the UI surface any "this provider's key is plaintext" warning, or is that purely a CLI thing (`openclaw secrets audit`)?

---

## After Steps 1–6 — paste back

Paste back: all 8 screenshots + one sentence per step on what felt natural, what felt broken, what's missing.

I'll then run **two `docker exec` commands** in this thread to:

1. Dump the current `openclaw.json` from the shared volume (baseline before lock).
2. Run `openclaw secrets audit --json` (baseline audit).

Then we run `worthless lock` via `docker compose exec proxy ...`, refresh the UI, and you screenshot what changed in:

- The Skills section (does a `worthless` skill appear now?)
- The Providers section (a new `worthless-openai` provider?)
- The chat ("are my API keys protected now?")
- The Secrets section / audit JSON

That diff is the Phase 0 reproduction, GUI edition.

---

## When done

Cleanup (after we've captured all evidence):

```bash
docker rm -f wor514-openclaw-1 wor514-proxy-1 testopenclaw testnet testport 2>/dev/null
docker compose -p wor514 down -v --remove-orphans 2>/dev/null
docker volume ls -q | grep wor514 | xargs -r docker volume rm 2>/dev/null
docker network ls -q --filter name=wor514 | xargs -r docker network rm 2>/dev/null
```

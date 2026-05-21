# WOR-514 — All-Docker quest (host stays clean)

> The "All-container setup" from `docs.wless.io/install/openclaw`. Both
> Worthless proxy and OpenClaw run in Docker. Nothing installs on your
> host. Your real `~/.openclaw` is **not touched**.

~15 minutes. macOS, Docker running. Paste back the **DEBUG-N** blocks and
the 📸 screenshots.

You're testing the published, documented all-container flow exactly as
written. Whether it works, breaks, or shows WOR-515 / WOR-516 — that's
the data.

---

## 0. Clean slate + setup

```bash
# Wipe any prior quest artifacts so this is truly fresh
docker compose -p wor514 down -v --remove-orphans 2>/dev/null

# IMPORTANT: run from this repo's deploy dir so docker's build context
# (`context: ..` in the compose file) resolves to the repo root, not /tmp.
cd "$(git rev-parse --show-toplevel)/deploy"
cp -f docker-compose.env.example docker-compose.env

# Fake-but-real-shaped key; no real credential at risk
KEY="$(python3 -c "import base64,hashlib;print('sk-proj-'+base64.urlsafe_b64encode(hashlib.sha256(b'quest-seed').digest()).decode().rstrip('=')[:48])")"
echo "KEY=$KEY"
```

The compose file (`deploy/docker-compose.yml`) is what `docs.wless.io`
tells users to `curl`. We run from the current clone's `deploy/` so the
build context resolves to the repo root. Nothing here writes to your `~`.

---

## 1. Start the worthless proxy

```bash
docker compose -p wor514 up -d proxy
# wait for healthy
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' wor514-proxy-1 2>/dev/null)" = "healthy" ] && break
  sleep 1
done
docker compose -p wor514 ps proxy
```

**📸 Screenshot 1** — proxy listed `running` and `healthy`.

---

## 2. Write key and run `worthless lock` — the documented commands

Straight from `docs.wless.io/install/openclaw` § All-container setup:

```bash
printf 'OPENAI_API_KEY=%s\n' "$KEY" | \
  docker compose -p wor514 exec -T proxy sh -c 'cat > /tmp/.env'

docker compose -p wor514 exec proxy worthless lock --env /tmp/.env
echo "lock exit=$?"
```

**📸 Screenshot 2** — full `lock` output. Look for `[OK]` and the
`OpenClaw integration` section.

---

## 3. Inspect what `lock` wrote into the shared volume

```bash
docker compose -p wor514 exec proxy sh -c '
  echo "--- openclaw.json ---"
  cat /data/.openclaw/openclaw.json 2>&1
  echo
  echo "--- ls -la ---"
  ls -la /data/.openclaw/
  echo
  echo "--- *.bak? ---"
  ls /data/.openclaw/*.bak 2>/dev/null || echo NO_BACKUP
'
```

**DEBUG-1: paste the output above.**

What we're looking for:
- Does `openclaw.json` contain a `gateway` key? `agents` key?
- Or just `{models:{providers:{worthless-openai}}}`?
- File mode 0644 (the shared-volume special case)?
- Is there any `*.bak`?

---

## 4. Start OpenClaw

```bash
docker compose -p wor514 --profile openclaw up -d openclaw
sleep 10
docker compose -p wor514 ps openclaw
echo "--- openclaw logs (last 15) ---"
docker compose -p wor514 logs --tail=15 openclaw
```

**📸 Screenshot 3** — OpenClaw's status and last log lines.

What we're looking for:
- Status: `running` (boots OK) or `exited (78)` (WOR-516-style block)?
- Log line: `Gateway start blocked: existing config is missing gateway.mode` would be the WOR-516 signature.

---

## 5. If OpenClaw is running, exercise it — try a chat

(Only run if Step 4 showed `running`. Otherwise skip to Step 6.)

```bash
# zero the proxy's requests counter for a clean read
docker compose -p wor514 exec proxy curl -s http://localhost:8787/healthz | python3 -c "import sys,json;print('proxied BEFORE:', json.load(sys.stdin).get('requests_proxied'))"

# documented user command
docker compose -p wor514 exec openclaw openclaw agent --local --message "hello" 2>&1 | tail -10

# did the request go through the proxy?
docker compose -p wor514 exec proxy curl -s http://localhost:8787/healthz | python3 -c "import sys,json;print('proxied AFTER :', json.load(sys.stdin).get('requests_proxied'))"
```

**DEBUG-2: paste the output above.**

If `proxied AFTER == proxied BEFORE` → the proxy was bypassed (WOR-515).
If it incremented → the proxy is in the path.

---

## 6. Cleanup

```bash
docker compose -p wor514 down -v --remove-orphans
rm -rf /tmp/wor514-docker
echo "Cleaned."
```

Nothing on your host was touched. `~/.openclaw` is untouched. Containers
and volumes are gone.

---

## What to paste back

- **📸 Screenshots 1–3** (proxy healthy, `lock` output, OpenClaw status+logs)
- **DEBUG-1** (what `lock` wrote into the shared volume)
- **DEBUG-2** (proxy requests counter before/after a chat — if OpenClaw ran)
- Any step where output diverged from what's documented — that diff is data

I'll diff your output against `live_demo.sh`'s deterministic findings.
Possible outcomes, all of them useful:
- OpenClaw boots and chat works, but `requests_proxied` doesn't move → WOR-515 in the all-container flow.
- OpenClaw exits 78 → the documented all-container flow itself is broken (a published-artifact gap).
- Everything works → the all-container flow does protect; the bypass is host-install-specific.

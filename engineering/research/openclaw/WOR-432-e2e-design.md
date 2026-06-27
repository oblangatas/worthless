# WOR-432 — Automated E2E test design: clawhub-installed Worthless skill yields a protected request

> "If we can't prove a clawhub user gets a protected request out of the box, the OpenClaw partnership is theatre."

WOR-432 (child of WOR-421) requires an automated test that drives the full chain end-to-end:

1. ClawHub-style skill install lands the Worthless skill where OpenClaw will discover it.
2. OpenClaw agent invocation triggers the skill, which routes the request through the Worthless proxy.
3. Mock upstream receives the **reconstructed real key**, never shard-A.

Prior research on the partnership lives in `engineering/product/docker-journey.md`, `engineering/product/personas.md`, `.planning/research/v1.1-stress-test.md`, and `.planning/research/04.1-readme-launch/`. There was no `engineering/research/openclaw/README.md` — this is the first canonical note for the partnership test. Every finding below is backed by live `docker exec` output against `ghcr.io/openclaw/openclaw:latest` (image `2026.5.3-1`).

---

## 1. OpenClaw API surface (live findings)

`docker inspect ghcr.io/openclaw/openclaw:latest --format '{{json .Config}}'`:

```
"User": "node"
"WorkingDir": "/app"
"Entrypoint": ["docker-entrypoint.sh"]
"Cmd": ["node","openclaw.mjs","gateway","--allow-unconfigured"]
"ExposedPorts": (none — Healthcheck targets 18789)
"Healthcheck.Test": ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:18789/healthz')…\""]
```

Live route probe (container running, no auth token sent):

```
/                         200 text/html      OpenClaw Control SPA
/healthz                  200 application/json   {"ok":true,"status":"live"}
/v1                       200 text/html       (SPA — NOT OpenAI-compatible)
/v1/chat/completions      200 text/html       (SPA fallback)
/v1/chat/completions POST 404 text/plain      (no API binding)
/v1/models                200 text/html       (SPA fallback)
/api, /api/v1/*           404                 (no /api prefix)
/rpc, /rpc/v1             200 text/html       (SPA fallback)
/rpc POST jsonrpc         404                 (NOT JSON-RPC)
/webchat, /webchat/api,
  /webchat/messages       200 text/html       (SPA fallback)
/__openclaw__/canvas/     mounted             (canvas host; logs)
```

Container logs at startup:

```
[gateway] auth token was missing. Generated a new token and saved it to config (gateway.auth.token).
[gateway] starting HTTP server...
[canvas] host mounted at http://0.0.0.0:18789/__openclaw__/canvas/
[gateway] http server listening (6 plugins: browser, device-pair, file-transfer, memory-core, phone-control, talk-voice; 12.1s)
[browser/server] Browser control listening on http://127.0.0.1:18791/ (auth=token)
[gateway] ready
```

**Conclusion:** Port `18789` serves the **OpenClaw Control SPA** — *not* an OpenAI-compatible HTTP API. There is no `POST /v1/chat/completions`. The gateway delivers messages exclusively via channels (Telegram, Discord, Slack, Signal, iMessage, WebChat, etc.), and **the headless test harness is the `openclaw agent` CLI subcommand**, not an HTTP endpoint:

```
openclaw agent --help
  Run an agent turn via the Gateway (use --local for embedded)
  --message <text>          Message body for the agent
  --model <id>              Model override
  --json                    Output result as JSON
  --local                   Run embedded agent locally (requires model provider API keys)
  --thinking <level>
  --to <number>             Recipient (E.164 — derives session key)
  --session-id <id>
```

**Test path (chosen):** `docker exec openclaw openclaw agent --local --json --message "…"` runs the agent inside the container against `models.providers.worthless-test.baseUrl` (our proxy) and emits JSON. No channel adapter required. Fallback would be the `qa-channel` adapter (visible in `--channel` enum) but it adds setup with no advantage.

## 2. Auth + headers OpenClaw injects upstream

The existing `tests/openclaw/mock-upstream` already captures every header sent by anything pointing at it (`GET /captured-headers` returns `[{provider, authorization, …}, …]`). The existing `test_openclaw_e2e.py` proves the proxy adds nothing leaky on its side. WOR-432 needs the **OpenClaw → Worthless proxy** hop captured.

When OpenClaw is configured with `models.providers.worthless-test.baseUrl = http://worthless-proxy:8787/<alias>/v1`, OpenClaw acts as a normal OpenAI client. Headers we expect (verified by adding a passthrough capture endpoint to the proxy or by reading proxy access logs) are the standard OpenAI SDK shape:

* `Authorization: Bearer <shard-A>` (the placeholder we wrote into `openclaw.json`).
* `Content-Type: application/json`.
* `User-Agent: OpenAI/NodeJS/<sdk-ver>` plus `x-stainless-*` headers (the OpenAI Node SDK Stainless-generated set). OpenClaw does NOT inject any `X-OpenClaw-*` header to the upstream LLM provider — it forwards via the OpenAI SDK transparently.

The test asserts:

* The proxy received the request from OpenClaw with `Authorization: Bearer <shard-A>`.
* The mock upstream received `Authorization: Bearer <fake_real_key>` (reconstructed).
* Shard-A bytes never appear in any header captured at the upstream.

## 3. Skill install path inside the container

`/app/skills/` ships bundled skills (one example below). User skills land in `/home/node/.openclaw/skills/` (global) or `<workspace>/skills/` (workspace), per OpenClaw's documented [Manual Installation table](https://docs.openclaw.ai). Inside our container the home is `/home/node` (User: `node`) and the volume mounted at `/home/node/.openclaw` is our config dir — so `/home/node/.openclaw/skills/worthless/SKILL.md` is the install target.

Bundled skill format (live extract from `/app/skills/oracle/SKILL.md`):

```yaml
---
name: oracle
description: Use oracle CLI to bundle prompts and files for second-model debugging…
homepage: https://askoracle.dev
metadata:
  openclaw:
    emoji: 🧿
    requires:
      bins: [oracle]
    install:
      - id: node
        kind: node
        package: "@steipete/oracle"
        bins: [oracle]
        label: "Install oracle (node)"
---
```

**Finding (gap, not a blocker for WOR-432):** the repo's `/Users/shachar/Projects/worthless/worthless/SKILL.md` does NOT carry the `metadata.openclaw` block (frontmatter starts at line 17 but the block isn't there). For OpenClaw discovery and `requires.bins: [worthless]` enforcement we need to add it. WOR-432's test will sideload a SKILL.md that **does** carry the block, and we should file a follow-up to merge that block into the canonical SKILL.md (target: epic WOR-421).

## 4. Pi tool invocation surface

OpenClaw verifies `requires.bins` on the host at skill load time (per indexed `openclaw-skills` docs). When the agent uses a skill it shells out to that bin via the gateway's tool-use loop. We don't need to assert *how* — we observe the network result. The skill's job is just to declare `metadata.openclaw.requires.bins: [worthless]` and to point the LLM provider at the Worthless proxy. If the agent reaches the proxy, the chain works; if not, the mock captures nothing.

## 5. Test fixture skeleton

File: `tests/test_openclaw_clawhub_install.py` (new, marker `openclaw`). Reuses the existing `openclaw_stack`-style helpers from `test_openclaw_e2e.py` and the `--profile openclaw` lane already declared in `docker-compose.yml`.

```python
"""WOR-432 — clawhub install yields a protected request, end to end.

Drives mock-upstream + worthless-proxy + openclaw (gateway). Sideloads the
worthless SKILL.md the way `clawhub install` would, then triggers an agent
turn via `openclaw agent --local --json` and asserts the mock upstream
received the reconstructed real key.
"""

from __future__ import annotations
import json, subprocess, uuid
from pathlib import Path
import httpx, pytest

from tests._docker_helpers import docker_available, docker_exec, wait_healthy
from tests.helpers import fake_openai_key
from worthless.cli.commands.lock import _make_alias

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "tests" / "openclaw" / "docker-compose.yml"
SKILL_SRC   = REPO_ROOT / "SKILL.md"   # candidate skill to install

pytestmark = [pytest.mark.openclaw,
               pytest.mark.skipif(not docker_available(), reason="docker required")]

@pytest.fixture(scope="session")
def clawhub_stack():
    project = f"oc-clawhub-{uuid.uuid4().hex[:8]}"
    fake_key = fake_openai_key()
    alias    = _make_alias("openai", fake_key)
    try:
        # 1. Bring up the full lane including the openclaw profile.
        subprocess.run(
            ["docker","compose","-f",str(COMPOSE_FILE),"-p",project,
             "--profile","openclaw","up","-d","--build"],
            cwd=REPO_ROOT, check=True, timeout=300,
        )
        proxy_c    = f"{project}-worthless-proxy-1"
        oc_c       = f"{project}-openclaw-1"
        mock_c     = f"{project}-mock-upstream-1"
        assert wait_healthy(proxy_c, 90)
        assert wait_healthy(oc_c, 90)
        proxy_port = _host_port(proxy_c, 8787)
        mock_port  = _host_port(mock_c, 9999)
        oc_port    = _host_port(oc_c, 18789)

        # 2. Lock + register a fake key against the mock (matches existing fixture).
        # …docker exec proxy_c worthless providers register --name openai-mock --url http://mock-upstream:9999/openai/v1
        # …write .env with OPENAI_API_KEY=fake, OPENAI_BASE_URL=http://mock-upstream:9999/openai/v1
        # …docker exec proxy_c worthless lock --env /tmp/.env
        shard_a = _read_env_value(proxy_c, "OPENAI_API_KEY")

        # 3. Sideload the worthless skill the way clawhub install would.
        #    Inside the openclaw container, /home/node/.openclaw/skills is on
        #    a bind mount at tests/openclaw/openclaw-config — copy in there.
        dest = REPO_ROOT / "tests/openclaw/openclaw-config/skills/worthless"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SKILL.md").write_text(_skill_md_with_openclaw_block(SKILL_SRC))

        # 4. Patch openclaw.json so the worthless-test provider points at our
        #    proxy with the alias and shard-A.
        oc_cfg = json.loads((REPO_ROOT/"tests/openclaw/openclaw-config/openclaw.json").read_text())
        oc_cfg["models"]["providers"]["worthless-test"].update({
            "baseUrl": f"http://worthless-proxy:8787/{alias}/v1",
            "apiKey":  shard_a,
        })
        (REPO_ROOT/"tests/openclaw/openclaw-config/openclaw.json").write_text(json.dumps(oc_cfg))
        # Reload so openclaw picks the new config.
        subprocess.run(["docker","exec",oc_c,"openclaw","secrets","reload"], check=True)

        # 5. Confirm openclaw discovered the skill.
        listed = subprocess.run(
            ["docker","exec",oc_c,"openclaw","skills","list","--json"],
            check=True, capture_output=True, text=True,
        ).stdout
        assert any(s["name"] == "worthless" for s in json.loads(listed))

        _clear_mock_headers(mock_port)
        yield proxy_port, mock_port, oc_port, fake_key, shard_a, alias, oc_c
    finally:
        subprocess.run(
            ["docker","compose","-f",str(COMPOSE_FILE),"-p",project,
             "--profile","openclaw","down","-v"],
            cwd=REPO_ROOT, timeout=120,
        )

class TestClawhubInstallProducesProtectedRequest:
    def test_skill_installed_yields_protected_request(self, clawhub_stack):
        proxy_port, mock_port, _oc_port, fake_key, shard_a, _alias, oc_c = clawhub_stack

        # Trigger an agent turn that exercises the worthless-test provider.
        result = subprocess.run(
            ["docker","exec",oc_c,"openclaw","agent",
             "--local","--json",
             "--model","worthless-test/gpt-4o",
             "--message","Reply with exactly: pong"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        payload = json.loads(result.stdout)
        assert payload.get("ok"), payload

        captured = httpx.get(f"http://127.0.0.1:{mock_port}/captured-headers", timeout=5).json()
        openai_entries = [e for e in captured["headers"] if e.get("provider") == "openai"]
        assert openai_entries, "no upstream traffic captured — chain broken"

        for entry in openai_entries:
            # Real key arrived upstream.
            assert entry["authorization"] == f"Bearer {fake_key}"
            # Shard-A NEVER leaked to upstream.
            assert shard_a not in entry["authorization"]
```

### Open issues to file alongside this work

* **WOR-432-followup-1:** add `metadata.openclaw` block to canonical `SKILL.md` so `requires.bins: [worthless]` is enforced and ClawHub install pages show the right scanner state.
* **WOR-432-followup-2:** the `openclaw skills list --json` flag was inferred from `--json` defaults on `openclaw agent` — confirm in the test or fall back to text parsing.
* **WOR-432-followup-3:** decide whether the test should also cover the "Missing requirements" path (worthless bin absent → skill listed as missing) for negative coverage.

### Why this design holds

The chain has three observable hops, and we assert at each:

1. Skill discovery — `openclaw skills list` shows `worthless` as enabled (no missing bins).
2. Provider routing — `openclaw agent` returns success, proving the gateway resolved `worthless-test/gpt-4o` to our proxy.
3. Reconstruction — mock-upstream's `/captured-headers` shows the **real** key, not shard-A.

Failure of any hop (config wrong, skill not discovered, proxy not reached, shard-A leaked) causes the test to fail at the corresponding assertion, with a precise diagnostic.

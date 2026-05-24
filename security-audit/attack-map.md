# Security Attack Map

Date: 2026-03-30
Method: static repo review only. No app execution, no tests, no code changes.

## Purpose

This document maps how Worthless is most likely to get attacked in practice.
It is not a generic LLM security list. It is centered on the current repo,
deployment guidance, and the product claim that stolen keys should become less
useful.

## Executive Read

The most dangerous attacks are not cryptographic breaks.

They are:

1. Turning an exposed proxy into an authenticated spend tunnel
2. Spending real money while metering records little or nothing
3. Running untrusted code as the same local user and reading both shards plus the Fernet key
4. Using install and package supply-chain paths to land code execution on developer or operator hosts
5. Knocking over the proxy with oversized or long-lived requests

## Attacker Types

### Internet opportunist

Intent: find a reachable proxy and convert it into billable provider access.

Motivation: free model access, resale, fraud, denial of wallet.

### Cost thief

Intent: keep the proxy "working" while bypassing caps and metering.

Motivation: burn someone else's budget without obvious detection.

### Same-user local adversary

Intent: run code as the developer or agent user and recover secrets offline.

Motivation: key theft, workspace theft, persistence.

### Supply-chain attacker

Intent: compromise the bootstrap path before Worthless' protections even start.

Motivation: large blast radius across many developer and operator machines.

### Nuisance / extortion actor

Intent: degrade proxy availability or trigger expensive upstream behavior.

Motivation: disruption, leverage, noise, or opportunistic abuse.

## Top Attack Paths

### 1. Exposed proxy becomes a spend tunnel

Severity: Critical

Attacker goal: send provider requests without possessing a usable customer key.

Why it works:

- The proxy can infer the alias from the request path when only one alias exists for a provider.
- The proxy can load Shard A from local disk if the client does not send it.
- TLS gating trusts `x-forwarded-proto` directly instead of a trusted proxy boundary.

Likely chain:

1. Operator exposes the proxy origin or misconfigures edge trust.
2. Attacker sends `POST /v1/chat/completions` or `/v1/messages`.
3. Attacker sets `X-Forwarded-Proto: https`.
4. Proxy infers the alias and loads Shard A from server disk.
5. Request is forwarded upstream as if it were authenticated.

Intent behind the attack:

This is the cleanest path for "turn guardrail into proxy service." It does not
need to steal a key first. It just needs deployment drift.

Primary evidence:

- `src/worthless/proxy/app.py`
- `README.md`

### 2. Metering blind spots let attackers spend while recorded usage stays low

Severity: Critical

Attacker goal: overspend while remaining under the system's apparent budget.

Why it works:

- Metering is post-response, not reserved up front.
- OpenAI streaming usage may never arrive unless the caller requests it.
- Anthropic extraction only reads `message_delta.output_tokens`.
- Anthropic non-streaming usage is effectively not counted by current parsing.
- Input tokens are missed for Anthropic streaming.

Likely chain:

1. Attacker chooses streaming where possible.
2. Attacker avoids usage-returning stream options or disconnect patterns.
3. Attacker chooses prompts that maximize input token cost.
4. Spend cap logic checks old totals and allows the request.
5. Recorded spend lags, undercounts, or records zero.

Intent behind the attack:

A rational attacker does not want a loud auth bypass if a quiet accounting
bypass works better.

Primary evidence:

- `src/worthless/proxy/metering.py`
- `src/worthless/proxy/app.py`
- `src/worthless/proxy/rules.py`

### 3. Token caps can be marketed as spend caps even though price varies by model

Severity: High

Attacker goal: maximize dollar burn per allowed token.

Why it works:

- The schema stores token totals, not currency.
- Docs promise a daily spend cap and hard cap.
- Different models and tools can have radically different prices per token or per event.

Likely chain:

1. Attacker stays below nominal token budget.
2. Attacker picks the most expensive model or provider path.
3. Real invoice rises faster than the configured cap implies.

Intent behind the attack:

This is what a cost thief does after reading the docs carefully. They optimize
for the accounting model, not the product slogan.

Primary evidence:

- `src/worthless/storage/schema.py`
- `src/worthless/proxy/rules.py`
- `docs/install-solo.md`

### 4. Same-user local execution defeats the split-secret story

Severity: High

Attacker goal: reconstruct keys offline without using the proxy at all.

Why it works:

- `worthless wrap` runs arbitrary child code as the same user.
- The same user can read `~/.worthless/fernet.key`, the DB, and `shard_a`.
- The threat model only excludes "full machine compromise," but same-user code execution is enough.

Likely chain:

1. Developer runs untrusted code, agent plugin, or package.
2. Malicious code reads local Worthless material.
3. It reconstructs provider keys directly or steals the Fernet key for later.

Intent behind the attack:

This is the most realistic developer-host attack. The attacker does not need
root, only the ability to execute under the same account.

Primary evidence:

- `src/worthless/cli/commands/wrap.py`
- `src/worthless/cli/bootstrap.py`
- `docs/security.md`

### 5. Ambient environment can silently redirect upstream traffic

Severity: High

Attacker goal: intercept or reroute provider-bound traffic after key reconstruction.

Why it works:

- Proxy subprocesses inherit ambient environment.
- `httpx` clients are created without explicitly disabling `trust_env`.
- Proxy and CA environment variables can alter transport behavior.

Likely chain:

1. Attacker sets `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, or related variables.
2. Worthless starts normally.
3. Upstream calls route through attacker-controlled infrastructure or trust attacker CA material.

Intent behind the attack:

This is stealthier than breaking Worthless directly. It turns Worthless into a
credential-forwarding client.

Primary evidence:

- `src/worthless/proxy/app.py`
- `src/worthless/cli/process.py`
- `src/worthless/cli/commands/wrap.py`

### 6. Request-body and streaming behavior allow practical DoS

Severity: High

Attacker goal: exhaust memory, worker time, or outbound connections.

Why it works:

- Body size checks only rely on `Content-Length`.
- Requests without `Content-Length` still get fully buffered with `request.body()`.
- Streaming responses are buffered chunk-by-chunk for later metering.
- Outbound connections are bounded while stream duration is fairly generous.

Likely chain:

1. Attacker sends chunked or slow oversized bodies.
2. Attacker opens long-running streams that produce large outputs.
3. Proxy accumulates body or SSE data in memory.
4. Outbound pool and worker capacity degrade.

Intent behind the attack:

Even if an attacker cannot steal spend, they can still deny protection by
killing the guardrail.

Primary evidence:

- `src/worthless/proxy/middleware.py`
- `src/worthless/proxy/app.py`

### 7. Install and package workflows are an initial access gift

Severity: High

Attacker goal: get code running on operator, developer, or agent hosts.

> Detailed surface-by-surface map of the `curl … | sh` front door (each
> control + residual gap, with cited real-world precedents) lives in
> [`threat-model-worthless-sh.md`](threat-model-worthless-sh.md). The
> `worthless` PyPI package is now version-pinned by default (WOR-559),
> closing the unpinned-`latest` auto-install vector.

Why it works:

- Docs recommend `curl ... | sh`.
- MCP install uses `npx -y` without pinning or verification.
- The `worthless` package version is pinned by default (WOR-559), but the
  wheel is not yet hash-verified, and other dependencies are not locked for
  reproducible, verified installs.

Likely chain:

1. Compromise bootstrap script, package publisher, registry path, or CI release path.
2. User installs Worthless exactly as documented.
3. Attacker lands before any shard or policy protection matters.

Intent behind the attack:

Supply-chain compromise scales better than targeting one proxy at a time.

Primary evidence:

- `docs/install-solo.md`
- `docs/install-self-hosted.md`
- `docs/install-mcp.md`
- `pyproject.toml`

### 8. Secret lifetime is longer than the product copy suggests

Severity: Medium

Attacker goal: recover secrets from memory or storage remnants after "cleanup."

Why it works:

- Python creates immutable header strings for provider auth.
- SQLite WAL and logical deletes retain history.
- The HMAC commitment is not an authenticity primitive once both shards are known.

Intent behind the attack:

This matters most after local foothold. Attackers often chain "minor" retention
issues after initial access.

Primary evidence:

- `docs/security.md` (Known limitations → `api_key.decode()` creates an immutable str copy)
- `src/worthless/crypto/splitter.py`
- `src/worthless/storage/schema.py`
- `src/worthless/storage/repository.py`

## What The Repo Is Already Doing Well

- Gate-before-reconstruct is real and consistently emphasized.
- Uniform 401 behavior reduces obvious alias enumeration.
- Upstream targets are hardcoded and redirects are disabled.
- Internal headers are stripped before upstream forwarding.
- The Python PoC limitations are documented instead of hidden.

## Recommended Remediation Order

1. Kill the exposed-proxy auth collapse.
2. Fix metering correctness before claiming hard spend control.
3. Disable ambient transport trust and tighten same-user threat claims.
4. Add real body and stream resource controls.
5. Replace insecure bootstrap and pin package distribution.

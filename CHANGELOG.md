# Changelog

All notable changes to Worthless are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Security
- **Spend cap stops the no-`max_tokens` money leak** (WOR-696, [#285](https://github.com/shacharm2/worthless/pull/285)). A request without `max_tokens` that disconnected mid-stream wrote a near-zero `spend_log` row — cap counter never moved, runaway loop could burn unbounded provider spend. `settle_at_estimate` now floors at a global 128K-token ceiling (`GLOBAL_CEILING_TOKENS`), so every fallback event bills honestly. Direction of error is conservative: gpt-4o-mini disconnect over-bills ~$0.017 vs the old ~$0.002 leak, but Opus 4.5 / gpt-5 disconnects bill exactly.
- **Streams can't outlast the cap** (WOR-696). Two new operator-tunable kill paths close slow-drip variants where no client disconnect ever fires:
  - `WORTHLESS_MAX_STREAM_DURATION_SECONDS` (default `900` = 15min) — hard wall-clock cap per stream.
  - `WORTHLESS_MAX_IDLE_BETWEEN_CHUNKS_SECONDS` (default `90`) — kills a stream that drips one chunk every N minutes.
  Either kill triggers the same settle path, which floors at the global ceiling.
- **Silent provider re-routes are observable** (WOR-696). When a provider responds with a different `model` than the request asked for (e.g. `gpt-4o-mini` → `gpt-5`), `app.state.response_model_mismatch_counter[(request_model, response_model)]` increments. Observation only — no enforcement, no header munging, passthrough preserved. **Counter semantics: once per stream**, not once per chunk-with-mismatch. The response model can't change mid-stream, so per-chunk counting was operator-noise (10k-chunk stream produced a count of 10k for the same logical event). Per-stream counting gives operators the right cardinality.
- **Worthless accepts ANY model string** (WOR-696). No registry, no admission-time model check. Works on OpenRouter, Azure custom deployments, Enterprise gateways, and any future model launch without operator intervention. Cap stays honest via the global-ceiling fallback regardless of model name.
- **Crash-orphan sweeper backstop bills the ceiling** (WOR-696, `worthless-osgt`). Brutus + chaos-engineer found that if the proxy was SIGKILL'd between stream-start and the BackgroundTask settle, the orphan `pending_charges` row would be swept later but billed at the stored estimate (zero for no-`max_tokens` requests). The sweeper now applies `max(estimate, GLOBAL_CEILING_TOKENS)` — same floor every other terminal path uses. Closes the gap at sweeper TTL (default ~60s).
- **`worthless lock` won't print [OK] until the proxy proves it received a test request** (WOR-658, [#340](https://github.com/shacharm2/worthless/pull/340)). After lock rewrites the OpenClaw provider entry, it now fires a HEAD against the proxy's new `/_bind_probe/{alias}` endpoint and reads a dedicated `bind_probe_count` field on `/healthz` before and after. Counter ticks → sentinel records `bind_confirmation: {status: pass, delta, reached, aliases}`. Counter doesn't tick → lock exits **91** (new code, distinct from 73/87) with `[FAIL] Bind-confirmation: test request did not reach the proxy`. The bind_probe counter is intentionally separated from `requests_proxied` (spend_log) so probe traffic never pollutes the real-traffic meter and a real-traffic burst can never fake a probe pass. Probe endpoint is loopback-only (`127.0.0.1` / `::1` — non-loopback origins get 404 without ticking the counter). When a recognised proxy isn't found at `/healthz` (missing `bind_probe_count` field), lock classifies the verdict as `skipped, reason=proxy_unrecognised` rather than `fail` — refuses to manufacture a failure against an unrecognised peer.
- **`worthless status` and `worthless doctor` surface the bind-confirmation verdict** (WOR-658). Status reports the specific reason (`Proof-of-routing FAILED — the test request didn't reach the proxy`, or `The service answering /healthz isn't a worthless proxy`) instead of generic DEGRADED. Doctor's new `bind_confirmation` check turns the same signal into a remediation hint (`restart OpenClaw's daemon` or `re-run worthless lock`). The DEGRADED exit-code from status remains 73 for backwards-compat; lock-side bind-fail is exit 91. **`worthless wrap` warns before spawning a child** when the last lock left a DEGRADED sentinel — the magic-moment command is no longer blind to bind-fail state.
- **Recovery path from bind-fail is tested** (WOR-658). The `[FAIL]` message now lists both repair routes: restart OpenClaw + re-run `worthless lock`, OR `worthless unlock` to roll back. `tests/openclaw/test_unlock_after_bind_fail.py` pins that unlock from the bind-fail state restores the `.env` byte-for-byte and clears the DEGRADED sentinel.

### Fixed
- **`worthless uninstall` survives a broken or half-deleted install** (WOR-713, [#360](https://github.com/shacharm2/worthless/pull/360)). A missing `fernet.key` or corrupted `worthless.db` used to crash uninstall (WRTLS-102/103); a deleted project (its locked `.env` gone) used to block uninstall forever via the key-shredder guard. Now a broken install refuses cleanly and points at `--force`; a missing `.env` is skipped with a warning and never blocks; and `worthless doctor` (both text and `--json`) diagnoses both states instead of crashing, each pointing at `worthless uninstall --force`. The restore-then-wipe guard is unchanged: it still aborts before deleting anything if a *recoverable* key can't first be restored, and `--force` only widens the wipe decision — it never skips a restore on a healthy install.

### What this does NOT defend against
- Future models with >128K max-output (Anthropic's next reasoning tier, a 256K-output OpenAI release, etc.) — these will under-bill by their excess until `GLOBAL_CEILING_TOKENS` is raised.
- **A stale OpenClaw daemon ignoring the rewritten `baseUrl`** (WOR-658 known gap, [WOR-756](https://linear.app/plumbusai/issue/WOR-756) closes it). Bind-confirmation proves the *proxy* received a test request — it does NOT prove OpenClaw's running daemon will use the new URL on the next chat. OpenClaw caches provider config; until WOR-756 ships an automatic daemon-reload trigger, the user must restart OpenClaw after `worthless lock` to guarantee end-to-end routing. Lock's `[OK]` is honest about the proxy side; OpenClaw's `[OK]` is on the user.
- **A co-resident malicious process impersonating the worthless proxy on the configured port** (WOR-658 known gap, [WOR-768](https://linear.app/plumbusai/issue/WOR-768) closes it). Squatter-resistance today is "does `/healthz` include `bind_probe_count`?" — a local service that mimics the protocol passes that check. The loopback-only gate closes the realistic remote attacker; the co-resident-with-protocol-knowledge case awaits a cryptographic identity check.
- A 14m59s drip stream still completes inside the duration window — the kill bounds wall-time, not provider cost within that window.
- A compromised proxy can disable any check that lives inside the proxy, including this ceiling. T7 defends against honest bugs, runaway agents, and zombie streams; the compromised-proxy threat model is WOR-269 territory.
- Response-model mismatch counter is observation-only — a silent re-route to a more expensive model is NOT blocked. The cap still moves only by token count, not by dollar-equivalent at the actual upstream model.
- Cap is per-key per-DB. Deleted DB row or filesystem-level tampering = no cap.
- Per-alias concurrency is unbounded in this PR. 200 parallel just-under-threshold streams could burn 25.6M tokens before admission denies request #201. Tracked as a follow-up.
- **`worthless uninstall --force` on a broken install does NOT recover your keys** (WOR-713). When the `fernet.key` or `worthless.db` is gone, the locked secrets can't be reconstructed — `--force` wipes the unrecoverable remains so the machine is left clean, but those API keys are lost. Rotate them at the provider.

### Changed
- **Bare `worthless` now starts the sidecar-supervised proxy path** (WOR-717). The default command spawns detached `worthless up` instead of the legacy sidecar-less `start_daemon` helper. The latter remains for internal compatibility but is deprecated for v1.2 removal. Service unit detection compares `WORTHLESS_HOME` by realpath so symlinked install paths (e.g. `/tmp` vs `/private/tmp`) match. **Does not yet** include foreign-unit guards on service mutators or default-command exit **2** when a platform service is stopped/failed — both land in wave 3b (#292).

## [0.3.8] — 2026-06-13

The "agents and exits" release. Two headline additions: a zero-Python npm wrapper lets editors (Claude Code, Cursor, Windsurf) install the MCP server in under 30 seconds, and `worthless uninstall` gives every locked `.env` its original key back before removing itself — no stranded files, clean exit. Alongside that: a proxy kill switch stops OpenClaw agents dead when the proxy goes down, the spend cap is now exact per process, and the install pipeline closes three supply-chain attack surfaces that were confirmed reachable.

### Added
- **One-line MCP setup for editors** (WOR-229, #be567bc). `worthless-mcp` npm package: drop one JSON block into `.mcp.json` and Claude Code / Cursor / Windsurf discover and launch the MCP server automatically. No Python or uv needed on the editor side; the wrapper bootstraps uv and pins the Python package to the matching npm version.
- **`worthless uninstall`** (WOR-435, #301). Reads every enrolled `.env` the tool ever locked, writes the original API key back, then removes itself. Leaves no stranded locked files and no user having to remember what the plaintext key was.
- **Proxy kill switch for agents** (WOR-621 Phase 3, #276). Stopping the Worthless proxy now halts any OpenClaw agent that is mid-flight on a locked provider. Agents can't leak around a downed proxy.

### Security
- **Spend cap is exact per process** (WOR-662, #273). The proxy refuses to start with `WEB_CONCURRENCY > 1`. Two workers could each independently run up to the full cap; now the cap means what it says.
- **Compromised proxy can no longer act as a key oracle** (#269). The locked vault stopped signing arbitrary upstream requests when the proxy process is breached — closes the master-key extraction path identified in the security audit.
- **Install is resistant to supply-chain poisoning** (WOR-709 + WOR-673 + WOR-679, #284 + #281 + #280). Three surfaces closed: (1) `install.sh` skips a pipx path-confusion check that was an empirically-confirmed RCE vector when pipx lives in an untrusted directory; (2) poisoned `UV_*` / `PIP_*` env vars can't redirect the install to a malicious host; (3) CDN integrity verification now has its own exit code — retry loops can't silently swallow a poisoned artifact.
- **Every commit to main is signed and author-verified** (WOR-589 + WOR-590, #305 + #308). A push-time hook and a pre-commit check enforce GPG-verified commits from the canonical author. A stolen GitHub token can't push unverifiable commits.

### Fixed
- **Error messages now show their reason** (worthless-k82c, #268). A parser bug was silently stripping the explanatory clause from error text — errors now say "because X", not just the error code.
- **Post-lock scan can't freeze the terminal** (worthless-8vvg, #264). The prompt scan that runs after a successful `worthless lock` now exits on large repos instead of hanging indefinitely.
- **14 dead documentation links repaired** (#303). Broken internal links that sent users to 404s are fixed; a CI guard blocks new dead links from shipping.

### Changed
- **CLI discloses "AS IS, no warranty" on first run** (WOR-488, #302). Shown once at first invocation. Honest, not noisy.
- **SECURITY.md is honest about response scope** (#306). Best-effort response commitment, no overstatements about SLAs we can't guarantee.
- **Dependabot tuned to batch non-major updates** (#326). Actions updates are grouped; semver-major bumps are held for manual review.

### Docs & Infrastructure
- **Install docs live in one place** (#309). The stale website copies are removed; `docs/install-*.md` is the single source and the website pulls from there.
- **OpenClaw routing contract test** (WOR-621, #266). Tag-pinned integration test catches routing drift before it reaches production.

## [0.3.7] — 2026-05-30

The "harden the whole front door" release. Everything merged since v0.3.6 ships at once: your API key now survives a proxy compromise (a crypto sidecar holds the key, not the proxy), OpenClaw runs fully containerised and `worthless lock` refuses to proceed when plaintext keys are present, and the entire install path — `worthless.sh`, the `?explain=1` audit, the PyPI publish, and the Worker deploy — is version-pinned and signed-tag-verified end to end. Plus a wave of `lock`/`doctor` fixes that tell you the truth instead of failing silently.

### Security
- **Your API key survives a proxy compromise** (WOR-306, #134). On the Docker topology a crypto sidecar holds the Fernet key under a separate uid; a breached proxy process can no longer read it.
- **`worthless lock` blocks on plaintext keys** (#210). The OpenClaw secrets-audit gate refuses to lock when an unprotected API key is present instead of silently locking around it.
- **A stolen shard-A is inert** (#208). Tightened the upsert API + doctor consistency so a leaked key-half can't be replayed.
- **The install front door is honest and signed end to end.** The `?explain=1` audit page no longer claims a version pin / line numbers that don't exist, and a CI check fails if a version literal drifts back in (WOR-558, #213). The default `curl | sh` pins a known-good PyPI release instead of running latest (WOR-559, #217). Every Worker deploy (WOR-391, #205) **and now every PyPI publish** verifies the maintainer's GPG-signed tag. The release-sync monitor anchors to signed git tags, not a forgeable GitHub Release object (#224). Production edge wire-defenses are probed daily, not only at deploy (#216).
- **Stolen creds can't deadlock cron jobs** (worthless-16x2, #198) — a stable auth token for the OpenClaw→proxy hop.
- **`lock` flags hardcoded provider URLs** that would route around the proxy (#174, #182).

### Added
- **OpenClaw runs fully containerised** — no host process required (#192); agents work through the proxy with the 400s and Docker connectivity fixed (#188).
- **`worthless doctor` heals itself** — `check-registry`, `--json` for agents, and 4 new checks (WOR-464, #190); it catches wrong-database confusion before you waste hours on phantom 401s (#195).
- **Verified end-to-end install journeys** for solo, Claude Code, and Docker users (WOR-502, #197), with proof traces (WOR-441, #194) and a user-journey → proof matrix (WOR-544, #206).
- Website: homepage incident ticker (#199, #204) and wless.io source migrated into the main repo (WOR-455, #179).

### Fixed
- **Re-lock tells you it worked**, not nothing (WOR-504, #207); **`lock` catches a broken app before you walk away** (WOR-493, #180).
- **Silent 401 fixed** — the canonical key now wins the `BASE_URL` slot (WOR-496, #176).
- **LAN mode actually binds the network** (worthless-rczo, #186).
- **`LOCK FAILED` summary** ends the mixed `[FAIL]`+`[OK]` ambiguity (#222).
- The last revoke wipes the orphan Fernet key from the keychain (#175).
- `worthless_status` (MCP) returns keys correctly from an async context (#196); ticker script loads under CSP (#200).

### Changed
- Version labels aligned to PyPI `v0.x` (WOR-489, #183).
- Internal security docs privatised (WOR-593, #236); Snyk reports the dependency tree we actually ship (#235, #237).

### Tests & Infrastructure
- New user-flow test foundation plus native and adversarial stress journeys (WOR-439/447/567/442, #177/#187/#215/#212); install-failure and repo-health monitoring with flaky-test quarantine (WOR-578, #226); Windows test collection no longer crashes on a POSIX-only `os.getuid()` (#211); xdist flake suppression (WOR-571, #218; #238); PR auto-labelling by branch prefix and security paths (#219).

## [0.3.6] — 2026-05-12

The "OpenClaw integration actually works for Docker users" release. v0.3.5 shipped the WOR-431 OpenClaw magic-integration (Phase 2), but Brutus review caught 3 release blockers and CodeRabbit caught 2 more before the developer-facing flow was sound. Headline: `worthless lock` on a host with a Dockerised OpenClaw now writes a `baseUrl` that OpenClaw can actually reach (loopback → docker0 bridge / `host.docker.internal`), SKILL.md ships the YAML frontmatter ClawHub needs for auto-install discovery, and cross-environment re-locks on non-default ports correctly refresh the apiKey instead of misclassifying our own entries as third-party conflicts.

### Fixed
- **`worthless lock` now writes a Docker-reachable proxy URL** (PR #168). `apply_lock` resolves the proxy host at lock-time via `_resolve_proxy_base_url()` — bare-metal returns `127.0.0.1:8787`, Docker Desktop returns `host.docker.internal:8787`, Docker on Linux reads the `docker0` bridge gateway (default `172.17.0.1`). Pre-fix every OpenClaw-in-Docker user hit a silent connection-refused; `127.0.0.1` from inside the container points back at the container, not the host. The probe uses `shutil.which("docker")` + a 3 s `docker info` timeout, so when Docker is absent there's zero startup latency cost.
- **`_is_proxy_url` cross-host fallback handles non-default ports** (PR #168, CodeRabbit catch). The original fallback hardcoded `:8787`. A user on `--port 9090` who locked without Docker then re-locked with Docker on would have the existing entry's `apiKey` silently skip refresh — primary prefix check fails on host mismatch, fallback regex fails on port mismatch, entry misclassified as third-party conflict. Now the fallback derives the port from `proxy_base_url` via `urlsplit()`, so `WORTHLESS_PORT`/`--port` deployments work end-to-end. Regression test pins port 9090 with host mismatch.
- **`health_check()` uses the same resolved host as `apply_lock`** (PR #168, CodeRabbit catch). Pre-fix, doctor compared the `openclaw.json` entry against a hardcoded `http://127.0.0.1:<port>/<alias>/v1`. On Docker hosts every healthy config got reported as drifted. Optional `proxy_base_url` parameter defaults to `_resolve_proxy_base_url()`; `proxy_port` is preserved so non-default deployments don't false-flag.
- **urllib3 bumped to 2.7.0** (PR #168). Closes GHSA-qccp and GHSA-mf9v via lockfile bump (no direct dependency added).

### Added
- **SKILL.md `metadata.openclaw` frontmatter** (PR #168). `requires.bins: [worthless]` enforces the worthless CLI is installed before the skill activates; `install` array gives ClawHub two recipes (`uv tool install` + `pip install`) for one-click bootstrap. Pre-fix ClawHub had no way to auto-install; the developer had to know they needed worthless on the host before the skill made sense.
- **WOR-432 e2e Docker test runs in CI** (PR #168). `tests/test_openclaw_skill_e2e.py` was already implemented but had been gated on a Docker daemon — confirmed it runs locally end-to-end (mock upstream receives the reconstructed key, shard-A absent from outbound traffic).
- **+8 unit tests covering all `_resolve_proxy_base_url()` branches** (PR #168). Linux/macOS/Windows + Docker present/absent + bridge inspection failure.

### Changed
- **`_is_proxy_url` rewrite** (PR #168). Architecturally the cleanest fix is an explicit `managedBy` marker on each entry; v0.3.6 ships the heuristic and tracks the proper fix as [WOR-487](https://linear.app/plumbusai/issue/WOR-487). Outstanding research: does OpenClaw's daemon preserve unknown fields on rewrite?

### Notes
- The end-to-end developer flow (clean machine → OpenClaw + worthless → first protected request) still leans on the developer reading docs to install worthless first. Real ClawHub publish (WOR-94 + WOR-478) is a separate ticket.

## [0.3.5] — 2026-05-08

The "WOR-431 Phase 2 lands + install front-door drift fixed" release. Ships the OpenClaw magic-integration that `worthless lock` had been promising — automatic detection + `openclaw.json` rewrite + SKILL.md install — plus a daily CI check that every install front door (`worthless.sh`, `docs.wless.io/install/`, `install.sh` digests) stays in sync.

### Added
- **`worthless lock` detects OpenClaw and rewires its config automatically** (WOR-431 Phase 2, #152). On any host where `~/.openclaw/` exists, `lock` injects `worthless-<provider>` entries into `openclaw.json` and installs the worthless SKILL.md into the skill workspace. Best-effort + idempotent — failures here surface as structured events in `--json` and never roll back the `.env`/DB writes. Symmetric undo on `unlock`. New `worthless doctor` rows surface drift between the proxy and `openclaw.json`.
- **Install front-door daily-drift CI** (WOR-452, #149). Cron check pulls `worthless.sh`, `docs.wless.io/install/`, and the `install.sh` digest from each surface — flags divergence as a Linear issue automatically.
- **`scripts/bump-version.sh`** (#145). Atomic version bumper that writes to `pyproject.toml`, `SKILL.md`, and the lockfile in one shot — prevents SKILL.md drift that previously slipped through.

### Fixed
- **`install.sh` surfaces uv's actual stderr instead of a generic banner** (#148). Previously a uv install failure showed only "installation failed" with no clue why; now the user sees uv's real error message.
- **xdist-isolated default-command tests don't collide with a real port-8787 daemon** (#147).
- **Worker-concurrency tests stop flaking the merge gate** (WOR-448, #142).
- **`DOCS_URL` points at live `docs.wless.io`** instead of stale staging (worthless-1lfi, #144).

### Removed
- **Dead `_build_child_env` helper in `wrap.py`** (#146).

## [0.3.4] — 2026-05-06

The "make `worthless wrap` actually work end-to-end" hotfix. v0.3.3's HF10 fresh-install verification surfaced that `worthless wrap python main.py` on a clean machine left the child unable to reach the proxy: `lock` writes port 8787 to `.env` but `wrap` was binding a random port the child had no way to discover. The earlier "wrap works" verdict was contaminated by a stale `worthless up` daemon hogging 8787 across sessions. Fix: `wrap` now binds the same port `lock` wrote.

### Fixed
- **`worthless wrap` proxy now binds the port `lock` wrote to `.env`** (worthless-djoe, closes worthless-hyb1). Pre-fix `wrap` called `spawn_proxy(port=0)` (OS-random), which gave the proxy a port the child couldn't discover — post-8rqs `wrap` had stopped injecting `*_BASE_URL` vars into child env, so the only port the child saw was `.env`'s. With lock writing 8787 and wrap binding random, the child hit 8787 and got connection-refused. Now `wrap` calls `_resolve_port(None)` (same priority chain `lock` and `up` use: arg → `WORTHLESS_PORT` env → `8787` default), so child + proxy agree. Regression introduced in v0.3.3 / PR #127 (worthless-8rqs).
- **`worthless wrap` gives a clean error when its port is already in use.** If `worthless up` is already running on the same port, wrap names it: *"port 8787 is already serving a worthless proxy (`worthless up` is running). Either run your command directly (the daemon proxies it already), or stop the daemon and re-run wrap."* If a non-worthless process holds the port, wrap names that case too. `up` and `wrap` are alternatives, not combinable on the same port.

## [0.3.3] — 2026-05-05

The "make `curl install.sh | sh` actually work" release. v0.3.2 dogfood surfaced 9 hotfixes (HF1-9) covering keychain UX, scan/status correctness, unlock messaging, and orphan recovery. Plus install-matrix supply-chain hardening (WOR-317-320) so the release pipeline can't be tampered with via floating-tag base images.

### Added
- **`WORTHLESS_DEPLOY_MODE` trust-boundary contract** (WOR-345). Three modes — `loopback` / `lan` / `public` — pin host bind, X-Forwarded-Proto trust source, and whether `WORTHLESS_ALLOW_INSECURE` is even legal. `public` mode requires `WORTHLESS_TRUSTED_PROXIES` (validated as CIDR; placeholders are rejected at startup). PaaS auto-detection (RENDER / FLY_APP_NAME / KUBERNETES_SERVICE_HOST) refuses silent loopback default.
- **`worthless doctor --fix`** (HF7, worthless-3907, PR #128). Recovers stuck states from the v0.3.2 dogfood scenario where `unlock` reported "no keys" but `status` reported "PROTECTED". Surgical delete by `(alias, env_path)` tuple. Shared `cli/orphans.py` module owns the `is_orphan` predicate plus canonical user-facing phrases — no drift between scan/status/doctor wording.
- **`worthless lock` supports multiple providers side-by-side** (PR #127). One `.env` can have OpenAI + Anthropic + Google + xAI keys; each enrolls with its own per-provider upstream URL.
- **Per-key unlock messaging** (HF4, worthless-5u6y, PR #123). `worthless unlock` now prints `Restored {var} ({provider}, alias {alias_id}) → {env_path}` per key, plus skip lines for missing shard-A vars. Final summary `Restored N, skipped K`. No more silent batch-fatal exceptions.
- **Scanner scope docs** (HF6, worthless-8axm, PR #123). README + SKILL.md + threat model document the LLM-provider-keys-only scope; recommend gitleaks/trufflehog as companions for general secret detection.
- **Cross-command state-machine integration tests** (HF8, worthless-5koc, PR #120). Tests covering commitment-mismatch, partial-unlock, scan-orphan, status-orphan, unlock-db-wipe, unlock-no-db-row contracts.
- **Install matrix supply-chain hardening** (WOR-317-320, PR #132). Pinned base-image digests (`@sha256:...`) on every fixture, Astral installer SHA verification in `Dockerfile.ubuntu-with-uv`, BuildKit cache mount on uv-running RUN steps, non-root user fixture (`ubuntu-nonroot`), idempotency check fixture (`ubuntu-idempotency`) that runs `install.sh` twice and diffs snapshots. `install.sh` gains a fast-path: `WORTHLESS_VERSION` set + matches installed → return early before `uv tool install/upgrade` writes metadata.

### Changed
- **BREAKING — Docker default bind is now loopback** (`127.0.0.1`), not `0.0.0.0`. The Dockerfile no longer hard-codes `--host 0.0.0.0`; bind is composed by `entrypoint.sh` from `WORTHLESS_DEPLOY_MODE`. `docker run -p 8787:8787 worthless` without setting the env var binds only inside the container — set `-e WORTHLESS_DEPLOY_MODE=lan` to restore network reachability behind a private network, or `=public` (with `WORTHLESS_TRUSTED_PROXIES`) for edge deployments. `deploy/docker-compose.env.example` and `deploy/render.yaml` updated accordingly.
- **`worthless scan` JSON shape** (HF5, worthless-gmky, PR #131): bare-array → `{schema_version: 2, findings, orphans}`. Schema version is pinned exactly in a contract test. Consumers must update.

### Fixed
- **OpenRouter API keys classified as `openrouter`** (HF1, worthless-lj0z, PR #124, advances WOR-381). `sk-or-v1-...` and `sk-or-...` keys were previously mislabeled `openai` because the generic `sk-` prefix won the longest-first match; the new `openrouter` prefixes now beat it. **Behaviour change:** SARIF/scan consumers filtering on `provider == "openai"` for OpenRouter keys will see relabels to `provider == "openrouter"` — update filter logic accordingly. Detection only; per-enrollment proxy routing for `provider == "openrouter"` is tracked separately under `worthless-8rqs` and remains future work.
- **macOS Keychain prompts collapse to one per CLI invocation** (HF2, worthless-mnlp, PR #125). `WorthlessHome.fernet_key` is now memoized per-instance via a private `_cached_fernet_key` field, so a single `worthless lock` triggers exactly one keychain ACL probe instead of 3+. Cache populate uses a per-instance `threading.Lock` with double-checked init so concurrent first-readers collapse to a single `read_fernet_key` call. Cache is process-scoped — new CLI invocations still re-prompt once until "Always Allow" is granted.
- **`worthless scan` and `worthless status` no longer prompt for keychain on read-only paths** (HF3, worthless-cmpf, PR #126). New `_fernet_key_present(home)` gate at the scan path; placeholder `bytearray(b"")` for the unused parameter on missing-key paths. Scans + status checks now produce zero popups even on a brand-new machine.
- **`worthless status` and `worthless scan` flag broken DB rows as `BROKEN`** (HF5, worthless-gmky, PR #131) instead of lying that they're `PROTECTED`. Plain-English wording: `PROBLEM_PHRASE = "can't restore"`, `FIX_PHRASE = "worthless doctor --fix"`. Per-alias aggregation: `BROKEN` iff all enrollments are orphan; `PROTECTED` if any enrollment is healthy.
- **`worthless unlock` default `--env` no longer surfaces HF4's hard error on implicit defaults** (pnn2, PR #129). Implicit `--env=.env` doesn't trigger the per-key skip messaging path that was meant only for explicit user-named paths.

### Security
- **Pinned base-image digests across the install test matrix** (WOR-319). Every `FROM` line uses `@sha256:<digest>` instead of floating tags, so a compromised upstream tag cannot ship malware via our matrix.
- **Astral uv installer SHA verification** in `Dockerfile.ubuntu-with-uv` (WOR-319). The fixture awks `ASTRAL_INSTALLER_SHA256` out of `install.sh` at build time so the SHA stays in lockstep with `UV_VERSION`.

### Verified manually
- **HF9 (worthless-xw2m) keychain popup contract on dev machine, 2026-05-05**. Wiped keychain (drained 6 entries to 0) + `~/.worthless/`, fresh `uv tool install` from main, ran `worthless lock` + status / scan / unlock / lock / up / down. **0 popups across all commands.** HF2 unit + user-flow tests prove the 1-popup contract on truly clean machines via real-keyring spy. Phase-2 second-machine run is best-practice but not blocker.

### Known limitations
- **Manual `worthless up` after every reboot** until WOR-174 (macOS launchd) and WOR-175 (Linux systemd) ship in v0.4.
- **Docker app + host worthless** requires manually editing `.env` to use `host.docker.internal:8787` instead of `127.0.0.1:8787` — `worthless lock` writes `127.0.0.1` blindly today (filed as v1.2 work).
- **Two `worthless up` proxy bugs** discovered during HF9 manual QA: stale orphan proxy on port 8787 (`worthless-6gkb`) and `worthless up &` exits prematurely (`worthless-n8tj`). Both filed as v0.3.4 / v1.2 work; do not affect lock/scan/status/unlock paths.

## [0.3.0] — 2026-04-18

First release published to PyPI. `pip install worthless` now works.

### Added
- **Magic default command** (`worthless` with no arguments). Detects API keys in `.env`/`.env.local`, prompts to lock, starts the proxy daemon, reports healthy — zero-config first-time setup. `--yes` for non-interactive, `--json` for read-only state.
- **Format-preserving key split** (WOR-207 Phase 1). Shard A now preserves the original key's prefix, charset, and length, so scanners and SDK validators see a key-shaped token. Database migration included for existing installs.
- **Anthropic key authentication** (WOR-207 Phase 2). `x-api-key` support alongside OpenAI-style `Authorization: Bearer`.
- **SR-09 shard separation enforcement**. Pre-commit hook blocks commits that would co-locate Shard A and Shard B in any code path.
- **Pre-commit stack**: gitleaks, semgrep, bandit, pip-audit, ruff, codespell, actionlint, zizmor, SR-rule custom checks.
- **Docker e2e test suite**. Single-container and compose-stack fixtures; read-only container + tmpfs for `/tmp`.
- **OpenClaw integration harness** (WOR-213). Live attack suite validates 9 attack vectors against real OpenAI + Anthropic.
- Security FAQ and threat-model docs (WOR-196).

### Changed
- `DEVELOPMENT.md` and `SECURITY.md` rewritten for doc accuracy — commands and paths now match the shipping CLI.
- Test suite no longer hardcodes version literals; assertions read from `importlib.metadata` / `pyproject.toml` to prevent drift.

### Fixed
- CodeQL alerts resolved: SR-01 bytearray usage, B603 subprocess hardening, tamper-detection test correctness, schema SQL formatting.
- CodeRabbit review comments across docs and CLI (WOR-196 #55, #58).

### Security
- All crypto operations use `bytearray` + explicit zeroing (SR-01).
- Constant-time comparisons on all digest/HMAC paths (SR-07).
- Gate evaluation strictly precedes shard reconstruction (SR-03).
- Published artifacts built via PyPI trusted publishing (OIDC, no long-lived tokens).

[0.3.8]: https://github.com/shacharm2/worthless/releases/tag/v0.3.8.0
[0.3.7]: https://github.com/shacharm2/worthless/releases/tag/v0.3.7
[0.3.6]: https://github.com/shacharm2/worthless/releases/tag/v0.3.6
[0.3.5]: https://github.com/shacharm2/worthless/releases/tag/v0.3.5
[0.3.4]: https://github.com/shacharm2/worthless/releases/tag/v0.3.4
[0.3.3]: https://github.com/shacharm2/worthless/releases/tag/v0.3.3
[0.3.0]: https://github.com/shacharm2/worthless/releases/tag/v0.3.0

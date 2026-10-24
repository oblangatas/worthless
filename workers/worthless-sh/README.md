# worthless-sh Worker

Cloudflare Worker at `worthless.sh` — serves `install.sh` to curl, redirects browsers to `wless.io`.

## Status

Scaffolding + RED tests only. **Implementation pending: WOR-300.**

## Contract (enforced by ./test)

| Request | Response |
|---------|----------|
| `curl` / `wget` / `fetch` / `Go-http-client` UA | `200` `text/plain`, body = `install.sh` |
| Chrome / Firefox / Safari UA | `302` → `https://wless.io` |
| Missing or unrecognized UA | `302` → `https://wless.io` (fail-safe) |
| `?explain=1` + curl UA | `200` `text/plain`, human-readable walkthrough |
| `?explain=1` + browser UA | `302` → `https://wless.io` |

## Run tests locally

```sh
cd workers/worthless-sh
npm install
npm test
```

All tests should be RED until the Worker is implemented in WOR-300.

## Host support matrix

The `install.sh` this Worker serves is validated across Ubuntu 22.04/24.04,
Debian 12, Alpine, and macOS. Full table + test invocation:
[README — support matrix](../../README.md#installsh--worthlesssh-support-matrix).

## Dependency overrides

`package.json` pins `overrides: { "sharp": "^0.35.5" }`. It answers
[GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c) — a libheif
heap overflow affecting sharp `<0.35.4` — and
[GHSA-wq5f-xc86-pv6w](https://github.com/advisories/GHSA-wq5f-xc86-pv6w) (librsvg,
`<0.35.5`), which reached this tree as
`sharp <- miniflare <- wrangler / @cloudflare/vitest-pool-workers`.

The override is needed because **miniflare pins `sharp` to an exact `0.35.2`**, so npm's
resolver can only walk backwards: the only fix it offered was
`@cloudflare/vitest-pool-workers` 0.22.0 -> 0.8.30, a semver-major downgrade of this
suite's test runner. `overrides` reaches the published patch instead. Nothing else moves —
wrangler, miniflare, vitest-pool-workers and vitest are all unchanged, and the suite is
byte-identical either way (244 passed, 9 expected-fail before and after).

**Remove it** once miniflare itself depends on sharp >= 0.35.5. Dropping it before then
silently reinstates 0.35.2 on the next `npm install`; `tests/test_dependency_audit_gate.py`
fails offline if that happens, and the `npm audit` job in `dependency-audit.yml` fails in CI.

`undici` and `zod` are overridden for the same reason: miniflare pins undici exactly, and
`@cloudflare/vitest-pool-workers` pins zod to exactly `4.4.3`, still true of their latest
releases on 2026-10-24. Each is pinned exactly to the first fixed version: undici `7.30.1`
([GHSA-4qv8-2p9j-2685](https://github.com/advisories/GHSA-4qv8-2p9j-2685),
[GHSA-f72v-6w45-q472](https://github.com/advisories/GHSA-f72v-6w45-q472),
[GHSA-xjj6-f33q-929c](https://github.com/advisories/GHSA-xjj6-f33q-929c)) and zod `4.6.6`
([GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)). Exact, not a
caret, so a relock can't float a newer release into a toolchain that deploys with Cloudflare
credentials; a later advisory means a deliberate bump here. Remove each once the package that
pins it depends on a fixed version; only the `npm audit` job guards these two.

## Tickets

- WOR-305 — this test suite
- WOR-300 — Worker implementation (parent)
- WOR-304 — depends on `?explain=1` shipping

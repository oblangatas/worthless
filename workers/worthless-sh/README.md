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

`package.json` pins `overrides: { "sharp": "^0.35.4" }`. It answers
[GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c) — a libheif
heap overflow affecting sharp `<0.35.4`, which reached this tree as
`sharp <- miniflare <- wrangler / @cloudflare/vitest-pool-workers`.

The override is needed because **miniflare pins `sharp` to an exact `0.35.2`**, so npm's
resolver can only walk backwards: the only fix it offered was
`@cloudflare/vitest-pool-workers` 0.22.0 -> 0.8.30, a semver-major downgrade of this
suite's test runner. `overrides` reaches the published patch instead. Nothing else moves —
wrangler, miniflare, vitest-pool-workers and vitest are all unchanged, and the suite is
byte-identical either way (244 passed, 9 expected-fail before and after).

**Remove it** once miniflare itself depends on sharp >= 0.35.4. Dropping it before then
silently reinstates 0.35.2 on the next `npm install`; `tests/test_dependency_audit_gate.py`
fails offline if that happens, and the `npm audit` job in `dependency-audit.yml` fails in CI.

## Tickets

- WOR-305 — this test suite
- WOR-300 — Worker implementation (parent)
- WOR-304 — depends on `?explain=1` shipping

// (No ambient module declarations needed in src/.)
//
// install.sh and walkthrough.txt are not imported into the Worker bundle —
// they're base64-encoded at build time by `scripts/embed-assets.mjs` into
// `src/embedded.ts`, which is a normal .ts file. See wrangler.toml for the
// CF WAF rationale.
//
// Test-only ambient declarations (e.g., Vite's `?raw` suffix) live in
// `test/vite-raw.d.ts` so they don't leak into the production type
// surface for the Worker bundle.

export {};

import { describe, it, expect } from "vitest";
import { INSTALL_SH_B64, WALKTHROUGH_B64 } from "../src/embedded";
// Vite `?raw` reads the on-disk file at bundle time and inlines it as a
// string constant. Works in the Cloudflare Workers test runtime because
// the file content is resolved by Vite before the bundle reaches the
// Workers pool — no `node:fs` at runtime.
import installShSource from "../../../install.sh?raw";
import walkthroughSource from "../src/walkthrough.txt?raw";
import { b64ToBytes } from "./_helpers";

// WOR-404 — embed:assets round-trip pin.
//
// The Worker serves bytes decoded-from-base64 at module load. The sibling
// `walkthrough-reveal.test.ts` (WOR-323) pins that the SERVED body equals
// the decoded WALKTHROUGH_B64 constant. It does NOT pin that the constant
// equals the ON-DISK source file.
//
// The deploy workflow's `Compute install.sh sha256` and `Compute
// walkthrough.txt sha256` steps hash the SOURCE files. The Worker serves
// the DECODED bytes. If a future "modernization" of
// `scripts/embed-assets.mjs` adds line-ending normalization, BOM
// stripping, timestamp injection, or any other transform on the
// source-file → base64 path, CI sha256 != served sha256 forever — the
// post-deploy smoke step would fail silently on every release.
//
// This test catches that drift at unit-test time, before any deploy.
// Guardrail against accidental future drift; not a defense against
// active tampering.

describe("embed:assets round-trip (WOR-404)", () => {
  it("decoded INSTALL_SH_B64 byte-equals on-disk install.sh", () => {
    const decoded = b64ToBytes(INSTALL_SH_B64);
    const source = new TextEncoder().encode(installShSource);
    expect(decoded).toEqual(source);
  });

  it("decoded WALKTHROUGH_B64 byte-equals on-disk walkthrough.txt", () => {
    const decoded = b64ToBytes(WALKTHROUGH_B64);
    const source = new TextEncoder().encode(walkthroughSource);
    expect(decoded).toEqual(source);
  });
});

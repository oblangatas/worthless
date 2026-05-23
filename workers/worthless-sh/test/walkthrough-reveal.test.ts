import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { WALKTHROUGH_B64 } from "../src/embedded";
import { b64ToBytes } from "./_helpers";

// WOR-323 — walkthrough REVEAL block contract.
//
// The walkthrough served at `?explain=1` is the curl-readable audit page.
// This file pins three invariants:
//
//   1. Served body byte-equals the bundled WALKTHROUGH_B64 source — catches
//      Worker-side mutation between embedded.ts and the response.
//   2. Body starts with the exact REVEAL block at offset 0 — catches a
//      regression that drops, reorders, or double-prepends the block.
//   3. ETag matches `W/"walkthrough-${sha256(body)}"` — catches cache
//      desync between the served body and the advertised hash.
//
// Honest framing (matches DEPLOY.md "Known residual risks"): these checks
// catch transit tampering and bundle drift. They do NOT defend against an
// attacker who controls the origin — that's WOR-303 (cosign).

const CURL_UA = "curl/8.4.0";

const REVEAL_BLOCK = `== Verify the bytes match what the Worker serves ==
  curl -sSL worthless.sh | sha256sum         # body hash
  curl -sSI worthless.sh | grep -i sha256    # header value
The two MUST match. Mismatch = abort and report.
(This catches transit tampering. Not origin compromise — see README.)
==================================================================
`;

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Walkthrough/install bytes contain em-dashes and other multi-byte UTF-8 —
// decode the raw bytes via TextDecoder to restore them as a JS string.
function b64ToUtf8(b64: string): string {
  return new TextDecoder("utf-8").decode(b64ToBytes(b64));
}

describe("walkthrough REVEAL block (WOR-323)", () => {
  it("served ?explain=1 body byte-equals decoded WALKTHROUGH_B64", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    const expected = b64ToUtf8(WALKTHROUGH_B64);
    expect(body).toBe(expected);
  });

  it("served walkthrough body starts with the REVEAL block at offset 0", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body.startsWith(REVEAL_BLOCK)).toBe(true);
    expect(body.indexOf("== Verify the bytes match what the Worker serves ==")).toBe(0);
  });

  it("ETag header equals W/\"walkthrough-${sha256(body)}\"", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    const sha = await sha256Hex(body);
    expect(res.headers.get("etag")).toBe(`W/"walkthrough-${sha}"`);
  });

  // WOR-558 — drift guard. The audit must never hardcode a value that rots
  // into a lie: the worthless package version (changes every release), source
  // line numbers (change every edit), or a version-pinned raw URL. The
  // deliberate UV_VERSION pin in Step 4 is the security fact being audited,
  // not drift, and is intentionally NOT matched by these patterns.
  it("walkthrough states no rot-able version literal", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).not.toMatch(/worthless==\d/); // package version pin
    expect(body).not.toMatch(/\blines?\s+\d/i); // "lines 1-30" citations
    expect(body).not.toMatch(/\/v\d/); // /v0.3.0/install.sh URL
  });
});

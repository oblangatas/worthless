import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED tests — Range requests, Accept-Encoding negotiation, and bounded
// response size (R-01..R-03 from security-audit/phase-2-pen-test-additions.md
// + Batch 1 pen-test-review §2 Brotli/wildcard gap).
//
// Threat model: the install-script response is the supply-chain trust
// boundary. Two truncation classes are catastrophic and three echo-defence
// classes are belt-and-suspenders:
//
//   1. Range-based truncation: `curl -r 0-100 worthless.sh | sh` getting a
//      206 with the first 101 bytes of the script. `set -e` does NOT save
//      a half-parsed shell file — a partial here-doc, an open `if`, an
//      unterminated quoted string can leave the system in a half-configured
//      state that's worse than no install. Defence: ignore Range entirely;
//      always 200 + full body. NEVER 206. Pen-tester ranks this HIGHEST
//      IMPACT (Batch 2 pen-tester review §4 #3).
//
//   2. Encoding-based corruption: a CDN that serves Brotli to a client that
//      doesn't decompress = garbled bytes piped to sh. Cloudflare Workers
//      auto-negotiate Brotli on the edge; the Worker contract must be that
//      decoded bodies are byte-identical regardless of `Accept-Encoding`
//      (gzip, br, identity, *).
//
//   3. Echo-defence size cap: a 10 MB User-Agent (or any other unbounded
//      input) MUST NOT inflate the response. Response is bounded < 50 KB
//      regardless of input size — anything bigger is a sign the Worker is
//      reflecting input into the body (Q-03 from the threat model, asserted
//      here from the size angle).
//
//   4. Response size ceiling: install.sh is ~12 KB. A response > 100 KB is
//      either corruption or template injection (attacker-supplied data
//      concatenated to the script).
//
// Note on the gap-6 test that already lives in `methods.test.ts`: that file
// covers `Range: bytes=0-100` end-to-end (200 + > 1KB body). This file
// extends with the four other RFC 9110 §14.2 range forms — open-ended
// suffix, suffix-length, invalid range, and a multi-range — that exercise
// distinct parser branches.
//
// Pre-implementation, the stub returns HTTP 500 — every assertion fails.
// Tests assert positive contracts; preconditions are unconditional.

const CURL_UA = "curl/8.4.0";

describe("Range request variants on install path always return full body (R-01)", () => {
  // R-01: every flavour of Range header must be ignored on the install
  // endpoint. We exhaustively cover RFC 9110 §14.2 syntaxes:
  //   - bytes=0- (open-ended suffix)
  //   - bytes=-100 (suffix length)
  //   - bytes=100-50 (invalid: end < start)
  //   - bytes=0-10,20-30 (multi-range)
  //   - bytes=999999999-999999999 (out of range)
  //
  // Any 206 response = silent partial install. Any 416 = curl|sh fails
  // hard (acceptable). Any 200 with full body = the safe contract.
  //
  // We pin status to 200 specifically — the pen-tester recommendation is
  // "ignore Range, always 200 full body" rather than "416 Range Not
  // Satisfiable" — because some `curl -r` invocations would treat 416 as
  // a transient error and retry without -r, yielding the script anyway,
  // but a 416 in a script with `set -e` would just abort. 200 is least
  // surprising.
  const ranges = [
    "bytes=0-",
    "bytes=-100",
    "bytes=100-50",
    "bytes=0-10,20-30",
    "bytes=999999999-999999999",
  ];

  for (const range of ranges) {
    it(`Range: ${range} → 200 (full body), never 206`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, range },
      });
      // Headline contract: status is 200, body is full script.
      expect(res.status).toBe(200);
      expect(res.status).not.toBe(206);
      const body = await res.text();
      // Length floor — the canonical script is ~12 KB. Anything < 1 KB
      // means Range was honored as truncation.
      expect(body.length).toBeGreaterThan(1000);
    });

    it(`Range: ${range} → response has no Content-Range header (would imply 206 semantics)`, async () => {
      // RFC 9110 §14.4: Content-Range is the 206 partner. Presence of it on
      // a 200 response is a semantics violation AND a sign that some
      // intermediate cache may decide to truncate.
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, range },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-range")).toBeNull();
    });
  }
});

describe("Accept-Encoding negotiation does not corrupt bytes (R-01 / Batch 1 review §2)", () => {
  // Cloudflare Workers auto-negotiate Brotli + gzip on the edge. The
  // Worker contract: decoded body bytes are identical regardless of which
  // encoding the client requests. Tests cover gzip, br, identity, *,
  // and an empty Accept-Encoding (server's choice).
  const encodings: Array<{ label: string; value: string }> = [
    { label: "gzip", value: "gzip" },
    { label: "br (Brotli — Workers auto-negotiates)", value: "br" },
    { label: "identity", value: "identity" },
    { label: "wildcard *", value: "*" },
    { label: "gzip, br, identity (multi)", value: "gzip, br, identity" },
  ];

  for (const enc of encodings) {
    it(`Accept-Encoding: ${enc.label} → 200, body is recognisable install.sh`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": enc.value },
      });
      expect(res.status).toBe(200);
      // SELF.fetch decompresses transparently. The decoded body must be
      // the canonical script regardless of which encoding was negotiated.
      const body = await res.text();
      expect(body).toMatch(/^#!\/bin\/sh/);
      expect(body).toContain("Worthless installer");
    });
  }

  it("decoded bodies are byte-identical across gzip / br / identity", async () => {
    // The strongest contract: pick three different Accept-Encoding values,
    // assert decoded bodies are exactly equal byte-for-byte. A negotiation
    // bug (e.g., Worker serves the script through a templating step only
    // for one encoding) would surface here.
    const [gzipRes, brRes, idRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "gzip" },
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "br" },
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "identity" },
      }),
    ]);
    expect(gzipRes.status).toBe(200);
    expect(brRes.status).toBe(200);
    expect(idRes.status).toBe(200);
    const [gzipBody, brBody, idBody] = await Promise.all([
      gzipRes.text(),
      brRes.text(),
      idRes.text(),
    ]);
    expect(gzipBody).toBe(idBody);
    expect(brBody).toBe(idBody);
  });
});

describe("response size is bounded regardless of input size (R-02)", () => {
  // R-02: a 10 MB User-Agent must not inflate the response. The threat is
  // request-data echo into the body — even a single `\n${userAgent}\n`
  // appended to the script would let an attacker get arbitrary shell
  // execution by crafting a UA that contains shell. Defence is twofold:
  //   (a) Worker doesn't reflect input into the body at all (Q-03 covers
  //       this from the reflection angle).
  //   (b) Even if it did, response is hard-capped < 50 KB so the inflation
  //       is bounded.
  it("10 MB User-Agent → response body still under 50 KB", async () => {
    // 10 MB UA. Most workerd builds enforce a 32KB header limit, in which
    // case the Worker either receives a truncated UA (still safe) or 4xx
    // before reaching the handler (also safe). Either outcome must NOT
    // produce a > 50 KB response.
    const hugeUA = "curl/8.4.0 " + "A".repeat(10 * 1024 * 1024);
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": hugeUA },
    });
    // Unconditional precondition: response was processed (no socket reset).
    // Status can be 200 (UA truncated, classified as curl), 302 (UA
    // mangled, fail-safe), 4xx (header too large), or 5xx (genuine error).
    // Assert the size cap regardless.
    const body = await res.text();
    expect(body.length).toBeLessThan(50_000);
  });

  it("10 MB User-Agent → response body never echoes the inflated UA suffix", async () => {
    // Independent assertion: a 10 MB suffix would be detectable as a
    // long run of 'A' characters in the body. The body must not contain
    // even a 1 KB run of the sentinel.
    const hugeUA = "curl/8.4.0 " + "A".repeat(10 * 1024 * 1024);
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": hugeUA },
    });
    const body = await res.text();
    expect(body).not.toMatch(/A{1024}/);
  });

  it("UA with sentinel marker is not echoed to body even truncated (pen-tester gap)", async () => {
    // Per pen-tester Batch-3 review: the `A{1024}` regex above catches a
    // long UA echo, but a Worker that truncates its echo to 49 KB would
    // pass that check while still leaking attacker bytes. Use a unique
    // marker token. If even ONE copy of "ZZSENTINEL" appears in the body,
    // the Worker is reflecting input — even a 10-byte echo fails this.
    // Use 30 KB UA (under workerd's 32 KB header line limit per
    // javascript-pro Batch-3 review) so the request actually reaches the
    // handler rather than being rejected at transport.
    const sentinel = "ZZSENTINEL_8847_" + "B".repeat(64);
    const ua = "curl/8.4.0 " + sentinel + " " + "A".repeat(30 * 1024);
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": ua },
    });
    const body = await res.text();
    expect(body).not.toContain("ZZSENTINEL_8847_");
    // And no header echo either — same class.
    for (const [, value] of res.headers) {
      expect(value).not.toContain("ZZSENTINEL_8847_");
    }
  });
});

describe("response size is bounded by the canonical-script ceiling (R-03)", () => {
  // R-03: install.sh is ~12 KB. A 100 KB response is 8× expected — that's
  // either corruption (CDN cached two copies concatenated), template
  // injection (attacker bytes appended), or a deploy-pipeline regression
  // (e.g., the Worker now serves install.sh + install.sh.bak by accident).
  it("install-script response body length is under 100 KB", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body.length).toBeLessThan(100_000);
  });

  it("install-script response Content-Length header is under 100 KB", async () => {
    // Defence in depth: even if the body is truncated by undici buffering,
    // the declared Content-Length must also be sane.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const cl = res.headers.get("content-length");
    expect(cl).not.toBeNull();
    const declared = Number(cl);
    expect(Number.isFinite(declared)).toBe(true);
    expect(declared).toBeLessThan(100_000);
  });

  it("walkthrough response body length is also bounded (under 50 KB)", async () => {
    // Walkthrough is human-readable text, expected ~2-5 KB. 50 KB is
    // generous — anything bigger means a templating bug or appended bytes.
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body.length).toBeLessThan(50_000);
  });
});

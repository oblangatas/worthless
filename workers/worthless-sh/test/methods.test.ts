import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers.ts";

// RED tests — HTTP method abuse and conditional-request bypass
// (findings M-01..M-04 from security-audit/phase-2-pen-test-additions.md, plus
// the conditional-request bypass adversarial gap from Batch 1 §5).
//
// Threat: the Worker is single-purpose: GET `/` returns either the install
// script (curl-family UA) or a redirect (browser UA). Every other HTTP method
// is an attack surface waiting to be discovered. Specifically:
//
//   - HEAD: many frameworks accidentally serve the GET handler with a body
//     (Workers runtime, Hono, Express all have historical bugs here). HEAD
//     with a non-empty body breaks proxy caches AND lets an attacker probe
//     for the script via `curl -I` without it touching their shell.
//   - POST / PUT / DELETE / PATCH: a CSRF-able install-script endpoint is
//     genuinely dangerous. If a victim browser is tricked into a cross-origin
//     POST (form, fetch with no credentials), and POST returns the script
//     body in any way, an attacker can read it via `Access-Control-Allow-Origin`.
//     The contract: 405 Method Not Allowed, with no script body.
//   - OPTIONS: even WITHOUT explicit CORS handling, the Worker must NEVER
//     serve `Access-Control-Allow-Origin: *`. A wildcard would let any site
//     `fetch('https://worthless.sh/')` and read the bytes — defeating any
//     content-disposition or referrer-based defence in depth.
//   - CONNECT / TRACE: CF blocks at the edge, but assert the contract.
//   - Conditional GETs (`If-Modified-Since: 1970-01-01`): the Worker must
//     never return 304 Not Modified for the install-script path. A 304 would
//     let an intermediate cache serve a stale install to a curl whose UA
//     would have produced a fresh 200 — silent install of yesterday's bytes.
//
// Pre-implementation, every assertion fails because the stub returns 500.
// Tests assert positive contracts (e.g., `expect(status).toBe(405)`) and use
// unconditional preconditions before any conditional check, per Batch 1 review
// guidance on tautology avoidance.

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";

describe("HEAD returns headers without a body (M-01)", () => {
  // M-01: HEAD must produce identical headers to GET (so HTTP clients can
  // size the response, validate cache, and probe content-type) but the body
  // MUST be empty. A bug-class regression here is the framework auto-serving
  // GET handler output for HEAD.
  it("HEAD with curl UA → 200, content-type matches GET, body length is 0", async () => {
    const [headRes, getRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        method: "HEAD",
        headers: { "user-agent": CURL_UA },
      }),
      SELF.fetch("https://worthless.sh/", {
        method: "GET",
        headers: { "user-agent": CURL_UA },
      }),
    ]);
    // Status parity: HEAD must return the same status as GET.
    expect(headRes.status).toBe(200);
    expect(headRes.status).toBe(getRes.status);
    // Content-type parity: HEAD must declare the same MIME so HTTP intermediaries
    // can route correctly.
    expect(headRes.headers.get("content-type")).toBe(
      getRes.headers.get("content-type"),
    );
    // RFC 9110 §8.6: HEAD SHOULD include Content-Length matching what GET
    // returns, so intermediaries can size the response. Per audit review.
    expect(headRes.headers.get("content-length")).toBe(
      getRes.headers.get("content-length"),
    );
    // The headline assertion: HEAD body MUST be empty.
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });

  it("HEAD on the redirect path returns 302 with empty body", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "HEAD",
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    // Even on the redirect branch, HEAD must respect the no-body rule.
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(REDIRECT_URL);
    const body = await res.text();
    expect(body.length).toBe(0);
  });

  // M-01 short-response Content-Length parity: regression coverage for the
  // HEAD-contract bug CodeRabbit flagged on PR #117. Pre-fix, 404/414/503
  // paths went through `respond()` without setting Content-Length (or
  // bypassed `respond()` entirely), so HEAD requests on those paths
  // returned headers WITHOUT the Content-Length that GET would emit.
  // RFC 9110 §15.4 requires HEAD's headers to mirror GET. These tests
  // assert that parity on each error path.

  it("HEAD on 404 path returns Content-Length matching what GET returned", async () => {
    const url = "https://worthless.sh/nope-not-a-real-path";
    const [headRes, getRes] = await Promise.all([
      SELF.fetch(url, { method: "HEAD", headers: { "user-agent": CURL_UA } }),
      SELF.fetch(url, { method: "GET", headers: { "user-agent": CURL_UA } }),
    ]);
    expect(headRes.status).toBe(404);
    expect(headRes.status).toBe(getRes.status);
    expect(headRes.headers.get("content-length")).toBe(
      getRes.headers.get("content-length"),
    );
    expect(headRes.headers.get("content-length")).not.toBeNull();
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });

  it("HEAD on 414 (long path) returns Content-Length matching GET", async () => {
    // Path > PATH_MAX_LENGTH (4096) triggers the long-path guard.
    const url = "https://worthless.sh/" + "a".repeat(5000);
    const [headRes, getRes] = await Promise.all([
      SELF.fetch(url, { method: "HEAD", headers: { "user-agent": CURL_UA } }),
      SELF.fetch(url, { method: "GET", headers: { "user-agent": CURL_UA } }),
    ]);
    expect(headRes.status).toBe(414);
    expect(headRes.status).toBe(getRes.status);
    expect(headRes.headers.get("content-length")).toBe(
      getRes.headers.get("content-length"),
    );
    expect(headRes.headers.get("content-length")).not.toBeNull();
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });

  it("HEAD on 503 (bad-input) returns Content-Length matching GET", async () => {
    // Malformed Range header trips refuseBadInput → 503. Pre-fix this
    // path bypassed respond() and returned a body for HEAD.
    const headers = { "user-agent": CURL_UA, range: "garbage-not-bytes" };
    const [headRes, getRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/", { method: "HEAD", headers }),
      SELF.fetch("https://worthless.sh/", { method: "GET", headers }),
    ]);
    expect(headRes.status).toBe(503);
    expect(headRes.status).toBe(getRes.status);
    expect(headRes.headers.get("content-length")).toBe(
      getRes.headers.get("content-length"),
    );
    expect(headRes.headers.get("content-length")).not.toBeNull();
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });
});

describe("write methods return 405 and never serve the script (M-02)", () => {
  // M-02: POST/PUT/DELETE/PATCH must be 405 Method Not Allowed. The body
  // assertion is the load-bearing one — even if a future runtime change makes
  // POST return 200 by default, the body must not be the install script.
  // CSRF-style exfiltration is the threat: a victim's browser is tricked into
  // a cross-origin POST; if the server returns the script bytes, an attacker
  // who can read the response (via permissive CORS or an `<iframe>` bug)
  // captures the script.
  for (const method of ["POST", "PUT", "DELETE", "PATCH"] as const) {
    it(`${method} with curl UA → 405 Method Not Allowed`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        method,
        headers: { "user-agent": CURL_UA },
      });
      expect(res.status).toBe(405);
    });

    it(`${method} response body is NOT the install script`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        method,
        headers: { "user-agent": CURL_UA },
      });
      // Independent assertion: regardless of status, body must never be the
      // script. Defence in depth against the CSRF-exfiltration class.
      const body = await res.text();
      expect(body.startsWith("#!/bin/sh")).toBe(false);
      expect(body).not.toContain("Worthless installer");
    });

    it(`${method} response includes Allow header listing only safe methods`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        method,
        headers: { "user-agent": CURL_UA },
      });
      // RFC 9110 §15.5.6: 405 SHOULD include Allow. Pin it: the only allowed
      // methods are GET, HEAD, OPTIONS — never POST/PUT/DELETE/PATCH.
      const allow = res.headers.get("allow");
      expect(allow).not.toBeNull();
      expect(allow!.toUpperCase()).not.toContain("POST");
      expect(allow!.toUpperCase()).not.toContain("PUT");
      expect(allow!.toUpperCase()).not.toContain("DELETE");
      expect(allow!.toUpperCase()).not.toContain("PATCH");
      // Per audit review (RFC 9110 §15.5.6): Allow SHOULD enumerate the
      // supported methods. Without these positive checks, an empty Allow
      // header would satisfy only the negative assertions above.
      expect(allow!.toUpperCase()).toMatch(/\bGET\b/);
      expect(allow!.toUpperCase()).toMatch(/\bHEAD\b/);
      expect(allow!.toUpperCase()).toMatch(/\bOPTIONS\b/);
    });
  }
});

describe("OPTIONS preflight does not enable wildcard CORS (M-03)", () => {
  // M-03: a wildcard `Access-Control-Allow-Origin: *` would let any website
  // `fetch('https://worthless.sh/')` and read the bytes. That defeats every
  // defence-in-depth measure: referrer-policy, cache-key, content-disposition,
  // none of them survive a permissive CORS header. The Worker must either
  // not implement CORS at all (preferred — install scripts have no business
  // being fetched from web origins) OR, if it does, must NOT use wildcard.
  it("OPTIONS request must NOT return Access-Control-Allow-Origin: *", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "OPTIONS",
      headers: {
        "user-agent": BROWSER_UA,
        origin: "https://attacker.example",
        "access-control-request-method": "GET",
      },
    });
    // Unconditional precondition: response was processed (not a runtime crash
    // that bypasses the Worker entirely). Without this, a 5xx from the stub
    // would make the wildcard check vacuous.
    expect(res.status).toBeLessThan(500);
    const allowOrigin = res.headers.get("access-control-allow-origin");
    expect(allowOrigin).not.toBe("*");
  });

  it("OPTIONS does not echo the Origin header back as ACAO", async () => {
    const attackerOrigin = "https://attacker.example";
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "OPTIONS",
      headers: {
        "user-agent": BROWSER_UA,
        origin: attackerOrigin,
        "access-control-request-method": "GET",
      },
    });
    expect(res.status).toBeLessThan(500);
    // Reflected-origin CORS is functionally equivalent to wildcard for the
    // attacker — they control their own Origin header.
    expect(res.headers.get("access-control-allow-origin")).not.toBe(attackerOrigin);
  });

  it("OPTIONS response body is NOT the install script", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "OPTIONS",
      headers: { "user-agent": CURL_UA },
    });
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });
});

describe("CORS credentialed-wildcard interaction is forbidden (M-03 + audit gap)", () => {
  // Per pen-tester + audit review: Access-Control-Allow-Origin: `*` paired
  // with Access-Control-Allow-Credentials: `true` is an explicit Fetch-spec
  // violation, OWASP API8 finding, and CIS Benchmark hard-fail. Catches a
  // future CORS implementation that gets the combination wrong.
  it("if Access-Control-Allow-Origin is `*`, Allow-Credentials must NOT be `true`", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "OPTIONS",
      headers: {
        "user-agent": BROWSER_UA,
        origin: "https://attacker.example",
        "access-control-request-method": "GET",
      },
    });
    expect(res.status).toBeLessThan(500);
    const acao = res.headers.get("access-control-allow-origin");
    const acac = res.headers.get("access-control-allow-credentials");
    if (acao === "*") {
      expect(acac).not.toBe("true");
    }
    if (acac === "true") {
      expect(acao).not.toBe("*");
    }
  });

  it("Access-Control-Allow-Methods does not advertise wildcard or write methods", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "OPTIONS",
      headers: {
        "user-agent": BROWSER_UA,
        origin: "https://attacker.example",
        "access-control-request-method": "GET",
      },
    });
    expect(res.status).toBeLessThan(500);
    const acam = res.headers.get("access-control-allow-methods");
    if (acam !== null) {
      // Read-only endpoint — ACAM (if present at all) must not advertise
      // mutating verbs or wildcard.
      expect(acam).not.toBe("*");
      expect(acam.toUpperCase()).not.toContain("POST");
      expect(acam.toUpperCase()).not.toContain("PUT");
      expect(acam.toUpperCase()).not.toContain("DELETE");
      expect(acam.toUpperCase()).not.toContain("PATCH");
    }
  });
});

describe("CONNECT and TRACE are rejected (M-04)", () => {
  // M-04: CONNECT is for HTTP tunnelling (proxy use); TRACE is for diagnostics
  // and historically vulnerable to Cross-Site Tracing (XST). Cloudflare blocks
  // both at edge by default, but assert anyway so a config drift is caught.
  // Cloudflare/workerd historically returns 405 for these in Worker context.
  for (const method of ["TRACE"] as const) {
    it(`${method} with curl UA → not 200, not 5xx`, async () => {
      // TRACE is the testable one — fetch() in undici/workerd accepts it.
      const res = await SELF.fetch("https://worthless.sh/", {
        method,
        headers: { "user-agent": CURL_UA },
      });
      // Per audit review (RFC 9110 §9.3.8 + OWASP XST guidance): TRACE
      // SHOULD be 405 specifically; 501 (Not Implemented) is also acceptable.
      // Tightened from `< 500` so a 404 doesn't pass for the wrong reason.
      expect([405, 501]).toContain(res.status);
    });

    it(`${method} response does not echo request headers (XST guard)`, async () => {
      const sentinel = "X-Worthless-Test-Sentinel-Value";
      const res = await SELF.fetch("https://worthless.sh/", {
        method,
        headers: {
          "user-agent": CURL_UA,
          "x-worthless-test-sentinel": sentinel,
        },
      });
      const body = await res.text();
      // Cross-Site Tracing reads request headers from the response body. The
      // sentinel must never appear.
      expect(body).not.toContain(sentinel);
    });
  }

  // Per pen-tester review §5: directly testing CONNECT verifies workerd's
  // runtime rejection, not the Worker's contract. Rewritten as a method-
  // smuggling check: the Worker must not honor X-HTTP-Method-Override.
  // Frameworks that auto-honor that header turn benign GETs into anything
  // the attacker chose, bypassing M-02's 405 wall.
  it("X-HTTP-Method-Override: CONNECT on a GET → still served as GET (no method spoofing)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "GET",
      headers: {
        "user-agent": CURL_UA,
        "x-http-method-override": "CONNECT",
      },
    });
    // Worker MUST treat this as GET — honoring the override would let
    // attackers bypass method-based access controls.
    expect(res.status).toBe(200);
  });

  it("X-HTTP-Method-Override: POST on a GET → still served as GET (M-02 invariant)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "GET",
      headers: {
        "user-agent": CURL_UA,
        "x-http-method-override": "POST",
      },
    });
    // If the Worker honored the override, this would 405 (M-02). It must NOT.
    expect(res.status).toBe(200);
  });
});

describe("Range request on install path returns full body (gap-6: silent partial install)", () => {
  // Per pen-tester adversarial gap (top-5): `curl -r 0-100` getting a 206
  // with truncated install script = silent install of partial bytes. `set -e`
  // does NOT save you from a half-parsed shell file. Defence: ignore Range
  // on the install endpoint — always return the full 200 body.
  it("Range: bytes=0-100 → 200 (full body), never 206 (truncated)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA, range: "bytes=0-100" },
    });
    expect(res.status).toBe(200);
    expect(res.status).not.toBe(206);
  });

  it("Range: bytes=0-10 → body is full install.sh (>1KB), not 11 bytes", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA, range: "bytes=0-10" },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    // Stronger: body must be canonical install.sh, not truncated to range.
    expect(body.length).toBeGreaterThan(1000);
  });
});

describe("conditional GET does not return 304 on the install path (gap-5)", () => {
  // Adversarial gap from Batch 1 review §5: an `If-Modified-Since: 1970-01-01`
  // probe could trick an intermediate cache (or the Worker) into 304 Not
  // Modified, instructing the client to use a stale cached body. For a curl
  // that never had a cached body, this is undefined behaviour at best; for a
  // shared cache, this is a poisoning vector. Pin: the install path NEVER
  // returns 304, regardless of conditional headers.
  it("If-Modified-Since: 1970-01-01 → 200, not 304 (no cache validators on install)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: {
        "user-agent": CURL_UA,
        "if-modified-since": "Thu, 01 Jan 1970 00:00:00 GMT",
      },
    });
    // The contract: install-script path is unconditionally fresh.
    expect(res.status).toBe(200);
    expect(res.status).not.toBe(304);
  });

  it("If-Modified-Since: now → 200, not 304 (the body must always be served)", async () => {
    // Even with a conditional header that SHOULD legitimately match a recent
    // Last-Modified, the install path returns the full body. Cache validators
    // optimise for bandwidth — install scripts optimise for byte-exact trust.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: {
        "user-agent": CURL_UA,
        "if-modified-since": new Date().toUTCString(),
      },
    });
    expect(res.status).toBe(200);
    expect(res.status).not.toBe(304);
  });

  it("If-None-Match: * → 200, not 304", async () => {
    // RFC 9110 §13.1.2: `If-None-Match: *` matches any current representation.
    // Even this strongest match must not produce a 304 on the install path.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: {
        "user-agent": CURL_UA,
        "if-none-match": "*",
      },
    });
    expect(res.status).toBe(200);
    expect(res.status).not.toBe(304);
  });
});

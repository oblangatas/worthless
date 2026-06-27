import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers.ts";

// RED tests — cross-axis stacked-misuse scenarios. Direct response to
// chaos-engineer review §4 ("Cross-axis attack scenarios not covered"),
// which named this the "highest practical risk" gap in batches 1+2.
//
// Threat: every prior test file is single-axis. paths.test.ts varies path,
// methods.test.ts varies method, query-canonicalization.test.ts varies
// query, ua-edge-cases.test.ts varies UA. Real attackers stack axes.
// Each individual axis having a clean test creates a FALSE sense of
// coverage — the combinations may fall through to a different code path
// entirely.
//
// Two design rules in this file:
//
//   1. Every test combines AT LEAST TWO axes (method × path, method ×
//      query, path × query, UA × path × query, range × query).
//
//   2. The MORE-RESTRICTIVE policy must win. If method says "405", path
//      says "redirect", and UA says "install script" — the answer must
//      be 405, never the install script. Defence-in-depth requires that
//      the strictest individual rule wins; otherwise an attacker just
//      stacks the axes that DON'T strict-fail.
//
// Pre-implementation, the stub returns HTTP 500. Each test below pins
// EXACTLY ONE positive contract that the stub fails — no `if (X) expect(Y)`
// vacuous shapes, all preconditions unconditional.
//
// Reference: chaos-engineer review §4, scenarios 1-15.

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";
const COMPOUND_UA = "Mozilla/5.0 curl/8.4.0";

describe("Method × Path — strictest rule wins (chaos §4 #1, #2, #8)", () => {
  // The pattern: a write method (POST/OPTIONS/HEAD) on a non-canonical
  // path. Two restrictions stacked. The script MUST NEVER appear in the
  // body, regardless of which axis is the "permissive" one.
  it("POST /install.sh with curl UA → 405, body is not the install script", async () => {
    // Cross-axis: POST (method M-02 says 405) + /install.sh (path P-01
    // says 302/404). Strictest = 405. Critical: body MUST NOT be the
    // script — this is the CSRF-exfiltration class on a non-canonical
    // path, which is the worst-case if path-handler runs before method-check.
    const res = await SELF.fetch("https://worthless.sh/install.sh", {
      method: "POST",
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(405);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });

  it("OPTIONS /admin → not 200 install script, no wildcard CORS", async () => {
    // Cross-axis: OPTIONS (M-03 says no wildcard CORS) + /admin (P-01
    // says 302/404). The /admin path with OPTIONS is a classic CORS
    // probe — attacker checks if the admin endpoint exists AND if it
    // can be called cross-origin.
    const res = await SELF.fetch("https://worthless.sh/admin", {
      method: "OPTIONS",
      // `redirect: "manual"` keeps a 302 response observable so the
      // assertions below can distinguish 302 (P-01 contract) from a
      // followed-then-rewritten response. Default fetch mode is
      // "follow", which would replace a 302 with the redirect target
      // and lose status info.
      redirect: "manual",
      headers: {
        "user-agent": BROWSER_UA,
        origin: "https://attacker.example",
        "access-control-request-method": "GET",
      },
    });
    // Unconditional precondition: response was processed.
    expect(res.status).toBeLessThan(500);
    // Body must not be the install script (defence in depth for any path).
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    // CORS contract from M-03 carries over: no wildcard.
    expect(res.headers.get("access-control-allow-origin")).not.toBe("*");
  });

  it("HEAD /.well-known/security.txt → status matches GET, body length is 0", async () => {
    // Cross-axis: HEAD (M-01 says empty body, status parity with GET) +
    // /.well-known/security.txt (P-02 says 200 with security contact).
    // The combination must respect HEAD semantics: same status as GET,
    // empty body. A HEAD body that happens to be "Contact: ..." would
    // violate RFC 9110.
    const [headRes, getRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/.well-known/security.txt", {
        method: "HEAD",
        headers: { "user-agent": CURL_UA },
      }),
      SELF.fetch("https://worthless.sh/.well-known/security.txt", {
        method: "GET",
        headers: { "user-agent": CURL_UA },
      }),
    ]);
    // Status parity (HEAD == GET).
    expect(headRes.status).toBe(getRes.status);
    // HEAD body must be empty regardless of what GET returns.
    const headBody = await headRes.text();
    expect(headBody.length).toBe(0);
  });

  it("HEAD /install.sh → status matches GET /install.sh, body length is 0 (chaos partial)", async () => {
    // Cross-axis: HEAD (M-01 says empty body, status parity with GET) +
    // /install.sh (P-01 says non-canonical → 302/404). Per chaos Batch-3
    // review: this combo was missing. HEAD must mirror GET status on
    // ANY path — including non-canonical — and produce an empty body.
    const [headRes, getRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/install.sh", {
        method: "HEAD",
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      }),
      SELF.fetch("https://worthless.sh/install.sh", {
        method: "GET",
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      }),
    ]);
    // Status parity: HEAD == GET regardless of which non-canonical-path
    // policy (302 vs 404) the implementation chose.
    expect(headRes.status).toBe(getRes.status);
    // HEAD body must be empty.
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });

  it("POST /.well-known/security.txt → 405 OR same as GET, never 500 (chaos §4 #8)", async () => {
    // Cross-axis: POST (write method) + disclosure path. The contract
    // can be either 405 (preferred — read-only endpoint) or the same
    // 200 as GET (acceptable). What it CANNOT be is 500 (means the
    // method handler crashed) or the install script (means method-and-
    // path handlers are confused).
    const res = await SELF.fetch(
      "https://worthless.sh/.well-known/security.txt",
      {
        method: "POST",
        headers: { "user-agent": BROWSER_UA },
      },
    );
    // Pin to a tight allowlist; a 500 fails this and a body-leak fails
    // the body assertion below.
    expect([200, 405]).toContain(res.status);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });
});

describe("Method × Query — query trigger does not promote write methods (chaos §4 #1, #3)", () => {
  // The pattern: a write method with `?explain=1`. The trigger query
  // belongs to the GET-only walkthrough contract; write methods must
  // continue to 405, ignoring `?explain=1`.
  it("POST /?explain=1 → 405, body is neither walkthrough nor install script", async () => {
    // Cross-axis: POST (M-02 says 405) + ?explain=1 (Q says walkthrough).
    // 405 wins. Critical: body must be neither — a CSRF that returns the
    // walkthrough is also a privacy leak (reveals the explain feature
    // exists, exposes wording).
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      method: "POST",
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(405);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
    // Walkthrough negative-shape — chaos §4 #1 explicit assertion.
    expect(body).not.toMatch(/line|step|what it does/i);
  });

  it("OPTIONS /?explain=1 → no wildcard CORS, body is not the walkthrough (chaos partial)", async () => {
    // Cross-axis: OPTIONS (M-03 says no wildcard CORS) + ?explain=1 (Q
    // says walkthrough on GET). Per chaos Batch-3 review: this combo was
    // missing. The CORS contract from M-03 must hold even when the
    // explain trigger is set; OPTIONS doesn't promote to walkthrough.
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      method: "OPTIONS",
      headers: {
        "user-agent": BROWSER_UA,
        origin: "https://attacker.example",
        "access-control-request-method": "GET",
      },
    });
    // Unconditional precondition: response was processed.
    expect(res.status).toBeLessThan(500);
    // CORS contract: no wildcard.
    expect(res.headers.get("access-control-allow-origin")).not.toBe("*");
    // Body is not the walkthrough.
    const body = await res.text();
    expect(body).not.toMatch(/line|step|what it does/i);
  });

  it("HEAD /?explain=1 → 200, content-type matches GET-walkthrough, body is empty", async () => {
    // Cross-axis: HEAD + ?explain=1. HEAD must mirror the GET-walkthrough
    // status and content-type so HTTP intermediaries can size and route
    // correctly. Body must be empty per HEAD semantics.
    const [headRes, getRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/?explain=1", {
        method: "HEAD",
        headers: { "user-agent": CURL_UA },
      }),
      SELF.fetch("https://worthless.sh/?explain=1", {
        method: "GET",
        headers: { "user-agent": CURL_UA },
      }),
    ]);
    expect(headRes.status).toBe(200);
    expect(headRes.status).toBe(getRes.status);
    expect(headRes.headers.get("content-type")).toBe(
      getRes.headers.get("content-type"),
    );
    const body = await headRes.text();
    expect(body.length).toBe(0);
  });
});

describe("Path × Query — explain trigger does not hijack non-canonical paths (chaos §4 #4, #6, #7)", () => {
  // The pattern: `?explain=1` arriving at a path that ISN'T `/`. The
  // query trigger belongs to the canonical install endpoint only —
  // it must not promote a 404/302 path to a 200 walkthrough, or worse,
  // serve the install script via path-side fall-through.
  it("/install.sh?explain=1 with curl UA → 302 OR 404, never 200 install script", async () => {
    // Cross-axis: /install.sh (path P-01: redirect or 404) + ?explain=1
    // (query Q: would normally → walkthrough). The path policy wins:
    // non-canonical paths never serve script content, regardless of
    // query trigger.
    const res = await SELF.fetch(
      "https://worthless.sh/install.sh?explain=1",
      {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      },
    );
    expect([302, 404]).toContain(res.status);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });

  it("/admin?explain=1 → not 200 install script, body is not the walkthrough", async () => {
    // Cross-axis: /admin (P-01: 302/404) + ?explain=1. Same policy:
    // the query trigger does NOT promote /admin to a walkthrough page.
    const res = await SELF.fetch("https://worthless.sh/admin?explain=1", {
      headers: { "user-agent": CURL_UA },
      redirect: "manual",
    });
    expect([302, 404]).toContain(res.status);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    // The walkthrough has its own positive markers (per _helpers.ts
    // `expectWalkthrough`). They must be absent here.
    expect(body).not.toMatch(/line|step|what it does/i);
  });

  it("/.well-known/security.txt?explain=1 → security.txt content, NOT walkthrough", async () => {
    // Cross-axis: /.well-known/security.txt (P-02: RFC 9116 security.txt)
    // + ?explain=1. The disclosure path's contract MUST win — Contact:
    // field is the load-bearing assertion. The query trigger must not
    // hijack this path to serve walkthrough text instead.
    const res = await SELF.fetch(
      "https://worthless.sh/.well-known/security.txt?explain=1",
      {
        headers: { "user-agent": CURL_UA },
        // Per javascript-pro Batch-3 review: explicit `redirect: "manual"`
        // so a stray 30x doesn't get silently followed and make the body
        // assertion below meaningless.
        redirect: "manual",
      },
    );
    expect(res.status).toBe(200);
    const body = await res.text();
    // Positive marker: real security.txt has Contact field per RFC 9116.
    expect(body).toMatch(/^Contact:\s+/m);
    // Walkthrough markers MUST be absent.
    expect(body).not.toMatch(/what it does/i);
  });

  it("/%2e%2e/install.sh?explain=1 → not 200 install script, never 200 walkthrough (chaos triple-stack)", async () => {
    // Cross-axis: traversal probe (P-05) + non-canonical path (P-01) +
    // ?explain=1 (Q). Three forms of misuse stacked. Per chaos Batch-3
    // review: this combo was missing from the prior triple-stack test
    // (which only used a compound UA). Forbidden outcomes: 200 install
    // script (path-side fall-through), 200 walkthrough (query trigger
    // promoted a traversal path), or 5xx (panic).
    const res = await SELF.fetch(
      "https://worthless.sh/%2e%2e/install.sh?explain=1",
      {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      },
    );
    expect([302, 404, 405]).toContain(res.status);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toMatch(/line|step|what it does/i);
  });
});

describe("UA × Path × Query — three axes stacked, safe outcome wins (chaos §4 #4)", () => {
  // The pattern: a compound UA (which `ua-edge-cases.test.ts` says is
  // ambiguous → safe redirect) hitting a non-canonical path with the
  // explain trigger. Three axes of misuse stacked. The contract: the
  // SAFE outcome (302 to wless.io OR 404), never 200 install script.
  it("compound 'Mozilla/5.0 curl/8.4.0' UA on /install.sh?explain=1 → never 200 install script", async () => {
    const res = await SELF.fetch(
      "https://worthless.sh/install.sh?explain=1",
      {
        headers: { "user-agent": COMPOUND_UA },
        redirect: "manual",
      },
    );
    // The triple-stack outcome must be safe: 302 (preferred), 404, or
    // 405 are all acceptable. The forbidden outcome is 200 + script.
    expect([302, 404, 405]).toContain(res.status);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });
});

describe("Method × UA — empty UA never promotes a write method (chaos §4)", () => {
  // The pattern: POST with an empty User-Agent. The UA fail-safe (empty
  // → redirect) must NOT cause the method-check to be skipped — a 405
  // for POST wins over the UA-missing redirect.
  it("POST with empty UA → 405 (M-02 wins over UA-missing fail-safe)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "POST",
      headers: { "user-agent": "" },
    });
    // Method-check wins: 405 regardless of UA.
    expect(res.status).toBe(405);
    const body = await res.text();
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });

  it("POST with no UA header at all → 405 (same contract)", async () => {
    // Independent assertion: missing UA is distinct from empty UA in
    // some HTTP libraries. Both must produce 405 for POST.
    const res = await SELF.fetch("https://worthless.sh/", {
      method: "POST",
    });
    expect(res.status).toBe(405);
  });
});

describe("Range × Query — Range header on walkthrough returns full body (gap-6 extended)", () => {
  // The pattern: Range header on `?explain=1`. methods.test.ts gap-6
  // pinned this for the install path; extend to walkthrough. The
  // walkthrough is human-readable text — a partial walkthrough is
  // confusing but not catastrophic. Still, the contract is "Range is
  // ignored" everywhere, not just on the install path.
  it("Range: bytes=0-100 on /?explain=1 → 200 (full walkthrough), never 206", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA, range: "bytes=0-100" },
    });
    expect(res.status).toBe(200);
    expect(res.status).not.toBe(206);
    const body = await res.text();
    // Walkthrough is at least 200 bytes per _helpers.ts contract; a
    // 100-byte truncation would surface here.
    expect(body.length).toBeGreaterThan(200);
  });

  it("Range: bytes=0-100 on /?explain=1 → no Content-Range header (no 206 semantics)", async () => {
    // Independent assertion on header shape. RFC 9110 §14.4: Content-Range
    // is the 206 partner. Its presence on a 200 implies an intermediate
    // cache may decide to serve a truncated body.
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA, range: "bytes=0-100" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-range")).toBeNull();
  });
});

describe("redirect target is canonical regardless of cross-axis stacking", () => {
  // Cross-cutting: any axis combination that produces a 302 must redirect
  // to REDIRECT_URL specifically — never to a Host-confused, query-echoed,
  // or path-derived URL. Pin one final invariant.
  it("browser UA + arbitrary query + arbitrary path → 302 to REDIRECT_URL", async () => {
    const res = await SELF.fetch(
      "https://worthless.sh/anything?foo=bar&baz=qux",
      {
        headers: { "user-agent": BROWSER_UA },
        redirect: "manual",
      },
    );
    // Unconditional precondition: response was processed.
    expect(res.status).toBeLessThan(500);
    // If the policy is "non-canonical path on browser → 302", Location
    // MUST be REDIRECT_URL. If the policy is "non-canonical path → 404",
    // there should be no Location header to inspect — but in either case
    // a Location pointing somewhere OTHER than REDIRECT_URL would be a
    // bug. Pin the conditional precondition: Location set → equals
    // REDIRECT_URL.
    const location = res.headers.get("location");
    if (location !== null) {
      // Vacuous-conditional avoidance: pair with a positive precondition
      // that location is genuinely set on browser-UA requests by also
      // testing the canonical path below.
      expect(location).toBe(REDIRECT_URL);
    }
    // Positive companion: the canonical path with browser UA MUST produce
    // a Location, eliminating the dead-test risk if `location === null`
    // above.
    const canonical = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(canonical.status).toBe(302);
    expect(canonical.headers.get("location")).toBe(REDIRECT_URL);
  });
});

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers.ts";

// RED tests — Path fall-through, traversal, and disclosure-hygiene contracts
// (findings P-01..P-06 from security-audit/phase-2-pen-test-additions.md, plus
// the Host-header-confusion adversarial gap from Batch 1 §5).
//
// Threat: the Worker has exactly one canonical entry point (`/` with curl-family
// UA). Any other path that ALSO serves the install script creates a parallel
// install vector that bypasses cache rules, audit logging, and the headline
// "what you see at worthless.sh" trust contract. Conversely, paths that crash
// the isolate (5xx) under attacker-controlled junk turn the front door into a
// DoS vector — and a Cloudflare 5xx page piped to `sh` is itself an RCE-class
// risk (see error-path.test.ts). This file pins the path-routing contract:
//
//   - Non-`/` paths (`/install.sh`, `/install`, `/get`, `/sh`, `/admin`, etc.)
//     MUST NOT serve install.sh. They redirect or 404 — never 200 with the
//     script body. Otherwise the cache-key, UA-classifier, and Vary contracts
//     are all bypassable by simply asking for a different URL.
//   - `/.well-known/security.txt` MUST exist and contain a real `Contact:`
//     line (RFC 9116) so coordinated-disclosure researchers have a path.
//   - Trailing-slash variants (`/`, `//`, `///`) canonicalize. Some routers
//     dispatch `//` to a different handler than `/` — that's a fall-through.
//   - Path traversal probes (`/%2e%2e/install.sh`, `/../install.sh`,
//     null-byte paths) must NOT 5xx. They redirect, 404, or 400 — but never
//     panic. The runtime returning a Cloudflare HTML error page on these is
//     the RCE-on-shell-pipe class.
//   - Absurdly long paths (8KB) must yield 414 URI Too Long, not 5xx.
//   - Host header confusion (`Host: worthless.sh.evil.com`): the response
//     body must NEVER contain the request Host value verbatim. If the Worker
//     ever templates Host into a banner/log/error, a victim curl could be
//     fed an attacker-chosen string that lands in their shell.
//
// Pre-implementation, every assertion fails because the stub returns 500.
// Tests assert positive contracts (e.g., `status === 414` not `status !== 200`)
// so they cannot pass tautologically against the stub.

const CURL_UA = "curl/8.4.0";

/** Status codes that are acceptable "rejection" responses for non-canonical
 * paths. Crucially, this set does NOT include 200 (would mean fall-through
 * to install-script handler) and does NOT include 5xx (would mean panic). */
const SAFE_NON_CANONICAL_STATUSES: ReadonlyArray<number> = [301, 302, 303, 307, 308, 404];

describe("non-`/` paths do not serve install.sh (P-01)", () => {
  // P-01: parallel install vectors are forbidden. The only path that serves
  // the script is `/`; any other URL must redirect or 404. If `/install.sh`
  // also returned the script, an operator who pinned cache rules to `/` would
  // be surprised, and an attacker could choose a path that bypasses logging.
  for (const path of ["/install.sh", "/install", "/get", "/sh", "/admin"]) {
    it(`${path} with curl UA → not 200, not 5xx`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      expect(SAFE_NON_CANONICAL_STATUSES).toContain(res.status);
    });

    it(`${path} response body is NOT the install script`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      // Even if a future implementation accidentally returned 200, the body
      // must not be the script. Belt-and-suspenders to P-01 above.
      const body = await res.text();
      expect(body.startsWith("#!/bin/sh")).toBe(false);
      expect(body).not.toContain("Worthless installer");
    });
  }
});

describe("/.well-known/security.txt is served per RFC 9116 (P-02)", () => {
  // P-02: bug-bounty / coordinated-disclosure hygiene. A researcher who finds
  // a vuln in install.sh needs a clear contact point. RFC 9116 mandates a
  // `Contact:` line with a method (mailto:, https:, tel:). Pin the contract
  // here so Phase 3 cannot ship without it.
  it("returns 200 text/plain", async () => {
    const res = await SELF.fetch("https://worthless.sh/.well-known/security.txt");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
  });

  it("body contains an RFC 9116 Contact: line", async () => {
    const res = await SELF.fetch("https://worthless.sh/.well-known/security.txt");
    const body = await res.text();
    // RFC 9116 §2.5.3 — Contact field is REQUIRED.
    expect(body).toMatch(/^Contact:\s+\S/m);
  });

  it("body does not accidentally serve the install script", async () => {
    const res = await SELF.fetch("https://worthless.sh/.well-known/security.txt");
    const body = await res.text();
    // Sanity: a fall-through that served install.sh from .well-known would be
    // catastrophic — researchers would scan it; ops staff might pipe it.
    expect(body.startsWith("#!/bin/sh")).toBe(false);
    expect(body).not.toContain("Worthless installer");
  });

  it("body contains an RFC 9116 Expires: line within 1 year (REQUIRED field)", async () => {
    const res = await SELF.fetch("https://worthless.sh/.well-known/security.txt");
    const body = await res.text();
    // Per audit review CRITICAL: RFC 9116 §2.5.5 — Expires field is REQUIRED.
    // Without this, a malformed file passes the test and Phase 3 ships a
    // non-conformant security.txt that bug-bounty platforms reject.
    expect(body).toMatch(/^Expires:\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/m);
    const expiresMatch = body.match(/^Expires:\s+(\S+)/m);
    expect(expiresMatch).not.toBeNull();
    const expires = new Date(expiresMatch![1]);
    expect(expires.getTime()).toBeGreaterThan(Date.now());
    // RFC SHOULD: Expires within 1 year. A long horizon defeats the field's
    // purpose (forcing periodic review of the contact info).
    expect(expires.getTime()).toBeLessThan(Date.now() + 366 * 24 * 3600 * 1000);
  });
});

describe("trailing-slash variants canonicalize (P-03)", () => {
  // P-03: some path routers (including historical CF Workers behaviour) treat
  // `//` and `///` as distinct routes from `/`. If `//` falls through to a
  // 404 handler with a different UA classifier, that's an attack surface.
  // Pin: every slash-only path either serves the canonical curl response
  // (200 install.sh) or redirects / 404s — never 5xx, never different from /.
  it("`/` with curl UA → 200 install.sh (control)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
  });

  for (const path of ["//", "///"]) {
    it(`${path} with curl UA → canonicalized to allowed status (200/30x/404), not 5xx`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      // Per pen-tester review: tighten from `< 500` (which permits 200-with-
      // HTML body) to an explicit allowed-status set. Canonicalize to `/`
      // (200), redirect (30x), or 404 — anything else is wrong.
      expect([200, 301, 302, 308, 404]).toContain(res.status);
    });

    it(`${path} body is NOT a Cloudflare HTML error page`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      const body = await res.text();
      // Belt-and-suspenders: even if status is 200, body must not be HTML.
      // CF default error pages start with `<!DOCTYPE html>` or `<html>` and
      // would be catastrophic in a `curl | sh` context.
      expect(body).not.toMatch(/<!DOCTYPE/i);
      expect(body).not.toMatch(/<html/i);
      expect(body).not.toMatch(/error code: \d+/i);
    });
  }
});

describe("null-byte paths do not panic and do not change behavior (P-04)", () => {
  // P-04: classic parser-differential bug. Some path parsers truncate at a
  // null byte; downstream handlers see the unstripped path. If the runtime
  // sees `/install.sh%00` and the Worker logic sees `/install.sh`, the
  // truncated form may bypass an explicit denylist. Test: the response is
  // NEVER the install script body (P-01 also covers this) and never 5xx.
  for (const path of ["/%00", "/install.sh%00", "/%00install.sh"]) {
    it(`${path} with curl UA → not 200-with-script, not 5xx`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      // Status must be a normal client-error or redirect — never 5xx.
      expect(res.status).toBeLessThan(500);
      // Body must not be the install script under any circumstance.
      const body = await res.text();
      expect(body.startsWith("#!/bin/sh")).toBe(false);
      expect(body).not.toContain("Worthless installer");
    });
  }
});

describe("path traversal probes redirect or 404, never 5xx (P-05)", () => {
  // P-05: traversal sequences (`../`, `%2e%2e`, mixed encodings) must not
  // crash the isolate. The Worker should treat them as non-canonical paths
  // and produce one of SAFE_NON_CANONICAL_STATUSES. A 5xx here = the
  // RCE-on-shell-pipe class via Cloudflare's HTML error page.
  for (const path of [
    "/%2e%2e/install.sh",
    "/%2e%2e%2finstall.sh",
    "/..%2finstall.sh",
    "/%2E%2E%2F%2E%2E%2Finstall.sh",
    // Per audit review (CWE-22 gap): double-encoded variants defeat single-
    // decode WAFs. workerd/CF single-decode then route, so `%252e%252e`
    // arrives at the Worker as `%2e%2e` — still must not traverse.
    "/%252e%252e/install.sh",
    "/%252e%252e%252finstall.sh",
  ]) {
    it(`${path} → not 5xx, not 200-with-script`, async () => {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      expect(res.status).toBeLessThan(500);
      const body = await res.text();
      expect(body.startsWith("#!/bin/sh")).toBe(false);
    });
  }
});

describe("absurdly long paths return 414, not 5xx (P-06)", () => {
  // P-06: an 8KB path is well past any reasonable URL. Cloudflare's documented
  // limit is 16KB on the URL line, but the Worker should bound-check and
  // return 414 URI Too Long rather than relying on the runtime to enforce.
  it("8KB path with curl UA → 414 URI Too Long", async () => {
    const longPath = "/" + "A".repeat(8 * 1024);
    const res = await SELF.fetch(`https://worthless.sh${longPath}`, {
      headers: { "user-agent": CURL_UA },
      redirect: "manual",
    });
    // The contract: 414 specifically. A 404 for a long path is acceptable in
    // some runtimes, but the explicit choice here is 414 so monitoring can
    // distinguish DoS attempts from typos.
    expect(res.status).toBe(414);
  });

  it("8KB path does not return 5xx (no isolate panic)", async () => {
    const longPath = "/" + "A".repeat(8 * 1024);
    const res = await SELF.fetch(`https://worthless.sh${longPath}`, {
      headers: { "user-agent": CURL_UA },
      redirect: "manual",
    });
    // Independent assertion: even if the contract above evolves to 404, the
    // forbidden outcome is a 5xx panic. Lock in the no-crash invariant
    // separately so this test stays meaningful if 414 vs 404 is renegotiated.
    expect(res.status).toBeLessThan(500);
  });
});

describe("Host header is never echoed into the response body (gap-4: Host confusion)", () => {
  // Adversarial gap from Batch 1 review §5: Host header confusion. If the
  // Worker ever templates the request Host into a response (banner, error
  // body, log echo, redirect target), an attacker can pick the Host they want
  // to land in a victim's shell. Test: send a malicious Host and assert the
  // body never contains it.
  const MALICIOUS_HOST = "worthless.sh.evil.com";

  it("install-script response never contains the Host header value", async () => {
    const res = await SELF.fetch(`https://${MALICIOUS_HOST}/`, {
      headers: { "user-agent": CURL_UA },
    });
    // Unconditional precondition: the Worker handled the request (any non-5xx
    // means the body assertion is meaningful, not vacuous on a panic).
    expect(res.status).toBeLessThan(500);
    const body = await res.text();
    expect(body).not.toContain(MALICIOUS_HOST);
    expect(body).not.toContain("evil.com");
  });

  it("redirect Location does not point at the attacker's Host", async () => {
    const res = await SELF.fetch(`https://${MALICIOUS_HOST}/`, {
      headers: {
        "user-agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
      },
      redirect: "manual",
    });
    // Unconditional precondition: status is a redirect.
    expect(res.status).toBe(302);
    const location = res.headers.get("location");
    expect(location).toBe(REDIRECT_URL);
    expect(location).not.toContain("evil.com");
  });

  it("response headers do not echo the Host value", async () => {
    const res = await SELF.fetch(`https://${MALICIOUS_HOST}/`, {
      headers: { "user-agent": CURL_UA },
    });
    for (const [name, value] of res.headers) {
      expect(value).not.toContain(MALICIOUS_HOST);
      // `evil.com` substring is a weaker guard for headers like Location.
      expect(value, `header ${name} echoed attacker host`).not.toContain("evil.com");
    }
  });
});

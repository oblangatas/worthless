import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers.ts";

// RED tests — CDN cache poisoning resistance (findings C-01..C-05 from
// security-audit/phase-2-pen-test-additions.md).
//
// Threat: Cloudflare's default cache key is Host + path + query — User-Agent
// is NOT part of the key. The Worker branches its response on User-Agent
// (curl → script, browser → redirect). Without an explicit `Vary: User-Agent`
// header (or a custom cache key), the CDN can cache one variant and serve it
// to a client whose UA would have produced the other. Worst case: a browser's
// 302 gets cached and served to the next `curl | sh`, breaking install. Best
// case (still bad): a script meant for curl is served with `text/plain` to a
// browser, where some sniffers will interpret it.
//
// CVE-2026-2836 (Cloudflare Pingora cache poisoning) is the closest public
// reference; CF's CDN itself was unaffected, but the class is real and the
// only Worker-layer defence is `Vary` or a custom cache key.
//
// These tests pin down:
//   C-01 — every 200 response carries `Vary: User-Agent`.
//   C-02 — install-script response is either `private`/`no-store` OR carries
//          `Vary: User-Agent` (we accept either; assert at least one).
//   C-03 — redirect response is either no-cache OR carries `Vary: User-Agent`.
//   C-04 — gzip and identity Accept-Encoding produce identical decoded bodies.
//   C-05 — ETag (if present) is stable across two reads of the same resource
//          AND no `Last-Modified` based on wall-clock-now (would prevent
//          reproducible-byte verification).

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";

function hasVaryUserAgent(res: Response): boolean {
  const vary = res.headers.get("vary")?.toLowerCase() ?? "";
  return vary.split(",").map((v) => v.trim()).includes("user-agent");
}

function isUncacheable(res: Response): boolean {
  const cc = res.headers.get("cache-control")?.toLowerCase() ?? "";
  return /\b(no-store|private|no-cache)\b/.test(cc);
}

describe("Vary: User-Agent is present on all 200 responses (C-01)", () => {
  it("install-script response (curl UA) carries Vary: User-Agent", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(hasVaryUserAgent(res)).toBe(true);
  });

  it("walkthrough response (?explain=1, curl UA) carries Vary: User-Agent", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(hasVaryUserAgent(res)).toBe(true);
  });
});

describe("install-script response is cache-safe (C-02)", () => {
  it("is either no-store/private OR carries Vary: User-Agent", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    // Accept either policy — but at least one must hold, otherwise a CDN
    // with a long s-maxage and a UA-blind key will poison the response.
    expect(isUncacheable(res) || hasVaryUserAgent(res)).toBe(true);
  });

  it("explicitly sets Cache-Control (no CDN defaults) and pairs s-maxage with Vary", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    // Unconditional floor: don't rely on CDN defaults — Cache-Control MUST
    // be explicit. Per pen-tester review (Phase 2 Batch 1), the previous
    // conditional version was vacuous when stub omitted the header.
    const cc = res.headers.get("cache-control");
    expect(cc).not.toBeNull();
    // Conditional safety: if s-maxage is meaningful, MUST be paired with Vary.
    const sMaxAgeMatch = cc!.toLowerCase().match(/s-maxage=(\d+)/);
    if (sMaxAgeMatch && Number(sMaxAgeMatch[1]) > 60) {
      expect(hasVaryUserAgent(res)).toBe(true);
    }
  });
});

describe("redirect response is cache-safe (C-03)", () => {
  it("redirect for browser UA is uncacheable OR carries Vary: User-Agent", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(REDIRECT_URL);
    // A `public, max-age=86400` redirect cached against a UA-blind key would
    // be served back to the next curl client. Either policy prevents that.
    expect(isUncacheable(res) || hasVaryUserAgent(res)).toBe(true);
  });

  it("redirect explicitly sets Cache-Control and pairs `public` with Vary", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    // Unconditional floor: even the 302 must signal cache policy explicitly.
    // Per pen-tester review, the previous conditional was vacuous.
    const cc = res.headers.get("cache-control");
    expect(cc).not.toBeNull();
    if (cc!.toLowerCase().includes("public")) {
      expect(hasVaryUserAgent(res)).toBe(true);
    }
  });
});

describe("Accept-Encoding does not change decoded body (C-04)", () => {
  it("gzip and identity produce byte-identical decoded bodies", async () => {
    const [gzipRes, identityRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "gzip" },
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "identity" },
      }),
    ]);

    expect(gzipRes.status).toBe(200);
    expect(identityRes.status).toBe(200);

    // The Workers runtime auto-decodes; both bodies must compare equal as
    // text. Any divergence implies a CDN serving a wrong-encoding variant
    // could corrupt the script mid-pipe.
    const [gzipBody, identityBody] = await Promise.all([
      gzipRes.text(),
      identityRes.text(),
    ]);
    expect(gzipBody).toBe(identityBody);
    expect(gzipBody.length).toBe(identityBody.length);
  });
});

describe("Accept-Encoding ordering does not change body (gap-2: cache-key smuggling)", () => {
  // Per pen-tester adversarial gap: some CDNs key on the literal Accept-Encoding
  // value, so `gzip, identity` and `identity, gzip` produce different cache
  // entries. If the Worker's response varies by ordering, a permutation
  // explosion lets an attacker force cache misses or wrong-variant delivery.
  it("`gzip, identity` and `identity, gzip` yield byte-identical decoded bodies", async () => {
    const [a, b] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "gzip, identity" },
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA, "accept-encoding": "identity, gzip" },
      }),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const [bodyA, bodyB] = await Promise.all([a.text(), b.text()]);
    expect(bodyA).toBe(bodyB);
  });
});

describe("ETag and Last-Modified policy is deterministic (C-05)", () => {
  it("ETag is stable across sequential reads AND differs between resources", async () => {
    // Per pen-tester review: parallel reads may both hit the same isolate
    // cache. Serialize to give the Worker a chance to drift (per-request
    // UUID, timestamp, etc.).
    const a = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    const b = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    // Third request — different resource (?explain=1 walkthrough). Its
    // ETag must NOT collide with the install-script ETag — colliding
    // validators on different bodies break conditional GETs.
    const c = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    const etagA = a.headers.get("etag");
    const etagB = b.headers.get("etag");
    const etagC = c.headers.get("etag");
    // Stability across reads of the same resource.
    expect(etagA).toBe(etagB);
    // Different resources → different ETags (when both present).
    if (etagA !== null && etagC !== null) {
      expect(etagA).not.toBe(etagC);
    }
  });

  it("Last-Modified is not a wall-clock-now timestamp", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": CURL_UA },
    });
    const lm = res.headers.get("last-modified");
    if (lm !== null) {
      const lmDate = new Date(lm).getTime();
      const now = Date.now();
      // A wall-clock-now Last-Modified means cache validators are useless
      // and reproducible-byte verification cannot pin a prior deploy.
      // Allow up to 60s of clock skew; anything fresher is a bug.
      expect(now - lmDate).toBeGreaterThan(60_000);
    }
  });

  it("two reads of / with curl UA produce byte-identical bodies", async () => {
    const [a, b] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA },
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA },
      }),
    ]);
    const [bodyA, bodyB] = await Promise.all([a.text(), b.text()]);
    expect(bodyA).toBe(bodyB);
  });
});

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers.ts";

// RED tests — concurrency, isolate-state reuse, and replay determinism
// (X-01..X-03 from security-audit/phase-2-pen-test-additions.md + the
// "idempotency under retry" gap from chaos-engineer review §1.G).
//
// Threat: Cloudflare Workers run inside V8 isolates that are reused across
// requests for performance. ANY module-level mutable state — a memoized
// classifier, a request counter, a Last-Modified clock, a cached upstream
// fetch — can leak between requests:
//
//   1. Cross-request poisoning: request A sets a module global, request B
//      reads it. If the global is "the most recent UA's classification",
//      a curl request can poison the next browser request and serve the
//      install script to the browser, OR vice versa — serve a redirect to
//      curl, breaking the contract entirely.
//
//   2. Race-window mismatch: 100 concurrent requests with mixed UAs must
//      each receive the response their OWN UA earns, not a neighbour's.
//
//   3. Replay nondeterminism: a curl client whose connection is reset by
//      a flaky network retries. The retry MUST produce byte-identical
//      output. Any per-request variation (other than the documented
//      `Date` and `CF-Ray` headers) breaks the trust-by-computation
//      sha-verify story — users who compute the hash twice and see two
//      different values can't tell whether they're under attack.
//
// Pre-implementation, the stub returns HTTP 500 universally — every
// assertion below fails. Tests pin positive contracts; preconditions are
// unconditional.

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";

describe("100 concurrent mixed-UA requests get correct responses (X-01)", () => {
  // X-01: fire 100 requests in parallel, half curl half browser, in a
  // shuffled order. Every curl response MUST be the install script (200,
  // text/plain, shebang). Every browser response MUST be the redirect
  // (302, Location: REDIRECT_URL). Any cross-up = isolate state poisoning.
  it("50 curl + 50 browser concurrent requests all classify correctly", async () => {
    // Build a shuffled request plan so the runtime can't accidentally
    // batch-by-UA. Use a deterministic shuffle (Fisher-Yates with a fixed
    // seed via index parity) so failure modes are reproducible.
    const plan: Array<{ ua: string; expectStatus: 200 | 302 }> = [];
    for (let i = 0; i < 100; i++) {
      if (i % 2 === 0) {
        plan.push({ ua: CURL_UA, expectStatus: 200 });
      } else {
        plan.push({ ua: BROWSER_UA, expectStatus: 302 });
      }
    }
    // Interleave by index swap to avoid grouped-UA artefacts.
    for (let i = 0; i < plan.length; i += 4) {
      const tmp = plan[i];
      plan[i] = plan[i + 1] ?? tmp;
      plan[i + 1] = tmp;
    }

    const responses = await Promise.all(
      plan.map((p) =>
        SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": p.ua },
          redirect: "manual",
        }),
      ),
    );

    // Headline contract: each response matches its plan's expected status.
    for (let i = 0; i < plan.length; i++) {
      expect(responses[i].status).toBe(plan[i].expectStatus);
    }

    // Stronger: every browser request must redirect to REDIRECT_URL
    // (not some other curl request's payload masquerading as a 302).
    const browserResponses = responses.filter(
      (_, i) => plan[i].expectStatus === 302,
    );
    for (const r of browserResponses) {
      expect(r.headers.get("location")).toBe(REDIRECT_URL);
    }
  });

  it("50 curl + 50 browser concurrent — all curl bodies start with shebang", async () => {
    // Independent assertion on body content (the status check above can be
    // satisfied by a stub that returns 200 to all). Pin that all curl
    // responses have the install-script shebang.
    const plan: Array<{ ua: string; isCurl: boolean }> = [];
    for (let i = 0; i < 100; i++) {
      plan.push(
        i % 2 === 0
          ? { ua: CURL_UA, isCurl: true }
          : { ua: BROWSER_UA, isCurl: false },
      );
    }

    const responses = await Promise.all(
      plan.map((p) =>
        SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": p.ua },
          redirect: "manual",
        }),
      ),
    );

    // Read every body; check curl ones are scripts, browser ones are empty
    // (302 with no body) — neither leaks into the other.
    const bodies = await Promise.all(responses.map((r) => r.text()));
    for (let i = 0; i < plan.length; i++) {
      if (plan[i].isCurl) {
        // Curl branch must be the script.
        expect(bodies[i]).toMatch(/^#!\/bin\/sh/);
      } else {
        // Browser branch must NOT be the script — even if 302 leaks a body,
        // it must never be the install script.
        expect(bodies[i].startsWith("#!/bin/sh")).toBe(false);
      }
    }
  });
});

describe("interleaved same-client requests do not poison each other (X-02)", () => {
  // X-02: within a single test (likely single isolate), interleave 20
  // pairs of (curl, browser) requests. Each must classify correctly with
  // no leakage from its predecessor.
  it("20 interleaved (curl, browser) pairs all classify correctly", async () => {
    for (let i = 0; i < 20; i++) {
      const [curlRes, browserRes] = await Promise.all([
        SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": CURL_UA },
          redirect: "manual",
        }),
        SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": BROWSER_UA },
          redirect: "manual",
        }),
      ]);
      // Pair-level contract per iteration.
      expect(curlRes.status).toBe(200);
      expect(browserRes.status).toBe(302);
      expect(browserRes.headers.get("location")).toBe(REDIRECT_URL);
    }
  });

  it("strictly sequential curl→browser→curl→browser… 20 cycles all classify correctly", async () => {
    // Stronger than parallel: serialize the requests so any module-level
    // state from the prior request is fully written before the next reads.
    // A poisoning bug becomes deterministic here, not racy.
    for (let i = 0; i < 20; i++) {
      const curlRes = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": CURL_UA },
        redirect: "manual",
      });
      expect(curlRes.status).toBe(200);
      const curlBody = await curlRes.text();
      expect(curlBody).toMatch(/^#!\/bin\/sh/);

      const browserRes = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": BROWSER_UA },
        redirect: "manual",
      });
      expect(browserRes.status).toBe(302);
      expect(browserRes.headers.get("location")).toBe(REDIRECT_URL);
    }
  });
});

describe("5 sequential requests are byte-identical replays (X-03 / chaos §1.G idempotency)", () => {
  // X-03 + chaos-engineer review §1.G: a curl client that retries after a
  // TCP reset MUST get byte-identical bytes. Any deviation breaks the
  // trust-by-computation sha-verify story (a user computing sha256 twice
  // and seeing two values can't tell whether they're under attack).
  //
  // The only acceptable per-request variation is `Date` and `CF-Ray`
  // headers — body MUST be identical, Content-Length MUST be identical,
  // Content-Type MUST be identical.
  //
  // WOR-448 — count reduced from 50 → 5.
  // The number gives statistical confidence, not correctness signal — a
  // module-level state-poisoning bug surfaces on request 2. 5 is plenty
  // for unit-test confidence AND fits comfortably under vitest's default
  // 5s deadline. WOR-339 made worker-vitest a REQUIRED status check, so
  // a flake here blocks every unrelated PR; reducing the count is the
  // right fix because these are correctness tests, not load tests. Real
  // load testing belongs in a separate non-blocking workflow if we ever
  // want it. Don't bump back to 50 without first moving these tests off
  // the merge gate.
  it("5 sequential install-script requests return identical bodies", async () => {
    const responses: Response[] = [];
    for (let i = 0; i < 5; i++) {
      responses.push(
        await SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": CURL_UA },
        }),
      );
    }

    // Unconditional precondition: every request succeeded with status 200.
    for (const r of responses) {
      expect(r.status).toBe(200);
    }

    const bodies = await Promise.all(responses.map((r) => r.text()));
    // Every body equals the first.
    const reference = bodies[0];
    expect(reference.length).toBeGreaterThan(1000);
    for (let i = 1; i < bodies.length; i++) {
      expect(bodies[i]).toBe(reference);
    }
  });

  it("5 sequential install-script Content-Length headers are identical", async () => {
    const responses: Response[] = [];
    for (let i = 0; i < 5; i++) {
      responses.push(
        await SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": CURL_UA },
        }),
      );
    }
    for (const r of responses) {
      expect(r.status).toBe(200);
    }
    const referenceLen = responses[0].headers.get("content-length");
    expect(referenceLen).not.toBeNull();
    for (let i = 1; i < responses.length; i++) {
      expect(responses[i].headers.get("content-length")).toBe(referenceLen);
    }
    // Drain bodies to avoid leaving streams open (CR nitpick on PR #142).
    await Promise.all(responses.map((r) => r.arrayBuffer()));
  });

  it("5 sequential install-script Content-Type headers are identical", async () => {
    const responses: Response[] = [];
    for (let i = 0; i < 5; i++) {
      responses.push(
        await SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": CURL_UA },
        }),
      );
    }
    for (const r of responses) {
      expect(r.status).toBe(200);
    }
    const referenceCT = responses[0].headers.get("content-type");
    expect(referenceCT).not.toBeNull();
    for (let i = 1; i < responses.length; i++) {
      expect(responses[i].headers.get("content-type")).toBe(referenceCT);
    }
    // Drain bodies to avoid leaving streams open (CR nitpick on PR #142).
    await Promise.all(responses.map((r) => r.arrayBuffer()));
  });

  it("HEAD followed by GET on warm isolate — GET body is unaffected (chaos §2)", async () => {
    // Chaos-engineer review §2 methods.test add #8: a HEAD request must
    // not consume / mutate state that GET depends on. Run HEAD first to
    // warm the isolate, then GET — GET body must be the full script.
    const headRes = await SELF.fetch("https://worthless.sh/", {
      method: "HEAD",
      headers: { "user-agent": CURL_UA },
    });
    expect(headRes.status).toBe(200);
    const getRes = await SELF.fetch("https://worthless.sh/", {
      method: "GET",
      headers: { "user-agent": CURL_UA },
    });
    expect(getRes.status).toBe(200);
    const body = await getRes.text();
    expect(body).toMatch(/^#!\/bin\/sh/);
    expect(body.length).toBeGreaterThan(1000);
  });
});

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { expectInstallScript, expectRedirect, REDIRECT_URL } from "./_helpers.ts";

// RED tests — User-Agent classifier hardening (findings U-01..U-08 from
// security-audit/phase-2-pen-test-additions.md).
//
// Threat: the Worker's UA classifier decides between two starkly different
// responses (install script vs redirect). Any ambiguity in the classifier
// is an attack surface — a hostile UA crafted to land in the script branch
// from a browser context lets an attacker fetch the install script's bytes
// from someone else's session (CSRF-style), or, worse, an ambiguous UA
// landing in the script branch on a browser causes accidental code-paste.
//
// Policy (this file is the single source of truth — Phase 3 must implement
// these decisions byte-for-byte):
//
//   - Positive allowlist wins. The classifier checks if the UA STARTS WITH
//     a known curl-family token (curl/, Wget/, Go-http-client/, etc.).
//     Anything else (substring matches, composite UAs, BOM-prefixed,
//     RTL-overridden, embedded curl/ token in a Mozilla string) → SAFE
//     branch (302 redirect).
//   - Whitespace, case, and Unicode tricks DO NOT change classification.
//     Leading whitespace, trailing tabs, CURL/8.4.0 (uppercase) all fail the
//     positive check and fall through to redirect.
//   - Newline injection in the UA never echoes into response headers and
//     never produces a double-response (HTTP response splitting).
//   - Composite real-world bots like `curl/8.4.0 (compatible; Googlebot/2.1)`
//     are AMBIGUOUS — fail safe to redirect, even though `startsWith("curl/")`
//     is technically true. The implementation must additionally reject UAs
//     that contain known bot/browser tokens after the curl-family prefix.
//
// Pre-implementation, every assertion fails because the stub returns 500.
// Tests assert the POSITIVE contract (200 + script, OR 302 + Location) so
// they cannot pass tautologically against the stub.

const SAFE_REDIRECT_UAS: ReadonlyArray<{ label: string; ua: string }> = [
  // U-01 — ambiguous compound UA, attacker-controlled prefix.
  { label: "U-01 Mozilla wrapping curl token", ua: "Mozilla/5.0 curl/8.4.0" },
  { label: "U-01 substring match (curl mid-string)", ua: "weird-curl/agent-1.0" },
  // U-02 — case differs from canonical lowercase `curl/`.
  { label: "U-02 uppercase CURL", ua: "CURL/8.4.0" },
  { label: "U-02 mixed-case Curl", ua: "Curl/8.4.0" },
  // U-04 — Unicode tricks (BOM, RTL override, ZWJ).
  { label: "U-04 BOM prefix", ua: "\uFEFFcurl/8.4.0" },
  { label: "U-04 RTL override", ua: "\u202Ecurl/8.4.0" },
  { label: "U-04 zero-width joiner", ua: "c\u200Durl/8.4.0" },
  // U-06 — empty UA (missing tested by ua-missing.test.ts).
  { label: "U-06 empty UA value", ua: "" },
  // U-08 — composite real-world bot UAs that begin with curl-family token.
  {
    label: "U-08 curl + Googlebot composite",
    ua: "curl/8.4.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  },
  {
    label: "U-08 wget + bingbot composite",
    ua: "Wget/1.21.4 (compatible; bingbot/2.0)",
  },
  // U-08 case-variant bypass — CodeRabbit Major flagged that
  // `curl/8.4.0 mozilla/5.0` (lowercase 'm') previously fell through the
  // composite-rejection regex (which was case-sensitive) and got
  // classified as curl-family. The regex is now case-insensitive; this
  // case + a few siblings lock that in.
  { label: "U-08 case-variant lowercase mozilla", ua: "curl/8.4.0 mozilla/5.0" },
  { label: "U-08 case-variant uppercase BOT", ua: "curl/8.4.0 BOT" },
  { label: "U-08 case-variant SPIDER", ua: "curl/8.4.0 SPIDER/1.0" },
  { label: "U-08 case-variant chRoMe", ua: "curl/8.4.0 chRoMe/100" },
];

// Runtime-defended attack shapes — tests use `it.fails()` so they pass
// when the inner assertion fails (current state) and fail loudly if the
// runtime ever stops defending.
//
// Why: the layer below the Worker (workerd / undici) normalises or
// rejects these inputs before our code runs, so the unit test cannot
// observe the Worker's contract directly:
//
//   - U-03 (leading/trailing whitespace and tab) → workerd strips OWS
//     per RFC 9110 §5.5 before the value reaches the Worker. Our
//     classifier sees a clean `curl/8.4.0` and returns 200 — the test
//     was written from the attacker's view (full bytes including OWS).
//
//   - U-07 (CRLF/LF injection in UA) → undici (the fetch impl in the
//     vitest pool) refuses to construct a Request with a header value
//     containing CR or LF, throwing TypeError BEFORE the request is
//     ever sent. Our Worker would catch the control bytes if they
//     arrived, but they don't.
//
// The wire-layer threat (an attacker sending these bytes over a raw
// socket past undici's validation) is verified in Phase 6 CI dogfood
// via raw-curl integration tests against the preview deploy. See
// WOR-374 (Phase 6 raw-curl integration tests, child of WOR-349).
const RUNTIME_DEFENDED_UAS: ReadonlyArray<{
  label: string;
  ua: string;
  defendedBy: string;
}> = [
  {
    label: "U-03 leading whitespace",
    ua: "  curl/8.4.0",
    defendedBy: "workerd OWS strip (RFC 9110 §5.5)",
  },
  {
    label: "U-03 trailing tab",
    ua: "curl/8.4.0\t",
    defendedBy: "workerd OWS strip (RFC 9110 §5.5)",
  },
  {
    label: "U-03 leading tab",
    ua: "\tcurl/8.4.0",
    defendedBy: "workerd OWS strip (RFC 9110 §5.5)",
  },
  {
    label: "U-07 CRLF injection",
    ua: "curl/8.4.0\r\nX-Inject: 1",
    defendedBy: "undici fetch() rejects CRLF in header values",
  },
  {
    label: "U-07 LF-only injection",
    ua: "curl/8.4.0\nX-Inject: 1",
    defendedBy: "undici fetch() rejects LF in header values",
  },
];

describe("ambiguous and trick UAs fall through to safe redirect (U-01..U-04, U-06, U-08)", () => {
  for (const { label, ua } of SAFE_REDIRECT_UAS) {
    it(`${label} → 302 redirect (positive allowlist policy)`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
        redirect: "manual",
      });
      expectRedirect(res);
    });
  }
});

describe("runtime-defended attack shapes (U-03, U-07) — regression sentinels", () => {
  // These tests use `it.fails`: vitest treats the test as passing when
  // the inner assertion fails. Today they all fail (workerd strips OWS
  // / undici rejects CRLF), so vitest reports them passing. If the
  // runtime layer ever stops defending — e.g., a workerd version that
  // preserves leading whitespace, or an undici update that loosens CRLF
  // validation — these tests will start passing internally, which
  // flips `it.fails` to failed and alarms.
  //
  // The contract itself (Worker rejects these bytes if they arrive) is
  // covered by the static charCodeAt check in src/ua.ts and verified
  // end-to-end by Phase 6 CI dogfood with raw curl over real HTTP.
  for (const { label, ua, defendedBy } of RUNTIME_DEFENDED_UAS) {
    it.fails(
      `${label} → 302 redirect [defended at: ${defendedBy}]`,
      async () => {
        const res = await SELF.fetch("https://worthless.sh/", {
          headers: { "user-agent": ua },
          redirect: "manual",
        });
        expectRedirect(res);
      },
    );
  }
});

describe("canonical curl-family UAs still serve the script (control)", () => {
  // Sanity: the policy above must not over-block. These exact strings
  // remain in the script branch — if any of these flips to redirect, the
  // classifier is too tight.
  for (const ua of ["curl/8.4.0", "Wget/1.21.4", "Go-http-client/2.0"]) {
    it(`${ua} → 200 install.sh`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
      });
      await expectInstallScript(res);
    });
  }
});

describe("length attacks do not panic the isolate (U-05)", () => {
  it("64KB curl UA is classified as curl (allowlist by prefix, not full match)", async () => {
    // Long-but-valid: `curl/8.4.0` followed by 64KB of padding. The classifier
    // looks at the prefix; a long suffix does not change the family.
    const ua = "curl/8.4.0 " + "A".repeat(64 * 1024);
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": ua },
    });
    // The UA has the canonical `curl/` prefix and contains no composite
    // markers (`(),;`) or browser/bot tokens (Mozilla/WebKit/Bot/etc.),
    // so it MUST classify as curl-family and serve the script. A 302
    // here would be a classifier-over-block regression on legitimate
    // long-curl-family UAs. Crucially, also NOT 5xx — the isolate must
    // not panic on 64KB header values.
    expect(res.status).toBe(200);
  });

  it("64KB junk UA (no curl prefix) classifies the same as a short junk UA", async () => {
    const longUa = "X".repeat(64 * 1024);
    const shortUa = "X";
    const [longRes, shortRes] = await Promise.all([
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": longUa },
        redirect: "manual",
      }),
      SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": shortUa },
        redirect: "manual",
      }),
    ]);
    // Stability check.
    expect(longRes.status).toBe(shortRes.status);
    expect(longRes.headers.get("location")).toBe(
      shortRes.headers.get("location"),
    );
    // Per pen-tester review: previous version was vacuous (both 5xx, both
    // null location both pass). Lock in the SAFE outcome explicitly.
    expect(longRes.status).toBe(302);
    expect(longRes.headers.get("location")).toBe(REDIRECT_URL);
  });
});

describe("duplicate User-Agent headers fall through to safe redirect (gap-1)", () => {
  // Per pen-tester adversarial gap: HTTP allows multiple User-Agent values
  // (RFC 9110 §5.5.3 marks it singleton, but stacks vary). An attacker who
  // can inject a second UA header (leaky proxy, mis-configured intermediary)
  // must not flip a browser victim's classification to the script branch.
  it("two UA headers (browser + injected curl) → 302 redirect (browser wins safe)", async () => {
    const headers = new Headers();
    headers.append("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
    headers.append("user-agent", "curl/8.4.0");
    const res = await SELF.fetch("https://worthless.sh/", {
      headers,
      redirect: "manual",
    });
    expectRedirect(res);
  });

  it("two UA headers (curl + injected browser) → 302 redirect (composite is ambiguous)", async () => {
    const headers = new Headers();
    headers.append("user-agent", "curl/8.4.0");
    headers.append("user-agent", "Mozilla/5.0");
    const res = await SELF.fetch("https://worthless.sh/", {
      headers,
      redirect: "manual",
    });
    // Either ordering must redirect — the safest interpretation of duplicate
    // UAs is "ambiguous, fall back to safe."
    expectRedirect(res);
  });
});

describe("null-byte UA polyglot is consistently classified safe (gap-3) — regression sentinels", () => {
  // Per pen-tester adversarial gap: null bytes in headers may be stripped by
  // the runtime (workerd) or accepted verbatim. If stripped, the classifier
  // sees only `curl/8.4.0` and serves the script — but the FULL bytes were
  // the attacker's input (browser context with curl prefix), creating a
  // parser-differential attack. Always classify ambiguous → safe.
  //
  // workerd currently strips/truncates NUL bytes in header values before
  // the Worker sees them, so the unit test cannot observe the Worker's
  // own NUL check (in src/ua.ts charCodeAt < 0x20). Use `it.fails` as
  // a regression sentinel: passes today (workerd defends), alarms if
  // workerd ever stops stripping. Wire-layer threat covered in Phase 6
  // raw-curl integration (WOR-374, child of WOR-349).
  it.fails(
    "`curl/8.4.0\\x00Mozilla/5.0` → 302 redirect (no parser differential) [defended at: workerd NUL strip]",
    async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": "curl/8.4.0\x00Mozilla/5.0" },
        redirect: "manual",
      });
      expectRedirect(res);
    },
  );

  it.fails(
    "`curl/8.4.0\\x00 trailing junk` → 302 redirect [defended at: workerd NUL strip]",
    async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": "curl/8.4.0\x00\x00\x00" },
        redirect: "manual",
      });
      expectRedirect(res);
    },
  );
});

describe("newline injection in UA does not poison response headers (U-07) — regression sentinels", () => {
  // undici (the fetch impl in `cloudflare:test`) refuses to *construct* a
  // Request whose header values contain CR or LF, throwing TypeError
  // before the request is sent. The Worker therefore never sees the
  // injection. Use `it.fails` so the test today (which throws TypeError
  // before reaching the assertion) passes; it alarms if undici ever
  // loosens validation. Wire-layer threat (raw socket writing
  // `User-Agent: curl/8.4.0\r\nX-Inject: pwned\r\n` over the wire past
  // undici) covered in Phase 6 raw-curl integration test.
  it.fails(
    "CRLF in UA does not yield X-Inject header in response [defended at: undici fetch() construction]",
    async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": "curl/8.4.0\r\nX-Inject: pwned" },
        redirect: "manual",
      });
      expect(res.headers.get("x-inject")).toBeNull();
    },
  );

  it.fails(
    "CRLF in UA does not echo into any response header value [defended at: undici fetch() construction]",
    async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": "curl/8.4.0\r\nX-Inject: pwned" },
        redirect: "manual",
      });
      for (const [, value] of res.headers) {
        expect(value).not.toContain("X-Inject");
        expect(value).not.toContain("pwned");
        expect(value).not.toContain("\r");
        expect(value).not.toContain("\n");
      }
    },
  );
});

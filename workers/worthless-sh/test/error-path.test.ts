import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED tests — failure-mode safety (findings E-01, E-02, E-03 from
// security-audit/phase-2-pen-test-additions.md).
//
// Threat: a user runs `curl https://worthless.sh | sh`. If the Worker throws
// an unhandled exception, Cloudflare's default behaviour is to return its own
// HTML error page (the 1xxx series) with status 5xx. That HTML — `<html>...`
// — is then piped into /bin/sh. `<` and `>` are valid shell redirection
// operators; the result ranges from a noisy `command not found` to outright
// code execution depending on the exact bytes.
//
// These tests pin down the contract every error path must satisfy:
//   E-01 — text/plain content-type and a shell-safe body (starts with `echo`,
//          `#`, or `set -e false`-equivalent guard) on any forced exception.
//   E-02 — Cloudflare's default 1xxx HTML error pages are shadowed; even an
//          uncaught panic yields text/plain, never `<html>`.
//   E-03 — no stack trace, file path, or internal source location leaks into
//          the response body — even on a real exception.
//
// We force the throw by sending pathological inputs (10MB User-Agent per R-02,
// malformed Range, etc.). Pre-implementation, the stub returns a flat 500 with
// "not implemented" — which IS shell-safe by accident, so the tests must
// assert the POSITIVE contract (text/plain + shell-safe prefix + no HTML
// markers) rather than `status !== 200`, otherwise they would pass tautologically.

const TEN_MB_UA = "curl/" + "A".repeat(10 * 1024 * 1024);

const FORCED_ERROR_INPUTS: ReadonlyArray<{
  label: string;
  init: RequestInit;
}> = [
  {
    label: "10MB User-Agent header",
    init: { headers: { "user-agent": TEN_MB_UA } },
  },
  {
    label: "malformed Range header (bytes=abc-xyz)",
    init: {
      headers: { "user-agent": "curl/8.4.0", range: "bytes=abc-xyz" },
    },
  },
  // Per CodeRabbit (PR #117): regression coverage that the tightened
  // VALID_RANGE_VALUE regex catches malformed inputs the old
  // `[0-9 ,\-]+` form would have silently accepted.
  {
    label: "malformed Range header (bytes=-- only hyphens)",
    init: {
      headers: { "user-agent": "curl/8.4.0", range: "bytes=--" },
    },
  },
  {
    label: "malformed Range header (bytes=, empty range)",
    init: {
      headers: { "user-agent": "curl/8.4.0", range: "bytes=," },
    },
  },
  {
    label: "malformed Range header (bytes=0-1-2 too many hyphens)",
    init: {
      headers: { "user-agent": "curl/8.4.0", range: "bytes=0-1-2" },
    },
  },
  {
    label: "absurd Accept-Encoding (1000 codings)",
    init: {
      headers: {
        "user-agent": "curl/8.4.0",
        "accept-encoding": Array(1000).fill("gzip").join(", "),
      },
    },
  },
];

function assertShellSafeBody(body: string): void {
  // Must NOT look like HTML — no opening tag, no DOCTYPE, no Cloudflare
  // 1xxx error page boilerplate.
  expect(body.startsWith("<")).toBe(false);
  expect(body).not.toMatch(/<!doctype/i);
  expect(body).not.toMatch(/<html/i);
  expect(body).not.toMatch(/cloudflare/i);
  expect(body).not.toMatch(/error 1\d{3}/i);
  // Positive shape: any POSIX-utility-name first token followed by space, OR
  // a shell comment, OR a shebang, OR set [+-] / exit / true / false / `:`
  // no-op. Anything else risks shell interpretation.
  // Per pen-tester review: original `set -e` literal would reject valid
  // guards like `command -v sh >/dev/null || exit 1`.
  expect(body).toMatch(/^(echo |# |#!|set [\-+]|exit |true$|false$|: |[a-zA-Z_][\w-]*\s)/m);
}

describe("error path is shell-safe (E-01)", () => {
  for (const { label, init } of FORCED_ERROR_INPUTS) {
    it(`${label} → text/plain + shell-safe body`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", init);

      // Must be a server-error status — the contract is about HOW we fail,
      // not whether we fail. 5xx is the honest signal to the client.
      expect([500, 502, 503]).toContain(res.status);

      // Critical: text/plain, never text/html.
      const ct = res.headers.get("content-type") ?? "";
      expect(ct).toMatch(/^text\/plain/);
      expect(ct).not.toMatch(/html/i);

      const body = await res.text();
      assertShellSafeBody(body);

      // Body should be small — error responses don't need bulk.
      expect(body.length).toBeLessThan(1024);
    });
  }
});

describe("Cloudflare default HTML error pages are shadowed (E-02)", () => {
  it("forced-error response never contains <html> or DOCTYPE markers", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": TEN_MB_UA },
    });

    const body = await res.text();
    // The smoking gun for a CF default error page leaking through.
    expect(body).not.toContain("<!DOCTYPE");
    expect(body).not.toContain("<html");
    expect(body).not.toContain("</html>");
    expect(body).not.toMatch(/error code: \d+/i);
  });

  it("error-path content-type is never text/html", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": TEN_MB_UA },
    });
    const ct = res.headers.get("content-type") ?? "";
    expect(ct.toLowerCase()).not.toContain("text/html");
  });
});

describe("error body leaks no internals (E-03)", () => {
  for (const { label, init } of FORCED_ERROR_INPUTS) {
    it(`${label} → no stack trace, no file path, no source location`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", init);
      const body = await res.text();

      // Stack-frame markers from V8 / workerd.
      expect(body).not.toMatch(/\s+at\s+\S+\s+\(/);
      expect(body).not.toMatch(/\.ts:\d+:\d+/);
      expect(body).not.toMatch(/\.js:\d+:\d+/);
      // Internal paths from the build / source tree.
      expect(body).not.toMatch(/\/src\//);
      expect(body).not.toMatch(/node_modules/);
      expect(body).not.toMatch(/workerd/i);
      // Generic "Error:" prefix from a serialized exception.
      expect(body).not.toMatch(/^\s*Error:/m);
      expect(body).not.toMatch(/TypeError|ReferenceError|SyntaxError/);
    });
  }
});

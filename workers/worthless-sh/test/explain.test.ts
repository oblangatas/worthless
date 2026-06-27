import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED test — fails until WOR-300 implements ?explain=1 walkthrough mode.
// Visitors who want to understand the script without executing it should
// get a line-by-line explanation.

describe("?explain=1 returns walkthrough", () => {
  it("curl UA + ?explain=1 → 200 text/plain walkthrough", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: { "user-agent": "curl/8.4.0" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/plain/);

    const body = await res.text();
    // Walkthrough must be human-readable, not the raw script.
    // Expect references to what the script does.
    expect(body.length).toBeGreaterThan(200);
    expect(body).toMatch(/line|step|what it does/i);
    // Must NOT be the raw shebang — that's the script, not the walkthrough.
    expect(body.startsWith("#!/bin/sh")).toBe(false);
  });

  it("browser UA + ?explain=1 still redirects (walkthrough is for curl-aware clients)", async () => {
    const res = await SELF.fetch("https://worthless.sh/?explain=1", {
      headers: {
        "user-agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0",
      },
      redirect: "manual",
    });

    expect(res.status).toBe(302);
  });
});

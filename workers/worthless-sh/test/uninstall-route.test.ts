import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// WOR-694 — the /uninstall route, symmetric to `/`:
//   curl       → uninstall.sh
//   ?explain=1 → the uninstall walkthrough (audit-before-run)
//   browser    → 302 to the uninstall docs page
//   POST       → 405 (never a script body)
//   /install.sh, /uninstall.sh → still 404 (no parallel vector)

const CURL_UA = "curl/8.4.0";
const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";

describe("/uninstall route", () => {
  it("curl → 200 text/plain uninstall.sh", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
    const body = await res.text();
    expect(body).toContain("#!/bin/sh");
    expect(body).toContain("Worthless uninstaller");
    expect(body).toContain("--print-keychain-account");
  });

  it("curl ?explain=1 → walkthrough, NOT the script", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall?explain=1", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Walkthrough for worthless uninstall.sh");
    expect(body).not.toContain("#!/bin/sh");
  });

  it("browser → 302 to the uninstall docs page", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall", {
      headers: { "user-agent": BROWSER_UA },
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://docs.wless.io/uninstall");
  });

  it("serves a sha256 verifiability header over the body", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall", {
      headers: { "user-agent": CURL_UA },
    });
    expect(res.headers.get("x-worthless-script-sha256")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("HEAD → 200, no body, Content-Length set", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall", {
      method: "HEAD",
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-length")).toMatch(/^\d+$/);
    expect(await res.text()).toBe("");
  });

  it("POST → 405 (never serves a script body)", async () => {
    const res = await SELF.fetch("https://worthless.sh/uninstall", {
      method: "POST",
      headers: { "user-agent": CURL_UA },
    });
    expect(res.status).toBe(405);
  });

  it("/uninstall.sh and /install.sh still 404 (no parallel vector)", async () => {
    for (const path of ["/uninstall.sh", "/install.sh"]) {
      const res = await SELF.fetch(`https://worthless.sh${path}`, {
        headers: { "user-agent": CURL_UA },
      });
      expect(res.status).toBe(404);
    }
  });
});

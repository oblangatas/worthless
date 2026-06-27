import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED test — fails until WOR-300 implements browser redirect.
// Real browsers must land on wless.io, not a wall of shell script.

const BROWSER_UAS = [
  // Chrome 121 macOS
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
  // Firefox 123 Linux
  "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
  // Safari 17 macOS
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
  // Mobile Safari iOS
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
];

describe("browser UA redirects to wless.io", () => {
  for (const ua of BROWSER_UAS) {
    it(`${ua.slice(0, 40)}... → 302 to wless.io`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
        redirect: "manual",
      });

      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe("https://wless.io");
    });
  }
});

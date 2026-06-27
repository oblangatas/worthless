import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// RED test — fails until WOR-300 implements UA detection + script proxy.
// When curl-family clients hit the endpoint, they must get install.sh as plain text.

// Real-world UAs emitted by the clients users pipe into sh. `fetch/1.0` was
// a placeholder; no standard client emits it. Replaced with python-urllib
// (scripts) and httpie (dev UX) which are common in the wild.
const CURL_UAS = [
  "curl/8.4.0",
  "curl/7.88.1",
  "Wget/1.21.4",
  "Go-http-client/2.0",
  "Python-urllib/3.11",
  "HTTPie/3.2.3",
];

describe("curl-family UA serves install.sh", () => {
  for (const ua of CURL_UAS) {
    it(`${ua} → 200 text/plain install.sh`, async () => {
      const res = await SELF.fetch("https://worthless.sh/", {
        headers: { "user-agent": ua },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/^text\/plain/);

      const body = await res.text();
      expect(body).toContain("#!/bin/sh");
      expect(body).toContain("Worthless installer");
      expect(body).toContain("EXIT_PLATFORM=20");
    });
  }
});

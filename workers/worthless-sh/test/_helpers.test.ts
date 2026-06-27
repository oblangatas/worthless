// Smoke test for test/_helpers.ts.
//
// This test exists for two reasons:
//   1. Validate that the helpers module type-checks and loads under vitest 4 +
//      pool-workers 0.15 — if the import chain breaks, every other test breaks
//      silently with a confusing collection failure. This file fails loudly.
//   2. Validate that `cloudflareTest` actually populates `env` from
//      `wrangler.toml`'s [vars] block. If that wiring regresses (wrangler
//      bump, plugin rename, etc.) we want to know on the next test run, not
//      when an adversarial test mysteriously starts using the literal "https://wless.io".
//
// The helper functions themselves (expectInstallScript / expectRedirect /
// expectWalkthrough) are exercised by the real test files in this directory —
// they need a Worker response, which we don't have until Phase 3 GREEN.

import { describe, it, expect } from "vitest";
import { REDIRECT_URL } from "./_helpers";

describe("_helpers test wiring", () => {
  it("REDIRECT_URL is populated from wrangler.toml [vars]", () => {
    // Asserts both that env binding flows through, AND that wrangler.toml
    // hasn't drifted from the wless.io contract.
    expect(REDIRECT_URL).toBe("https://wless.io");
  });
});

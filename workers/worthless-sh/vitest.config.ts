import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Migrated from `defineWorkersConfig` (pool-workers 0.5.x) to the v4 pattern
// (pool-workers 0.15.x + vitest 4.x). The pool now ships as a Vite plugin
// rather than a poolOptions block. See:
// https://developers.cloudflare.com/workers/testing/vitest-integration/

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
  test: {},
});

// Test helpers for worthless-sh Worker.
//
// The Worker has three response shapes — install script, redirect, walkthrough —
// and most tests assert against the same invariants. Centralise those assertions
// here so individual tests stay focused on the input dimension they vary
// (UA family, query string, headers) and the contract is changed in one place.
//
// REDIRECT_URL is read from `cloudflare:test`'s `env`, which the
// `cloudflareTest` plugin populates from `wrangler.toml`'s `[vars]` block.
// If that wiring breaks, _helpers.test.ts fails loudly.

import { env } from "cloudflare:test";
import { expect } from "vitest";

interface WorkerTestEnv {
  REDIRECT_URL: string;
  GITHUB_RAW_URL: string;
}

const testEnv = env as unknown as WorkerTestEnv;

/** Canonical landing page for non-curl visitors (read from wrangler [vars]). */
export const REDIRECT_URL = testEnv.REDIRECT_URL;

/** First bytes any valid Worthless installer must begin with. */
export const INSTALL_SH_SHEBANG = /^#!\/bin\/sh/;

/**
 * Decode a base64 string to its raw bytes. Binary-safe.
 *
 * `atob` returns a binary string (each char = one byte 0..255), not a UTF-8
 * decoded string. For text round-trips, wrap with TextDecoder; for byte
 * comparison, use the result directly.
 */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Assert a response is the install script served to curl-family clients:
 * 200 status, text/plain content-type, body that starts with the canonical
 * shebang and is recognisably the Worthless installer.
 *
 * Use in tests that exercise the curl/wget/Go-http UA branch.
 */
export async function expectInstallScript(res: Response): Promise<void> {
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
  const body = await res.text();
  expect(body).toMatch(INSTALL_SH_SHEBANG);
  expect(body).toContain("Worthless installer");
  // Sanity floor — the real script is ~12KB; anything under 1KB is a stub.
  expect(body.length).toBeGreaterThan(1000);
}

/**
 * Assert a response is the safe redirect to the wless.io landing page:
 * 302 status, Location header pointing at REDIRECT_URL.
 *
 * Pass an explicit `expectedLocation` only when testing a non-default redirect
 * target (e.g., a future per-route override). Default reads from env so the
 * test binding stays the source of truth.
 */
export function expectRedirect(
  res: Response,
  expectedLocation: string = REDIRECT_URL,
): void {
  expect(res.status).toBe(302);
  expect(res.headers.get("location")).toBe(expectedLocation);
}

/**
 * Assert a response is the human-readable ?explain=1 walkthrough:
 * 200 text/plain, long enough to be useful, references step/line semantics,
 * and is NOT the raw script (no shebang prefix).
 */
export async function expectWalkthrough(res: Response): Promise<void> {
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
  const body = await res.text();
  expect(body.length).toBeGreaterThan(200);
  expect(body).toMatch(/line|step|what it does/i);
  expect(body.startsWith("#!/bin/sh")).toBe(false);
}

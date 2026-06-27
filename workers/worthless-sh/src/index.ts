// worthless.sh Cloudflare Worker — installation endpoint.
//
// Contract this Worker fulfills (driven by the test suite in ./test):
//
//   - GET / + curl-family UA  → 200 text/plain, body = install.sh
//   - GET /?explain=1 + curl  → 200 text/plain, body = walkthrough
//   - GET / + browser/missing → 302 to REDIRECT_URL (fail-safe)
//   - GET /.well-known/security.txt → 200 text/plain (RFC 9116)
//   - Any other path          → 404 (never the install script body)
//   - POST/PUT/DELETE/PATCH   → 405 Method Not Allowed (Allow header set)
//   - HEAD                    → mirrors GET status + content-length, no body
//   - OPTIONS                 → 204, no wildcard CORS, no Origin echo
//   - TRACE                   → 405 (no XST)
//
// Cross-cutting headers, applied via `withSecurityHeaders` to every Response:
//
//   X-Content-Type-Options: nosniff
//   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
//   Referrer-Policy: no-referrer
//
// Verifiability headers added on the install-script branch only:
//
//   X-Worthless-Script-Sha256: <hex64>   — sha256(response body)
//   X-Worthless-Script-Tag: <tag>        — git tag, e.g. v0.3.0
//   X-Worthless-Script-Commit: <sha>     — full git commit sha
//
// The big invariant: even on an uncaught panic, the response is shell-safe
// (text/plain, never `<html>`). The fetch handler is wrapped in a top-level
// try/catch that returns a hand-built 500 with `# worthless-sh: error\n` —
// piping that into /bin/sh is a no-op (just a comment).

// install.sh and walkthrough.txt are base64-encoded at build time by
// `scripts/embed-assets.mjs` into `src/embedded.ts` (gitignored, run
// automatically as `pretest`/`predev`/`predeploy`). Base64 in JS source
// avoids tripping Cloudflare's WAF on api.cloudflare.com, which rejects
// multipart upload parts containing shell-injection signatures. See
// wrangler.toml comment for the full story.
import { INSTALL_SH_B64, WALKTHROUGH_B64 } from "./embedded";
import { isCurlFamily } from "./ua";

export interface Env {
  REDIRECT_URL: string;
  SCRIPT_TAG: string;
  SCRIPT_COMMIT: string;
  // URL of the GitHub Actions run that built+deployed this Worker.
  // Injected at deploy time via `wrangler deploy --var SCRIPT_BUILD_PROVENANCE:...`
  // from deploy-worker.yml; falls back to wrangler.toml dev placeholders
  // for `npm run dev` and tests. Surfaced as the
  // `X-Worthless-Build-Provenance` response header per ADR-001.
  SCRIPT_BUILD_PROVENANCE: string;
}

// ---- Constants computed once at module load ------------------------------

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

// Decode base64 → bytes → string once at module load. The decoded
// bytes are byte-identical to the source files at the repo root.
function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const INSTALL_SH_BYTES = b64ToBytes(INSTALL_SH_B64);
const INSTALL_SH_LENGTH = INSTALL_SH_BYTES.byteLength;
const INSTALL_SH = DECODER.decode(INSTALL_SH_BYTES);

const WALKTHROUGH_BYTES = b64ToBytes(WALKTHROUGH_B64);
const WALKTHROUGH_LENGTH = WALKTHROUGH_BYTES.byteLength;
const WALKTHROUGH = DECODER.decode(WALKTHROUGH_BYTES);

const TEXT_PLAIN = "text/plain; charset=utf-8";
const NO_STORE = "no-store";
const CACHEABLE = "public, max-age=300, must-revalidate";
const HSTS = "max-age=63072000; includeSubDomains; preload";
const CSP_NONE = "default-src 'none'";
const ALLOW_READONLY = "GET, HEAD, OPTIONS";

// sha256 is computed lazily on first request (Web Crypto digest is async)
// and cached for the isolate's lifetime. Body is static, so the value is
// stable across the cache.
let installSha256Cache: string | null = null;
let walkthroughSha256Cache: string | null = null;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer to satisfy the BufferSource typing
  // and avoid any SharedArrayBuffer ambiguity.
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const view = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < view.length; i++) {
    out += view[i].toString(16).padStart(2, "0");
  }
  return out;
}

async function getInstallSha256(): Promise<string> {
  if (installSha256Cache !== null) return installSha256Cache;
  installSha256Cache = await sha256Hex(INSTALL_SH_BYTES);
  return installSha256Cache;
}

async function getWalkthroughSha256(): Promise<string> {
  if (walkthroughSha256Cache !== null) return walkthroughSha256Cache;
  walkthroughSha256Cache = await sha256Hex(WALKTHROUGH_BYTES);
  return walkthroughSha256Cache;
}

// ---- security.txt (RFC 9116) --------------------------------------------

// Built per-request because `Expires:` MUST be future-dated and SHOULD be
// within 1 year. RFC 9116 §2.5.5. Cheap to compute.
function buildSecurityTxt(): string {
  const expires = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000);
  const expiresIso = expires.toISOString().replace(/\.\d{3}Z$/, "Z");
  return [
    "# Worthless security policy — RFC 9116",
    "Contact: mailto:security@worthless.sh",
    "Contact: https://github.com/shacharm2/worthless/security/advisories/new",
    `Expires: ${expiresIso}`,
    "Preferred-Languages: en",
    "Canonical: https://worthless.sh/.well-known/security.txt",
    "",
  ].join("\n");
}

// ---- Header builders -----------------------------------------------------

/**
 * Apply the security-headers contract to a response Headers object.
 * Every response leaves the Worker with these set — there is no path that
 * skips them. Mutates and returns the same object for fluency.
 *
 * Read-only endpoint with no JSON or browser-script consumers; do NOT emit
 * any `Access-Control-Allow-*` headers. M-03 forbids wildcard ACAO; the
 * simplest defence is to not set CORS at all.
 */
function withSecurityHeaders(h: Headers): Headers {
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Strict-Transport-Security", HSTS);
  h.set("Referrer-Policy", "no-referrer");
  return h;
}

/**
 * Build the headers shared by every short, non-cacheable text response
 * (404, 405, 414, 500, 503, OPTIONS). Callers add Allow / Content-Length /
 * etc. as needed.
 */
function buildShortResponseHeaders(): Headers {
  const h = new Headers();
  h.set("Content-Type", TEXT_PLAIN);
  h.set("Cache-Control", NO_STORE);
  return withSecurityHeaders(h);
}

function buildInstallHeaders(env: Env, sha: string): Headers {
  const h = new Headers();
  h.set("Content-Type", TEXT_PLAIN);
  h.set("Content-Length", String(INSTALL_SH_LENGTH));
  h.set("Cache-Control", CACHEABLE);
  h.set("Vary", "User-Agent, Accept-Encoding");
  h.set("ETag", `"${sha}"`);
  h.set("X-Worthless-Script-Sha256", sha);
  h.set("X-Worthless-Script-Tag", env.SCRIPT_TAG);
  h.set("X-Worthless-Script-Commit", env.SCRIPT_COMMIT);
  h.set("X-Worthless-Build-Provenance", env.SCRIPT_BUILD_PROVENANCE);
  // Defence-in-depth: even though browsers never see this content (UA gate
  // routes them to the redirect), pin a strict CSP to neutralise any sniffer
  // that ignores nosniff.
  h.set("Content-Security-Policy", CSP_NONE);
  return withSecurityHeaders(h);
}

function buildWalkthroughHeaders(sha: string): Headers {
  const h = new Headers();
  h.set("Content-Type", TEXT_PLAIN);
  h.set("Content-Length", String(WALKTHROUGH_LENGTH));
  h.set("Cache-Control", CACHEABLE);
  h.set("Vary", "User-Agent, Accept-Encoding");
  h.set("ETag", `W/"walkthrough-${sha}"`);
  h.set("Content-Security-Policy", CSP_NONE);
  return withSecurityHeaders(h);
}

function buildRedirectHeaders(location: string): Headers {
  const h = new Headers();
  h.set("Location", location);
  h.set("Cache-Control", NO_STORE);
  h.set("Vary", "User-Agent");
  h.set("Content-Length", "0");
  // Browser-side defence: even if a body somehow leaks through a 302
  // (intermediaries quirk), CSP prevents any script from running.
  h.set("Content-Security-Policy", CSP_NONE);
  return withSecurityHeaders(h);
}

function buildSecurityTxtHeaders(body: string): Headers {
  const h = new Headers();
  h.set("Content-Type", TEXT_PLAIN);
  h.set("Content-Length", String(ENCODER.encode(body).byteLength));
  h.set("Cache-Control", "public, max-age=86400");
  return withSecurityHeaders(h);
}

function buildMethodNotAllowedHeaders(): Headers {
  const h = buildShortResponseHeaders();
  // RFC 9110 §15.5.6 — the Allow header MUST list the methods this resource
  // accepts. Listing the read-only set so HTTP intermediaries can hint
  // their callers without us advertising mutating verbs.
  h.set("Allow", ALLOW_READONLY);
  return h;
}

function buildOptionsHeaders(): Headers {
  const h = buildShortResponseHeaders();
  // Read-only endpoint; advertise only safe methods. NOT setting
  // Access-Control-Allow-Origin at all is the safest CORS policy
  // (M-03 forbids wildcard, and any value here is risk we don't need).
  h.set("Allow", ALLOW_READONLY);
  h.set("Content-Length", "0");
  return h;
}

// ---- Pathological-input guards (E-01 contract) --------------------------

// Maximum acceptable User-Agent header length. Real-world UAs sit at
// 100–500 bytes; 1 MB is far beyond any legitimate use. 10 MB UA is the
// canonical E-01 attack — refuse with 503 + shell-safe body so the error
// itself can't escalate to RCE in a `curl | sh` pipe. The threshold sits
// above 64 KB so the U-05 length-attack tests (which send 64 KB padded
// UAs and require the isolate not to panic, accepting either 200 or 302)
// still pass through to the classifier rather than tripping this guard.
const UA_MAX_LENGTH = 1 * 1024 * 1024;

// Maximum acceptable URL pathname length. RFC 9110 §15.5.15 (414) — any
// path beyond a generous bound is treated as DoS rather than typo.
const PATH_MAX_LENGTH = 4096;

// Range header is structurally `bytes=<spec>` per RFC 9110 §14.2. We
// ignore Range entirely on the install path (R-01), but a malformed
// value like `bytes=abc-xyz` is a probe — fail fast.
// RFC 9110 §14.1.2 byte-range-set: a non-empty list of byte-range-spec
// (`first-pos "-" last-pos?`) or suffix-byte-range-spec (`"-" suffix-len`)
// separated by `,`. This regex tightens the previous `[0-9 ,\-]+` form
// which accepted clearly malformed inputs like `bytes=--`, `bytes=,`,
// and `bytes=0-1-2`. The Worker doesn't actually serve byte ranges
// (R-01 always returns the full body) — this guard exists so
// refuseBadInput's intent (reject malformed Range headers) matches its
// implementation.
const VALID_RANGE_VALUE = /^bytes=(\d+-\d*|-\d+)(,(\d+-\d*|-\d+))*$/;

// Accept-Encoding with hundreds of codings is a DoS / oddity. Real
// clients send 1–4 codings.
const ACCEPT_ENCODING_MAX_CODINGS = 64;

/**
 * Return a 503 + shell-safe body if the request carries a pathological
 * input that the Worker refuses to parse. Returning shell-safe text is
 * load-bearing — these requests come over `curl | sh` pipes too, and a
 * Cloudflare HTML error page would be catastrophic.
 *
 * Returns null when the request is acceptable.
 */
function refuseBadInput(req: Request): Response | null {
  const ua = req.headers.get("user-agent");
  const range = req.headers.get("range");
  const ae = req.headers.get("accept-encoding");

  const bad =
    (ua !== null && ua.length > UA_MAX_LENGTH) ||
    (range !== null && !VALID_RANGE_VALUE.test(range)) ||
    (ae !== null && ae.split(",").length > ACCEPT_ENCODING_MAX_CODINGS);

  if (!bad) return null;
  return respond(
    req.method === "HEAD",
    503,
    buildShortResponseHeaders(),
    "# worthless-sh: bad-input\n",
  );
}

// ---- HEAD-aware response helper -----------------------------------------

/**
 * Build a Response that respects HEAD semantics: same status + headers as
 * GET, but with no body. Content-Length is preserved on the headers (RFC
 * 9110 §9.3.2) so HTTP clients can size what they would have downloaded.
 *
 * `bodyText` is the GET body; pass null/undefined for inherently bodyless
 * responses (302, 204, 405 with no message).
 */
function respond(
  isHead: boolean,
  status: number,
  headers: Headers,
  bodyText: string | null,
): Response {
  // RFC 9110 §15.4: HEAD MUST return the same headers as GET, including
  // Content-Length matching what GET would have served. Set it from the
  // bodyText byte length (UTF-8 can be multi-byte) UNLESS the caller
  // already chose a value — buildInstallHeaders / buildWalkthroughHeaders /
  // buildRedirectHeaders / buildSecurityTxtHeaders all pin their own
  // Content-Length and we must not stomp on those.
  if (bodyText !== null && !headers.has("Content-Length")) {
    headers.set("Content-Length", String(ENCODER.encode(bodyText).byteLength));
  }
  if (isHead || bodyText === null) {
    return new Response(null, { status, headers });
  }
  return new Response(bodyText, { status, headers });
}

// ---- Path canonicalisation ----------------------------------------------

/**
 * Reduce repeated leading slashes (`//`, `///`) to a single `/`. Trailing
 * slashes are preserved (a `/foo/` may be a legitimate distinct route).
 * Anything that decodes to a control character or null byte is left as-is
 * for the route-not-found branch to handle — we never decode further than
 * URL.pathname's already-normalised form.
 */
function canonicalisePath(rawPath: string): string {
  if (rawPath.length === 0) return "/";
  let i = 0;
  while (i < rawPath.length && rawPath[i] === "/") i++;
  if (i > 1) return "/" + rawPath.slice(i);
  return rawPath;
}

// ---- Main router ---------------------------------------------------------

async function handle(req: Request, env: Env): Promise<Response> {
  const method = req.method;
  const isHead = method === "HEAD";

  // OPTIONS — preflight handling. Respond before any other branching so
  // CORS preflight isn't accidentally routed through the UA classifier.
  if (method === "OPTIONS") {
    return respond(false, 204, buildOptionsHeaders(), null);
  }

  // Non-readonly methods → 405 immediately. The method check WINS over
  // path/UA — POST /install.sh is 405 (not 302/404), so a CSRF-mounted
  // POST never reads the install script even if the path or UA would
  // otherwise classify into the script branch.
  if (method !== "GET" && method !== "HEAD") {
    return respond(false, 405, buildMethodNotAllowedHeaders(), "");
  }

  // Pathological-input guards (E-01). Run AFTER the method check so a
  // POST with a 10 MB UA still gets 405, not 503 — the method shape is
  // the most-restrictive policy (cross-axis tests assert this).
  const refusal = refuseBadInput(req);
  if (refusal !== null) return refusal;

  const url = new URL(req.url);

  // Long-path guard (P-06). Return 414 with a shell-safe body so a
  // misconfigured client piping the response into `sh` sees a no-op.
  if (url.pathname.length > PATH_MAX_LENGTH) {
    return respond(
      isHead,
      414,
      buildShortResponseHeaders(),
      "# worthless-sh: uri-too-long\n",
    );
  }

  const path = canonicalisePath(url.pathname);
  const ua = req.headers.get("user-agent");

  // Route: /.well-known/security.txt — RFC 9116. UA-blind on purpose;
  // researchers run automated scanners that emit arbitrary UAs.
  if (path === "/.well-known/security.txt") {
    const body = buildSecurityTxt();
    return respond(isHead, 200, buildSecurityTxtHeaders(body), body);
  }

  // Route: anything other than `/` → 404. We do NOT serve the install
  // script from `/install.sh` or other conveniences; that would create a
  // parallel install vector that bypasses the cache-key, audit, and
  // "what you see at worthless.sh" trust contract.
  if (path !== "/") {
    return respond(isHead, 404, buildShortResponseHeaders(), "Not Found\n");
  }

  // From here, path is `/`. Branch on UA.
  //
  // Duplicate User-Agent header → fail-safe redirect. `Headers.get()`
  // already collapses to a comma-joined value; if that value ends up
  // not starting with a curl prefix (because of the `Mozilla/...,curl/...`
  // shape), the classifier returns false and we redirect.
  if (!isCurlFamily(ua)) {
    return respond(isHead, 302, buildRedirectHeaders(env.REDIRECT_URL), null);
  }

  // Curl-family branch. ?explain=1 (case-sensitive, exact value `1`) →
  // walkthrough; otherwise the install script.
  if (url.searchParams.get("explain") === "1") {
    const sha = await getWalkthroughSha256();
    return respond(isHead, 200, buildWalkthroughHeaders(sha), WALKTHROUGH);
  }

  const sha = await getInstallSha256();
  return respond(isHead, 200, buildInstallHeaders(env, sha), INSTALL_SH);
}

// ---- Top-level fetch handler --------------------------------------------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handle(req, env);
    } catch {
      // Catastrophic failure path. Emit a shell-safe body — a single
      // comment line — so a `curl | sh` pipeline gets a no-op rather than
      // Cloudflare's default HTML error page (which contains `<` and `>`,
      // both valid shell redirection operators). Routed through
      // `respond()` so HEAD on the error path correctly returns no body
      // with a matching Content-Length header.
      return respond(
        req.method === "HEAD",
        500,
        buildShortResponseHeaders(),
        "# worthless-sh: error\n",
      );
    }
  },
} satisfies ExportedHandler<Env>;

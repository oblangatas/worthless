// User-Agent classifier — strict positive allowlist by exact prefix,
// with composite-UA rejection.
//
// Policy (single source of truth — test/ua-edge-cases.test.ts asserts
// these decisions byte-for-byte):
//
//   1. The UA must START WITH a known curl-family token (`curl/`, `Wget/`,
//      `Go-http-client/`, `Python-urllib/`, `HTTPie/`). Substring matches,
//      composite UAs (`Mozilla/5.0 curl/8.4.0`), BOM-prefixed strings,
//      RTL-overridden strings, and embedded curl tokens in a Mozilla
//      string all fall through to the SAFE branch (302 redirect).
//
//   2. Any control character (`\x00`–`\x1F`, `\x7F`) anywhere in the UA
//      forces the safe branch. This catches NUL polyglots
//      (`curl/8.4.0\x00Mozilla/5.0`), tab/CR/LF injection, etc. workerd
//      may strip these before the Worker sees them; this check is the
//      Worker-layer floor when they are preserved.
//
//   3. Leading whitespace (SP or HTAB) forces the safe branch. workerd
//      may also normalise OWS per RFC 9110, but where it does not, this
//      check defends.
//
//   4. Composite-UA syntax — parentheses, semicolons, or commas — forces
//      the safe branch. Real curl-family UAs are simple `<name>/<version>`
//      tokens, optionally followed by space-delimited library tokens
//      (`curl/8.4.0 (x86_64-pc-linux-gnu)` would be unusual but is
//      rejected here for safety). Browser composite UAs always contain
//      these characters.
//
//   5. Browser/bot identifier substrings (`Mozilla`, `WebKit`, `Chrome`,
//      `bot`, `Bot`, `spider`, `Spider`, `crawl`) anywhere in the UA
//      force the safe branch. This catches `curl/8.4.0 ... Googlebot ...`
//      composites that real curl never emits.
//
//   6. Empty string and undefined → false (fail-safe to redirect).
//
// Why positive allowlist (not denylist of known browsers): scanners,
// proxies, and lab tools rotate UAs faster than any denylist can keep up,
// and the cost of wrongly serving the install script to an unknown UA is
// far higher than the cost of redirecting a legitimate-but-unrecognised
// scripting client to wless.io.

const CURL_FAMILY_PREFIXES = [
  "curl/",
  "Wget/",
  "Go-http-client/",
  "Python-urllib/",
  "HTTPie/",
] as const;

// Composite-UA rejection in a single regex pass:
//   - parens / comma / semicolon: composite-UA grammar markers (real
//     curl-family UAs use space-and-slash only)
//   - browser/bot identifier substrings: `Mozilla`, `WebKit`, `Gecko`,
//     `Chrome`, `Safari`, `Firefox`, `Edge`, `Opera`, `OPR`, `Bot`,
//     `Spider`, `Crawl`. Matched **case-insensitive** because attackers
//     can vary case to bypass the rejection (e.g. `curl/8.4.0 mozilla/5.0`
//     would otherwise fall through this check). Legitimate curl-family
//     library tokens — `OpenSSL`, `zlib`, `nghttp2`, etc. — don't
//     collide with these substrings in any casing.
const COMPOSITE_REJECT =
  /[(),;]|Mozilla|WebKit|Gecko|Chrome|Safari|Firefox|Edge|Opera|OPR|Bot|Spider|Crawl/i;

/**
 * Classify a User-Agent header value as curl-family or not.
 *
 * Returns true ONLY when the UA, treated as an opaque string, starts with
 * one of the allowlisted prefixes, contains no control characters or
 * leading whitespace, and contains none of the composite-UA tokens.
 * False otherwise. Pure, synchronous.
 */
export function isCurlFamily(ua: string | null | undefined): boolean {
  if (ua === null || ua === undefined) return false;
  if (ua.length === 0) return false;

  // Composite-rejection: any control character (incl. NUL, CR, LF, TAB)
  // forces the safe branch. Tab is RFC-allowed OWS but never in a
  // legitimate UA value's content.
  for (let i = 0; i < ua.length; i++) {
    const code = ua.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }

  // Explicit leading-SP rejection — even if RFC OWS-stripping was bypassed
  // by an upstream proxy, defend at this layer. (Leading HTAB caught above.)
  if (ua.charCodeAt(0) === 0x20) return false;

  // Composite-UA grammar markers and browser/bot identifier substrings.
  if (COMPOSITE_REJECT.test(ua)) return false;

  // Strict prefix match — no trim, no lowercase. `CURL/8.4.0` and
  // `  curl/8.4.0` both fail by design.
  for (const prefix of CURL_FAMILY_PREFIXES) {
    if (ua.startsWith(prefix)) return true;
  }
  return false;
}

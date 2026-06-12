# Risk: Reconstructed Key Material in Python Memory

**Status:** Accepted (PoC phase) | **Resolved by:** Rust reconstruction service (Harden phase)

## Description

When the proxy dispatches an upstream request, the reconstructed API key
is converted to a Python `str` via `.decode()` for the HTTP Authorization
header.  This creates an **immutable copy** that cannot be zeroed by
`secure_key` or `_zero_buf`.  The bytearray is zeroed on context manager
exit, but the `str` object persists until Python's garbage collector
reclaims it.

**Location:** `src/worthless/proxy/app.py` - inside the `with secure_key(key_buf)` block,
the adapter's `prepare_request` calls `api_key.decode()`.

## Impact

An attacker with memory read access to the proxy process (`/proc/pid/mem`,
core dump, cold boot) could recover the reconstructed API key from the
Python heap after the request completes.

**Likelihood:** Low - requires local process access or memory dump.
**Severity:** High - full key recovery.
**Risk:** Medium - accepted for PoC, mitigated by operational controls.

## Current Mitigations (PoC)

1. `secure_key` context manager zeros the `bytearray` copy immediately
   after the upstream HTTP call returns.
2. The `str` copy is not assigned to any long-lived variable - it exists
   only as a transient argument to httpx.
3. Python's GC will eventually collect the `str` object (non-deterministic).
4. The proxy runs as a single-purpose process - no untrusted code shares
   the address space.

## Resolution Path (Harden Phase)

The Rust reconstruction service eliminates this risk entirely:

1. **Reconstruction happens in Rust**, not Python.  The key is assembled
   in a `zeroize`-backed struct that overwrites memory on `Drop`.
2. **The upstream HTTP call is made from Rust** directly.  The key never
   crosses a language boundary or enters Python's heap.
3. **Process isolation**: the reconstruction service runs in a distroless
   container with its own memory space.  The Python proxy never has
   access to key material at all.

After the Harden phase, the Python proxy receives only an opaque request
handle - not the key, not the shards, not any secret material.

## Monitoring

Until the Rust service is deployed:

- Do NOT enable core dumps on the proxy process.
- Do NOT attach debuggers or profilers to production proxy instances.
- Run the proxy with `PYTHONDONTWRITEBYTECODE=1` to minimize disk artifacts.
- Ensure the proxy container has no sidecar processes that share the
  memory namespace.

## References

- `SECURITY_RULES.md` SR-02 (explicit memory zeroing)
- `proxy/app.py` line 352 (documented PoC limitation comment)
- Build order: PoC (Python) -> Harden (Rust) -> Attack (pen-test)

# Operations and Maintenance

## Local state

The current implementation relies on local state under the user's home directory, including:

- local database state
- local shard files / metadata
- PID/log/runtime state for daemon mode
- optional keyring-backed storage paths

This local-first model is central to the current product shape and should be assumed by maintainers unless explicitly changing the architecture.

## Primary runtime modes

- one-shot default setup via `worthless`
- explicit lock/unlock/revoke workflows
- foreground proxy via `worthless up`
- daemon proxy via `worthless up -d`
- ephemeral process-scoped proxy via `worthless wrap`

## Environment and configuration surfaces

Common important configuration surfaces include:

- provider `BASE_URL` overrides for wrapped traffic
- proxy port selection
- local allow-insecure behavior for deployments behind trusted TLS terminators
- keyring availability vs file fallback

## Maintainer checks

When changing runtime behavior, verify at least:

- CLI path still matches documented command behavior
- proxy lifecycle commands still work together (`up`, `status`, `down`, `wrap`)
- rules remain gate-before-reconstruct
- metering still records usage for both streaming and non-streaming paths
- error handling still preserves sanitized non-debug behavior

## What not to assume

- Do not assume README or old planning docs fully capture current implementation details.
- Do not assume a rule present in code is active at runtime.
- Do not assume provider SDK wrappers exist; the current model is raw HTTP proxying plus `BASE_URL` routing.

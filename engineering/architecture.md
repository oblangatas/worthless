# Architecture Overview

## System shape

`worthless` is a Python CLI plus a local FastAPI reverse proxy that protects API keys by splitting them into two shards and reconstructing the key only for approved upstream calls.

The current codebase is organized around six main subsystems:

1. `cli/`: user-facing command surface and interactive workflows
2. `proxy/`: gate-before-reconstruct request handling and upstream relay
3. `storage/`: encrypted Shard B repository, schema, and enrollment records
4. `crypto/`: split, reconstruct, secure zeroing, and key material types
5. `adapters/`: provider-specific HTTP/auth translation
6. `mcp/`: optional MCP server integration layered on top of the local proxy model

## Runtime boundaries

### CLI boundary

The CLI entrypoint is `src/worthless/cli/app.py`.

It owns:

- global flags (`--quiet`, `--json`, `--debug`, `--yes`)
- the no-argument default pipeline via `run_default`
- registration of the command modules under `cli/commands/`
- top-level error rendering and debug traceback behavior

### Proxy boundary

The proxy entrypoint is `src/worthless/proxy/app.py`.

It owns:

- FastAPI app lifecycle
- database and repository initialization
- the rules engine wiring
- alias extraction from request paths
- shard extraction from provider auth headers
- gate-before-reconstruct enforcement
- upstream request relay and metering

### Storage boundary

The storage layer is centered on `src/worthless/storage/repository.py` and `src/worthless/storage/schema.py`.

It owns:

- encrypted Shard B storage in SQLite
- enrollment records and decoy hashes
- decryption boundaries for shard retrieval
- migrations and schema initialization

### Crypto boundary

The crypto layer is centered on `src/worthless/crypto/splitter.py` and `src/worthless/crypto/types.py`.

It owns:

- shard splitting and reconstruction
- bytearray-wrapped key material types
- zeroing helpers and SR-01/SR-02-oriented APIs
- format/prefix metadata needed to reconstruct provider-compatible keys

### Adapter boundary

The adapters under `src/worthless/adapters/` map provider-specific HTTP conventions into a shared proxy model.

They own:

- provider path/header translation
- upstream auth header construction
- provider-specific usage extraction support
- adapter lookup through the registry

### MCP boundary

`src/worthless/mcp/server.py` exposes management-oriented integration over MCP.

It is not the core protection path, but it matters for trust boundaries because it can surface operational controls around the same underlying proxy/runtime state.

## Current implementation shape

The current implementation is intentionally Python-first and local-first:

- local process model, not a remote hosted control plane
- SQLite + Fernet for current storage/encryption boundaries
- raw HTTP proxying rather than provider SDK wrappers
- CLI workflows for lock/wrap/up/down/unlock/revoke instead of a first-party SDK

## Important caveats

- The repo still contains architecture and planning material outside `engineering/`; those older docs are not the source of truth for current structure.
- The README currently describes the product accurately at a high level, but many implementation details live only in code and tests.
- Security-specific judgments, control strengths, and gaps belong in `security-audit/`, not here.

# Future Research

Ideas and questions that came up during development but are out of scope for the current phase. Each entry should be evaluated before starting a new milestone.

## Distribution & Installation
- **pipx install worthless** — easiest UX win for global CLI install without venv activation
- **Standalone binary** (PyInstaller/Nuitka) — no Python dependency for end users
- **Homebrew formula** — `brew install worthless`
- **Docker image** — fully contained, useful for CI
- Must it be Python? Go/Rust single binary is a v2 decision

## Security (deferred from Phase 4 audits)
- **OS keychain for fernet.key** — replace plaintext file with Apple Keychain / SecretService (`keyring` library)
- **Fernet → AES-256-GCM with AEAD** — bind alias into ciphertext to prevent cross-alias swapping
- **Rust FFI for key reconstruction** — eliminate Python immutable str copies in memory

## Storage & Scalability
- **Schema migration system** — currently additive-only (CREATE TABLE IF NOT EXISTS). Non-additive changes need ALTER TABLE or migration framework
- **Per-request alias cache in proxy** — avoid filesystem scan on every request. Cache at startup, invalidate on SIGHUP

## UX
- **`worthless down` / `stop` command** — currently users must manually kill daemon
- **Unsupported provider warning in wrap** — wrap silently skips google/xai BASE_URL injection. Should warn.
- **.env parser edge cases** — multiline values, `export` prefix, embedded quotes, quote round-trip stripping

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.x (Python PoC) | Yes, security fixes applied |

## Reporting a Vulnerability

Worthless exists to protect API keys, a vulnerability here has real consequences.

### How to Report

- **Preferred:** [GitHub Private Vulnerability Reporting](https://github.com/shacharm2/worthless/security/advisories/new)
- **Alternative:** Email `security@wless.io`

### Response timeline

Solo maintainer, response time is bounded by real life. Best-effort
acknowledgment within one week. Triage, fix, and coordinated disclosure are
handled proportional to severity; 90 days is the default
coordinated-disclosure window by convention. If a report sits for longer than
two weeks without reply, ping again or escalate publicly.

### Scope

Vulnerabilities in the following areas are in scope:

- **Crypto**, key splitting, reconstruction, commitment scheme, zeroing
- **Proxy**, gate-before-reconstruct bypass, request smuggling, error leakage
- **Storage**, shard encryption at rest, repository access controls
- **CLI**, credential handling, shard exposure, command injection
- **Installer**, the `curl -sSL https://worthless.sh | sh` supply chain. Trust roots and what `install.sh` verifies today: [docs/install-security.md](docs/install-security.md).

### Out of Scope

- Denial of service against the self-hosted proxy (it's your infrastructure)
- Social engineering
- Attacks requiring physical access to the host machine
- Issues in dependencies (report upstream; I'll update promptly)

## Testing Guidelines

As an open-source project, you are encouraged to audit and test the code. Please ensure you:

- Only test against infrastructure and accounts that you own or have explicit permission to test against.
- Report vulnerabilities through the channels above before discussing them publicly, giving me time to patch the code.

## Preferred Languages

English.

## How the split-key model works (in one paragraph)

Your API key is split in two on the client using a format-preserving one-time
pad. Shard A replaces the original key in your `.env`, it looks like a real
key but is cryptographically useless alone. Shard B lives on the proxy,
Fernet-encrypted at rest. Every request hits the rules engine **before** the
key reconstructs: spend cap blown, rate limit exceeded, model not allowed =
the key never forms and the request never leaves the proxy.

## Full threat model

Architectural invariants, known limitations, breach scenarios, forensic
logging gaps, and residual risk: [docs/security.md](docs/security.md).

Contributor invariants (the SR-\* rules enforced by CI):
[CONTRIBUTING-security.md](CONTRIBUTING-security.md).

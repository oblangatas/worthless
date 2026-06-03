# Contributing to Worthless

> Worthless makes API keys worthless to steal. Every contribution should protect that promise.

## Before you open a PR

1. **Sign the [CLA](CLA.md).** No PR is merged without a signed Contributor License Agreement. The first time you open a PR, [CLA Assistant](https://cla-assistant.io/) will prompt you to sign electronically. *(Until CLA Assistant is wired as a required GitHub check, the maintainer will request signature manually before merging.)*

2. **Read [CONTRIBUTING-security.md](CONTRIBUTING-security.md).** These are the non-negotiable security invariants protecting users from key leaks. The pre-commit hooks enforce them; the verifier checks against them. If your change touches `src/worthless/crypto/`, `src/worthless/storage/`, or any code that reconstructs, zeroes, redacts, compares, or logs key material, expect extra review.

3. **Sign off your commits.** Use `git commit -s` to add the `Signed-off-by:` trailer ([Developer Certificate of Origin](https://developercertificate.org/)). The DCO attests provenance, that you wrote (or are authorized to contribute) the code. The CLA grants the license; the DCO attests origin. Both are required.

4. **Make sure pre-commit hooks pass locally.** Run `uv run pre-commit run --files <changed files>` before pushing. The push will be rejected otherwise.

5. **Use a conventional branch name and commit prefix.** Branches: `feature/<slug>`, `fix/<slug>`, `chore/<slug>`, `refactor/<slug>`, `docs/<slug>`, `test/<slug>`. Commit subjects: `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`.

## Reporting a security issue

**Do not open a public issue or PR.** Use GitHub's [Private Vulnerability Reporting](https://github.com/shacharm2/worthless/security/advisories/new) or email `security@wless.io`. See [SECURITY.md](SECURITY.md) for details and expected response.

## Reporting a non-security bug or feature request

Open a [GitHub Issue](https://github.com/shacharm2/worthless/issues). Describe what happened, what you expected, your platform, and minimal steps to reproduce.

## What kinds of changes are welcome

- Bug fixes (with a regression test)
- Documentation improvements
- Test coverage on non-security paths
- Performance work on non-security-critical paths
- Provider-adapter hardening (with snapshots + protocol tests)

## What needs a design discussion first

- Anything touching the three architectural invariants: **client-side splitting**, **gate before reconstruction**, **server-side direct upstream call**. Open an issue describing the change before writing code.
- Anything modifying `CONTRIBUTING-security.md` itself.
- Adding a new provider adapter or a new rule type.

## License of contributions

By contributing, you agree that your Contribution is licensed under the project's [LICENSE](LICENSE) (AGPL-3.0-only) and that you grant the rights described in [CLA.md](CLA.md). The CLA permits the Project Maintainer to also license your Contribution under proprietary or commercial terms, including as part of a commercial hosted service, this is what enables open-core development without violating contributors' rights.

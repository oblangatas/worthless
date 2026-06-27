# User-flow tests

These tests exercise Worthless the way a user experiences it: real CLI command
dispatch, real filesystem writes, real SQLite state, and real keyring access
only when the test explicitly guards for it.

Run them explicitly:

```bash
pytest -m user_flow
```

The default test sweep excludes `user_flow` because these tests can be slower,
can start real subprocesses, and may require platform facilities such as a
native keyring.

For product review and manual UX traceability, see
[`UX_PRODUCT_REPORT.md`](UX_PRODUCT_REPORT.md). Its `WOR-544` section maps the
top-down user journey to pytest proof, terminal traces, CI artifacts, and
explicitly owned gaps. For literal command output, `.env` before/after
snapshots, and redacted terminal proof, see
[`TERMINAL_TRACES.md`](TERMINAL_TRACES.md).
The trace report also includes deterministic install/reinstall/manual-uninstall
guidance evidence for `WOR-441`; checkout-local install proof comes from the
GitHub `Install Smoke (checkout install.sh)` workflow artifacts.
Docker journeys live in the Docker-marked suite, not under this directory:
`tests/test_install_docker.py` covers `WOR-442` clean distro install plus the
host-Worthless/app-container `.env` bridge proof.
For the follow-on destructive-state and platform stress backlog, see
[`STRESS_TEST_MATRIX.md`](STRESS_TEST_MATRIX.md).

Refresh terminal traces with:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python tests/user_flows/render_traces.py \
  --output tests/user_flows/TERMINAL_TRACES.md
```

Rules for new tests:

- Always isolate `WORTHLESS_HOME` under `tmp_path`; never touch the developer's
  real `~/.worthless`.
- Use scanner-safe fake keys from `tests.helpers`.
- Scrub real provider credentials from subprocess environments before invoking
  a child process.
- Guard real keyring tests with `keyring_available()` and clean up with
  `delete_fernet_key(home_dir=...)`.
- Prefer chained assertions over isolated command checks when the regression is
  about a real user journey.
- Keep suite scope aligned with Linear `WOR-439` and its child issues.

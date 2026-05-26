"""Static-content checks on install.sh.

Regression guards for safety/config markers. Complement subprocess tests
in test_install_logic.py and Docker tests in test_install_docker.py.
"""

from __future__ import annotations

import re

import pytest

from tests._install_helpers import INSTALL_FIXTURES, INSTALL_SH, REPO_ROOT


@pytest.fixture(scope="module")
def install_text() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def test_set_eu_present(install_text: str) -> None:
    assert re.search(r"^\s*set\s+-eu\b", install_text, re.MULTILINE), (
        "install.sh must use 'set -eu' to prevent silent-empty-pipe class bugs"
    )


def test_uv_version_pinned(install_text: str) -> None:
    assert re.search(r"\bUV_VERSION\s*=\s*['\"]?\d+\.\d+", install_text), (
        "install.sh must pin UV_VERSION to a specific release"
    )


# --- WOR-558: single-origin + discoverable audit (?explain=1) ----------------


def test_installer_not_leaked_to_website() -> None:
    # The installer is served only by the worthless.sh Worker (one
    # content-negotiated path). A copy under website/ would create a second,
    # unverified install vector on the marketing site — the parallel path the
    # Worker design forbids.
    leaked = REPO_ROOT / "website" / "install.sh"
    assert not leaked.exists(), f"install.sh must never be copied to the marketing site: {leaked}"


def test_explain_audit_discoverable() -> None:
    # ?explain=1 must be findable wherever a cautious dev looks BEFORE running:
    # the install.sh header (piped to `less`), the README, the security doc, the SKILL file.
    header = "\n".join((REPO_ROOT / "install.sh").read_text(encoding="utf-8").splitlines()[:8])
    assert "?explain=1" in header, "install.sh header must point to the ?explain=1 audit mode"
    for rel in ("README.md", "docs/install-security.md", "SKILL.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "?explain=1" in text, f"{rel} must mention the ?explain=1 audit command"


# --- WOR-319: supply-chain pinning of base images + Astral installer SHA -----


def test_dockerfiles_pin_base_image_digests() -> None:
    """Every FROM line in install fixtures must pin to @sha256:<digest>.

    Floating tags (`ubuntu:24.04`, `python:3.13-slim-bookworm`) let a
    compromised upstream ship malware through our install matrix. Pinning
    by sha256 digest makes the supply chain reproducible — the digest is
    the contract, the tag is just a label.
    """
    dockerfiles = sorted(INSTALL_FIXTURES.glob("Dockerfile.*"))
    assert dockerfiles, "expected Dockerfile fixtures under tests/install_fixtures/"

    digest_re = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}\b", re.MULTILINE)
    from_re = re.compile(r"^FROM\s+\S+", re.MULTILINE)

    unpinned: list[str] = []
    for f in dockerfiles:
        text = f.read_text(encoding="utf-8")
        from_lines = from_re.findall(text)
        digest_lines = digest_re.findall(text)
        if len(from_lines) != len(digest_lines):
            unpinned.append(f"{f.name}: {from_lines}")

    assert not unpinned, (
        "install fixtures must pin base images by @sha256 digest — "
        "floating tags allow upstream tampering to enter the matrix.\n"
        "Unpinned FROM lines:\n  " + "\n  ".join(unpinned)
    )


def test_ubuntu_with_uv_pins_astral_installer() -> None:
    """Dockerfile.ubuntu-with-uv must verify the Astral installer SHA.

    A raw `curl … | sh` pipeline executes whatever Astral serves at fetch
    time. The fixture must instead: (1) download to a file, (2) verify
    against the same SHA constant install.sh enforces, (3) only then run.
    Without this, a compromised CDN slips arbitrary code into our test
    matrix even though install.sh itself is hardened.
    """
    dockerfile = INSTALL_FIXTURES / "Dockerfile.ubuntu-with-uv"
    text = dockerfile.read_text(encoding="utf-8")

    # Negative: no `curl … astral.sh … | sh` pipe (raw remote-exec).
    assert not re.search(
        r"curl[^|]*astral\.sh[^|]*\|\s*sh\b",
        text,
    ), (
        "Dockerfile.ubuntu-with-uv must NOT run `curl … astral.sh … | sh` — "
        "fetch to a file and verify SHA256 before executing."
    )

    # Positive: download → sha256 verification → execute.
    assert re.search(r"sha256sum|shasum\s+-a\s+256", text), (
        "Dockerfile.ubuntu-with-uv must verify the downloaded Astral "
        "installer with sha256sum (or shasum -a 256) before running it."
    )

    # Positive: SHA constant is sourced from install.sh, not a copy.
    # We `awk` it out of the on-disk install.sh so a UV_VERSION bump in
    # install.sh propagates into the fixture without manual edits.
    assert re.search(r"ASTRAL_INSTALLER_SHA256", text), (
        "Dockerfile.ubuntu-with-uv must reference ASTRAL_INSTALLER_SHA256 "
        "(extracted from install.sh) so the SHA stays in lockstep."
    )


# --- WOR-320: BuildKit cache mount for uv downloads --------------------------


def _run_blocks(dockerfile_text: str) -> list[str]:
    """Return each RUN command in a Dockerfile as a single string.

    A RUN command spans the `RUN` line plus any `\\`-continuation lines.
    It ends when a line not ending in `\\` is reached. CMD / COPY lines
    that follow the RUN do NOT belong to it.
    """
    blocks: list[str] = []
    lines = dockerfile_text.splitlines()
    i = 0
    while i < len(lines):
        if re.match(r"^RUN\b", lines[i]):
            buf: list[str] = []
            while i < len(lines):
                stripped = lines[i].rstrip()
                continuation = stripped.endswith("\\")
                buf.append(stripped[:-1].rstrip() if continuation else stripped)
                i += 1
                if not continuation:
                    break
            blocks.append(" ".join(buf))
        else:
            i += 1
    return blocks


def _run_clauses(dockerfile_text: str) -> list[tuple[str, str]]:
    """Return (block, clause) pairs for each command inside RUN blocks.

    A multi-clause RUN (chained with `&&` or `;`) splits into one clause
    per command so `chmod +x install.sh` and `sh /work/install.sh` are
    classified independently. The full block is returned alongside so
    callers can locate the cache-mount directive (which lives on the
    RUN keyword, not inside individual clauses).
    """
    pairs: list[tuple[str, str]] = []
    for block in _run_blocks(dockerfile_text):
        body = block[3:]  # drop leading "RUN"
        for clause in re.split(r"&&|;", body):
            clause = clause.strip()
            if clause:
                pairs.append((block, clause))
    return pairs


def test_dockerfiles_use_uv_cache_mount() -> None:
    """Build-time RUN that runs uv must use BuildKit cache mount.

    /root/.cache/uv holds Astral installer downloads + Python bootstrap
    tarballs (PBS) + wheel cache. Without the cache mount, every matrix
    run re-fetches the same MB-sized payloads from astral.sh, slowing CI
    and exposing us to upstream rate limits.

    Scope: any Dockerfile fixture with a build-time RUN that executes
    install.sh, the Astral installer, or a `uv …` command. CMD-only
    fixtures (where install.sh runs at container start) are skipped —
    BuildKit cache mounts apply at build time only.
    """
    dockerfiles = sorted(INSTALL_FIXTURES.glob("Dockerfile.*"))
    cache_mount_re = re.compile(
        r"--mount=type=cache,target=/root/\.cache/uv\b",
    )
    syntax_directive_re = re.compile(r"^#\s*syntax=docker/dockerfile:1\.\d", re.MULTILINE)

    # A RUN clause is "uv-running" if its FIRST verb executes install.sh,
    # downloads the Astral installer, runs the installer, or invokes a
    # `uv` subcommand. Anchoring at the start of a clause excludes
    # chmod-on-install.sh (sets bits) and `! command -v uv` (sentinel).
    # The `(?:\S+/)?install\.sh\b` shape pins the WHOLE filename — earlier
    # `\S*install\.sh` would over-match `verify_install.sh` if it ever
    # appeared as the verb of a RUN clause.
    uv_run_re = re.compile(
        r"^(?:sh|bash)\s+(?:\S+/)?install\.sh\b"  # `sh /work/install.sh`
        r"|^(?:sh|bash)\s+(?:\S+/)?uv-installer\.sh\b"  # `sh /tmp/uv-installer.sh`
        r"|astral\.sh/uv/"  # downloading from astral
        r"|^/\S*\.local/bin/uv\s"  # running the installed binary
        r"|^uv\s+(?:tool|install|sync|run|cache|venv|python|self)\b"
    )

    missing: list[str] = []
    for f in dockerfiles:
        text = f.read_text(encoding="utf-8")
        uv_blocks = sorted(
            {block for block, clause in _run_clauses(text) if uv_run_re.search(clause)}
        )
        if not uv_blocks:
            continue  # CMD-only fixture — cache mount doesn't apply
        # EVERY uv-running RUN block must carry the cache mount, not just one.
        # `any` here would silently allow a mixed fixture (one mounted RUN + one
        # unmounted RUN) where the unmounted RUN keeps re-fetching from astral.
        unmounted = [b for b in uv_blocks if not cache_mount_re.search(b)]
        if unmounted:
            missing.append(
                f"{f.name}: {len(unmounted)} of {len(uv_blocks)} uv-running RUN "
                "block(s) without cache mount"
            )
            continue
        if not syntax_directive_re.search(text):
            missing.append(
                f"{f.name}: cache mount used but `# syntax=docker/dockerfile:1.x` "
                "directive missing — RUN --mount requires the directive"
            )

    assert not missing, (
        "Build-time RUN steps invoking uv must mount the BuildKit cache:\n  " + "\n  ".join(missing)
    )


# --- WOR-318: non-root user fixture ------------------------------------------


def test_nonroot_fixture_exists() -> None:
    """A hardened non-root container must be in the install matrix.

    install.sh writes to ~/.local/bin and ~/.cache/uv — both rooted at
    $HOME — so it should already work for non-root users. This fixture
    proves it: a `worthless` UID under `useradd` (no sudo, no root)
    completes install and ends up with the binary on PATH.

    The actual matrix wiring lives in tests/test_install_docker.py
    INSTALL_MATRIX. This static guard pins the file's existence and
    minimal shape so the matrix entry can never reference a missing
    fixture.
    """
    dockerfile = INSTALL_FIXTURES / "Dockerfile.ubuntu-nonroot"
    assert dockerfile.is_file(), (
        f"missing fixture: {dockerfile.name} — non-root install must be in the matrix"
    )

    text = dockerfile.read_text(encoding="utf-8")
    assert re.search(r"^RUN\s+useradd\b", text, re.MULTILINE), (
        f"{dockerfile.name} must `useradd` a non-root user before `USER` switch"
    )
    assert re.search(r"^USER\s+worthless\b", text, re.MULTILINE), (
        f"{dockerfile.name} must drop privileges via `USER worthless`"
    )


# --- WOR-317: idempotency — second install.sh run is a no-op ----------------


def test_idempotency_fixture_wired() -> None:
    """Idempotency check must be present in the install matrix.

    A re-run of `curl … | sh` must not bump the installed version, must
    not re-download wheels, must not change the binary hash. This guards
    the "safe to put in CI" promise — re-running the installer on every
    job must be cheap and deterministic.

    Pins both the Dockerfile and the verify script so the matrix entry
    can never reference a half-built fixture.
    """
    dockerfile = INSTALL_FIXTURES / "Dockerfile.ubuntu-idempotency"
    verify = INSTALL_FIXTURES / "verify_idempotency.sh"

    assert dockerfile.is_file(), f"missing fixture: {dockerfile.name}"
    assert verify.is_file(), f"missing fixture: {verify.name}"

    df_text = dockerfile.read_text(encoding="utf-8")
    sh_text = verify.read_text(encoding="utf-8")

    # The fixture must pin WORTHLESS_VERSION so PyPI drift between the
    # two install.sh runs cannot false-fail the diff.
    assert re.search(r"^ENV\s+WORTHLESS_VERSION=", df_text, re.MULTILINE), (
        f"{dockerfile.name} must `ENV WORTHLESS_VERSION=…` so a new release "
        "between the two runs cannot make the diff drift."
    )

    # Verify script must run install.sh twice and diff snapshots.
    assert sh_text.count("install.sh") >= 2, (
        f"{verify.name} must invoke install.sh at least twice (idempotency check)"
    )
    assert re.search(r"\bdiff\b", sh_text), (
        f"{verify.name} must `diff` the two snapshots — the test signal "
        "is non-zero diff between snapshot 1 and snapshot 2."
    )
    assert re.search(r"FAIL.*idempoten[ct]", sh_text, re.IGNORECASE), (
        f"{verify.name} must emit a 'FAIL: …idempoten…' message on diff "
        "so a regression is grep-able in CI logs."
    )


def test_idempotency_marker_matches_python_dict() -> None:
    """Drift guard: the success marker the verify script emits must match
    the marker the test runner asserts on.

    `tests/test_install_docker.py` imports SUCCESS_MARKER and checks for
    `"OK: install.sh is idempotent"` in run.stdout. `verify_idempotency.sh`
    `echo`s a corresponding success line. If either side gets edited
    without the other, the test silently asserts on a string the script
    never prints (false-pass risk).
    """
    from tests.test_install_docker import SUCCESS_MARKER

    expected = SUCCESS_MARKER["ubuntu-idempotency"]
    verify = INSTALL_FIXTURES / "verify_idempotency.sh"
    sh_text = verify.read_text(encoding="utf-8")
    assert expected in sh_text, (
        f"SUCCESS_MARKER['ubuntu-idempotency']={expected!r} but "
        f"{verify.name} does not echo that exact string. The test would "
        "false-pass if the script changes its success message without "
        "updating SUCCESS_MARKER, or vice versa."
    )


def test_worthless_version_pinned(install_text: str) -> None:
    """WOR-559: default install pins a baked version — never unpinned latest.

    install.sh declares `WORTHLESS_VERSION_PIN="x.y.z"` (bumped per release,
    vouched for by the signed tag at deploy) and installs `worthless==<that>`.
    The `WORTHLESS_VERSION` env var still overrides. Both sources are
    validated against a PEP-440-ish charset before reaching `uv tool install`.
    """
    # Positive: a concrete baked pin literal exists.
    assert re.search(r'^WORTHLESS_VERSION_PIN="\d+\.\d+\.\d+', install_text, re.MULTILINE), (
        'install.sh must declare a concrete WORTHLESS_VERSION_PIN="x.y.z" '
        "default (WOR-559) so the default install is pinned, not latest."
    )
    # Positive: the spec installed is always pinned with `==`.
    assert re.search(r'spec="worthless==\$\{?effective_version\}?"', install_text), (
        'install.sh must build a pinned spec: spec="worthless==${effective_version}"'
    )
    # Positive: override precedence — WORTHLESS_VERSION wins over the pin.
    assert re.search(
        r'effective_version="\$\{WORTHLESS_VERSION:-\$WORTHLESS_VERSION_PIN\}"',
        install_text,
    ), (
        "install.sh must resolve effective_version as "
        "${WORTHLESS_VERSION:-$WORTHLESS_VERSION_PIN} (override beats pin)."
    )
    # Negative: never installs or upgrades an unpinned `worthless` IN CODE.
    # (Comments legitimately mention the old `uv tool install worthless` /
    # `uv tool upgrade` patterns to explain why they're forbidden.)
    code_lines = "\n".join(
        line for line in install_text.splitlines() if not line.lstrip().startswith("#")
    )
    assert not re.search(r"uv tool install[^\n]*\bworthless\b(?!==)", code_lines), (
        "install.sh must never `uv tool install worthless` without `==<version>`."
    )
    assert "uv tool upgrade" not in code_lines, (
        "install.sh must not run `uv tool upgrade` — it resolves PyPI latest, "
        "re-opening the supply-chain window. Use `uv tool install --force`."
    )
    # Positive: input validator (defends against shell metachars and
    # arg-confusion before `uv tool install` is invoked).
    assert re.search(r"\[\!0-9A-Za-z\.\+\!-\]", install_text), (
        "install.sh must validate the effective version against a PEP-440-ish "
        "charset (POSIX case pattern with bracket negation)."
    )
    # Positive: fail-closed on an empty/unset pin (no silent latest fallback).
    assert re.search(r"Refusing to install an unpinned", install_text), (
        "install.sh must FAIL CLOSED when no version is pinned — never fall "
        "back to unpinned latest."
    )


def test_pin_not_ahead_of_pyproject() -> None:
    """The baked pin tracks the latest PUBLISHED release, so it must never
    point AHEAD of the in-prep pyproject version (you can't have published a
    version that doesn't exist yet). Offline guard against a typo'd/future
    pin; the "pin == latest PyPI" freshness check lives in release-sync-check
    (needs network, so it runs in CI, not here).
    """
    import sys

    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    from packaging.version import Version

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pyproject_version = pyproject["project"]["version"]

    match = re.search(
        r'^WORTHLESS_VERSION_PIN="([^"]*)"',
        INSTALL_SH.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, "install.sh must declare WORTHLESS_VERSION_PIN"
    pin = match.group(1)
    assert Version(pin) <= Version(pyproject_version), (
        f"install.sh pin {pin!r} is ahead of pyproject version "
        f"{pyproject_version!r} — the pin must be a version that's actually "
        "been released (≤ the in-prep version)."
    )


def test_pin_is_valid_pep440(install_text: str) -> None:
    """The baked pin must itself satisfy the same PEP-440-ish charset the
    script validates against — a malformed pin should never ship."""
    match = re.search(r'^WORTHLESS_VERSION_PIN="([^"]*)"', install_text, re.MULTILINE)
    assert match, "install.sh must declare WORTHLESS_VERSION_PIN"
    pin = match.group(1)
    assert pin, "baked pin must be non-empty (fail-closed default is dev-only)"
    assert re.fullmatch(r"[0-9A-Za-z.+!-]+", pin), (
        f"baked pin {pin!r} contains characters outside [0-9A-Za-z.+!-]"
    )


def test_sha256_verification_referenced(install_text: str) -> None:
    assert re.search(r"sha256", install_text, re.IGNORECASE), (
        "install.sh must reference SHA256 verification of the Astral installer"
    )


def test_distinct_exit_codes(install_text: str) -> None:
    """Named constants for network/platform/pipx-conflict/internal (UX contract)."""
    for name, code in [
        ("EXIT_NETWORK", 10),
        ("EXIT_PLATFORM", 20),
        ("EXIT_PIPX_CONFLICT", 30),
        ("EXIT_INTERNAL", 40),
    ]:
        assert re.search(rf"^\s*{name}\s*=\s*{code}\b", install_text, re.MULTILINE), (
            f"install.sh must declare {name}={code} as a named exit-code constant"
        )


def test_uv_python_preference_only_managed(install_text: str) -> None:
    assert "UV_PYTHON_PREFERENCE" in install_text, (
        "install.sh must set UV_PYTHON_PREFERENCE for reproducibility"
    )
    assert "only-managed" in install_text, (
        "UV_PYTHON_PREFERENCE must be 'only-managed' (not 'managed') for fresh-box reliability"
    )


def test_per_shell_activation_messages(install_text: str) -> None:
    for shell in ("bash", "zsh", "fish"):
        assert shell in install_text, (
            f"install.sh must include {shell}-specific activation guidance"
        )


def _extract_shell_function(text: str, name: str) -> str:
    """Return the body of a POSIX-sh function definition `name() { ... }`."""
    match = re.search(rf"^{re.escape(name)}\s*\(\)\s*\{{(.*?)^\}}", text, re.DOTALL | re.MULTILINE)
    assert match, f"Expected function {name}() to be defined in install.sh"
    return match.group(1)


def test_wsl_allowed_not_rejected(install_text: str) -> None:
    """WSL2 must be allowed; only /mnt/c gets a warning (OS + UX)."""
    body = _extract_shell_function(install_text, "detect_linux_subenv")
    lower = body.lower()
    assert "microsoft" in lower or "wsl" in lower, (
        "detect_linux_subenv() must detect WSL via /proc/version"
    )
    assert re.search(r"\bdie\b", body) is None, (
        "WSL2 detection must NOT call die() — only /mnt/c gets a warning"
    )
    assert "exit " not in body, "WSL2 detection must NOT exit non-zero — WSL2 is supported"


def test_pipx_conflict_detection(install_text: str) -> None:
    assert "pipx" in install_text, "install.sh must detect pre-existing pipx-installed worthless"


def test_macos_min_version_check(install_text: str) -> None:
    assert "sw_vers" in install_text, "install.sh must use sw_vers to enforce macOS >=11 minimum"


def test_curl_fail_retry(install_text: str) -> None:
    assert "--fail" in install_text, "curl must use --fail to error on HTTP 4xx/5xx"
    assert "--retry" in install_text, "curl must use --retry for transient failures"


def test_idempotent_install_path(install_text: str) -> None:
    """Re-runs stay idempotent without ever resolving latest.

    Mechanism (WOR-559): a fast-path that short-circuits when the installed
    version already equals the resolved version, plus `uv tool install
    --force` for the pin-bump case. The old `uv tool upgrade` path resolved
    PyPI latest and was removed.
    """
    assert "uv tool install --force" in install_text, (
        "install.sh must use `uv tool install --force` for idempotent re-runs "
        "and pin bumps (stays pinned, unlike `uv tool upgrade`)."
    )
    assert "already installed" in install_text, (
        "install.sh must keep the fast-path that short-circuits when the "
        "resolved version is already installed (idempotency)."
    )


def test_doctor_breadcrumb_printed(install_text: str) -> None:
    assert "worthless doctor" in install_text, (
        "install.sh must end with 'Run worthless doctor if anything looks off' breadcrumb"
    )


def test_proxy_remediation_hints(install_text: str) -> None:
    assert any(
        marker in install_text
        for marker in ("HTTPS_PROXY", "UV_PYTHON_INSTALL_MIRROR", "SSL_CERT_FILE")
    ), "install.sh must surface proxy/mirror remediation hints on network failures"


def test_smoke_test_uses_uv_run_version(install_text: str) -> None:
    """Smoke test stays stateless — 'worthless lock' would bootstrap state we don't own."""
    assert "uv run worthless" in install_text or "worthless --version" in install_text, (
        "install.sh must smoke-test via 'uv run worthless --version' (PATH-independent)"
    )
    # Scope the "no stateful smoke" invariant to the smoke_test() function
    # body. The user-facing post-install banner legitimately mentions
    # `worthless lock` as a "Try it" hint — that is not a smoke-test action,
    # and a whole-script grep falsely flagged it. Pin the structural
    # contract: the function exists AND its body contains no `worthless lock`.
    smoke_match = re.search(
        r"^smoke_test\(\)\s*\{(.+?)^\}",
        install_text,
        re.MULTILINE | re.DOTALL,
    )
    assert smoke_match is not None, (
        "could not locate `smoke_test()` function in install.sh — "
        "test needs updating if the function was renamed"
    )
    smoke_body = smoke_match.group(1)
    assert "worthless lock" not in smoke_body, (
        "Do NOT smoke-test with 'worthless lock' — too stateful for an installer"
    )


def test_install_smoke_uploads_terminal_artifacts() -> None:
    """WOR-441 live install proof must leave CI logs as downloadable artifacts."""
    workflow = REPO_ROOT / ".github" / "workflows" / "install-smoke.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "actions/upload-artifact" in text, (
        "install-smoke.yml must upload terminal traces/artifacts so the PR proves "
        "what live install.sh printed on each OS runner."
    )
    assert "install-smoke-traces" in text, (
        "install-smoke.yml artifact name should be grep-able as install-smoke-traces."
    )
    assert "install-smoke-traces-${{ matrix.os }}-${{ github.run_id }}" in text, (
        "live matrix artifact names must use matrix.os, not runner.os, so "
        "macos-14/macos-15 and ubuntu-22.04/ubuntu-24.04 uploads do not collide."
    )
    assert "install-smoke-traces-${{ runner.os }}-${{ github.run_id }}" not in text, (
        "runner.os collapses macos-14/macos-15 and ubuntu-22.04/ubuntu-24.04 "
        "into duplicate artifact names under upload-artifact@v4."
    )
    assert "install-smoke-traces-proxy-${{ github.run_id }}" in text, (
        "proxy install proof should upload a separate artifact from the OS matrix."
    )
    assert "tee install-smoke-traces/" in text, (
        "install.sh steps must tee command output into install-smoke-traces/ before upload."
    )


# --- WOR-568: public install proof must not be overclaimed -------------------


def test_install_smoke_name_matches_checkout_local_proof() -> None:
    """Workflow + job labels must not overclaim public install proof.

    A PR reviewer reads the GitHub checks list, which shows
    `<workflow name> / <job name>`. Per-PR CI runs checkout-local
    `sh ./install.sh`, not public `curl https://worthless.sh | sh` (which hits
    the deployed Worker and is a release/manual gate). So neither the workflow
    name nor any job name may carry public-domain `curl|sh` / `worthless.sh`
    wording or the ambiguous standalone word "live" while CI stays
    checkout-local. If the workflow is changed to run the public command, a
    label must say so explicitly.
    """
    workflow = REPO_ROOT / ".github" / "workflows" / "install-smoke.yml"
    text = workflow.read_text(encoding="utf-8")

    # Strip comments so a clarifying comment that *mentions* the public command
    # cannot flip detection and force a misleading rename.
    non_comment = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    runs_public_curl = bool(
        re.search(r"curl\s+(?:-\S+\s+)*https://worthless\.sh\s*\|\s*sh", non_comment)
    )

    # Workflow name (col 0) + each job name (indented). Step `- name:` lines have
    # a leading dash and are intentionally excluded — they are not check labels.
    labels = re.findall(r"^[ \t]*name:[ \t]*(.+)$", text, re.MULTILINE)
    assert labels, "install-smoke.yml must define a workflow name and job names"

    if not runs_public_curl:
        for label in labels:
            low = label.lower()
            assert (
                "curl|sh" not in low
                and "worthless.sh" not in low
                and not re.search(r"\blive\b", low)
            ), (
                f"install-smoke.yml label {label!r} overclaims public-domain "
                "proof, but CI runs checkout-local `sh ./install.sh`. Use "
                "checkout-local/execute wording (no `live`, `curl|sh`, or "
                "`worthless.sh` in workflow/job names)."
            )
    else:
        assert any(
            "worthless.sh" in label.lower() or "curl|sh" in label.lower() for label in labels
        ), (
            "if install-smoke.yml is changed to run public "
            "`curl -sSL https://worthless.sh | sh`, a workflow/job name should "
            "say that explicitly."
        )


def test_public_curl_manual_gate_requires_terminal_evidence() -> None:
    """The public worthless.sh gate must require pasteable terminal output.

    A checked box that says "I ran curl" is weak product proof. The manual
    release gate must preserve the actual install output, version output, and
    any failure wording, recorded somewhere durable, so a top-down UX review
    can trace the public journey back to evidence.
    """
    manual = INSTALL_FIXTURES / "MANUAL_SMOKE.md"
    text = manual.read_text(encoding="utf-8")
    normalized = text.lower()

    assert "curl -sSL https://worthless.sh | sh" in text, (
        "MANUAL_SMOKE.md must preserve the canonical copy-paste public "
        "install command with curl's case-sensitive `-sSL` flags."
    )
    assert "terminal output" in normalized or "terminal transcript" in normalized, (
        "MANUAL_SMOKE.md must require copy-pasted terminal output/transcript "
        "for public `curl https://worthless.sh | sh` release proof."
    )
    assert "--version" in text, (
        "MANUAL_SMOKE.md public evidence must include version output (`worthless --version`)."
    )
    assert (
        "linear" in normalized
        or "pull request" in normalized
        or "release notes" in normalized
        or re.search(r"\bpr\b", normalized) is not None
    ), (
        "public curl proof must say where the terminal evidence is recorded "
        "(Linear, PR, or release notes), not just local memory."
    )

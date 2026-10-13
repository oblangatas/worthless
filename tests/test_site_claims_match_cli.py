"""C2-C6: the CLI behaviors wless.io describes in words.

Every assertion here mirrors a sentence the website says out loud. If the CLI
stops behaving this way the website is lying to visitors, and this file goes
red. That is the entire point: launch copy cannot silently drift away from
the product the way it did between June and October 2026.

The CLI under test is the PUBLISHED release. ``install.sh`` runs at image
build time inside ``Dockerfile.debian-12-lock-e2e``, so what these tests
exercise is what ``curl https://worthless.sh | sh`` gives a visitor today --
not the working tree.

Does NOT cover: a CLI change landing on ``main`` that contradicts the copy
before it is released. That gap stays open until the next release by design --
closing it the other way would let the site describe software nobody can
install yet. ``src/worthless/cli/**`` is in this lane's detect paths, so a
CLI change still re-runs these tests; it just grades them against the last
published build.

Isolation: one container per test (``--network none``), so no test can see
another's keys, proxy or ``~/.worthless``. The image build is shared.

Marked ``docker`` (excluded from the default pytest run via pyproject.toml).
Run with: pytest -m docker tests/test_site_claims_match_cli.py
"""

from __future__ import annotations

import base64
import os
import subprocess
import uuid
from dataclasses import dataclass

import pytest

from tests._docker_helpers import docker_available
from tests._install_helpers import INSTALL_FIXTURES, REPO_ROOT
from tests.helpers import fake_anthropic_key, fake_key, fake_openai_key

pytestmark = pytest.mark.docker

# Reuse the lock-lifecycle image: it already installs the published release
# via install.sh. A second Dockerfile would be a second thing to keep honest.
DOCKERFILE = INSTALL_FIXTURES / "Dockerfile.debian-12-lock-e2e"
IMAGE_TAG = "worthless-site-claims:pytest"

PROXY_PORT = 8787
PROJECT_DIR = "/work/siteclaims"
ENV_PATH = f"{PROJECT_DIR}/.env"
WORTHLESS_HOME = "/root/.worthless"
# Sibling of PROJECT_DIR, not inside it: `lock` offers a code scan of the
# working directory, and the proxy log has no business being part of that.
UP_LOG = "/work/up.log"

BUILD_S = 900
EXEC_S = 180
# Generous per-test cap: the global pytest timeout is 30s and it KILLS the
# whole xdist session, so every docker-marked case must set its own.
CASE_TIMEOUT = 420

# Prefixes are split so secret scanners don't flag this file, matching the
# convention in tests/helpers.py.
GEMINI_PREFIX = "AIza" + "Sy"


def fake_gemini_key() -> str:
    """A Google AI Studio key shape. High entropy: ``scan_env_keys`` drops
    low-entropy values as placeholders, so a repetitive literal would be
    invisible to the scanner and prove nothing."""
    return GEMINI_PREFIX + fake_key("", seed="gemini-site-claims-seed")[:33]


def _fmt(proc: subprocess.CompletedProcess[str]) -> str:
    return f"rc={proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"


def _build_args() -> list[str]:
    """``--build-arg WORTHLESS_VERSION=<v>`` only when CI set it.

    On a release PR the baked pin isn't on PyPI yet, so install.sh would fail.
    CI sets WORTHLESS_VERSION to the latest published release; on push/tag it
    is unset and the baked pin is exercised instead. Same contract as
    tests/test_install_docker.py.
    """
    version = os.environ.get("WORTHLESS_VERSION")
    return ["--build-arg", f"WORTHLESS_VERSION={version}"] if version else []


@pytest.fixture(scope="session")
def site_claims_image() -> str:
    """Build the published-release image once for the whole module."""
    if not docker_available():
        pytest.skip("docker unavailable")
    assert DOCKERFILE.is_file(), f"missing fixture: {DOCKERFILE}"
    build = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "-f",
            str(DOCKERFILE),
            "-t",
            IMAGE_TAG,
            *_build_args(),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        timeout=BUILD_S,
        check=False,
    )
    assert build.returncode == 0, f"image build failed:\n{_fmt(build)}"
    return IMAGE_TAG


@dataclass(frozen=True)
class Cli:
    """A throwaway container running the published CLI."""

    container: str

    def sh(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["docker", "exec", "-w", PROJECT_DIR, self.container, "sh", "-c", script],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=EXEC_S,
            check=False,
        )

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["docker", "exec", "-w", PROJECT_DIR, self.container, "worthless", *args],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=EXEC_S,
            check=False,
        )

    def spawn(self, script: str) -> None:
        """Start a long-lived process (the proxy) and return immediately."""
        subprocess.run(  # noqa: S603
            ["docker", "exec", "-d", "-w", PROJECT_DIR, self.container, "sh", "-c", script],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=EXEC_S,
            check=False,
        )

    def write_env(self, text: str, *, mode: str = "644") -> None:
        """Write .env as exact bytes (base64 avoids any shell quoting risk)."""
        blob = base64.b64encode(text.encode()).decode()
        script = (
            f'python3 -c "import base64,pathlib;'
            f"pathlib.Path('{ENV_PATH}').write_bytes(base64.b64decode('{blob}'))\" && "
            f"chmod {mode} {ENV_PATH}"
        )
        result = self.sh(script)
        assert result.returncode == 0, _fmt(result)

    def read_env(self) -> str:
        result = self.sh(f"cat {ENV_PATH}")
        assert result.returncode == 0, _fmt(result)
        return result.stdout

    def env_digest(self) -> str:
        result = self.sh(f"sha256sum {ENV_PATH}")
        assert result.returncode == 0, _fmt(result)
        return result.stdout.split()[0]

    def env_mode(self) -> str:
        result = self.sh(f"stat -c %a {ENV_PATH}")
        assert result.returncode == 0, _fmt(result)
        return result.stdout.strip()

    def port_state(self, port: int) -> int:
        """``connect_ex`` on loopback: 0 means something IS listening."""
        probe = (
            "import socket,sys;s=socket.socket();s.settimeout(1);"
            f"sys.stdout.write(str(s.connect_ex(('127.0.0.1',{port}))))"
        )
        result = self.sh(f'python3 -c "{probe}"')
        assert result.returncode == 0, _fmt(result)
        return int(result.stdout.strip())

    def wait_for_port(self, port: int, *, deadline_s: float = 45.0) -> bool:
        probe = (
            "import socket,sys,time\n"
            f"deadline=time.monotonic()+{deadline_s}\n"
            "while time.monotonic()<deadline:\n"
            "    s=socket.socket(); s.settimeout(1)\n"
            f"    rc=s.connect_ex(('127.0.0.1',{port})); s.close()\n"
            "    if rc==0: sys.stdout.write('up'); raise SystemExit(0)\n"
            "    time.sleep(0.5)\n"
            "sys.stdout.write('down')\n"
        )
        blob = base64.b64encode(probe.encode()).decode()
        result = self.sh(f"python3 -c \"import base64;exec(base64.b64decode('{blob}').decode())\"")
        return result.stdout.strip() == "up"

    def start_proxy(self) -> None:
        self.spawn(f"worthless up > {UP_LOG} 2>&1")

    def up_log(self) -> str:
        return self.sh(f"cat {UP_LOG} 2>&1").stdout


@pytest.fixture
def cli(site_claims_image: str) -> Cli:
    """A fresh container per test. Teardown is unconditional."""
    name = f"worthless-siteclaims-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    start = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            # No network: these claims are all local. Nothing here needs an
            # upstream, and a sealed container can't reach a real provider
            # even if a fake key somehow looked real.
            "--network",
            "none",
            site_claims_image,
            "sleep",
            "infinity",
        ],
        capture_output=True,
        text=True,
        timeout=EXEC_S,
        check=False,
    )
    assert start.returncode == 0, f"container start failed:\n{_fmt(start)}"
    try:
        # `docker exec -w DIR` chdirs BEFORE the command runs, so the project
        # dir has to exist before any other exec in this module can work.
        mkdir = subprocess.run(  # noqa: S603
            ["docker", "exec", name, "mkdir", "-p", PROJECT_DIR],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=EXEC_S,
            check=False,
        )
        assert mkdir.returncode == 0, f"could not create {PROJECT_DIR}:\n{_fmt(mkdir)}"
        yield Cli(container=name)
    finally:
        subprocess.run(  # noqa: S603
            ["docker", "rm", "-f", name],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=EXEC_S,
            check=False,
        )


def _single_key_env() -> str:
    return f"OPENAI_API_KEY={fake_openai_key()}\n"


# --------------------------------------------------------------------------
# C2 -- what `lock` does, and what it does NOT do
# --------------------------------------------------------------------------
@pytest.mark.timeout(CASE_TIMEOUT)
def test_lock_names_the_next_command_and_starts_no_proxy(cli: Cli) -> None:
    """Pins the site's setup steps and kills three false claims at once.

    The copy must say: install, then ``worthless lock``, then
    ``worthless wrap <command>``. NOT "two commands" (blog/index.html:213,
    261-263) and NOT the installer's "lock ... starts a local proxy"
    (install.sh:658-659), which is false -- nothing listens until `up`/`wrap`.

    Red when: lock stops printing the next-step hint (lock.py:2436), starts
    listening on the proxy port itself, or stops pointing .env at that port.
    """
    cli.write_env(_single_key_env())

    lock = cli.run("lock", "--env", ENV_PATH)
    assert lock.returncode == 0, _fmt(lock)
    out = lock.stdout + lock.stderr

    # The site tells the visitor what to run next, so lock must say it too.
    assert "worthless wrap <command>" in out, out
    assert "worthless up" in out, out

    # The load-bearing negative: "lock starts a local proxy" is FALSE.
    assert cli.port_state(PROXY_PORT) != 0, (
        f"`worthless lock` left something listening on {PROXY_PORT}. The site "
        "and installer both say the proxy starts later, with `up` or `wrap`."
    )

    # ...but .env is already pointed at where the proxy WILL be.
    env = cli.read_env()
    assert f"OPENAI_BASE_URL=http://127.0.0.1:{PROXY_PORT}/openai-" in env, env

    # Where the other half goes is platform-dependent (lock.py:119): a system
    # keystore when one exists, a local key file otherwise. The how-it-works
    # and privacy copy must describe BOTH branches, never just ~/.worthless.
    assert ("a local key file" in out) or ("your system keystore" in out), out


# --------------------------------------------------------------------------
# C3 -- `up` is what actually starts the proxy
# --------------------------------------------------------------------------
@pytest.mark.timeout(CASE_TIMEOUT)
def test_up_is_what_actually_starts_the_proxy(cli: Cli) -> None:
    """Pins the other half of C2's division of labour.

    Red when: `up` no longer brings the proxy up on the documented port --
    which would make the site's setup steps unfollowable.
    """
    cli.write_env(_single_key_env())
    assert cli.run("lock", "--env", ENV_PATH).returncode == 0

    assert cli.port_state(PROXY_PORT) != 0, "something was listening before `up` ran"

    cli.start_proxy()
    assert cli.wait_for_port(PROXY_PORT), f"`worthless up` never listened:\n{cli.up_log()}"
    assert f"127.0.0.1:{PROXY_PORT}" in cli.up_log(), cli.up_log()


# --------------------------------------------------------------------------
# C4 -- `unlock` restores the file; the proxy keeps running
# --------------------------------------------------------------------------
@pytest.mark.timeout(CASE_TIMEOUT)
def test_unlock_restores_the_file_byte_for_byte_but_leaves_the_proxy_running(
    cli: Cli,
) -> None:
    """The site currently says "Original .env restored. Proxy gone. Shares
    deleted." (how-it-works.html:256-257, features.html:188). One of those is
    true and one is false, and "exactly as it was" is false about permissions.

    Proven here: contents come back byte-for-byte, the mode stays owner-only
    (644 -> 600 -> 600, NOT restored), and the proxy is still serving.

    Red when: unlock stops restoring exactly, starts restoring the old mode
    (then the permissions caveat should be deleted from the copy), or starts
    stopping the proxy (then "Proxy gone." becomes true again).
    """
    cli.write_env(_single_key_env(), mode="644")
    original = cli.env_digest()
    assert cli.env_mode() == "644"

    assert cli.run("lock", "--env", ENV_PATH).returncode == 0
    assert cli.env_digest() != original, "lock left .env unchanged"
    assert cli.env_mode() == "600", (
        "lock no longer tightens .env to owner-only; the site's permissions caveat is now wrong"
    )

    cli.start_proxy()
    assert cli.wait_for_port(PROXY_PORT), cli.up_log()

    unlock = cli.run("unlock", "--env", ENV_PATH)
    assert unlock.returncode == 0, _fmt(unlock)

    assert cli.env_digest() == original, (
        "unlock did not restore .env byte-for-byte -- the site may not claim "
        "the contents come back exactly"
    )
    assert cli.env_mode() == "600", (
        "unlock now restores the original permissions; drop the caveat from "
        "how-it-works.html and features.html"
    )
    assert cli.port_state(PROXY_PORT) == 0, (
        "`worthless unlock` stopped the proxy. The site says the proxy keeps "
        "running and points at `worthless uninstall` to remove it -- if that "
        "changed, the copy must change back."
    )


# --------------------------------------------------------------------------
# C5 -- `uninstall` removes the data, not the command
# --------------------------------------------------------------------------
@pytest.mark.timeout(CASE_TIMEOUT)
def test_uninstall_removes_the_data_but_not_the_command(cli: Cli) -> None:
    """The replacement copy points at ``worthless uninstall`` as the way to
    "remove everything". It removes the DATA -- keys restored, ~/.worthless
    deleted, proxy stopped -- but the ``worthless`` command stays on PATH.
    The copy must not promise more than that.

    Red when: ~/.worthless survives, the proxy survives, or the CLI itself is
    removed (at which point "removes everything" would finally be literal).
    """
    cli.write_env(_single_key_env())
    assert cli.run("lock", "--env", ENV_PATH).returncode == 0
    assert cli.sh(f"test -d {WORTHLESS_HOME}").returncode == 0, "lock created no home dir"

    cli.start_proxy()
    assert cli.wait_for_port(PROXY_PORT), cli.up_log()

    uninstall = cli.run("uninstall", "--yes")
    assert uninstall.returncode == 0, _fmt(uninstall)

    assert cli.sh(f"test -d {WORTHLESS_HOME}").returncode != 0, (
        f"{WORTHLESS_HOME} survived `uninstall --yes`"
    )
    assert cli.port_state(PROXY_PORT) != 0, "`uninstall --yes` left the proxy running"
    assert cli.sh("command -v worthless").returncode == 0, (
        "`uninstall --yes` removed the CLI itself. The site says it removes "
        "Worthless's data, not the command -- update the copy if that changed."
    )


# --------------------------------------------------------------------------
# C6 -- what a shard looks like, and what happens to an unsupported key
# --------------------------------------------------------------------------
@pytest.mark.timeout(CASE_TIMEOUT)
def test_shard_keeps_prefix_and_length_and_unsupported_key_is_left_alone(
    cli: Cli,
) -> None:
    """Pins the homepage's .env panel and the "reveals nothing" claim.

    index.html:2001-2015 shows ``wrls_share_a_...`` for three providers. Real
    shards keep the provider prefix and the original length, so the panel must
    show realistic values -- and must say Gemini is NOT protected, because the
    real key stays in the file untouched.

    features.html:168 / blog:294 / how-it-works:229-230 say a shard "reveals
    nothing". It reveals the prefix and the length; it never reveals the key.

    Red when: a shard stops preserving prefix or length (the panel becomes
    fiction), a shard equals the real key (no protection at all), or Gemini
    starts being supported (then the "not supported yet" line must go).
    """
    openai_key = fake_openai_key()
    anthropic_key = fake_anthropic_key()
    gemini_key = fake_gemini_key()
    cli.write_env(
        f"OPENAI_API_KEY={openai_key}\n"
        f"ANTHROPIC_API_KEY={anthropic_key}\n"
        f"GEMINI_API_KEY={gemini_key}\n"
    )

    lock = cli.run("lock", "--env", ENV_PATH)
    assert lock.returncode == 0, _fmt(lock)
    out = lock.stdout + lock.stderr

    values = dict(
        line.split("=", 1)
        for line in cli.read_env().splitlines()
        if "=" in line and not line.startswith("#")
    )

    for var, real, prefix in (
        ("OPENAI_API_KEY", openai_key, "sk-" + "proj-"),
        ("ANTHROPIC_API_KEY", anthropic_key, "sk-" + "ant-api03-"),
    ):
        shard = values[var]
        assert shard != real, f"{var} was left as the real key -- nothing was protected"
        assert shard.startswith(prefix), (
            f"{var} shard lost the provider prefix ({shard[:12]}...); the "
            "homepage .env panel shows the prefix surviving"
        )
        assert len(shard) == len(real), (
            f"{var} shard changed length ({len(shard)} vs {len(real)}); the "
            "site says the split keeps the key's shape"
        )

    # Gemini: untouched, and said out loud. The site must not imply otherwise.
    assert values["GEMINI_API_KEY"] == gemini_key, (
        "GEMINI_API_KEY was modified -- Gemini is now supported, so the "
        "homepage's 'Not supported yet -- stays your real key' line is wrong"
    )
    assert "GEMINI_API_KEY" in out and "not yet supported" in out, (
        f"lock did not say it skipped the Gemini key:\n{out}"
    )

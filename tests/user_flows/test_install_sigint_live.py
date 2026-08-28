"""worthless-ixca: Ctrl+C during `curl … | sh` must abort the installer.

Drives the REAL ``install.sh`` in a child process attached to a real
pseudo-terminal, in its own session, and delivers a genuine ``SIGINT`` to the
whole process group — the way a terminal does when a user presses Ctrl+C.

**Why the ceremony.** POSIX sets ``SIGINT`` to ``SIG_IGN`` for background jobs
of a non-interactive shell. A test that backgrounds the script and runs
``kill -INT`` has its signal discarded, so every variant — fixed or broken —
looks identical. A prototype for this very bug did exactly that and produced a
false negative. Anything short of a PTY plus ``killpg`` does not exercise the
code path at all.

**What is actually broken (measured, not assumed).** The cleanup traps do not
exit::

    install.sh   trap 'rm -rf "$tmpdir"' EXIT INT TERM

A POSIX trap handler that does not exit returns control to the script. A real
Ctrl+C signals the whole foreground group, so ``curl`` dies too and the script
takes its failure branch:

* exits **10** — ``EXIT_NETWORK`` — so a deliberate user abort is reported as a
  transient network problem, and CI keyed on 10 **auto-retries it**;
* or, interrupted between the download and the hash comparison, exits **50**,
  whose documented contract is "CDN-poisoned download — CI MUST NOT auto-retry";
* and it keeps running with ``$tmpdir`` already deleted, then re-opens
  ``$installer`` by path to execute it — after SHA verification has passed.

Sibling to ``test_uninstall_sigint_live.py`` (worthless-6xuv), which pinned the
same class in the Python CLI. Nothing had ever covered the installer:
``git log -S'SIGINT' -- install.sh`` returns no commits.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

if sys.platform == "win32":  # pragma: no cover - guarded before the pty import
    pytest.skip("needs a POSIX pty and SIGINT process groups", allow_module_level=True)

import pty  # noqa: E402  — must follow the win32 guard

pytestmark = [pytest.mark.user_flow]

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "install.sh"

# Exit codes install.sh documents in its own header. A user interrupt must be
# none of them — they all mean "something went wrong on its own".
EXIT_NETWORK = 10
EXIT_INTEGRITY = 50

_END_MARKER = "Done!"


def _stub_env(tmp: Path) -> tuple[dict[str, str], Path]:
    """A contained environment where install.sh reaches its download and waits.

    ``curl`` is stubbed to announce itself and then sleep, which gives the test a
    deterministic window to interrupt in. Everything else is a real code path.
    ``WORTHLESS_TRUST_PATH=1`` is how this repo's install tests inject stubs; it
    is the documented hatch and never set by real users.
    """
    home = tmp / "home"
    binz = tmp / "bin"
    home.mkdir()
    binz.mkdir()
    # Create the file at --output before sleeping: install.sh passes
    # `--output "$installer"`, and a cleanup failure is only observable if that
    # file exists to be left behind. TMPDIR is redirected into our tree so the
    # `mktemp -d` the script performs lands somewhere the test can inspect.
    (binz / "curl").write_text(
        '#!/bin/sh\nfor a in "$@"; do [ "$prev" = --output ] && : > "$a"; prev="$a"; done\n'
        "echo CURL-STARTED >&2\nsleep 30\n"
    )
    (binz / "uname").write_text("#!/bin/sh\necho Darwin\n")
    (binz / "sw_vers").write_text("#!/bin/sh\necho 14.0\n")
    for stub in ("curl", "uname", "sw_vers"):
        (binz / stub).chmod(0o755)
    scratch = tmp / "scratch"
    scratch.mkdir()
    return {
        "PATH": f"{binz}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(scratch),  # so the script's `mktemp -d` lands where we can see it
        "WORTHLESS_TRUST_PATH": "1",
        "NO_COLOR": "1",
    }, tmp


def _run_and_interrupt(sig: int = signal.SIGINT, timeout: float = 30.0) -> tuple[int, str, Path]:
    """Run install.sh under a PTY; signal its process group once it is working.

    Returns (returncode, combined output, the temp HOME) — the caller inspects
    the temp tree to assert cleanup. ``returncode`` is negative when the child
    was killed by a signal, which is the distinction this test exists to check.
    """
    tmp = Path(tempfile.mkdtemp(prefix="ixca-"))
    env, home = _stub_env(tmp)

    master, slave = pty.openpty()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        ["/bin/sh", str(INSTALL_SH)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,  # own process group, so we can signal it like a terminal does
        env=env,
    )
    os.close(slave)

    out = ""
    sent = False
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            try:
                chunk = os.read(master, 4096).decode(errors="replace")
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if not sent and "CURL-STARTED" in out:
                time.sleep(0.4)  # let the script settle inside the curl call
                os.killpg(os.getpgid(proc.pid), sig)
                sent = True
            if sent and proc.poll() is not None:
                break
        assert sent, f"never reached the download window; output was:\n{out}"
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)

    return proc.wait(), out, home


class TestInterruptAbortsTheInstaller:
    def test_ctrl_c_is_not_reported_as_a_network_failure(self) -> None:
        """The headline bug: a deliberate abort must not look like a flaky network.

        Exit 10 is ``EXIT_NETWORK``. CI that retries on 10 will silently re-run an
        install the operator stopped on purpose — which is worse than reporting
        success, because it is a plausible-looking reason to try again.
        """
        rc, out, _ = _run_and_interrupt()
        assert rc != EXIT_NETWORK, (
            "Ctrl+C reported EXIT_NETWORK (10). A user interrupt is not a network "
            f"problem, and CI keyed on 10 will auto-retry it.\n{out[-600:]}"
        )
        assert rc != EXIT_INTEGRITY, (
            "Ctrl+C reported EXIT_INTEGRITY (50), whose contract is 'CDN-poisoned "
            f"download — CI MUST NOT auto-retry'. An interrupt must never raise it.\n{out[-600:]}"
        )

    def test_the_script_actually_stops(self) -> None:
        """Cleanup running is not the same as aborting."""
        rc, out, _ = _run_and_interrupt()
        assert _END_MARKER not in out, (
            f"install.sh ran to completion after SIGINT — it did not abort.\n{out[-600:]}"
        )
        assert rc != 0, f"interrupted install reported success (exit 0).\n{out[-600:]}"

    def test_the_interrupt_propagates_as_a_signal(self) -> None:
        """The parent must learn this was a signal, not an ordinary failure.

        A handler that merely ``exit 130``s stops this script but does not
        propagate: a caller looping over installs continues to the next
        iteration. Dying *by* SIGINT is what makes an enclosing shell stop too.
        ``subprocess`` reports signal death as a negative returncode.
        """
        rc, out, _ = _run_and_interrupt()
        assert rc < 0 or rc == 130, (
            "expected death by SIGINT (negative returncode) or the conventional "
            f"130; got {rc}. A plain exit code hides the interrupt from the caller.\n{out[-600:]}"
        )
        if rc < 0:
            assert rc == -signal.SIGINT, f"died by signal {-rc}, expected SIGINT"

    def test_the_temp_dir_is_cleaned_up(self) -> None:
        """Aborting must not trade a hung install for a leaked directory."""
        _rc, out, tmp = _run_and_interrupt()
        leaked = [p for p in tmp.rglob("uv-installer*")]
        assert not leaked, f"downloaded installer left behind after abort: {leaked}\n{out[-400:]}"

    def test_sigterm_also_aborts(self) -> None:
        """A supervisor's TERM deserves the same treatment as a user's INT."""
        rc, out, _ = _run_and_interrupt(sig=signal.SIGTERM)
        assert _END_MARKER not in out, f"install.sh ran to completion after SIGTERM.\n{out[-600:]}"
        # Pin the exact code. "not in (0, 10, 50)" would stay green if the handler
        # regressed to any arbitrary non-zero — a coverage audit caught that this
        # test was weaker than it looked. 143 is 128+SIGTERM, the convention a
        # supervisor reads.
        assert rc in (-signal.SIGTERM, 143), (
            f"SIGTERM must report 143 (128+15) or die by the signal; got {rc}.\n{out[-600:]}"
        )

    def test_sighup_aborts_and_cleans_up(self) -> None:
        """A dropped SSH session mid `curl | sh` is common, and currently leaks.

        install.sh traps EXIT INT TERM but not HUP, so a closed terminal leaves
        the downloaded installer behind.
        """
        rc, out, tmp = _run_and_interrupt(sig=signal.SIGHUP)
        assert _END_MARKER not in out, f"install.sh ran to completion after SIGHUP.\n{out[-600:]}"
        # SIGHUP's DEFAULT action already terminates the shell, so "it stopped"
        # and "rc != 0" hold with no trap at all — asserting only those made this
        # test pass against the unfixed script. What a HUP trap actually buys is
        # CLEANUP: untrapped, the shell dies and the download is orphaned.
        leaked = [p for p in tmp.rglob("uv-installer*")]
        assert not leaked, (
            f"SIGHUP left the downloaded installer behind: {leaked}. Without a HUP "
            "trap the shell dies on the default action and never cleans up — a "
            "dropped SSH session mid `curl | sh` orphans the temp dir."
        )
        assert rc in (-signal.SIGHUP, 129), (
            f"SIGHUP must report 129 (128+1) or die by the signal; got {rc}."
        )

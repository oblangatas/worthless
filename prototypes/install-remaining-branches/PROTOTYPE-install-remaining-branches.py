#!/usr/bin/env python3
"""PROTOTYPE — throwaway. worthless-oi9b, remaining install.sh branches.

Question per branch: can it be REACHED against the real install.sh, and what
is the cheapest faithful way to OBSERVE it? Runs the on-disk install.sh from
the oi9b worktree; never edits it. Prints full observable state per case.

Run:  python3 PROTOTYPE-install-remaining-branches.py
"""

import os
import pty
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

WT = Path(
    "/Users/shachar/Projects/worthless/worthless/.claude/worktrees/"
    "test+worthless-oi9b-installer-branch-coverage"
)
INSTALL = WT / "install.sh"
SRC = INSTALL.read_text()
PIN_SHA = re.search(r'ASTRAL_INSTALLER_SHA256="([0-9a-f]+)"', SRC).group(1)
UV_VER = re.search(r'^UV_VERSION="([^"]+)"', SRC, re.M).group(1)

# tools install.sh genuinely needs, EXCLUDING the hashers — lets a case hide
# sha256sum/shasum without also losing awk/cut/mktemp.
TOOLS = [
    "awk",
    "cut",
    "mktemp",
    "grep",
    "basename",
    "sed",
    "head",
    "tr",
    "cat",
    "rm",
    "mkdir",
    "chmod",
    "dirname",
    "env",
    "sh",
    "tail",
    "wc",
]


def toolbox(root: Path, exclude=()) -> Path:
    tb = root / "toolbox"
    tb.mkdir()
    for t in TOOLS:
        if t in exclude:
            continue
        real = shutil.which(t, path="/usr/bin:/bin")
        if real:
            (tb / t).symlink_to(real)
    return tb


def stub(d: Path, name: str, body: str) -> None:
    p = d / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


def run(env, cwd, tty=False, timeout=25):
    if not tty:
        r = subprocess.run(
            ["/bin/sh", str(INSTALL)],
            env=env,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, r.stdout + r.stderr
    m, s = pty.openpty()
    p = subprocess.Popen(
        ["/bin/sh", str(INSTALL)],
        env=env,
        cwd=cwd,
        stdin=s,
        stdout=s,
        stderr=s,
        start_new_session=True,
    )
    os.close(s)
    out, end = b"", time.time() + timeout
    while time.time() < end:
        try:
            c = os.read(m, 4096)
        except OSError:
            break
        if not c:
            break
        out += c
        if p.poll() is not None:
            try:
                out += os.read(m, 4096)
            except OSError:
                pass
            break
    os.close(m)
    if p.poll() is None:
        p.kill()
    return p.wait(), out.decode(errors="replace")


def show(label, rc, out, markers=()):
    lines = [ln for ln in out.splitlines() if ln.strip()]
    print(f"\n── {label}")
    print(f"   rc={rc}")
    for ln in lines[-5:]:
        print(f"   │ {ln[:110]}")
    for name, path in markers:
        print(f"   marker[{name}] = {'WRITTEN' if path.exists() else 'absent'}")


def base(tmp: Path, *, uname="Darwin", sw="echo 14.5", hide_hashers=False):
    home = tmp / "home"
    home.mkdir()
    bind = tmp / "bin"
    bind.mkdir()
    stub(bind, "uname", f"echo {uname}")
    if sw is not None:
        stub(bind, "sw_vers", sw)
    tb = toolbox(tmp, exclude=("sha256sum", "shasum") if hide_hashers else ())
    env = {"HOME": str(home), "NO_COLOR": "1", "WORTHLESS_TRUST_PATH": "1", "PATH": f"{bind}:{tb}"}
    return env, home, bind


# ─────────────────────────────────────────────────────────────────────────────
print("=" * 78)
print(" install.sh remaining branches — reachability prototype")
print(f" pin sha={PIN_SHA[:12]}…  uv={UV_VER}")
print("=" * 78)

# (2) unsupported OS
with tempfile.TemporaryDirectory() as t:
    env, home, bind = base(Path(t), uname="FreeBSD")
    show("(2) unknown OS  uname=FreeBSD", *run(env, t))

# (3a) sw_vers missing — PATH deliberately lacks /usr/bin (mac has a real one)
with tempfile.TemporaryDirectory() as t:
    env, home, bind = base(Path(t), sw=None)
    stub(bind, "curl", "exit 22")  # stop right after the version check
    rc, out = run(env, t)
    show("(3a) Darwin, no sw_vers on PATH", rc, out)
    print(f"   reached warn? {'sw_vers not found' in out}")

# (3b) unparsable macOS version
with tempfile.TemporaryDirectory() as t:
    env, home, bind = base(Path(t), sw="echo notaversion")
    show("(3b) sw_vers -> 'notaversion'", *run(env, t))

# (1a) no trusted hasher
with tempfile.TemporaryDirectory() as t:
    tp = Path(t)
    env, home, bind = base(tp, hide_hashers=True)
    stub(bind, "curl", 'for a in "$@"; do [ "$p" = --output ] && echo x > "$a"; p="$a"; done')
    rc, out = run(env, t)
    show("(1a) hashers absent from PATH (escape hatch on)", rc, out)

# (1b) Astral installer fails AFTER a passing hash check
with tempfile.TemporaryDirectory() as t:
    tp = Path(t)
    env, home, bind = base(tp, hide_hashers=True)
    stub(
        bind,
        "curl",
        'for a in "$@"; do [ "$p" = --output ] && printf "exit 1\\n" > "$a"; p="$a"; done',
    )
    stub(bind, "sha256sum", f'echo "{PIN_SHA}  $1"')
    show("(1b) installer exits 1, stub hasher returns pinned sha", *run(env, t))

# (1c) installer 'succeeds' but no uv anywhere afterwards
with tempfile.TemporaryDirectory() as t:
    tp = Path(t)
    env, home, bind = base(tp, hide_hashers=True)
    stub(
        bind,
        "curl",
        'for a in "$@"; do [ "$p" = --output ] && printf "exit 0\\n" > "$a"; p="$a"; done',
    )
    stub(bind, "sha256sum", f'echo "{PIN_SHA}  $1"')
    show("(1c) installer exits 0, places no uv", *run(env, t))

# (4) colour arm — needs a TTY on stdout
for no_color in (None, "1"):
    with tempfile.TemporaryDirectory() as t:
        env, home, bind = base(Path(t), uname="FreeBSD")
        env.pop("NO_COLOR")
        if no_color:
            env["NO_COLOR"] = no_color
        rc, out = run(env, t, tty=True)
        esc = "\x1b[" in out
        print(f"\n── (4) PTY, NO_COLOR={no_color!s:<4} rc={rc}  ANSI escapes present: {esc}")

# (5) REAL trusted loops — escape hatch OFF, planted binaries first on PATH.
#     resolve_uv runs before any network, so the uv half may not need a container.
with tempfile.TemporaryDirectory() as t:
    tp = Path(t)
    home = tp / "home"
    home.mkdir()
    evil = tp / "evil"
    evil.mkdir()
    mk = tp / "markers"
    mk.mkdir()
    stub(evil, "uv", f'touch {mk}/uv-ran; echo "uv {UV_VER}"')
    stub(evil, "sha256sum", f'touch {mk}/sha-ran; echo "{PIN_SHA}  $1"')
    env = {"HOME": str(home), "NO_COLOR": "1", "PATH": f"{evil}:/usr/bin:/bin"}
    rc, out = run(env, t, timeout=40)
    show(
        "(5) NO escape hatch, planted uv + sha256sum first on PATH (real mac)",
        rc,
        out,
        [("planted uv", mk / "uv-ran"), ("planted sha256sum", mk / "sha-ran")],
    )
    print(
        f"   took the 'already installed' shortcut via planted uv? "
        f"{('uv ' + UV_VER + ' already installed') in out}"
    )
    real_uvs = [p for p in ("/opt/homebrew/bin/uv", "/usr/local/bin/uv") if Path(p).exists()]
    print(f"   host has a real uv in resolve_uv's list: {real_uvs or 'none'}  <- confounder")

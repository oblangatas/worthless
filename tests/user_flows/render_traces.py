"""Render deterministic terminal traces for user-flow UX proof.

The renderer drives the real ``worthless`` console script in subprocesses
against isolated project directories and a throwaway ``WORTHLESS_HOME``. It
uses deterministic fake keys only and redacts key bodies before writing the
Markdown report.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests._install_helpers import run_install, write_happy_path_stubs, write_stub  # noqa: E402


TRACE_ROOT = Path(tempfile.gettempdir()) / "worthless-terminal-traces"
FERNET_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(b"terminal-trace-fernet-key").digest()
).decode()
SECRET_VARS = frozenset({"OPENAI_API_KEY", "ANTHROPIC_API_KEY"})
FAKE_KEY_SEEDS = [
    ("sk-proj-", "trace-openai-round-trip"),
    ("sk-proj-", "trace-handoff-owner"),
    ("sk-proj-", "trace-rotation-old"),
    ("sk-proj-", "trace-rotation-new"),
    ("sk-proj-", "trace-shape-old"),
    ("sk-", "trace-shape-new"),
    ("sk-proj-", "trace-project-a"),
    ("sk-proj-", "trace-project-b"),
    ("sk-proj-", "trace-rewrite-refusal"),
    ("sk-proj-", "trace-tamper-original"),
    ("sk-proj-", "trace-tampered-locked-env"),
]
_PROTECTED_LABELS: dict[str, str] = {}


def fake_key(prefix: str, seed: str) -> str:
    """Generate a deterministic high-entropy fake key at runtime."""
    raw = hashlib.sha256(seed.encode()).digest()
    body = base64.urlsafe_b64encode(raw).decode().rstrip("=")[:48]
    return prefix + body


@dataclass
class EnvSnapshot:
    label: str
    files: dict[Path, str]


@dataclass
class CommandTrace:
    command: list[str]
    cwd: Path
    home: Path
    exit_code: int
    stdout: str
    stderr: str
    before: EnvSnapshot
    after: EnvSnapshot


@dataclass
class Journey:
    title: str
    summary: str
    root: Path
    home: Path
    traces: list[CommandTrace] = field(default_factory=list)


class TraceRunner:
    def __init__(self, root: Path, *, title: str, summary: str) -> None:
        self.journey = Journey(
            title=title,
            summary=summary,
            root=root,
            home=root / ".worthless",
        )

    def run(
        self,
        args: list[str],
        *,
        cwd: Path,
        env_files: Iterable[Path],
        home: Path | None = None,
        expect_exit: Callable[[int], bool] | None = None,
    ) -> None:
        command_home = home or self.journey.home
        before = snapshot_env_files("before", env_files)
        proc = subprocess.run(  # noqa: S603 - fixed executable plus controlled args.
            [resolve_worthless(), *args],
            cwd=cwd,
            env=scrubbed_env(command_home),
            text=True,
            capture_output=True,
            check=False,
        )
        after = snapshot_env_files("after", env_files)
        if expect_exit is None:
            expect_exit = expected_success
        if not expect_exit(proc.returncode):
            raise RuntimeError(
                f"unexpected exit {proc.returncode} for {' '.join(args)}\n"
                f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )
        self.journey.traces.append(
            CommandTrace(
                command=["worthless", *args],
                cwd=cwd,
                home=command_home,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                before=before,
                after=after,
            )
        )

    def run_install_case(
        self,
        name: str,
        *,
        expect_exit: Callable[[int], bool] | None = None,
    ) -> None:
        case_root = self.journey.root / slugify(name)
        bin_dir = case_root / "bin"
        bin_dir.mkdir(parents=True)
        state_file = case_root / "install-state.txt"
        state_file.write_text(f"case={name}\nphase=before\n")
        before = snapshot_env_files("before", [state_file])

        if name == "fresh install with persistent PATH":
            write_happy_path_stubs(bin_dir, with_worthless=False)
            (case_root / ".zshrc").write_text('export PATH="$HOME/.local/bin:$PATH"\n')
            result = run_install(bin_dir)
            command = ["sh", "./install.sh"]
        elif name == "fresh install without persistent PATH":
            write_happy_path_stubs(bin_dir, with_worthless=False)
            result = run_install(bin_dir)
            command = ["sh", "./install.sh"]
        elif name == "reinstall pinned version already installed":
            write_happy_path_stubs(bin_dir)
            write_stub(
                bin_dir,
                "uv",
                """case "$1" in
  --version) echo "uv 0.11.7" ;;
  tool) shift; case "$1" in
    list) echo "worthless v0.3.0" ;;
    install|upgrade) echo "unexpected reinstall" >&2; exit 1 ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  run) echo "worthless 0.3.0" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
            )
            result = run_install(bin_dir, env_extra={"WORTHLESS_VERSION": "0.3.0"})
            command = ["WORTHLESS_VERSION=0.3.0", "sh", "./install.sh"]
        elif name == "pipx conflict shows uninstall guidance":
            write_stub(bin_dir, "uname", "echo Darwin")
            write_stub(bin_dir, "sw_vers", 'echo "14.5"')
            write_stub(
                bin_dir,
                "pipx",
                """case "$1" in
  list) echo "package worthless 0.3.0, installed using Python 3.12.0" ;;
  *) echo "pipx stub: $@" ;;
esac
exit 0""",
            )
            result = run_install(bin_dir)
            command = ["sh", "./install.sh"]
        elif name == "uv failure surfaces network hints":
            write_stub(bin_dir, "uname", "echo Darwin")
            write_stub(bin_dir, "sw_vers", 'echo "14.5"')
            write_stub(
                bin_dir,
                "uv",
                """case "$1" in
  --version) echo "uv 0.11.7" ;;
  tool) shift; case "$1" in
    list) ;;
    install) echo "x No solution found when resolving dependencies" >&2; exit 1 ;;
    upgrade) echo "x package not installed" >&2; exit 1 ;;
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
            )
            result = run_install(bin_dir)
            command = ["sh", "./install.sh"]
        elif name == "manual uninstall current limitation":
            write_stub(
                bin_dir,
                "uv",
                """case "$1 $2 $3" in
  "tool uninstall worthless") echo "uninstalled worthless" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
            )
            result = subprocess.run(  # noqa: S603 - controlled stub in temp PATH.
                [str(bin_dir / "uv"), "tool", "uninstall", "worthless"],
                cwd=case_root,
                env={
                    **scrubbed_env(self.journey.home),
                    "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            command = ["uv", "tool", "uninstall", "worthless"]
        else:
            raise ValueError(f"unknown install trace case: {name}")

        if expect_exit is None:
            expect_exit = expected_success
        if not expect_exit(result.returncode):
            raise RuntimeError(
                f"unexpected exit {result.returncode} for install trace case {name}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        state_file.write_text(f"case={name}\nphase=after\nexit={result.returncode}\n")
        after = snapshot_env_files("after", [state_file])
        self.journey.traces.append(
            CommandTrace(
                command=command,
                cwd=case_root,
                home=self.journey.home,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                before=before,
                after=after,
            )
        )


def resolve_worthless() -> str:
    executable = shutil.which("worthless")
    if executable is None:
        raise RuntimeError(
            "Could not find the 'worthless' console script. "
            "Run this renderer via 'uv run python tests/user_flows/render_traces.py'."
        )
    return executable


def scrubbed_env(home: Path) -> dict[str, str]:
    keep = {
        "HOME": str(home.parent / "user-home"),
        "USERPROFILE": str(home.parent / "user-home"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", ""),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "TERM": os.environ.get("TERM", "dumb"),
        "TMPDIR": os.environ.get("TMPDIR", tempfile.gettempdir()),
        "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", ""),
        "VIRTUAL_ENV": os.environ.get("VIRTUAL_ENV", ""),
    }
    user_home = home.parent / "user-home"
    user_home.mkdir(parents=True, exist_ok=True)
    return {
        key: value
        for key, value in {
            **keep,
            "WORTHLESS_HOME": str(home),
            "WORTHLESS_FERNET_KEY": FERNET_KEY,
            "WORTHLESS_DB_PATH": "",
            "WORTHLESS_FERNET_KEY_PATH": "",
            "WORTHLESS_FERNET_FD": "",
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": "",
            "OPENAI_API_KEY": "",
            "ANTHROPIC_API_KEY": "",
            "OPENAI_BASE_URL": "",
            "ANTHROPIC_BASE_URL": "",
            "COLUMNS": "120",
        }.items()
        if value
    }


def expected_success(code: int) -> bool:
    return code == 0


def snapshot_env_files(label: str, env_files: Iterable[Path]) -> EnvSnapshot:
    return EnvSnapshot(
        label=label,
        files={path: path.read_text() if path.exists() else "<missing>\n" for path in env_files},
    )


def reset_root() -> None:
    if TRACE_ROOT.exists():
        shutil.rmtree(TRACE_ROOT)
    TRACE_ROOT.mkdir(parents=True)


def slugify(value: str) -> str:
    return "-".join(value.lower().replace("/", " ").split())


def build_install_lifecycle() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "install-lifecycle",
        title="Install, Reinstall, Manual Uninstall Guidance",
        summary=(
            "The installer succeeds with and without persistent PATH setup, re-running a "
            "pinned install is a no-op, failure paths keep actionable diagnostics visible, "
            "and uninstall is currently documented as the manual `uv tool uninstall worthless` "
            "command plus platform cleanup notes until WOR-435 ships a first-class command."
        ),
    )
    runner.run_install_case("fresh install with persistent PATH")
    runner.run_install_case("fresh install without persistent PATH")
    runner.run_install_case("reinstall pinned version already installed")
    runner.run_install_case(
        "pipx conflict shows uninstall guidance",
        expect_exit=lambda code: code == 30,
    )
    runner.run_install_case(
        "uv failure surfaces network hints",
        expect_exit=lambda code: code == 10,
    )
    runner.run_install_case("manual uninstall current limitation")
    return runner.journey


def build_lock_status_scan_unlock() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "lock-status-scan-unlock",
        title="Lock, Status, Scan, Unlock",
        summary=(
            "A project key is protected, status shows one enrollment, scan no longer finds "
            "raw keys, and unlock restores the original fake key."
        ),
    )
    project = runner.journey.root / "project"
    project.mkdir(parents=True)
    env_file = project / ".env"
    env_file.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-openai-round-trip')}\n")

    runner.run(["lock", "--env", str(env_file)], cwd=project, env_files=[env_file])
    runner.run(["status"], cwd=project, env_files=[env_file])
    runner.run(["scan", str(project)], cwd=project, env_files=[env_file])
    runner.run(["unlock", "--env", str(env_file)], cwd=project, env_files=[env_file])
    runner.run(["status"], cwd=project, env_files=[env_file])
    return runner.journey


def build_teammate_handoff_failure() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "teammate-handoff-failure",
        title="Teammate Handoff Failure",
        summary=(
            "A locked .env copied without the local Worthless home fails with a "
            "plain-English recovery hint instead of a traceback."
        ),
    )
    owner_project = runner.journey.root / "owner-project"
    teammate_project = runner.journey.root / "teammate-project"
    owner_project.mkdir(parents=True)
    teammate_project.mkdir(parents=True)
    owner_env = owner_project / ".env"
    teammate_env = teammate_project / ".env"
    owner_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-handoff-owner')}\n")

    runner.run(["lock", "--env", str(owner_env)], cwd=owner_project, env_files=[owner_env])
    teammate_env.write_text(owner_env.read_text())

    teammate_home = runner.journey.root / "teammate" / ".worthless"
    runner.run(
        ["unlock", "--env", str(teammate_env)],
        cwd=teammate_project,
        env_files=[teammate_env],
        home=teammate_home,
        expect_exit=lambda code: code != 0,
    )
    return runner.journey


def build_rotation_relock() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "rotation-relock",
        title="Rotation Relock",
        summary=(
            "A raw replacement key is treated as a new key, including when the replacement "
            "has a different OpenAI key shape."
        ),
    )
    same_shape = runner.journey.root / "same-shape"
    different_shape = runner.journey.root / "different-shape"
    same_shape.mkdir(parents=True)
    different_shape.mkdir(parents=True)
    same_env = same_shape / ".env"
    different_env = different_shape / ".env"

    same_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-rotation-old')}\n")
    runner.run(["lock", "--env", str(same_env)], cwd=same_shape, env_files=[same_env])
    same_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-rotation-new')}\n")
    runner.run(["lock", "--env", str(same_env)], cwd=same_shape, env_files=[same_env])
    runner.run(["unlock", "--env", str(same_env)], cwd=same_shape, env_files=[same_env])

    different_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-shape-old')}\n")
    runner.run(
        ["lock", "--env", str(different_env)],
        cwd=different_shape,
        env_files=[different_env],
    )
    different_env.write_text(f"OPENAI_API_KEY={fake_key('sk-', 'trace-shape-new')}\n")
    runner.run(
        ["lock", "--env", str(different_env)],
        cwd=different_shape,
        env_files=[different_env],
    )
    runner.run(
        ["unlock", "--env", str(different_env)],
        cwd=different_shape,
        env_files=[different_env],
    )
    return runner.journey


def build_multi_project_isolation() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "multi-project-isolation",
        title="Multi-Project Isolation",
        summary=(
            "Two projects share one Worthless home; unlocking one project leaves the other "
            "project protected until explicitly unlocked."
        ),
    )
    project_a = runner.journey.root / "project-a"
    project_b = runner.journey.root / "project-b"
    project_a.mkdir(parents=True)
    project_b.mkdir(parents=True)
    env_a = project_a / ".env"
    env_b = project_b / ".env"
    env_a.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-project-a')}\n")
    env_b.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-project-b')}\n")

    runner.run(["lock", "--env", str(env_a)], cwd=project_a, env_files=[env_a, env_b])
    runner.run(["lock", "--env", str(env_b)], cwd=project_b, env_files=[env_a, env_b])
    runner.run(["unlock", "--env", str(env_a)], cwd=project_a, env_files=[env_a, env_b])
    runner.run(["status"], cwd=project_a, env_files=[env_a, env_b])
    runner.run(["unlock", "--env", str(env_b)], cwd=project_b, env_files=[env_a, env_b])
    return runner.journey


def build_native_stress() -> Journey:
    runner = TraceRunner(
        TRACE_ROOT / "native-stress",
        title="Native Stress: Refused Rewrite and Tampered Lock",
        summary=(
            "Unsafe rewrite refusal leaves the raw .env recoverable and unenrolled; "
            "tampering with a locked value fails with an actionable commitment-mismatch "
            "message without destroying state."
        ),
    )
    refusal_project = runner.journey.root / "rewrite-refusal"
    tamper_project = runner.journey.root / "tampered-lock"
    refusal_project.mkdir(parents=True)
    tamper_project.mkdir(parents=True)
    refusal_env = refusal_project / ".env"
    tamper_env = tamper_project / ".env"

    refusal_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-rewrite-refusal')}\n")
    os.link(refusal_env, refusal_project / ".env.link")
    runner.run(
        ["lock", "--env", str(refusal_env)],
        cwd=refusal_project,
        env_files=[refusal_env],
        expect_exit=lambda code: code != 0,
    )
    runner.run(["status"], cwd=refusal_project, env_files=[refusal_env])
    runner.run(
        ["scan", str(refusal_env)],
        cwd=runner.journey.root,
        env_files=[refusal_env],
        expect_exit=lambda code: code != 0,
    )

    tamper_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-tamper-original')}\n")
    runner.run(["lock", "--env", str(tamper_env)], cwd=tamper_project, env_files=[tamper_env])
    tamper_env.write_text(f"OPENAI_API_KEY={fake_key('sk-proj-', 'trace-tampered-locked-env')}\n")
    runner.run(
        ["unlock", "--env", str(tamper_env)],
        cwd=tamper_project,
        env_files=[tamper_env],
        expect_exit=lambda code: code != 0,
    )
    runner.run(["status"], cwd=tamper_project, env_files=[tamper_env])
    return runner.journey


def render_report(journeys: list[Journey]) -> str:
    _PROTECTED_LABELS.clear()
    lines = [
        "# Terminal Traces",
        "",
        "Deterministic UX proof generated by `tests/user_flows/render_traces.py`.",
        "Commands run against isolated temp projects with fake key material only.",
        "Key bodies and local temp paths are redacted for documentation safety.",
        "",
    ]
    for journey in journeys:
        lines.extend(render_journey(journey))
    return "\n".join(lines).rstrip() + "\n"


def render_journey(journey: Journey) -> list[str]:
    lines = [
        f"## {journey.title}",
        "",
        journey.summary,
        "",
        f"- Workspace: `{redact_paths(journey.root)}`",
        "",
    ]
    for index, trace in enumerate(journey.traces, start=1):
        lines.extend(render_trace(index, trace))
    return lines


def render_trace(index: int, trace: CommandTrace) -> list[str]:
    lines = [
        f"### {index}. `{redact_text(' '.join(trace.command))}`",
        "",
        f"- cwd: `{redact_paths(trace.cwd)}`",
        f"- WORTHLESS_HOME: `{redact_paths(trace.home)}`",
        f"- exit: `{trace.exit_code}`",
        "",
        "**Files before**",
        "",
        *render_snapshot(trace.before),
        "**stdout**",
        "",
        fenced(redact_text(trace.stdout) if trace.stdout else "<empty>\n"),
        "",
        "**stderr**",
        "",
        fenced(redact_text(trace.stderr) if trace.stderr else "<empty>\n"),
        "",
        "**Files after**",
        "",
        *render_snapshot(trace.after),
    ]
    return lines


def render_snapshot(snapshot: EnvSnapshot) -> list[str]:
    lines: list[str] = []
    for path, content in snapshot.files.items():
        lines.append(f"`{redact_paths(path)}`")
        lines.append("")
        lines.append(fenced(redact_env_content(content)))
        lines.append("")
    return lines


def fenced(content: str) -> str:
    normalized = "\n".join(line.rstrip() for line in content.rstrip().splitlines())
    return f"```text\n{normalized}\n```"


def redact_env_content(content: str) -> str:
    redacted_lines = []
    for line in content.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            redacted_lines.append(redact_text(line))
            continue
        key, value = line.split("=", 1)
        if key in SECRET_VARS:
            redacted_lines.append(f"{key}={redact_key_value(value)}")
        else:
            redacted_lines.append(f"{key}={redact_text(value)}")
    return "\n".join(redacted_lines) + ("\n" if content.endswith("\n") else "")


def redact_key_value(value: str) -> str:
    prefix = key_prefix(value)
    if value in known_fake_keys():
        digest = hashlib.sha256(value.encode()).hexdigest()[:10]
        return f"{prefix}<redacted:fake-raw:len={len(value)}:sha256={digest}>"

    label = _PROTECTED_LABELS.setdefault(value, f"protected-{len(_PROTECTED_LABELS) + 1}")
    return f"{prefix}<redacted:{label}:len={len(value)}>"


def key_prefix(value: str) -> str:
    for prefix in ("sk-ant-api03-", "sk-proj-", "sk-"):
        if value.startswith(prefix):
            return prefix
    return ""


def redact_text(value: str) -> str:
    redacted = redact_paths(value)
    redacted = redact_known_fake_values(redacted)
    return redacted


def redact_paths(value: object) -> str:
    return str(value).replace(str(TRACE_ROOT), "$TRACE_ROOT")


def redact_known_fake_values(value: str) -> str:
    redacted = value
    for fake in known_fake_keys():
        redacted = redacted.replace(fake, redact_key_value(fake))
    return redacted


def known_fake_keys() -> frozenset[str]:
    return frozenset(fake_key(prefix, seed) for prefix, seed in FAKE_KEY_SEEDS)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/user_flows/TERMINAL_TRACES.md"),
        help="Markdown file to write.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reset_root()
    journeys = [
        build_lock_status_scan_unlock(),
        build_teammate_handoff_failure(),
        build_rotation_relock(),
        build_multi_project_isolation(),
        build_native_stress(),
        build_install_lifecycle(),
    ]
    report = render_report(journeys)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

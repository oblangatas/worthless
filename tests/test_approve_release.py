"""scripts/approve-release.sh: one `y` approves a whole release (WOR-1165).

Every test drives the real script against a fake `gh` on PATH. The fake records
every call and refuses `release create`, `workflow run` and `issue create`, so no
test can touch GitHub. It is stateful: each poll of the tag's runs advances one
snapshot, so runs can appear, wait, finish or fail while the script watches.

Interactive answers go through a real pseudo-terminal: the script reads /dev/tty,
so `yes | tag-release.sh` must never approve anything.

TestGuardsCanActuallyFail in test_deploy_static.py mutates the script and requires
the guards below to go red.
"""

from __future__ import annotations

import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
APPROVE_SCRIPT = REPO_ROOT / "scripts" / "approve-release.sh"
TAG_RELEASE_SCRIPT = REPO_ROOT / "scripts" / "tag-release.sh"
REAL_GIT = shutil.which("git") or "git"

TAG = "v9.9.9"
REPO = "acme/widget"
OLD_SHA = "b" * 40
RESUME = f"scripts/approve-release.sh {TAG}"
# Short so a mutated script that never finishes still ends quickly with exit 2.
TIMEOUT_S = 3
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
# A fixed commit object, so the local tag's sha is known before any repo exists.
_COMMIT = (
    f"tree {_EMPTY_TREE}\nauthor T <t@example.invalid> 0 +0000\n"
    "committer T <t@example.invalid> 0 +0000\n\nrelease\n"
).encode()
SHA = hashlib.sha1(b"commit %d\0" % len(_COMMIT) + _COMMIT).hexdigest()  # noqa: S324
YES = ("--yes", "--expect-sha", SHA)


def _tag_repo(path: Path) -> Path:
    """A git repo whose refs/tags/v9.9.9 points at SHA. The script reads it locally."""
    path.mkdir()
    git = [REAL_GIT, "-C", str(path), "-c", "core.hooksPath=/dev/null"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run(
        [*git, "hash-object", "-w", "-t", "tree", "/dev/null"], check=True, capture_output=True
    )
    made = (
        subprocess.run(
            [*git, "hash-object", "-w", "-t", "commit", "--stdin"],
            input=_COMMIT,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )
    assert made == SHA
    subprocess.run([*git, "update-ref", f"refs/tags/{TAG}", SHA], check=True)
    return path


# Fake gh. Every call is logged to $GH_CALLS as args joined by \x1f, one per line.
#   SNAPS       JSON list of {runs, rn, pending}. Each GET of the tag's runs advances
#               one snapshot; the last one repeats. rn and pending read the current one.
#   TAG_SHA     commit GitHub says the tag points at (/commits/<tag>)
#   POST_FAIL_EID / POST_FAIL_MSG  an approve POST for that environment id fails
#   RELEASE_LIVE_AFTER  `gh release view` succeeds once this string is in the log
# A pending environment drops out once it was POSTed for that run, like the real API.
_GH_SHIM = r"""#!/usr/bin/env bash
printf '%s\x1f' "$@" >>"$GH_CALLS"; printf '\n' >>"$GH_CALLS"
method=GET; path=""; jqf=""; prev=""
for a in "$@"; do
  case "$prev" in -X) method="$a";; --jq) jqf="$a";; esac
  case "$a" in /repos/*|repos/*) [ -z "$path" ] && path="${a#/}";; esac
  prev="$a"
done
# -rc: like real `gh --jq`, strings come out raw and objects compact.
emit() { if [ -n "$jqf" ]; then printf '%s' "$1" | jq -rc "$jqf"; else printf '%s\n' "$1"; fi; }
snap() {
  local n i
  n=$(cat "$GH_STATE" 2>/dev/null || echo 0)
  i=$((n > 0 ? n - 1 : 0))
  printf '%s' "$SNAPS" | jq -c --argjson i "$i" '.[[$i, length - 1] | min]'
}
case "${1:-} ${2:-}" in
  "repo view") echo "acme/widget"; exit 0 ;;
  "release view")
    if [ -n "${RELEASE_LIVE_AFTER:-}" ] && grep -qF -- "$RELEASE_LIVE_AFTER" "$GH_CALLS"; then
      echo "https://github.com/acme/widget/releases/tag/$3"; exit 0
    fi
    echo "release not found" >&2; exit 1 ;;
  "release "*|"workflow "*|"issue "*) echo "shim: refusing gh $*" >&2; exit 99 ;;
esac
case "$method $path" in
  "POST "*/pending_deployments)
    fail_arg="environment_ids[]=${POST_FAIL_EID:-none}"
    if printf '%s\n' "$@" | grep -qxF -- "$fail_arg"; then
      echo "$POST_FAIL_MSG" >&2; exit 1
    fi
    echo '[]'; exit 0 ;;
  "GET "*/commits/*) emit "{\"sha\": \"$TAG_SHA\"}"; exit 0 ;;
  "GET "*/actions/workflows/release-notes.yml/runs)
    emit "$(snap | jq -c '{workflow_runs: .rn}')"; exit 0 ;;
  "GET "*/actions/runs/*/pending_deployments)
    rid=$(printf '%s' "$path" | sed -E 's#.*/actions/runs/([^/]+)/pending_deployments#\1#')
    done_ids=$(grep -F "POST" "$GH_CALLS" | grep -F "actions/runs/${rid}/pending_deployments" \
      | grep -oE 'environment_ids\[\]=[0-9]+' | cut -d= -f2 \
      | jq -Rsc 'split("\n") | map(select(. != "") | tonumber)')
    emit "$(snap | jq -c --arg r "$rid" --argjson d "$done_ids" \
      '(.pending[$r] // []) | map(select(.environment.id as $e | ($d | index($e)) | not))')"
    exit 0 ;;
  "GET "*/actions/runs)
    n=$(cat "$GH_STATE" 2>/dev/null || echo 0); echo $((n + 1)) >"$GH_STATE"
    emit "$(snap | jq -c '{workflow_runs: .runs}')"; exit 0 ;;
esac
echo "shim: unhandled gh $*" >&2; exit 98
"""

# Fake git: only `verify-tag` is faked (no signing key in tests); the rest is real git.
_GIT_SHIM = r"""#!/usr/bin/env bash
if [ "${1:-}" = "verify-tag" ]; then
  [ "${GIT_VERIFY_OK:-1}" = 1 ] && exit 0
  echo "error: no signature found" >&2; exit 1
fi
exec "$REAL_GIT" "$@"
"""


def _run(run_id: int, name: str, wf: str, status: str, conclusion=None, sha: str = SHA) -> dict:
    return {
        "id": run_id,
        "name": name,
        "path": f".github/workflows/{wf}",
        "status": status,
        "conclusion": conclusion,
        "head_sha": sha,
        "event": "push",
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
    }


def _pending(env_id: int, name: str, can: bool = True) -> list[dict]:
    return [{"environment": {"id": env_id, "name": name}, "current_user_can_approve": can}]


def _pubs(status: str = "waiting", docker: str = "in_progress", conclusion=None) -> list[dict]:
    """The four publishers of the tag. Docker never waits on an approval."""
    docker_conclusion = "success" if docker == "completed" else None
    return [
        _run(101, "Publish to PyPI", "publish.yml", status, conclusion),
        _run(102, "Publish worthless-mcp to npm", "publish-npm.yml", status, conclusion),
        _run(103, "Publish Docker image to GHCR", "publish-docker.yml", docker, docker_conclusion),
        _run(104, "Deploy Worker (worthless-sh)", "deploy-worker.yml", status, conclusion),
    ]


_PUB_PENDING = {
    "101": _pending(11, "pypi"),
    "102": _pending(12, "npm-publish"),
    "104": _pending(14, "worthless-sh-production"),
}


def _rn(status: str, conclusion=None, title: str | None = None, event: str = "workflow_run"):
    return {
        "id": 201,
        "status": status,
        "conclusion": conclusion,
        "event": event,
        "display_title": title or f"Create GitHub Release {TAG} {SHA}",
        "html_url": f"https://github.com/{REPO}/actions/runs/201",
    }


def _snap(runs=(), rn=(), pending=None) -> dict:
    return {"runs": list(runs), "rn": list(rn), "pending": pending or {}}


def _flow(waiting=None, after_y=None, release=None, release_pending=None) -> list[dict]:
    """No runs yet -> publishers waiting (twice: the prompt, then the re-read after y)
    -> publishers running, release run started -> all green, release run waiting."""
    waiting = waiting or _snap(_pubs(), pending=_PUB_PENDING)
    return [
        _snap(),
        waiting,
        after_y or waiting,
        _snap(_pubs("in_progress", docker="completed"), rn=[_rn("in_progress")]),
        _snap(
            _pubs("completed", docker="completed", conclusion="success"),
            rn=[release or _rn("waiting")],
            pending={"201": release_pending or _pending(21, "release")},
        ),
    ]


def _approve(
    tmp_path: Path,
    *args: str,
    answer: str | None = None,
    stdin: str = "",
    snaps: list[dict] | None = None,
    gh_repo: str | None = REPO,
    api_sha: str = SHA,
    verify_ok: bool = True,
    post_fail: tuple[int, str] | None = None,
    poll_s: int = 0,
    timeout_s: int = TIMEOUT_S,
):
    """Run the script. With `answer`, it is typed into a real terminal; without one
    there is no controlling terminal at all."""
    repo = _tag_repo(tmp_path / "checkout")
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    for name, body in (("gh", _GH_SHIM), ("git", _GIT_SHIM)):
        (shim_dir / name).write_text(body)
        (shim_dir / name).chmod(0o755)
    calls = tmp_path / "gh_calls.log"
    calls.write_text("")
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GH_REPO")}
    env.update(
        PATH=f"{shim_dir}{os.pathsep}{env['PATH']}",
        REAL_GIT=REAL_GIT,
        GIT_VERIFY_OK="1" if verify_ok else "0",
        GH_CALLS=str(calls),
        GH_STATE=str(tmp_path / "gh_state"),
        TAG_SHA=api_sha,
        SNAPS=json.dumps(_flow() if snaps is None else snaps),
        RELEASE_LIVE_AFTER="environment_ids[]=21",
        APPROVE_POLL_SECONDS=str(poll_s),
        APPROVE_TIMEOUT_SECONDS=str(timeout_s),
    )
    if post_fail:
        env["POST_FAIL_EID"], env["POST_FAIL_MSG"] = str(post_fail[0]), post_fail[1]
    if gh_repo is not None:
        env["GH_REPO"] = gh_repo
    cmd = ["bash", str(APPROVE_SCRIPT), TAG, *args]  # noqa: S607
    if answer is None:
        # A new session with no terminal: /dev/tty cannot be opened.
        proc = subprocess.run(
            cmd,
            cwd=repo,
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
            timeout=25,
            check=False,
            start_new_session=True,
        )
    else:
        proc = _run_on_terminal(cmd, env, repo, answer, stdin)
    log = [ln.split("\x1f")[:-1] for ln in calls.read_text().splitlines() if ln]
    return proc, log


def _run_on_terminal(cmd, env, cwd, answer: str, stdin: str) -> subprocess.CompletedProcess:
    """Run cmd with a real controlling terminal that receives `answer`.

    stdin is a separate pipe, so a test can put a DIFFERENT answer on stdin and
    prove only the terminal counts. forkpty sets the controlling terminal itself;
    the master side must be drained, or the terminal's echo can stall the child.
    """
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    pid, master = pty.fork()
    if pid == 0:  # child: exec immediately
        os.chdir(cwd)
        # Keep one descriptor on the terminal: macOS revokes the controlling
        # terminal once the last one closes ("Device not configured").
        os.dup2(0, 10, inheritable=True)
        os.dup2(in_r, 0)
        os.dup2(out_w, 1)
        os.dup2(err_w, 2)
        os.execvpe(cmd[0], cmd, env)  # noqa: S606
    for fd in (in_r, out_w, err_w):
        os.close(fd)
    os.write(in_w, stdin.encode())
    os.close(in_w)
    os.write(master, answer.encode())
    bufs = {out_r: b"", err_r: b""}
    open_fds = {out_r, err_r}
    deadline = time.monotonic() + 25
    try:
        while open_fds:
            left = deadline - time.monotonic()
            if left <= 0:
                os.kill(pid, signal.SIGKILL)
                raise subprocess.TimeoutExpired(cmd, 25)
            ready, _, _ = select.select([*open_fds, master], [], [], left)
            if master in ready:
                try:
                    os.read(master, 4096)
                except OSError:
                    pass
            for fd in open_fds & set(ready):
                chunk = os.read(fd, 4096)
                if chunk:
                    bufs[fd] += chunk
                else:
                    open_fds.discard(fd)
    finally:
        _, status = os.waitpid(pid, 0)
        for fd in (out_r, err_r, master):
            os.close(fd)
    return subprocess.CompletedProcess(
        cmd, os.waitstatus_to_exitcode(status), bufs[out_r].decode(), bufs[err_r].decode()
    )


def _approvals(log: list[list[str]]) -> list[tuple[str, str]]:
    """(run id, environment id) for every approve POST, in order."""
    out = []
    for call in log:
        if "POST" not in call:
            continue
        path = next(a for a in call if "pending_deployments" in a)
        run_id = re.search(r"/runs/([^/]+)/pending_deployments", path).group(1)
        env_id = next(a.split("=", 1)[1] for a in call if a.startswith("environment_ids[]="))
        assert "state=approved" in call, f"approve POST without state=approved: {call}"
        out.append((run_id, env_id))
    return out


def _out(proc) -> str:
    return proc.stdout + proc.stderr


class TestPrompt:
    def test_lists_every_waiting_environment_with_its_run(self, tmp_path):
        proc, _ = _approve(tmp_path, answer="n\n")
        for env, run_id in (("pypi", 101), ("npm-publish", 102), ("worthless-sh-production", 104)):
            assert env in proc.stdout, proc.stdout
            assert f"https://github.com/{REPO}/actions/runs/{run_id}" in proc.stdout, proc.stdout
        assert SHA[:12] in proc.stdout, "the commit to check must be shown before approving"

    def test_answering_no_approves_nothing(self, tmp_path):
        proc, log = _approve(tmp_path, answer="n\n")
        assert "Approve all? [y/N]" in proc.stdout
        assert _approvals(log) == []
        assert proc.returncode == 3, _out(proc)

    def test_an_empty_answer_approves_nothing(self, tmp_path):
        proc, log = _approve(tmp_path, answer="\n")
        assert _approvals(log) == []
        assert proc.returncode == 3

    def test_the_answer_comes_from_the_terminal_not_stdin(self, tmp_path):
        # `yes | tag-release.sh` puts y on stdin. Only the terminal may answer.
        proc, log = _approve(tmp_path, answer="n\n", stdin="y\n" * 20)
        assert _approvals(log) == []
        assert proc.returncode == 3, _out(proc)

    def test_no_terminal_and_no_yes_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, stdin="y\n")
        assert proc.returncode == 64, _out(proc)
        assert _approvals(log) == []
        assert "--expect-sha" in _out(proc)

    def test_yes_without_expect_sha_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes")
        assert proc.returncode == 64, _out(proc)
        assert _approvals(log) == []

    def test_one_y_approves_the_publishers_then_the_release(self, tmp_path):
        proc, log = _approve(tmp_path, answer="y\n")
        assert proc.returncode == 0, _out(proc)
        approvals = _approvals(log)
        assert sorted(approvals[:3]) == [("101", "11"), ("102", "12"), ("104", "14")], approvals
        assert approvals[3:] == [("201", "21")], (
            "the release environment must be approved after the publishers, without a second prompt"
        )
        assert proc.stdout.count("Approve all?") == 1
        assert f"Release {TAG} is live: https://github.com/{REPO}/releases/tag/{TAG}" in proc.stdout

    def test_yes_with_expect_sha_never_prompts(self, tmp_path):
        proc, log = _approve(tmp_path, *YES)
        assert proc.returncode == 0, _out(proc)
        assert "Approve all?" not in proc.stdout
        assert len(_approvals(log)) == 4

    def test_runs_absent_at_first_poll_are_waited_for(self, tmp_path):
        snaps = [_snap(), _snap(), *_flow()]
        proc, log = _approve(tmp_path, *YES, snaps=snaps)
        assert proc.returncode == 0, _out(proc)
        assert len(_approvals(log)) == 4


class TestFailures:
    def test_a_failed_publisher_is_named_and_exits_1(self, tmp_path):
        runs = _pubs()
        runs[2] = _run(
            103, "Publish Docker image to GHCR", "publish-docker.yml", "completed", "failure"
        )
        proc, log = _approve(tmp_path, *YES, snaps=[_snap(runs, pending=_PUB_PENDING)])
        assert proc.returncode == 1, _out(proc)
        assert "Publish Docker image to GHCR" in _out(proc)
        assert f"https://github.com/{REPO}/actions/runs/103" in _out(proc)
        assert _approvals(log) == [], "never approve a release a publisher refused"

    def test_a_cancelled_publisher_exits_1(self, tmp_path):
        runs = _pubs()
        runs[0] = _run(101, "Publish to PyPI", "publish.yml", "completed", "cancelled")
        proc, _ = _approve(tmp_path, *YES, snaps=[_snap(runs)])
        assert proc.returncode == 1
        assert "Publish to PyPI" in _out(proc)

    def test_a_publisher_failing_while_the_prompt_is_open_approves_nothing(self, tmp_path):
        failed = _pubs()
        failed[2] = _run(
            103, "Publish Docker image to GHCR", "publish-docker.yml", "completed", "failure"
        )
        snaps = _flow(after_y=_snap(failed, pending=_PUB_PENDING))
        proc, log = _approve(tmp_path, answer="y\n", snaps=snaps)
        assert _approvals(log) == [], "a stale y must not approve a release that already failed"
        assert proc.returncode == 1, _out(proc)
        assert "runs/103" in _out(proc)

    def test_a_failed_release_gate_exits_1_fast(self, tmp_path):
        snaps = _flow()[:3] + [_snap(_pubs("in_progress"), rn=[_rn("completed", "failure")])]
        started = time.monotonic()
        proc, _ = _approve(tmp_path, *YES, snaps=snaps)
        assert proc.returncode == 1, _out(proc)
        assert f"https://github.com/{REPO}/actions/runs/201" in _out(proc)
        assert time.monotonic() - started < TIMEOUT_S, "a failed gate must not wait for the timeout"

    def test_release_you_cannot_approve_exits_1(self, tmp_path):
        proc, log = _approve(
            tmp_path, *YES, snaps=_flow(release_pending=_pending(21, "release", can=False))
        )
        assert proc.returncode == 1, _out(proc)
        assert ("201", "21") not in _approvals(log)
        assert "cannot approve release (you are not a reviewer)" in _out(proc)

    def test_a_publisher_you_cannot_approve_exits_1(self, tmp_path):
        pending = {**_PUB_PENDING, "102": _pending(12, "npm-publish", can=False)}
        proc, log = _approve(tmp_path, *YES, snaps=_flow(waiting=_snap(_pubs(), pending=pending)))
        assert proc.returncode == 1, _out(proc)
        assert _approvals(log) == []
        assert "cannot approve npm-publish (you are not a reviewer)" in _out(proc)

    def test_timeout_before_the_prompt_exits_2_with_the_resume_command(self, tmp_path):
        runs = [_run(101, "Publish to PyPI", "publish.yml", "in_progress")]
        proc, log = _approve(tmp_path, *YES, snaps=[_snap(runs)])
        assert proc.returncode == 2, _out(proc)
        assert "Timed out" in _out(proc) and RESUME in _out(proc)
        assert "runs/101" in _out(proc), "say which run is still going"
        assert _approvals(log) == []

    def test_timeout_after_the_y_names_the_run_still_going(self, tmp_path):
        proc, _ = _approve(tmp_path, *YES, snaps=_flow()[:4])
        assert proc.returncode == 2, _out(proc)
        assert RESUME in _out(proc)
        assert "runs/201" in _out(proc)

    def test_the_deadline_starts_at_your_y(self, tmp_path):
        # Polls 2s apart: no runs (t0, t2), publishers waiting (t4: the y), the re-read
        # and approvals (t4), release run started (t6), release waiting (t8: approved,
        # live). With a 6s timeout counted from the start this dies at t6; counted
        # from the y it lasts to t10. Wide margins, so load cannot flip the verdict.
        snaps = [_snap(), *_flow()]
        proc, log = _approve(tmp_path, *YES, snaps=snaps, poll_s=2, timeout_s=6)
        assert proc.returncode == 0, _out(proc)
        assert ("201", "21") in _approvals(log)

    def test_an_already_approved_environment_is_not_an_error(self, tmp_path):
        msg = "gh: No pending deployment requests to approve or reject (HTTP 422)"
        proc, _ = _approve(tmp_path, *YES, post_fail=(12, msg))
        assert proc.returncode == 0, _out(proc)

    def test_a_failed_approve_call_exits_4_and_says_what_was_approved(self, tmp_path):
        proc, log = _approve(tmp_path, *YES, post_fail=(12, "gh: Server Error (HTTP 502)"))
        assert proc.returncode == 4, _out(proc)
        out = _out(proc)
        assert "safe to run again" in out and RESUME in out
        names = {"11": "pypi", "12": "npm-publish", "14": "worthless-sh-production"}
        tried = [names[e] for _, e in _approvals(log)]
        assert tried[-1] == "npm-publish", "the failed call must be the last one made"
        done = ", ".join(tried[:-1]) or "nothing"
        assert f"Approved so far: {done}\n" in out, out
        not_done = (set(names.values()) - set(tried[:-1])) | {"release"}
        line = re.search(r"Not approved: (.*)", out).group(1)
        assert set(line.split(", ")) == not_done, out

    def test_never_creates_a_release_or_dispatches(self, tmp_path):
        _, log = _approve(tmp_path, answer="y\n")
        for call in log:
            assert call[:2] not in (
                ["release", "create"],
                ["workflow", "run"],
                ["issue", "create"],
            ), call
        code = "\n".join(
            ln for ln in APPROVE_SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")
        )
        assert not re.search(r"\bgh\s+(release\s+create|workflow\s+run|issue\s+create)\b", code)


class TestOnlyThisTagIsApproved:
    def test_a_run_at_another_commit_is_never_approved(self, tmp_path):
        # Newer id than the real run: a re-run of an older tag is the NEWEST run, so
        # only the commit filter keeps it out, not "pick the latest per workflow".
        stale = _run(199, "Publish to PyPI", "publish.yml", "waiting", sha=OLD_SHA)
        waiting = _snap([*_pubs(), stale], pending={**_PUB_PENDING, "199": _pending(9, "pypi")})
        proc, log = _approve(tmp_path, *YES, snaps=_flow(waiting=waiting))
        assert proc.returncode == 0, _out(proc)
        assert all(run_id != "199" for run_id, _ in _approvals(log))
        assert re.search(r"skipped: .*runs/199 \(not this tag's push\)", proc.stdout), proc.stdout

    def test_a_dispatched_run_on_the_same_environment_is_never_approved(self, tmp_path):
        # e.g. `gh workflow run deploy-worker.yml --ref v9.9.9`: same tag, same
        # commit, same environment, newest id — but not the tag's push.
        dispatched = {
            **_run(150, "Deploy Worker (worthless-sh)", "deploy-worker.yml", "waiting"),
            "event": "workflow_dispatch",
        }
        pending = {**_PUB_PENDING, "150": _pending(14, "worthless-sh-production")}
        proc, log = _approve(
            tmp_path, *YES, snaps=_flow(waiting=_snap([*_pubs(), dispatched], pending=pending))
        )
        assert proc.returncode == 0, _out(proc)
        assert all(run_id != "150" for run_id, _ in _approvals(log)), _approvals(log)
        assert ("104", "14") in _approvals(log)
        assert re.search(r"skipped: .*runs/150 \(not this tag's push\)", proc.stdout), proc.stdout

    def test_an_unexpected_environment_is_never_approved(self, tmp_path):
        extra = {
            "environment": {"id": 15, "name": "pypi-staging"},
            "current_user_can_approve": True,
        }
        pending = {**_PUB_PENDING, "101": [*_PUB_PENDING["101"], extra]}
        proc, log = _approve(tmp_path, *YES, snaps=_flow(waiting=_snap(_pubs(), pending=pending)))
        assert proc.returncode == 0, _out(proc)
        assert ("101", "15") not in _approvals(log)
        assert ("101", "11") in _approvals(log)
        assert "skipped: pypi-staging" in proc.stdout, proc.stdout

    def test_an_environment_is_approved_only_on_its_own_workflow(self, tmp_path):
        # npm-publish is a release environment, but not PyPI's.
        pending = {**_PUB_PENDING, "101": _pending(16, "npm-publish")}
        proc, log = _approve(tmp_path, *YES, snaps=_flow(waiting=_snap(_pubs(), pending=pending)))
        assert ("101", "16") not in _approvals(log), _approvals(log)
        assert ("102", "12") in _approvals(log)
        assert "skipped: npm-publish  Publish to PyPI" in proc.stdout, proc.stdout

    def test_a_run_that_appears_after_the_y_is_not_approved(self, tmp_path):
        # A re-pushed tag makes a NEW run; the y covered only what was shown.
        repushed = _run(105, "Publish to PyPI", "publish.yml", "waiting")
        after_y = _snap([*_pubs(), repushed], pending={**_PUB_PENDING, "105": _pending(17, "pypi")})
        proc, log = _approve(tmp_path, *YES, snaps=_flow(after_y=after_y))
        assert ("105", "17") not in _approvals(log), _approvals(log)
        assert ("101", "11") in _approvals(log)
        assert re.search(
            r"Not approved: pypi .*runs/105 \(appeared after you answered", proc.stdout
        ), proc.stdout

    def test_github_tag_moved_from_the_local_signed_tag_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, *YES, api_sha=OLD_SHA)
        assert proc.returncode == 1, _out(proc)
        assert _approvals(log) == []
        assert SHA[:12] in _out(proc) and OLD_SHA[:12] in _out(proc)

    def test_expect_sha_mismatch_refuses(self, tmp_path):
        proc, log = _approve(tmp_path, "--yes", "--expect-sha", OLD_SHA)
        assert proc.returncode == 1, _out(proc)
        assert _approvals(log) == []
        assert OLD_SHA[:12] in _out(proc)

    def test_an_unsigned_tag_refuses_without_expect_sha(self, tmp_path):
        proc, log = _approve(tmp_path, answer="y\n", verify_ok=False)
        assert proc.returncode == 1, _out(proc)
        assert _approvals(log) == []
        assert "signature" in _out(proc)

    def test_expect_sha_skips_the_local_signature_check(self, tmp_path):
        # CI has no signing key: the Action's human gate plus --expect-sha stand in.
        proc, _ = _approve(tmp_path, *YES, verify_ok=False)
        assert proc.returncode == 0, _out(proc)

    def test_a_release_run_for_an_old_commit_is_never_approved(self, tmp_path):
        title = f"Create GitHub Release {TAG} {OLD_SHA}"
        proc, log = _approve(tmp_path, *YES, snaps=_flow(release=_rn("waiting", title=title)))
        assert ("201", "21") not in _approvals(log)
        assert proc.returncode == 2

    def test_a_release_titled_run_that_is_not_a_workflow_run_is_never_approved(self, tmp_path):
        # A PR that edits release-notes.yml runs under the same path and can title
        # itself like a release; only workflow_run runs use the default branch's file.
        proc, log = _approve(
            tmp_path, *YES, snaps=_flow(release=_rn("waiting", event="pull_request"))
        )
        assert ("201", "21") not in _approvals(log)
        assert proc.returncode == 2

    def test_the_release_run_approves_only_the_release_environment(self, tmp_path):
        proc, log = _approve(tmp_path, *YES, snaps=_flow(release_pending=_pending(22, "pypi")))
        assert ("201", "22") not in _approvals(log)
        assert proc.returncode == 2

    def test_a_release_run_that_is_not_waiting_is_never_approved(self, tmp_path):
        # Stale pending data on a running run must not be acted on.
        proc, log = _approve(tmp_path, *YES, snaps=_flow(release=_rn("in_progress")))
        assert ("201", "21") not in _approvals(log)
        assert proc.returncode == 2

    def test_repo_defaults_from_gh_repo_view(self, tmp_path):
        proc, log = _approve(tmp_path, *YES, gh_repo=None)
        assert proc.returncode == 0, _out(proc)
        assert any(c[:2] == ["repo", "view"] for c in log)


def _critical_path_min(workflow: str) -> int:
    """Longest chain of job timeout-minutes through a workflow's `needs:`."""
    jobs = yaml.safe_load((REPO_ROOT / ".github/workflows" / workflow).read_text())["jobs"]

    def path(name: str) -> int:
        needs = jobs[name].get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        return int(jobs[name]["timeout-minutes"]) + max((path(n) for n in needs), default=0)

    return max(path(n) for n in jobs)


def test_default_timeout_outlasts_the_slowest_publisher():
    """The Release needs the GHCR image, then the release-notes run. A default shorter
    than both chained times out a release that is still going, and the maintainer
    reads it as broken. Same sum as the WOR-1167 Action's test."""
    default = int(re.search(r"^timeout_min=(\d+)$", APPROVE_SCRIPT.read_text(), re.M).group(1))
    docker = _critical_path_min("publish-docker.yml")
    release = _critical_path_min("release-notes.yml")
    assert default >= docker + release + 10, (
        f"--timeout-min defaults to {default}, but publish-docker.yml ({docker} min) then "
        f"release-notes.yml ({release} min) can take {docker + release} min by their job "
        "timeouts. Keep at least 10 min of margin."
    )


def _tag_release_hook_line() -> tuple[int, int, str]:
    lines = [
        ln.strip()
        for ln in TAG_RELEASE_SCRIPT.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    push = lines.index('git push origin "$tag"')
    calls = [i for i, ln in enumerate(lines) if 'scripts/approve-release.sh "$tag"' in ln]
    assert calls, 'tag-release.sh must run scripts/approve-release.sh "$tag"'
    return push, calls[0], lines[calls[0]]


class TestTagReleaseCallsApprove:
    def test_tag_release_hands_off_to_approve_after_the_push(self):
        push, call, line = _tag_release_hook_line()
        assert call > push, "approve-release must run after the tag is pushed"
        # The tag is already pushed: a failed approval must not abort under set -e
        # as if tagging failed. It must be guarded and fall back to the GitHub UI.
        assert line.startswith("if ") or "||" in line, f"the approve call is unguarded: {line!r}"

    def test_tag_release_never_passes_yes(self):
        # The maintainer's own y on their own terminal is the consent. --yes would
        # turn the hand-off into an unattended approval.
        _, _, line = _tag_release_hook_line()
        assert "--yes" not in line, f"tag-release.sh must not pre-answer the prompt: {line!r}"

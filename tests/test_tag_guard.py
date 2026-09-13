"""The reference-transaction tag guard refuses an unsigned release tag at creation.

Hermetic: no real keys, no network. Signed tags are synthesised by writing a tag object
whose body carries the OpenPGP armor line, which is exactly what the guard inspects --
it deliberately never invokes gpg. See RELEASING.md (WOR-908) for why.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from tests._install_helpers import REPO_ROOT

GIT = shutil.which("git") or "git"
HOOK = REPO_ROOT / "scripts" / "hooks" / "reference-transaction"
FLOOR = "v0.3.12"


def git(repo: Path, *args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([GIT, *args], cwd=repo, capture_output=True, text=True, **kw)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "lab"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "T")
    git(r, "config", "commit.gpgsign", "false")
    git(r, "config", "tag.gpgsign", "false")
    (r / "a").write_text("x")
    git(r, "add", "a")
    git(r, "commit", "-qm", "init", "--no-gpg-sign")
    hooks = r / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    dest = hooks / "reference-transaction"
    dest.write_bytes(HOOK.read_bytes())
    dest.chmod(0o755)
    return r


def write_tag_object(repo: Path, name: str, armor: str) -> str:
    """Write a tag object whose body carries `armor`, and return its sha."""
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    body = (
        f"object {head}\ntype commit\ntag {name}\n"
        "tagger T <t@example.invalid> 1700000000 +0000\n\n"
        f"{name}\n"
        f"-----BEGIN {armor} SIGNATURE-----\n\nZmFrZQ==\n-----END {armor} SIGNATURE-----\n"
    )
    return subprocess.run(
        [GIT, "hash-object", "-w", "-t", "tag", "--stdin"],
        cwd=repo,
        input=body,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def signed_tag(repo: Path, name: str, armor: str = "PGP") -> subprocess.CompletedProcess:
    """Create a signed-looking tag object, then publish the ref through the hook."""
    return git(repo, "update-ref", f"refs/tags/{name}", write_tag_object(repo, name, armor))


def has_tag(repo: Path, name: str) -> bool:
    return bool(git(repo, "tag", "-l", name).stdout.strip())


class TestRejects:
    def test_lightweight_tag_is_refused(self, repo: Path) -> None:
        """A bare `git tag v9.9.9` -- the failure this guard exists for."""
        r = git(repo, "tag", "v9.9.9")
        assert r.returncode != 0
        assert not has_tag(repo, "v9.9.9")
        assert "tag-release.sh" in r.stderr

    def test_unsigned_annotated_tag_is_refused(self, repo: Path) -> None:
        r = git(repo, "tag", "-a", "v9.9.9", "-m", "m")
        assert r.returncode != 0
        assert not has_tag(repo, "v9.9.9")

    def test_non_pgp_signature_is_refused(self, repo: Path) -> None:
        """An SSH-signed tag says BEGIN SSH SIGNATURE. This is the 0.3.7 / v0.3.12 bug."""
        r = signed_tag(repo, "v9.9.9", armor="SSH")
        assert r.returncode != 0
        assert not has_tag(repo, "v9.9.9")

    def test_rejection_is_logged(self, repo: Path) -> None:
        git(repo, "tag", "v9.9.9")
        log = repo / ".git" / "worthless-tag-guard.log"
        assert log.is_file()
        assert "reject refs/tags/v9.9.9" in log.read_text()


class TestAllows:
    def test_pgp_signed_tag_is_allowed(self, repo: Path) -> None:
        assert signed_tag(repo, "v9.9.9").returncode == 0
        assert has_tag(repo, "v9.9.9")

    @pytest.mark.parametrize("name", ["v0.3.4", "v0.3.0", "v0.3.0rc1", "v0.3.0rc2"])
    def test_tags_below_the_floor_are_allowed(self, repo: Path, name: str) -> None:
        """These four exist unsigned on origin. Rejecting one aborts an entire fetch."""
        assert git(repo, "tag", name).returncode == 0
        assert has_tag(repo, name)

    def test_non_release_tags_are_ignored(self, repo: Path) -> None:
        assert git(repo, "tag", "nightly-1").returncode == 0

    def test_deletion_is_allowed(self, repo: Path) -> None:
        """`git tag -d` sends all-zeros as *both* old and new."""
        signed_tag(repo, "v9.9.9")
        assert git(repo, "tag", "-d", "v9.9.9").returncode == 0

    def test_override_is_allowed_and_logged(self, repo: Path) -> None:
        r = git(repo, "tag", "v9.9.9", env={"WORTHLESS_TAG_OVERRIDE": "1", "PATH": "/usr/bin:/bin"})
        assert r.returncode == 0
        assert has_tag(repo, "v9.9.9")
        assert "override" in (repo / ".git" / "worthless-tag-guard.log").read_text()


class TestDoesNotBreakGit:
    def test_pack_refs_survives_unsigned_history(self, repo: Path) -> None:
        """pack-refs replays every ref as a creation. A rejection here makes `gc` exit 0
        while silently failing, permanently losing ref packing."""
        git(repo, "tag", "v0.3.4")
        assert git(repo, "pack-refs", "--all").returncode == 0

    def test_gc_survives_unsigned_history(self, repo: Path) -> None:
        git(repo, "tag", "v0.3.4")
        assert git(repo, "gc", "--prune=now").returncode == 0

    def test_fetching_unsigned_tags_is_not_blocked(self, tmp_path: Path, repo: Path) -> None:
        """A rejection aborts the whole transaction, taking good refs and branch
        updates with it. Historical tags must therefore pass untouched."""
        git(repo, "tag", "v0.3.4")
        git(repo, "tag", "v0.3.0")
        clone = tmp_path / "clone"
        subprocess.run([GIT, "clone", "-q", "--no-tags", str(repo), str(clone)], check=True)
        dest = clone / ".git" / "hooks" / "reference-transaction"
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(HOOK.read_bytes())
        dest.chmod(0o755)
        r = git(clone, "fetch", "--tags", "origin")
        assert r.returncode == 0, r.stderr
        assert has_tag(clone, "v0.3.4")


def test_floor_is_hardcoded_not_derived() -> None:
    """A `--no-tags` clone would derive an empty floor and then reject everything."""
    src = HOOK.read_text()
    assert f'FLOOR="{FLOOR}"' in src
    assert "git describe" not in src
    assert "git tag -l" not in src


def test_guard_never_invokes_gpg() -> None:
    """`git verify-tag` accepts SSH-signed tags whenever gpg.ssh.allowedSignersFile is
    set, which is the exact failure this guards. It would also couple every ref
    transaction to keyring health."""
    src = HOOK.read_text()
    code = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "verify-tag" not in code
    assert "gpg" not in code

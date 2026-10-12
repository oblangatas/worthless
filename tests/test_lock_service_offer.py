"""WOR-853 — `lock` offers to keep the proxy running after the terminal closes.

`curl worthless.sh | sh` leaves nothing running. The offer cannot live in
``install.sh``: ``preflight_service_install`` (``service/_common.py:112-126``)
refuses with KEY_NOT_FOUND unless a Fernet key exists, and at ``curl | sh``
time there is no project, no ``.env`` and no key. ``lock`` is the first moment
the key exists, so the offer belongs here.

The load-bearing case is the one with nobody watching: a piped or CI ``lock``
must DECLINE and carry on, never block waiting for an answer that will not
come. That is the assertion that makes this safe to ship.
"""

from __future__ import annotations

import re
import subprocess
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from worthless.cli import default_command
from worthless.cli.app import app
from worthless.cli.commands.lock import _offer_service_after_lock
from worthless.cli.console import WorthlessConsole
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.errors import ErrorCode, WorthlessError


@pytest.fixture
def console() -> WorthlessConsole:
    return WorthlessConsole()


@pytest.fixture(autouse=True)
def _not_in_a_container():
    """The suite itself may run inside Docker; the container skip is tested explicitly."""
    with patch("worthless.cli.commands.lock._in_container", return_value=False):
        yield


def _flat(captured) -> str:
    """Rich wraps at terminal width; assert on the message, not the layout."""
    return re.sub(r"\s+", " ", captured.out + captured.err)


def _home() -> MagicMock:
    return MagicMock(name="WorthlessHome")


class TestNonInteractive:
    """The case that must never hang."""

    def test_no_terminal_declines_instead_of_blocking(self, console: WorthlessConsole) -> None:
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", side_effect=typer.Abort()),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)

        assert accepted is False
        install.assert_not_called()

    def test_eof_on_stdin_also_declines(self, console: WorthlessConsole) -> None:
        """A closed pipe raises EOFError rather than Abort; both mean 'nobody there'."""
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", side_effect=EOFError()),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        install.assert_not_called()

    def test_json_mode_never_prompts(self) -> None:
        """Machine output must not grow an interactive question."""
        console = WorthlessConsole(json_mode=True)
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        confirm.assert_not_called()
        install.assert_not_called()


class TestConsent:
    def test_yes_installs_the_service(self, console: WorthlessConsole) -> None:
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is True
        install.assert_called_once()

    def test_no_leaves_the_banner_behind(self, console: WorthlessConsole, capsys) -> None:
        """Declining is not a dead end — the user still learns the command."""
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=False),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        install.assert_not_called()
        assert "worthless service install" in _flat(capsys.readouterr())

    def test_assume_yes_skips_the_question(self, capsys) -> None:
        """`worthless --yes lock` must not stop to ask."""
        console = WorthlessConsole(assume_yes=True)
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is True
        confirm.assert_not_called()
        install.assert_called_once()


class TestHonestCopy:
    def test_does_not_promise_reboot_survival(self, console: WorthlessConsole, capsys) -> None:
        """WOR-725 has never proven survives-reboot; do not claim it here.

        The existing service banner does make that claim. This offer must not
        repeat it until there is a test behind it.
        """
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True),
            patch("worthless.cli.commands.lock.install_service_for_offer"),
        ):
            _offer_service_after_lock(console, home=_home(), port=8787)
        assert "reboot" not in _flat(capsys.readouterr()).lower()

    def test_install_failure_does_not_fail_the_lock(self, console: WorthlessConsole) -> None:
        """The keys are already protected by the time we ask.

        A service that will not install is a worse outcome than no service, but
        it is not a reason to report that `lock` failed.
        """
        from worthless.cli.errors import ErrorCode, WorthlessError

        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True),
            patch(
                "worthless.cli.commands.lock.install_service_for_offer",
                side_effect=WorthlessError(ErrorCode.SERVICE_INSTALL_FAILED, "nope"),
            ),
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False


class TestTtyGate:
    """The prompt must never be reached when nobody can answer it.

    Regression: a captured stdin raises OSError, not EOFError, so catching the
    exception was not enough — five unrelated lock suites broke on it. The gate
    also suppresses under CI env vars, where a pseudo-TTY looks interactive.
    """

    def test_no_tty_declines_without_prompting(self, console: WorthlessConsole) -> None:
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=False),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        confirm.assert_not_called()
        install.assert_not_called()

    def test_assume_yes_does_not_win_over_a_missing_tty(self, console: WorthlessConsole) -> None:
        """REVERSED 2026-10-08. This test used to assert the opposite, on the
        reasoning that "`--yes` is an explicit instruction; it does not need a
        terminal". That reasoning shipped a defect: `worthless --yes lock` with
        stdin piped installed a user service, and enabled linger, with no
        prompt and no way to decline — confirmed live. `--yes` auto-approves
        prompts, and where nobody can see a prompt there is nothing to approve.

        See TestConsentIsNotBypassable for the full argument.
        """
        console = WorthlessConsole(assume_yes=True)
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=False),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        install.assert_not_called()


class TestConsentIsNotBypassable:
    """`--yes` must not create account-level state nobody asked for.

    Review, 2026-10-05, confirmed live: `worthless --yes lock` with stdin piped
    installed a user service with no prompt. Installing one also runs
    `loginctl enable-linger`, which `worthless service uninstall` never
    reverses — so a blanket "auto-approve prompts" flag in a Dockerfile or CI
    job was enough to leave persistent state on the account.

    `--yes` is documented as auto-approving PROMPTS. A prompt nobody can see is
    not a prompt, so there is nothing for it to approve.
    """

    def test_yes_flag_does_not_install_when_nobody_is_watching(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str]
    ) -> None:
        console.assume_yes = True
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=False),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)

        assert accepted is False
        install.assert_not_called()
        confirm.assert_not_called()
        assert "worthless service install" in _flat(capsys.readouterr())

    def test_yes_flag_still_accepts_at_a_real_terminal(self, console: WorthlessConsole) -> None:
        """The flag keeps working where a human could have answered."""
        console.assume_yes = True
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
            patch("worthless.cli.commands.lock._print_service_banner"),
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)

        assert accepted is True
        install.assert_called_once()
        confirm.assert_not_called()

    def test_the_question_defaults_to_no(self, console: WorthlessConsole) -> None:
        """Pin the default. Without this, flipping it to True keeps every test green."""
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=False) as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer"),
        ):
            _offer_service_after_lock(console, home=_home(), port=8787)

        assert confirm.call_args.kwargs["default"] is False


class TestFailedInstallIsSurvivable:
    """A lock that worked must never report that it crashed.

    `run_cmd` uses `check=True` (`service/_common.py`), so a failing
    `launchctl bootstrap` or `systemctl enable` raises CalledProcessError, not
    WorthlessError. Catching only WorthlessError let that escape to
    `@error_boundary`, which printed `WRTLS-199: an internal error occurred`
    and exited 1 — after the keys were already protected. Proven live.
    """

    @pytest.mark.parametrize(
        "boom",
        [
            subprocess.CalledProcessError(1, ["launchctl", "bootstrap"]),
            OSError("no such file: launchctl"),
            WorthlessError(ErrorCode.KEY_NOT_FOUND, "no fernet key"),
        ],
        ids=["activation-failed", "binary-missing", "preflight-refused"],
    )
    def test_install_failure_never_fails_the_lock(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str], boom: Exception
    ) -> None:
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True),
            patch("worthless.cli.commands.lock.install_service_for_offer", side_effect=boom),
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)

        assert accepted is False
        out = _flat(capsys.readouterr())
        assert "still protected" in out
        assert "WRTLS-199" not in out


class TestWslIsAskedHonestly:
    """Do not ask a question whose answer we know is no.

    Measured on real WSL2 (CI, WOR-853): with the default config the distro —
    and the proxy with it — stops ~15 s after the last WSL terminal closes. So
    "keep the proxy running after this terminal closes?" is a promise WSL does
    not keep. The warning used to print only AFTER the unit was written and
    linger enabled. Consent collected after the irreversible step is not
    consent.
    """

    def _ask(self, console: WorthlessConsole, *, on_wsl: bool) -> str:
        with (
            patch("worthless.cli.commands.lock.is_wsl", return_value=on_wsl),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=False) as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer"),
        ):
            _offer_service_after_lock(console, home=_home(), port=8787)
        return confirm.call_args.args[0]

    def test_wsl_is_told_it_stops_before_being_asked(self, console: WorthlessConsole) -> None:
        question = self._ask(console, on_wsl=True)
        assert "15" in question, "the WSL user must learn the lifetime in the question itself"
        assert "instanceIdleTimeout" in question

    def test_wsl_question_does_not_promise_what_wsl_breaks(self, console: WorthlessConsole) -> None:
        question = self._ask(console, on_wsl=True).lower()
        assert "keep the proxy running after this terminal closes" not in question

    def test_off_wsl_the_question_is_unchanged(self, console: WorthlessConsole) -> None:
        question = self._ask(console, on_wsl=False)
        assert "after this terminal closes" in question
        assert "instanceIdleTimeout" not in question


class TestNoOfferWhenAlreadyInstalled:
    """Do not re-run install() over a service that already exists.

    Review (Cursor Bugbot, 2026-10-08): the offer never checked. A second lock
    with new keys asked again, and accepting called the full install(), which
    rewrites the unit and on launchd boots out the running agent first. If
    activation then failed, rollback would NOT restore it — `created_here` is
    false for a file that already existed — so a working proxy could be left
    stopped while lock reported success.
    """

    def _offer_with_state(self, console: WorthlessConsole, state):
        backend = MagicMock()
        backend.detect_status.return_value = MagicMock(state=state)
        with (
            patch("worthless.cli.commands.lock._backend", return_value=backend),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True) as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
            patch("worthless.cli.commands.lock._print_service_banner"),
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)
        return accepted, confirm, install

    @pytest.mark.parametrize(
        "state", [ServiceState.RUNNING, ServiceState.STOPPED, ServiceState.FAILED]
    )
    def test_existing_service_is_not_touched(self, console: WorthlessConsole, state) -> None:
        accepted, confirm, install = self._offer_with_state(console, state)
        assert accepted is False
        confirm.assert_not_called()
        install.assert_not_called()

    def test_still_offers_when_nothing_is_installed(self, console: WorthlessConsole) -> None:
        accepted, confirm, install = self._offer_with_state(console, ServiceState.NOT_INSTALLED)
        assert accepted is True
        confirm.assert_called_once()
        install.assert_called_once()

    def test_a_broken_detect_does_not_fail_the_lock(self, console: WorthlessConsole) -> None:
        """If we cannot tell, say nothing rather than crash a successful lock."""
        backend = MagicMock()
        backend.detect_status.side_effect = OSError("launchctl missing")
        with (
            patch("worthless.cli.commands.lock._backend", return_value=backend),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        confirm.assert_not_called()
        install.assert_not_called()


class TestYesFlagThroughTheRealCli:
    """Cover the wiring, not just the helper.

    Review (Jenny, then karen, 2026-10-08): every other test here constructs
    `WorthlessConsole(assume_yes=True)` directly, so `app.py`'s `assume_yes=yes`
    — the single line that carries `--yes` to the offer, and the line defect 1
    lived on — was asserted nowhere. Deleting it broke no test.

    CliRunner's stdin is not a terminal, which is exactly the shape that
    installed a service with no prompt before the gate was reordered.
    """

    def _project(self, tmp_path: Path) -> Path:
        proj = tmp_path / "proj"
        proj.mkdir()
        # A fixed literal, not generated: the scanner skips repeated-character
        # placeholders, and `random` is banned here (CRYP-04).
        body = "T3mP9kQw2ZxA7bNf4YrL6hJd8VsG1cUeM5oPi0ElRtXnKaBz"
        (proj / ".env").write_text(f"OPENAI_API_KEY=sk-proj-{body}\n")
        return proj / ".env"

    def test_yes_lock_installs_nothing_without_a_terminal(self, tmp_path: Path) -> None:
        env_file = self._project(tmp_path)
        with patch("worthless.cli.commands.lock.install_service_for_offer") as install:
            result = CliRunner().invoke(
                app,
                ["--yes", "lock", "--env", str(env_file)],
                env={
                    "WORTHLESS_HOME": str(tmp_path / ".worthless"),
                    "WORTHLESS_KEYRING_BACKEND": "null",
                    "HOME": str(tmp_path),
                },
            )

        assert result.exit_code == 0, result.output
        install.assert_not_called(), "--yes installed a service with nobody watching"

    def test_the_flag_actually_reaches_the_console(self, tmp_path: Path) -> None:
        """Pin app.py's wiring itself, so deleting it fails something."""
        env_file = self._project(tmp_path)
        seen: list[bool] = []
        real_offer = _offer_service_after_lock

        def spy(console, **kwargs):
            seen.append(console.assume_yes)
            return real_offer(console, **kwargs)

        with (
            patch("worthless.cli.commands.lock._offer_service_after_lock", side_effect=spy),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=False),
        ):
            CliRunner().invoke(
                app,
                ["--yes", "lock", "--env", str(env_file)],
                env={
                    "WORTHLESS_HOME": str(tmp_path / ".worthless"),
                    "WORTHLESS_KEYRING_BACKEND": "null",
                    "HOME": str(tmp_path),
                },
            )

        assert seen == [True], f"--yes did not reach the offer's console: {seen}"


class TestTheOfferCannotAbortACommittedLock:
    """The lock is finished before we ask. An optional extra must not undo it.

    Review (task-completion-validator, 2026-10-08), defect 8 — the same shape
    as defect 7, fixed in the backends and left in the caller. `install()` ends
    with `report_proxy_health()`, which prints "Waiting up to 45s..." and
    blocks; the code itself documents that operators interrupt exactly that
    wait. KeyboardInterrupt is not in (WorthlessError, CalledProcessError,
    OSError), so it escaped the offer, propagated out of `_lock_keys`, and
    became exit 130 — on a lock that had fully succeeded and a service that was
    fully installed. `_sync_fernet_after_lock` was ordered AFTER the offer, so
    it was skipped too.
    """

    @pytest.mark.parametrize(
        "boom", [KeyboardInterrupt(), SystemExit(1)], ids=["ctrl-c", "systemexit"]
    )
    def test_an_interrupt_during_install_does_not_escape(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str], boom: BaseException
    ) -> None:
        backend = MagicMock()
        backend.detect_status.return_value = MagicMock(state=ServiceState.NOT_INSTALLED)
        with (
            patch("worthless.cli.commands.lock._backend", return_value=backend),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm", return_value=True),
            patch("worthless.cli.commands.lock.install_service_for_offer", side_effect=boom),
        ):
            accepted = _offer_service_after_lock(console, home=_home(), port=8787)

        assert accepted is False
        out = _flat(capsys.readouterr())
        assert "still protected" in out
        assert "worthless service status" in out, "an interrupt may leave it installed; say so"

    def test_the_fernet_sync_happens_before_the_offer(self) -> None:
        """Ordering, pinned. The offer must not be able to skip post-lock work."""
        source = Path("src/worthless/cli/commands/lock.py").read_text()
        sync_at = source.index("_sync_fernet_after_lock(home)")
        offer_at = source.index("_offer_service_after_lock(console, home=home")
        assert sync_at < offer_at, (
            "_sync_fernet_after_lock must run BEFORE the service offer: anything "
            "raised by the offer would otherwise skip it on a committed lock"
        )


class TestTheDeclineHintIsHonestOnWsl:
    """The hint must not re-make the promise the question was rewritten to drop.

    Review (Cursor Bugbot, 2026-10-08), defect 11 — the same shape as 9 and 10:
    one message was fixed and its sibling left alone. `_offer_question()` stops
    telling WSL users the proxy keeps running after their terminal closes, but
    the decline hint still said exactly that. On a piped lock the hint is the
    ONLY thing printed, and on a declined prompt it lands one line under the
    honest question and contradicts it.
    """

    def _hint(self, console: WorthlessConsole, capsys, *, on_wsl: bool, tty: bool) -> str:
        with (
            patch("worthless.cli.commands.lock.is_wsl", return_value=on_wsl),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=tty),
            patch("worthless.cli.commands.lock._backend") as backend,
            patch("worthless.cli.commands.lock.typer.confirm", return_value=False),
            patch("worthless.cli.commands.lock.install_service_for_offer"),
        ):
            backend.return_value.detect_status.return_value = MagicMock(
                state=ServiceState.NOT_INSTALLED
            )
            _offer_service_after_lock(console, home=_home(), port=8787)
        return _flat(capsys.readouterr())

    @pytest.mark.parametrize("tty", [True, False], ids=["declined-at-tty", "piped"])
    def test_wsl_is_not_promised_terminal_survival(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str], tty: bool
    ) -> None:
        hint = self._hint(console, capsys, on_wsl=True, tty=tty).lower()
        assert "keep running after you close this terminal" not in hint
        assert "worthless service install" in hint, "it must still name the command"

    @pytest.mark.parametrize("tty", [True, False], ids=["declined-at-tty", "piped"])
    def test_off_wsl_the_hint_is_unchanged(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str], tty: bool
    ) -> None:
        hint = self._hint(console, capsys, on_wsl=False, tty=tty).lower()
        assert "keep running after you close this terminal" in hint


class TestTheQuestionIsExplicit:
    """WOR-859 ruling: off by default, asked explicitly.

    A one-line "installs a user service" let people agree to a login item and a
    master-key file without knowing either existed. Reverting `_offer_question`
    to that one line turns every assertion here red.
    """

    def _ask(
        self,
        console: WorthlessConsole,
        *,
        backend: str,
        on_wsl: bool = False,
        key_path: Path | None = None,
    ) -> str:
        with (
            patch(
                "worthless.cli.commands.lock.current_platform_backend_name", return_value=backend
            ),
            patch("worthless.cli.commands.lock.is_wsl", return_value=on_wsl),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock._backend") as b,
            patch("worthless.cli.commands.lock.typer.confirm", return_value=False) as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer"),
        ):
            b.return_value.detect_status.return_value = MagicMock(state=ServiceState.NOT_INSTALLED)
            home = _home()
            home.fernet_key_path = key_path or Path.home() / ".worthless" / "fernet.key"
            _offer_service_after_lock(console, home=home, port=8787)
        return confirm.call_args.args[0]

    @pytest.mark.parametrize(
        ("backend", "unit_name"),
        [("launchd", "sh.worthless.proxy.plist"), ("systemd", "worthless-proxy.service")],
    )
    def test_names_what_it_adds_the_trade_off_and_the_undo(
        self, console: WorthlessConsole, backend: str, unit_name: str
    ) -> None:
        question = self._ask(console, backend=backend)
        assert unit_name in question, "the user must see the file being added"
        assert "starts Worthless" in question
        assert "fernet.key" in question, "the master-key file is the trade-off"
        assert "worthless service uninstall (the key file stays)" in question
        assert "Say no" in question

    def test_mac_wording_says_login_item(self, console: WorthlessConsole) -> None:
        question = self._ask(console, backend="launchd")
        assert "macOS login item" in question
        assert "when you log in" in question
        assert "linger" not in question, "launchd has no lingering"

    def test_linux_is_told_about_lingering_before_answering(
        self, console: WorthlessConsole
    ) -> None:
        """Lingering starts it at boot and outlives uninstall (worthless-fzas).

        It used to be said only in the banner AFTER install. Saying "when you
        log in" here was false on systemd (PR #673 review).
        """
        question = self._ask(console, backend="systemd")
        assert "when this computer" in question
        assert "lingering" in question
        assert "loginctl disable-linger" in question
        assert "when you log in" not in question

    def test_a_moved_key_file_is_shown_where_it_really_is(
        self, console: WorthlessConsole, tmp_path: Path
    ) -> None:
        """WORTHLESS_FERNET_KEY_PATH moves the file; the question must follow it."""
        moved = tmp_path / "elsewhere" / "my.key"
        assert str(moved) in self._ask(console, backend="launchd", key_path=moved)

    @pytest.mark.parametrize(
        ("backend", "on_wsl"), [("launchd", False), ("systemd", False), ("systemd", True)]
    )
    def test_every_line_fits_an_80_column_terminal(
        self, console: WorthlessConsole, backend: str, on_wsl: bool
    ) -> None:
        """typer.confirm prints plain text; the terminal wraps it mid-word otherwise."""
        question = self._ask(console, backend=backend, on_wsl=on_wsl)
        too_long = [line for line in question.splitlines() if len(line) > 80]
        assert not too_long, too_long

    def test_never_claims_restart_survival(self, console: WorthlessConsole) -> None:
        """Reboot survival is unproven (WOR-725); say what the unit does, not more."""
        question = self._ask(console, backend="launchd").lower()
        assert "reboot" not in question
        assert "restart" not in question

    def test_wsl_keeps_its_warning_and_gets_the_details(self, console: WorthlessConsole) -> None:
        question = self._ask(console, backend="systemd", on_wsl=True)
        assert "instanceIdleTimeout" in question
        assert "fernet.key" in question


class TestContainersAreNotAsked:
    """Docker Desktop and Codespaces terminals are real TTYs, so the tty gate
    lets them through, and the install can only fail. Delete the container
    check in `_offer_service_after_lock` and these turn red."""

    def test_no_question_and_no_install_in_a_container(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with (
            patch("worthless.cli.commands.lock._in_container", return_value=True),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
            patch("worthless.cli.commands.lock.typer.confirm") as confirm,
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is False
        confirm.assert_not_called()
        install.assert_not_called()

    def test_the_hint_does_not_send_them_in_a_circle(
        self, console: WorthlessConsole, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with (
            patch("worthless.cli.commands.lock._in_container", return_value=True),
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=True),
        ):
            _offer_service_after_lock(console, home=_home(), port=8787)
        out = _flat(capsys.readouterr())
        assert "service install" not in out
        assert "worthless up" in out


class TestPlainWorthlessAsks:
    """WOR-859: the command the docs send new users to must ask too.

    Before this, plain `worthless` locked with quiet=True and the offer never
    fired. Delete the offer call in `_run_enrollment_if_needed` and
    `test_asks_after_locking` turns red.
    """

    def _enroll(self, *, yes: bool, locked: int = 1, found: int = 1) -> MagicMock:
        home = MagicMock(name="WorthlessHome")
        home.db_path.exists.return_value = False
        with (
            patch.object(default_command, "_has_enrolled_keys", return_value=False),
            patch.object(default_command, "find_env_file", return_value=Path(".env")),
            patch.object(default_command, "scan_env_keys", return_value=[MagicMock()] * found),
            patch.object(default_command, "show_detected_keys"),
            patch.object(default_command.typer, "confirm", return_value=True),
            patch.object(default_command, "acquire_lock", return_value=nullcontext()),
            patch.object(default_command, "_lock_keys", return_value=locked),
            patch.object(default_command, "_offer_service_after_lock") as offer,
        ):
            default_command._run_enrollment_if_needed(
                home, WorthlessConsole(), interactive=True, yes=yes
            )
        return offer

    def test_asks_after_locking(self) -> None:
        self._enroll(yes=False).assert_called_once()

    def test_yes_never_installs_a_service_on_this_path(self) -> None:
        """`worthless --yes` is documented as 'never service install'."""
        self._enroll(yes=True).assert_not_called()

    def test_a_lock_that_skipped_an_oauth_token_still_asks(self) -> None:
        """`found` counts OAuth tokens lock skips on purpose; 1 of 2 is a success.

        A `count == total` guard here never asked these users (Cursor Bugbot, PR #673).
        """
        self._enroll(yes=False, locked=1, found=2).assert_called_once()

    def test_nothing_locked_gets_no_offer(self) -> None:
        self._enroll(yes=False, locked=0, found=1).assert_not_called()

    def test_asks_before_the_proxy_starts(self) -> None:
        """Asking after the detached proxy starts would race it for the port."""
        order: list[str] = []
        with (
            patch.object(default_command, "get_home", return_value=MagicMock()),
            patch.object(
                default_command,
                "_run_enrollment_if_needed",
                side_effect=lambda *a, **k: order.append("enroll+offer"),
            ),
            patch.object(
                default_command,
                "_ensure_proxy_running",
                side_effect=lambda *a, **k: order.append("proxy") or (True, None, 8787),
            ),
        ):
            default_command.run_default(interactive=True, yes=False)
        assert order == ["enroll+offer", "proxy"]

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
from unittest.mock import MagicMock, patch

import pytest
import typer

from worthless.cli.commands.lock import _offer_service_after_lock
from worthless.cli.console import WorthlessConsole


@pytest.fixture
def console() -> WorthlessConsole:
    return WorthlessConsole()


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

    def test_assume_yes_wins_over_a_missing_tty(self, console: WorthlessConsole) -> None:
        """`--yes` is an explicit instruction; it does not need a terminal."""
        console = WorthlessConsole(assume_yes=True)
        with (
            patch("worthless.cli.commands.lock._scan_prompt_is_tty", return_value=False),
            patch("worthless.cli.commands.lock.install_service_for_offer") as install,
        ):
            assert _offer_service_after_lock(console, home=_home(), port=8787) is True
        install.assert_called_once()

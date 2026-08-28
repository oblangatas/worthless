"""Unit coverage for user-flow terminal trace rendering helpers."""

from __future__ import annotations

from pathlib import Path

from tests.user_flows import render_traces


def test_teammate_handoff_trace_keeps_distinct_command_homes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """The handoff trace must not mutate the owner's journey home."""
    monkeypatch.setattr(render_traces, "TRACE_ROOT", tmp_path)

    def _fake_run(
        self,
        args,
        *,
        cwd,
        env_files,
        home=None,
        expect_exit=None,
    ) -> None:
        command_home = home or self.journey.home
        before = render_traces.snapshot_env_files("before", env_files)
        after = render_traces.snapshot_env_files("after", env_files)
        self.journey.traces.append(
            render_traces.CommandTrace(
                command=["worthless", *args],
                cwd=cwd,
                home=command_home,
                exit_code=1 if expect_exit else 0,
                stdout="",
                stderr="",
                before=before,
                after=after,
            )
        )

    monkeypatch.setattr(render_traces.TraceRunner, "run", _fake_run)

    journey = render_traces.build_teammate_handoff_failure()

    assert journey.home == tmp_path / "teammate-handoff-failure" / ".worthless"
    assert len(journey.traces) == 2
    assert journey.traces[0].home == journey.home
    assert journey.traces[1].home == (
        tmp_path / "teammate-handoff-failure" / "teammate" / ".worthless"
    )


def test_install_lifecycle_trace_documents_current_install_contract(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """WOR-441 trace proof must include install, reinstall, and uninstall UX."""
    monkeypatch.setattr(render_traces, "TRACE_ROOT", tmp_path)

    journey = render_traces.build_install_lifecycle()
    report = "\n".join(render_traces.render_journey(journey))

    assert len(journey.traces) == 8
    assert [trace.exit_code for trace in journey.traces] == [0, 0, 0, 0, 0, 30, 10, 0]
    assert "Install, Reinstall, Manual Uninstall Guidance" in report
    assert "fresh install" in report.lower()
    assert "reinstall" in report.lower()
    assert "Done! 'worthless' is on your PATH." in report
    assert "Done! 'worthless' is installed." in report
    assert "Heads up: this terminal will not find 'worthless' until PATH is updated" in report
    assert "Heads up: this terminal finds a different 'worthless' first on PATH" in report
    assert "PATH version:       worthless 0.1.0" in report
    assert "Installed version:  worthless 0.3.0" in report
    assert "Open a new terminal, or activate this one now" in report
    assert "Try after PATH" in report
    assert "worthless 0.3.0 already installed" in report
    assert "upgrade older uv tool install" in report
    assert "pipx uninstall worthless" in report
    assert "No solution found when resolving dependencies" in report
    # WOR-673 (A2): proxy_hints() no longer recommends env-var overrides for
    # index URL, mirror, or CA bundle — install.sh scrubs all of those before
    # any uv call (Hermetic install). The trace must reflect the new contract:
    # corp users install CAs in the system trust store, edit install.sh for
    # mirror overrides. The OLD `export UV_PYTHON_INSTALL_MIRROR=...` hint is
    # gone and must stay gone (defense-in-depth: re-introducing it would be a
    # contradiction with the scrub).
    assert "deliberately scrubbed" in report, (
        "proxy_hints() must name the env-var scrub contract so users reading "
        "the install trace see WHY their UV_INDEX_URL/UV_PYTHON_INSTALL_MIRROR "
        "won't be honored."
    )
    assert "system trust store" in report, (
        "proxy_hints() must point corp users at the system trust store for "
        "CAs (the in-the-clear replacement for SSL_CERT_FILE, which is scrubbed)."
    )
    assert "export UV_PYTHON_INSTALL_MIRROR=" not in report, (
        "proxy_hints() must NOT recommend setting UV_PYTHON_INSTALL_MIRROR — "
        "A2 scrubs it. Recommending what we strip is self-contradicting."
    )
    assert "export SSL_CERT_FILE=" not in report, (
        "proxy_hints() must NOT recommend setting SSL_CERT_FILE — A2 scrubs it."
    )
    assert "uv tool uninstall worthless" in report
    assert "uv tool uninstall does not purge this" in report
    assert "worthless uninstall" not in report

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

    assert len(journey.traces) == 6
    assert [trace.exit_code for trace in journey.traces] == [0, 0, 0, 30, 10, 0]
    assert "Install, Reinstall, Manual Uninstall Guidance" in report
    assert "fresh install" in report.lower()
    assert "reinstall" in report.lower()
    assert "Done! 'worthless' is on your PATH." in report
    assert "Done! 'worthless' is installed." in report
    assert "Heads up: this terminal will not find 'worthless' until PATH is updated" in report
    assert "Open a new terminal, or activate this one now" in report
    assert "Try after PATH" in report
    assert "worthless 0.3.0 already installed" in report
    assert "pipx uninstall worthless" in report
    assert "No solution found when resolving dependencies" in report
    assert "UV_PYTHON_INSTALL_MIRROR" in report
    assert "uv tool uninstall worthless" in report
    assert "worthless uninstall" not in report

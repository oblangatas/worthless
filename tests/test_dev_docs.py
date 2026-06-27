from __future__ import annotations

from pathlib import Path

from worthless.dev.docs import _generate_command


def test_generate_command_targets_codewiki_wrapper_and_pilot_output() -> None:
    command = _generate_command(["--update"])

    assert command[0].endswith("scripts/codewiki.sh")
    assert command[1:3] == ["generate", "--output"]
    assert command[3].endswith("engineering/generated/codewiki-pilot")
    assert command[-1] == "--update"


def test_generate_command_uses_repo_root() -> None:
    output_dir = Path(_generate_command([])[3])

    assert output_dir.name == "codewiki-pilot"
    assert output_dir.parent.name == "generated"
    assert output_dir.parent.parent.name == "engineering"

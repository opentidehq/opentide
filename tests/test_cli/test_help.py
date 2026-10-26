"""Help: grouped panels, a summary of at most 60 characters and an example on every command."""

from __future__ import annotations

import re

import pytest
import typer.main
from typer.testing import CliRunner

from opentide.cli.commands import ROOT_COMMANDS
from opentide.cli.help import EXAMPLES, MAX_SUMMARY, SUMMARIES
from opentide.cli.root import app

_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _visible(command, path: str = ""):
    for name, child in (getattr(command, "commands", None) or {}).items():
        if child.hidden:
            continue
        full = f"{path} {name}".strip()
        yield full, child
        yield from _visible(child, full)


def _tree():
    return list(_visible(typer.main.get_group(app)))


@pytest.mark.parametrize(("path", "command"), _tree(), ids=lambda value: str(value))
def test_every_command_has_a_short_summary_and_an_example(path: str, command) -> None:
    summary = (command.short_help or command.help or "").strip().split("\n\n")[0]
    assert summary, f"{path} has no summary"
    assert len(summary) <= MAX_SUMMARY, f"{path}: {summary!r} is {len(summary)} characters"
    assert command.epilog and "Examples" in command.epilog, f"{path} has no example"


def test_the_tables_name_only_real_commands() -> None:
    paths = {path for path, _ in _tree()}
    assert set(SUMMARIES) <= paths
    assert set(EXAMPLES) - {""} <= paths


def test_every_example_starts_with_opentide() -> None:
    for examples in EXAMPLES.values():
        assert all(example.startswith("opentide") for example in examples)


def test_root_help_groups_commands_and_carries_the_tagline(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    result = CliRunner().invoke(app, ["--help"], terminal_width=100)
    text = _SGR.sub("", result.stdout)
    assert "Spec-driven development for agentic detection engineering" in text
    assert "DetectionOps" not in text
    for panel in ("Author", "Ship", "Workspace", "Agents and integrations"):
        assert f"─ {panel} " in text
    assert "$ opentide --json validate" in text
    assert "[user:pass@]host:port" in text and "\\]" not in text
    assert {spec.rich_help_panel for spec in ROOT_COMMANDS if not spec.hidden} == {
        "Author",
        "Ship",
        "Workspace",
        "Agents and integrations",
    }


def test_platform_options_show_a_readable_metavar(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    result = CliRunner().invoke(app, ["deploy", "--help"], terminal_width=120)
    text = _SGR.sub("", result.stdout)
    assert "PLATFORM" in text
    assert "<sentinel|" not in text
    assert "sentinel, splunk" in text

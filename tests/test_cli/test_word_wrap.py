"""Rows wider than the terminal wrap between words (post-merge AFTER shots, B44).

At a terminal the plan, the explain index and doctor rows were left to the
terminal, which broke them mid-word (``status DEV`` / ``ELOPMENT`` at 100
columns, ``AZURE_WORKSP`` / ``ACE_ID`` at 60).
"""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from rich.cells import cell_len
from rich.console import Console

from opentide.cli.services import doctor
from opentide.cli.services.doctor import Check
from opentide.cli.ui.plan import render_plan


def _terminal(width: int) -> Console:
    return Console(file=io.StringIO(), width=width, force_terminal=True, color_system=None)


def _output(console: Console) -> str:
    text = console.file.getvalue()  # ty: ignore[unresolved-attribute]  # a StringIO, set above
    lines = text.splitlines()
    assert all(cell_len(line) <= console.width for line in lines), lines
    return text


def test_a_plan_row_wider_than_the_terminal_wraps_at_words() -> None:
    console = _terminal(100)
    change = {
        "platform": "defender_for_endpoint",
        "tenant": "mde-preview",
        "name": "LSASS access on defender_for_endpoint variant 003 with a longer name",
        "uuid": "00000000-0000-4000-8003-e088e3cd1f16",
        "status": "DEVELOPMENT",
        "action": "create",
    }
    render_plan(console, {"changes": [change]})
    assert "status DEVELOPMENT" in _output(console)


def test_an_explain_index_line_wider_than_the_terminal_wraps_at_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.cli.commands import explain

    console = _terminal(100)
    monkeypatch.setattr("opentide.core.logging.config.get_stdout_console", lambda: console)
    summary = "A value the platform cannot use, written for a reason opentide cannot name more"
    explain._render_index([SimpleNamespace(code="compile_unsupported_value", summary=summary)])
    assert " ".join(_output(console).split()) == f"compile_unsupported_value {summary}"


def test_a_doctor_check_wider_than_the_terminal_wraps_at_words() -> None:
    console = _terminal(60)
    message = (
        "sentinel: 3 of 3 variables unset: AZURE_WORKSPACE_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID"
    )
    doctor.render_checks(console, [Check("credentials", "fail", message, "set them").to_dict()])
    assert "AZURE_WORKSPACE_ID," in _output(console)

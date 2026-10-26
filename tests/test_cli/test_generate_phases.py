"""`generate` phase discoverability and timing.

A pipeline that can outrun a CI job timeout has to say two things: that the
cheap phases can be named individually, and which phase consumed the budget.
Neither was true before #510.
"""

from __future__ import annotations

import re

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.commands.generate import _NAMED_GENERATE_PHASES

runner = CliRunner()

# Rich emits SGR colour codes whenever it believes the sink supports them, and
# CI's captured output does while a local non-TTY run does not. It also wraps
# to the terminal width, so a multi-word phrase can be split across lines.
# Assertions here are about CONTENT, so strip styling and collapse wrapping
# before matching -- otherwise the test passes locally and fails on CI.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _flatten(text: str) -> str:
    """Return *text* with ANSI styling removed and whitespace collapsed."""
    return " ".join(_ANSI.sub("", text).split())


def test_help_names_every_positional_phase() -> None:
    """The phases must be discoverable without reading an error string.

    `opentide generate schemas templates vocabs snippets` is the documented
    remedy for a stale editor schema. Typer renders the sub-app's `help=`
    rather than the callback docstring, so a phase missing from that string
    is invisible to `--help`.
    """
    result = runner.invoke(app, ["generate", "--help"])
    assert result.exit_code == 0
    helptext = _flatten(result.stdout)

    for phase in sorted(_NAMED_GENERATE_PHASES):
        assert phase in helptext, f"{phase!r} is accepted but absent from --help"


def test_help_declares_the_phases_outside_the_example_command() -> None:
    """The phase list must survive rendering, not just the example sentence.

    A first attempt wrote the list as `[schemas|templates|vocabs|snippets]`.
    Rich parses square brackets as console markup and rendered it as
    nothing, leaving `in the order given: .` -- yet a naive assertion still
    passed, because the example command below it repeats all four names. So
    this checks the declaration with the example text removed.
    """
    result = runner.invoke(app, ["generate", "--help"])
    helptext = _flatten(result.stdout)

    example = "opentide generate schemas templates vocabs snippets"
    assert example in helptext, "the example command itself went missing"
    without_example = helptext.replace(example, "")

    for phase in sorted(_NAMED_GENERATE_PHASES):
        assert phase in without_example, (
            f"{phase!r} appears only inside the example command, so the phase list is not rendering"
        )


def test_unknown_phase_error_lists_the_accepted_phases() -> None:
    """The error reads its list from the one source of truth."""
    result = runner.invoke(app, ["generate", "nonsense"])
    assert result.exit_code != 0
    message = _flatten(result.stdout + result.stderr)

    assert "nonsense" in message
    for phase in sorted(_NAMED_GENERATE_PHASES):
        assert phase in message, f"{phase!r} missing from the unknown-phase error"


def test_full_run_logs_per_phase_timing(monkeypatch, caplog) -> None:
    """Every phase reports its own cost, and the run names the slowest."""
    import logging

    from opentide.cli.services import generation

    ran: list[str] = []
    monkeypatch.setattr(generation, "run_generate_phase", ran.append)
    monkeypatch.setattr(generation, "_PHASE_ORDER", ("vocabs", "schemas"))

    with caplog.at_level(logging.INFO):
        generation.run_generate_all()

    assert ran == ["vocabs", "schemas"]
    logged = caplog.text
    assert "generation_phase_complete" in logged
    assert "generation_complete" in logged
    assert "slowest" in logged


def test_a_failing_phase_still_reports_its_cost(monkeypatch, caplog) -> None:
    """Timing is recorded in `finally`, so a killed run is still diagnosable.

    This is the case that matters: the 0.13.0 report could not tell which
    phase consumed an hour precisely because the job died before any
    summary was emitted.
    """
    import logging

    from opentide.cli.services import generation

    def explode(phase: str) -> None:
        raise RuntimeError(f"{phase} failed")

    monkeypatch.setattr(generation, "run_generate_phase", explode)
    monkeypatch.setattr(generation, "_PHASE_ORDER", ("docs",))

    with caplog.at_level(logging.INFO), __import__("pytest").raises(RuntimeError):
        generation.run_generate_all()

    assert "generation_phase_complete" in caplog.text
    assert "docs" in caplog.text

"""Human output prints payload text verbatim (#292).

Every emit helper writes through a Rich console, and Rich parses ``[...]`` as
markup. A message carrying ``[error]`` or ``opentide[sentinel]`` lost the
bracketed part in human output while ``--json`` kept it, ``--no-color``
included, and a stray ``[/]`` raised ``MarkupError`` instead of printing.
"""

from __future__ import annotations

from collections.abc import Iterator
from io import StringIO

import pytest
from rich.console import Console
from rich.text import Text
from typer.main import get_command

from opentide.cli import app
from opentide.cli.context import CliContext
from opentide.cli.output import (
    CommandResult,
    emit_deprecation,
    emit_error,
    emit_result,
    emit_success,
)
from opentide.core.logging import config
from opentide.core.logging.config import LoggingConfig, init_logging
from opentide.core.logging.console import emit_fatal, emit_section

#: Payload fields that tell the reader what to do next; ``--json`` always has them.
REMEDIATION_FIELDS = ("detail", "advice")

#: Strings Rich would eat, restyle, or choke on if they reached it as markup.
MARKUP_LOOKALIKES = (
    "install opentide[sentinel]",
    "[error] detection_model: unknown reference",
    "enabled=True [deploy, validate]",
    "[bold]not bold[/bold]",
    "a stray [/] closer",
    "C:\\tide\\",
)


@pytest.fixture(params=[True, False], ids=["plain", "rich"])
def rendered(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> StringIO:
    """Point both shared consoles at one buffer, in ``--no-color`` and panel modes.

    ``no_color`` only drops styles; Rich still parses markup, which is the bug.
    """
    init_logging(LoggingConfig(plain=request.param), force=True)
    buffer = StringIO()
    console = Console(file=buffer, width=400, force_terminal=False, no_color=True, highlight=False)
    monkeypatch.setattr(config, "_console", console)
    monkeypatch.setattr(config, "_stdout_console", console)
    return buffer


def _field_texts(text: str) -> dict[str, str]:
    return {name: f"{name} {text}" for name in ("message", "warning", *REMEDIATION_FIELDS)}


@pytest.mark.parametrize("text", MARKUP_LOOKALIKES)
@pytest.mark.parametrize("status", ["completed", "skipped", "failed"])
def test_emit_result_prints_every_field_verbatim(
    rendered: StringIO, status: str, text: str
) -> None:
    fields = _field_texts(text)
    result = CommandResult(
        message=fields["message"],
        ok=status != "failed",
        status=status,
        data={name: fields[name] for name in REMEDIATION_FIELDS},
        warnings=(fields["warning"],),
    )
    emit_result(CliContext(json_output=False), result)
    output = rendered.getvalue()
    for name, value in fields.items():
        assert value in output, f"{status} {name} lost: {output!r}"


@pytest.mark.parametrize("status", ["completed", "skipped", "failed"])
def test_emit_result_prints_advice_json_carries(rendered: StringIO, status: str) -> None:
    """``--live`` without the SDK printed the FATAL line and dropped the extra (#292)."""
    payload = {
        "status": status,
        "message": "Live query validation for sentinel needs a vendor SDK",
        "advice": "install opentide[sentinel] (provides azure-identity, azure-monitor-query)",
    }
    emit_result(CliContext(json_output=False), CommandResult.from_payload(payload))
    output = rendered.getvalue()
    assert payload["message"] in output
    assert payload["advice"] in output


@pytest.mark.parametrize("text", MARKUP_LOOKALIKES)
def test_emit_error_and_success_print_messages_verbatim(rendered: StringIO, text: str) -> None:
    ctx = CliContext(json_output=False)
    emit_success(ctx, {"message": f"done {text}", "advice": f"next {text}"})
    with pytest.raises(SystemExit):
        emit_error(ctx, f"failed {text}")
    output = rendered.getvalue()
    for expected in (f"done {text}", f"next {text}", f"failed {text}"):
        assert expected in output


@pytest.mark.parametrize("text", MARKUP_LOOKALIKES)
def test_emit_fatal_prints_message_detail_and_advice_verbatim(
    rendered: StringIO, text: str
) -> None:
    emit_fatal(f"fatal {text}", detail=f"detail {text}", advice=f"advice {text}")
    output = rendered.getvalue()
    for expected in (f"fatal {text}", f"detail {text}", f"advice {text}"):
        assert expected in output


@pytest.mark.parametrize("text", MARKUP_LOOKALIKES)
def test_emit_section_and_deprecation_print_verbatim(rendered: StringIO, text: str) -> None:
    emit_section(f"Section {text}")
    emit_deprecation(f"legacy {text}", f"replacement {text}")
    output = rendered.getvalue()
    for expected in (f"Section {text}", f"legacy {text}", f"replacement {text}"):
        assert expected in output


def _help_texts() -> Iterator[tuple[str, str]]:
    def walk(command, path: str) -> Iterator[tuple[str, str]]:
        for label, text in (("help", command.help), ("short_help", command.short_help)):
            if text:
                yield f"{path} ({label})", text
        for param in command.params:
            if text := getattr(param, "help", None):
                yield f"{path} {param.name}", text
        for name, sub in getattr(command, "commands", {}).items():
            yield from walk(sub, f"{path} {name}")

    yield from walk(get_command(app), "opentide")


def test_help_text_renders_its_brackets() -> None:
    """Typer renders help as Rich markup: `opentide[sentinel]` and `[deprecated]` vanished.

    Write a literal bracket in help text as ``\\[``.
    """
    texts = list(_help_texts())
    assert len(texts) > 50
    lost = [
        (where, text)
        for where, text in texts
        if Text.from_markup(text).plain != text.replace("\\[", "[")
    ]
    assert not lost, lost

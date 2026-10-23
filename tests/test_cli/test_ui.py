"""The output contract's building blocks: mode resolution, glyphs and line renderers."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from opentide.cli.ui.contract import Failure, NextAction, did_you_mean
from opentide.cli.ui.glyphs import GLYPHS, glyph
from opentide.cli.ui.mode import (
    OutputMode,
    detect_agent,
    detect_ci,
    get_mode,
    reset_mode,
    resolve_mode,
    set_mode,
)
from opentide.cli.ui.render import (
    render_error,
    render_next_actions,
    render_notes,
    render_outcome,
    render_warnings,
)


class _Stream(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    def isatty(self) -> bool:
        return self._tty

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding


_TTY = _Stream(tty=True)

# --------------------------------------------------------------------------
# Mode resolution
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "env", "expected"),
    [
        pytest.param({}, {}, OutputMode.HUMAN, id="tty"),
        pytest.param({"command": ("mcp", "start")}, {}, OutputMode.MCP, id="mcp-start"),
        pytest.param(
            {"command": ("mcp", "start"), "json_flag": True},
            {"OPENTIDE_OUTPUT": "json", "CLAUDECODE": "1"},
            OutputMode.MCP,
            id="mcp-beats-everything",
        ),
        pytest.param({"command": ("mcp",)}, {}, OutputMode.HUMAN, id="mcp-help-is-not-mcp"),
        pytest.param({"json_flag": True}, {"OPENTIDE_OUTPUT": "plain"}, OutputMode.JSON, id="json"),
        pytest.param({}, {"OPENTIDE_OUTPUT": "json"}, OutputMode.JSON, id="env-json"),
        pytest.param({}, {"OPENTIDE_OUTPUT": "Plain "}, OutputMode.PLAIN, id="env-plain"),
        pytest.param(
            {}, {"OPENTIDE_OUTPUT": "human", "CLAUDECODE": "1"}, OutputMode.HUMAN, id="env-human"
        ),
        pytest.param({}, {"OPENTIDE_OUTPUT": "mcp"}, OutputMode.HUMAN, id="env-mcp-ignored"),
        pytest.param({}, {"OPENTIDE_OUTPUT": "agent"}, OutputMode.AGENT, id="env-agent"),
        pytest.param({}, {"AI_AGENT": "cursor"}, OutputMode.AGENT, id="ai-agent"),
        pytest.param({}, {"CLAUDECODE": "1", "CI": "true"}, OutputMode.AGENT, id="agent-in-ci"),
        pytest.param({}, {"CLAUDECODE": "0"}, OutputMode.HUMAN, id="agent-var-off"),
        pytest.param({"no_color": True}, {}, OutputMode.PLAIN, id="no-color-flag"),
        pytest.param({}, {"NO_COLOR": "1"}, OutputMode.PLAIN, id="NO_COLOR"),
        pytest.param({}, {"NO_COLOR": ""}, OutputMode.HUMAN, id="NO_COLOR-empty"),
        pytest.param({}, {"TERM": "dumb"}, OutputMode.PLAIN, id="dumb-terminal"),
        pytest.param({}, {"GITHUB_ACTIONS": "true"}, OutputMode.PLAIN, id="ci"),
    ],
)
def test_resolve_mode_precedence(
    kwargs: dict[str, object], env: dict[str, str], expected: OutputMode
) -> None:
    assert resolve_mode(env=env, stdout=_TTY, **kwargs) is expected  # type: ignore[arg-type]


def test_a_pipe_is_plain() -> None:
    assert resolve_mode(env={}, stdout=_Stream(tty=False)) is OutputMode.PLAIN


def test_detect_agent_names_the_agent() -> None:
    assert detect_agent({"AI_AGENT": "claude-code_2"}) == "claude-code_2"
    assert detect_agent({"CURSOR_AGENT": "1"}) == "cursor_agent"
    assert detect_agent({"AI_AGENT": "", "CODEX_CI": "1"}) == "codex_ci"
    assert detect_agent({}) is None


def test_detect_ci_names_the_provider() -> None:
    assert detect_ci({"GITHUB_ACTIONS": "true"}) == "github"
    assert detect_ci({"GITLAB_CI": "true", "CI": "true"}) == "gitlab"
    assert detect_ci({"TF_BUILD": "True"}) == "azure"
    assert detect_ci({"CI": "1"}) == "ci"
    assert detect_ci({"CI": "false"}) is None


def test_set_mode_holds_until_reset() -> None:
    set_mode(OutputMode.AGENT)
    assert get_mode() is OutputMode.AGENT
    reset_mode()
    assert get_mode() is not OutputMode.AGENT


# --------------------------------------------------------------------------
# Glyphs and suggestions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GLYPHS))
def test_every_glyph_has_an_ascii_fallback(name: str) -> None:
    assert glyph(name, encoding="utf-8") == GLYPHS[name].symbol
    fallback = glyph(name, encoding="ascii")
    assert fallback == GLYPHS[name].fallback
    fallback.encode("ascii")


def test_glyph_reads_the_stream_encoding() -> None:
    assert glyph("ok", _Stream(tty=False, encoding="cp1252")) == "ok"
    assert glyph("ok", _Stream(tty=False, encoding="utf-8")) == "✓"
    assert glyph("ok", encoding="no-such-codec") == "ok"


def test_unknown_glyph_name_fails_loudly() -> None:
    with pytest.raises(KeyError):
        glyph("tick")


def test_did_you_mean() -> None:
    assert did_you_mean("valdate", ["validate", "deploy"]) == "validate"
    assert did_you_mean("zzz", ["validate", "deploy"]) is None


def test_failure_dict_has_every_key() -> None:
    assert Failure("usage_unknown_command", "No such command").to_dict() == {
        "code": "usage_unknown_command",
        "message": "No such command",
        "argument": None,
        "suggestion": None,
        "crash_log": None,
    }


# --------------------------------------------------------------------------
# Renderers (snapshots at a fixed width)
# --------------------------------------------------------------------------

_ACTIONS = (
    NextAction("opentide lint --fix", "rename 2 files to match their names"),
    NextAction("opentide validate --strict"),
    NextAction("opentide generate"),
    NextAction("opentide deploy --dry-run --strategy PREVIEW", "never shown: three at most"),
)
_LONG_PATH = "/home/you/detections/objects/rules/" + "a-very-long-rule-file-name-" * 3 + "x.yaml"


def _session(console: Console, mode: OutputMode) -> None:
    render_warnings(
        console,
        [f"{_LONG_PATH}:24: configurations.splunk: this block will not deploy", "[bracketed]"],
    )
    render_outcome(console, "ok", "3 objects valid · 0.9s")
    render_outcome(console, "warning", "3 findings in 2 files")
    render_outcome(console, "skipped", "no configured tenant reached")
    render_outcome(console, "failed", "2 errors in 1 file")
    render_notes(console, [("note", "a detail"), ("help", "some advice")])
    render_next_actions(console, _ACTIONS)
    render_error(
        console, "Unknown info section: rulez", notes=[("help", "did you mean 'rules'?")], mode=mode
    )


@pytest.mark.parametrize("mode", [OutputMode.HUMAN, OutputMode.PLAIN, OutputMode.AGENT])
def test_renderers_snapshot(mode: OutputMode, snapshot) -> None:
    """Human mode is snapshotted with its styles; plain and agent carry none."""
    human = mode is OutputMode.HUMAN
    console = Console(
        record=True,
        width=60,
        file=io.StringIO(),
        force_terminal=human,
        color_system="standard" if human else None,
    )
    _session(console, mode)
    assert console.export_text(styles=human) == snapshot


def test_a_path_is_never_broken() -> None:
    console = Console(record=True, width=40, file=io.StringIO(), color_system=None)
    render_warnings(console, [_LONG_PATH])
    assert console.export_text() == f"warning: {_LONG_PATH}\n"


def test_ascii_console_gets_fallback_glyphs() -> None:
    stream = _Stream(tty=False, encoding="ascii")
    console = Console(file=stream, width=60, color_system=None)
    render_outcome(console, "ok", "done")
    render_next_actions(console, [NextAction("opentide generate", "why")])
    assert stream.getvalue() == "ok done\n-> opentide generate - why\n"

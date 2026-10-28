"""Root flags anywhere before ``--``, usage errors through the contract, and the debug env."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.lazy import LazyTyperGroup, hoist_root_flags

runner = CliRunner()


def _invoke(*argv: str, env: dict[str, str] | None = None) -> Result:
    return runner.invoke(app, list(argv), env=env)


def _document(result: Result) -> dict[str, Any]:
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


# --------------------------------------------------------------------------
# Hoisting
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("info", "--json"),
        ("--json", "info"),
        ("info", "rules", "--json"),
        ("info", "--platform", "sentinel", "--json"),
    ],
)
def test_json_is_accepted_before_or_after_the_command(
    tmp_path: Path, argv: tuple[str, ...]
) -> None:
    result = _invoke("--repo", str(tmp_path), *argv)
    assert result.exit_code == 0, result.output
    payload = _document(result)
    assert payload["ok"] is True
    assert payload["command"] == "info"


def test_validate_json_after_the_subcommand(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "validate", "--json")
    assert result.exit_code == 0, result.output
    assert _document(result)["command"] == "validate"


def _hoist(argv: list[str]) -> list[str]:
    from typer.main import get_command

    group = get_command(app)
    assert isinstance(group, LazyTyperGroup)
    ctx = group.make_context("opentide", ["--help"], resilient_parsing=True)
    return hoist_root_flags(group, ctx, argv)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        pytest.param(["validate", "--json"], ["--json", "validate"], id="after-command"),
        pytest.param(
            ["--repo", "x", "validate", "query", "--platform", "sentinel", "--quiet", "--json"],
            ["--quiet", "--json", "--repo", "x", "validate", "query", "--platform", "sentinel"],
            id="after-subcommand",
        ),
        pytest.param(
            ["setup", "skills", "discover", "--query", "--json"],
            ["setup", "skills", "discover", "--query", "--json"],
            id="option-value-stays",
        ),
        pytest.param(
            ["setup", "skills", "discover", "-q", "--json", "--debug"],
            ["--debug", "setup", "skills", "discover", "-q", "--json"],
            id="short-option-value-stays",
        ),
        pytest.param(
            ["validate", "--", "--json"], ["validate", "--", "--json"], id="after-double-dash"
        ),
        pytest.param(["valdate", "--json"], ["--json", "valdate"], id="unknown-command"),
        pytest.param(["generate", "schemas", "--no-color"], ["--no-color", "generate", "schemas"]),
        pytest.param(["validate", "--strict"], ["validate", "--strict"], id="nothing-to-hoist"),
    ],
)
def test_hoist_root_flags(argv: list[str], expected: list[str]) -> None:
    assert _hoist(argv) == expected


def test_quiet_prints_only_the_outcome(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "lint", "--quiet")
    assert result.exit_code == 0, result.output
    assert result.stdout == (
        f"✓ Catalogue lint passed, but found no object files under {tmp_path.resolve()}\n"
    )
    assert result.stderr == ""


# --------------------------------------------------------------------------
# Usage errors
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "code", "argument", "suggestion", "command"),
    [
        (("valdate",), "usage_unknown_command", "valdate", "validate", ""),
        (("validate", "--stirct"), "usage_unknown_option", "--stirct", "--strict", "validate"),
        (
            ("validate", "query", "--platform", "sentinal"),
            "usage_invalid_choice",
            "--platform",
            "sentinel",
            "validate query",
        ),
        # The tenant check is one platform's: --live needs --platform (offline does not).
        (
            ("validate", "query", "--live"),
            "usage_missing_option",
            "--platform",
            None,
            "validate query",
        ),
        (("info", "rulez"), "usage_invalid_choice", "section", "rules", "info"),
        (("validate", "--type", "rul"), "usage_invalid_choice", "--type", "rule", "validate"),
        (("generate", "schemaz"), "usage_invalid_choice", "phase", "schemas", "generate"),
        (("info", "coverage"), "usage_missing_option", "--technique", None, "info"),
        # Case-only typos still get a suggestion.
        (("VALIDATE",), "usage_unknown_command", "VALIDATE", "validate", ""),
        (("info", "RULES"), "usage_invalid_choice", "section", "rules", "info"),
        (("validate", "--type", "RULE"), "usage_invalid_choice", "--type", "rule", "validate"),
        (
            ("deploy", "--strategy", "PREVEW"),
            "usage_invalid_choice",
            "--strategy",
            "PREVIEW",
            "deploy",
        ),
        (("deploy", "--dry-run", "--all"), "usage_missing_option", "--strategy", None, "deploy"),
        # S1QL has no offline engine: the check is the tenant's.
        (
            ("validate", "query", "--platform", "sentinel_one"),
            "usage_missing_option",
            "--live",
            None,
            "validate query",
        ),
        (
            ("rules", "unreviewed", "--older-than", "9x"),
            "usage_invalid_value",
            "--older-than",
            None,
            "rules unreviewed",
        ),
        (("mcp",), "usage_error", None, None, "mcp"),
    ],
)
def test_usage_errors_print_one_json_document(
    tmp_path: Path,
    argv: tuple[str, ...],
    code: str,
    argument: str,
    suggestion: str | None,
    command: str,
) -> None:
    result = _invoke("--repo", str(tmp_path), *argv, "--json")
    assert result.exit_code == 2, result.output
    payload = _document(result)
    assert payload["ok"] is False
    assert payload["status"] == "failed"
    assert isinstance(payload["error"], str) and payload["error"] == payload["message"]
    assert payload["exit_code"] == 2
    assert payload["command"] == command
    failure = payload["failure"]
    assert failure["code"] == code
    assert failure["argument"] == argument
    assert failure["suggestion"] == suggestion
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("argv", "exit_code"),
    [(("--json", "valdate"), 2), (("--json", "info"), 0)],
    ids=["usage-error", "result"],
)
def test_a_json_document_ends_with_exactly_one_newline(
    tmp_path: Path, argv: tuple[str, ...], exit_code: int
) -> None:
    """A trailing blank line reads as an empty record to a JSON-lines consumer."""
    result = _invoke("--repo", str(tmp_path), *argv)
    assert result.exit_code == exit_code, result.output
    assert result.stdout.endswith("}\n")
    assert not result.stdout.endswith("\n\n")
    _document(result)


def test_missing_choice_option_is_one_line(tmp_path: Path) -> None:
    """Typer lists the choices one per line under ``Choose from:``; the contract folds them."""
    result = _invoke("--repo", str(tmp_path), "--json", "deploy", "metadata")
    message = _document(result)["message"]
    assert message.startswith("Missing option '--platform': choose from sentinel, splunk, ")
    assert "\n" not in message and "Choose from:" not in message
    human = _invoke("--repo", str(tmp_path), "deploy", "metadata")
    assert human.stderr.splitlines()[0] == f"error: {message}"


def test_a_group_alone_is_a_usage_error_for_a_program(tmp_path: Path) -> None:
    """``no_args_is_help`` would print the help screen on stdout, which no parser reads."""
    result = _invoke("--repo", str(tmp_path), "--json", "mcp")
    assert result.exit_code == 2
    assert _document(result)["message"] == "Missing command: choose from start."
    agent = _invoke("--repo", str(tmp_path), "mcp", env={"CLAUDECODE": "1"})
    assert agent.exit_code == 2
    assert agent.stdout == ""
    assert agent.stderr.splitlines()[:2] == [
        "error: Missing command: choose from start.",
        "  usage: opentide mcp [OPTIONS] COMMAND [ARGS]...",
    ]


def test_a_group_alone_still_prints_help_for_a_person(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "mcp")
    assert result.exit_code == 2
    assert "Usage: opentide mcp" in result.output
    assert "error:" not in result.output


def test_usage_error_in_plain_mode_is_an_error_line(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "valdate")
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.splitlines() == [
        "error: No such command 'valdate'.",
        "  help: did you mean 'validate'?",
        "  usage: opentide [OPTIONS] COMMAND [ARGS]...",
        "  help: run 'opentide --help'",
    ]


def test_agent_mode_adds_the_json_tip(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "info", "rulez", env={"CLAUDECODE": "1"})
    assert result.exit_code == 2
    assert result.stderr.splitlines()[-1] == "tip: add --json for machine-readable output"


@pytest.mark.parametrize("framed", [True, False])
def test_the_agent_tip_comes_after_the_next_steps(framed: bool) -> None:
    """It sat between the outcome line and its next steps (post-merge end-to-end run)."""
    import io

    from rich.console import Console

    from opentide.cli.output import CommandResult, render_result
    from opentide.cli.ui.contract import ISSUES_FOUND, Failure, NextAction
    from opentide.cli.ui.mode import OutputMode

    console = Console(file=io.StringIO(), width=200, color_system=None)
    result = CommandResult(
        message="Validation failed",
        ok=False,
        status="failed",
        outcome="1 error in 1 file",
        exit_code=1,
        failure=Failure(code=ISSUES_FOUND if framed else "command_failed", message="x"),
        next_actions=(NextAction("opentide validate", "check again"),),
    )
    render_result(result, stdout=console, stderr=console, mode=OutputMode.AGENT)
    lines = console.file.getvalue().splitlines()
    assert lines[-1] == "tip: add --json for machine-readable output"
    assert lines[-2].startswith("→ opentide validate")


def test_opentide_output_json_selects_json(tmp_path: Path) -> None:
    result = _invoke("--repo", str(tmp_path), "info", env={"OPENTIDE_OUTPUT": "json"})
    assert result.exit_code == 0, result.output
    assert _document(result)["ok"] is True


def test_agent_mode_never_prompts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even on a TTY: an agent cannot answer a prompt, so it gets the flags instead."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    result = _invoke(
        "--json",
        "setup",
        "repo",
        str(tmp_path),
        env={"OPENTIDE_OUTPUT": "agent", "AI_AGENT": "test-agent"},
    )
    # --json wins over the agent: the refusal is a JSON document.
    assert result.exit_code == 2, result.output
    assert _document(result)["failure"]["code"] == "usage_needs_input"
    plain = _invoke("setup", "repo", str(tmp_path), env={"AI_AGENT": "test-agent"})
    assert plain.exit_code == 2, plain.output
    assert "does not prompt in a coding agent (test-agent)" in plain.stderr
    assert "(--name, --platform)" in " ".join(plain.stderr.split())
    assert "--yes" in plain.stderr
    assert not (tmp_path / "objects").exists()


# --------------------------------------------------------------------------
# --debug and the environment
# --------------------------------------------------------------------------


def test_debug_star_is_ignored(tmp_path: Path) -> None:
    """Node tooling exports DEBUG='*'; it failed every command with exit 2."""
    result = _invoke("--repo", str(tmp_path), "--json", "info", env={"DEBUG": "*"})
    assert result.exit_code == 0, result.output
    assert _document(result)["ok"] is True


@pytest.mark.parametrize(
    ("env", "debug"),
    [
        ({"DEBUG": "1"}, True),
        ({"DEBUG": "yes"}, True),
        ({"DEBUG": "*"}, False),
        ({"DEBUG": "0"}, False),
        ({"OPENTIDE_DEBUG": "true"}, True),
        ({"OPENTIDE_DEBUG": "0", "DEBUG": "1"}, False),
    ],
)
def test_debug_env(tmp_path: Path, env: dict[str, str], debug: bool) -> None:
    from opentide.core.logging.config import current_config

    result = _invoke("--repo", str(tmp_path), "--json", "info", env=env)
    assert result.exit_code == 0, result.output
    assert current_config().debug is debug


def test_debug_flag_does_not_export_debug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEBUG", raising=False)
    result = _invoke("--repo", str(tmp_path), "--json", "--debug", "info")
    assert result.exit_code == 0, result.output
    assert "DEBUG" not in os.environ
    assert os.environ["OPENTIDE_DEBUG"] == "1"

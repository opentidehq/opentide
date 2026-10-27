"""``opentide commands``: the command tree for agents, read from Click."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.commands import ROOT_COMMANDS
from opentide.cli.services.introspect import example
from opentide.cli.ui.results import NO_DOCUMENT, CommandError, result_model

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;[^\x1b]*\x1b\\")
#: The root callback exports the workspace variables for the engine modules.
#: Naming them here makes CliRunner put them back after each run: left set to
#: the checkout, OPENTIDE_TIDE_WORKSPACE made a later test in the worker merge
#: tests/fixtures/generation and fail schema generation with KeyError: 'name'.
_CLI_EXPORTS = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "OPENTIDE_DATA_ROOT")
_ENV = {
    "NO_COLOR": "1",
    "OPENTIDE_OUTPUT": None,
    "CLAUDECODE": None,
    "AI_AGENT": None,
    **dict.fromkeys(_CLI_EXPORTS),
}

_COMMAND_KEYS = {
    "path",
    "name",
    "summary",
    "help",
    "group",
    "runs_alone",
    "subcommands",
    "deprecated",
    "arguments",
    "options",
    "example",
    "output_schema",
}
_OPTION_KEYS = {
    "name",
    "flags",
    "secondary_flags",
    "type",
    "choices",
    "default",
    "required",
    "multiple",
    "is_flag",
    "envvars",
    "help",
}


@pytest.fixture(scope="module")
def tree() -> dict:
    result = runner.invoke(app, ["--json", "commands"], env=_ENV)
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def _entry(tree: dict, path: str) -> dict:
    return next(entry for entry in tree["commands"] if entry["path"] == path)


def _option(entry: dict, flag: str) -> dict:
    return next(option for option in entry["options"] if flag in option["flags"])


def test_a_run_leaves_no_workspace_export_behind(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _CLI_EXPORTS:
        monkeypatch.delenv(name, raising=False)
    result = runner.invoke(app, ["--json", "commands"], env=_ENV)
    assert result.exit_code == 0, result.output
    assert not [name for name in _CLI_EXPORTS if name in os.environ]


def test_document_carries_the_envelope_and_counts(tree: dict) -> None:
    assert tree["schema_version"] == 1
    assert tree["command"] == "commands"
    assert tree["exit_code"] == 0
    assert tree["failure"] is None
    assert tree["ok"] is True
    assert tree["program"] == "opentide"
    count = len(tree["commands"])
    assert tree["summary"] == {
        "commands": count,
        "groups": sum(1 for entry in tree["commands"] if entry["group"]),
    }
    assert tree["message"] == f"{count} commands"


def test_every_entry_has_the_documented_keys(tree: dict) -> None:
    for entry in tree["commands"]:
        assert set(entry) == _COMMAND_KEYS, entry["path"]
        for option in entry["options"]:
            assert set(option) == _OPTION_KEYS, (entry["path"], option["name"])
    for option in tree["global_options"]:
        assert set(option) == _OPTION_KEYS


def test_each_command_that_runs_names_its_output_schema(tree: dict) -> None:
    """A $ref into the document's $defs; CommandError alone for a group that only prints help."""
    for entry in tree["commands"]:
        schema = entry["output_schema"]
        if entry["path"] in NO_DOCUMENT:
            # stdout is JSON-RPC (mcp start, lsp start).
            assert schema is None
            continue
        if not entry["runs_alone"] or result_model(entry["path"]) is CommandError:
            # A group that only prints help, or a command that only ever prints a
            # usage error (tui refuses --json).
            assert schema == {"$ref": "#/$defs/CommandError"}, entry["path"]
            continue
        refs = [option["$ref"] for option in schema["anyOf"]]
        assert refs[-1] == "#/$defs/CommandError", entry["path"]
        for ref in refs:
            assert ref.removeprefix("#/$defs/") in tree["$defs"], (entry["path"], ref)


def test_output_schemas_resolve_and_check_a_real_document(tree: dict) -> None:
    import jsonschema

    jsonschema.Draft202012Validator.check_schema({"$defs": tree["$defs"]})
    schema = {**_entry(tree, "commands")["output_schema"], "$defs": tree["$defs"]}
    jsonschema.validate(tree, schema)
    broken = {**tree, "commands": "not a list"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, schema)


def test_human_tree_builds_no_schema() -> None:
    from opentide.cli.services.introspect import command_tree

    root = typer.main.get_command(app)
    payload = command_tree(root, schemas=False)
    assert "$defs" not in payload
    assert all("output_schema" not in entry for entry in payload["commands"])


def test_tree_lists_every_visible_root_command_in_help_order(tree: dict) -> None:
    roots = [entry["path"] for entry in tree["commands"] if " " not in entry["path"]]
    assert roots == [spec.name for spec in ROOT_COMMANDS if not spec.hidden]
    assert "commands" in roots


def test_hidden_commands_and_plumbing_options_are_left_out(tree: dict) -> None:
    paths = {entry["path"] for entry in tree["commands"]}
    for spec in ROOT_COMMANDS:
        if spec.hidden:
            assert spec.name not in paths
    flags = {
        flag
        for entry in tree["commands"]
        for option in entry["options"]
        for flag in option["flags"]
    }
    assert not flags & {"--help", "--install-completion", "--show-completion"}


def test_subcommands_name_entries_that_follow_their_group(tree: dict) -> None:
    paths = [entry["path"] for entry in tree["commands"]]
    for index, entry in enumerate(tree["commands"]):
        if not entry["group"]:
            assert entry["subcommands"] == [], entry["path"]
        for name in entry["subcommands"]:
            child = f"{entry['path']} {name}"
            assert child in paths
            assert paths.index(child) > index


def test_options_carry_types_choices_defaults_and_envvars(tree: dict) -> None:
    strict = _option(_entry(tree, "validate"), "--strict")
    assert strict["type"] == "boolean"
    assert strict["is_flag"] is True
    assert strict["default"] is False

    files = _option(_entry(tree, "validate"), "--file")
    assert files["type"] == "string"
    assert files["multiple"] is True

    platform = _option(_entry(tree, "validate query"), "--platform")
    assert platform["type"] == "choice"
    assert "sentinel" in platform["choices"]

    by_flag = {option["flags"][0]: option for option in tree["global_options"]}
    assert by_flag["--repo"]["envvars"] == ["OPENTIDE_REPO_ROOT"]
    assert by_flag["--debug"]["envvars"] == ["OPENTIDE_DEBUG"]
    assert by_flag["--json"]["is_flag"] is True
    assert by_flag["--version"]["flags"] == ["--version", "-V"]


def test_every_command_has_an_example_that_names_it(tree: dict) -> None:
    for entry in tree["commands"]:
        assert entry["example"].startswith(f"opentide {entry['path']}"), entry["path"]


def test_group_that_only_prints_help_takes_its_first_subcommand_example(tree: dict) -> None:
    mcp = _entry(tree, "mcp")
    assert mcp["runs_alone"] is False
    assert mcp["example"] == "opentide mcp start"
    assert _entry(tree, "validate")["runs_alone"] is True


def test_flag_after_the_command_is_accepted() -> None:
    result = runner.invoke(app, ["commands", "--json"], env=_ENV)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["command"] == "commands"


def test_human_mode_prints_a_compact_tree_and_one_outcome_line() -> None:
    result = runner.invoke(app, ["commands"], env=_ENV)
    assert result.exit_code == 0, result.output
    lines = _ANSI.sub("", result.stdout).splitlines()
    # The tree follows ROOT_COMMANDS, which #643 orders panel by panel.
    first = next(spec.name for spec in ROOT_COMMANDS if not spec.hidden)
    assert first == "validate"
    assert lines[0].startswith(f"{first} ")
    assert any(line.startswith("  query ") for line in lines)
    assert re.fullmatch(r"\S+ \d+ commands", lines[-1])


# --------------------------------------------------------------------------
# Examples
# --------------------------------------------------------------------------


def _click(command: typer.Typer) -> typer.main.TyperCommand:
    built = typer.main.get_command(command)
    assert isinstance(built, typer.main.TyperCommand)
    return built


def test_example_reads_the_first_one_the_help_epilog_shows() -> None:
    demo = typer.Typer()

    @demo.command(epilog="[dim]Examples[/dim]\n\n  [bold]$ opentide demo \\[x] --y[/bold]")
    def run() -> None:
        """Demo."""

    assert example(_click(demo), ("demo",)) == "opentide demo [x] --y"


def test_example_fills_required_arguments_and_options() -> None:
    demo = typer.Typer()

    @demo.command()
    def run(
        name: str = typer.Argument(...),
        target: str = typer.Option(..., "--target"),
        optional: str = typer.Option("", "--optional"),
    ) -> None:
        """Demo."""

    assert example(_click(demo), ("demo",)) == "opentide demo <name> --target <target>"


def test_commands_json_imports_no_registry() -> None:
    """Walking the tree loads each command module, but never builds the registry."""
    script = (
        "import sys\n"
        "from opentide.core.registry import Opentide\n"
        "from opentide.cli import app\n"
        "try:\n"
        "    app(['--json', 'commands'], standalone_mode=False)\n"
        "except SystemExit:\n"
        "    pass\n"
        "assert Opentide.is_initialised is False\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "NO_COLOR": "1"},
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["command"] == "commands"


def test_document_names_the_version_and_the_environment(tree: dict) -> None:
    from opentide import __version__
    from opentide.cli.ui.mode import AGENT_VARIABLES

    assert tree["version"] == __version__
    names = [entry["name"] for entry in tree["environment"]]
    assert names[:4] == ["OPENTIDE_OUTPUT", "OPENTIDE_DEBUG", "NO_COLOR", "OPENTIDE_JSON_INDENT"]
    assert set(AGENT_VARIABLES) <= set(names)
    assert all(entry["meaning"] for entry in tree["environment"])


#: ``OPENTIDE_*`` names in ``src/`` that a user does not set for the CLI.
_UNDOCUMENTED_ENV = {
    # deploy --persist-state-externally sets it for its own run.
    "OPENTIDE_PERSIST_STATE_EXTERNALLY",
    # An Azure pipeline variable the generated pipeline sets and reads.
    "OPENTIDE_DEPLOY_STARTED",
    # Read by the maintainer scripts in scripts/vocabulary/, not by a command.
    "OPENTIDE_ATTACK_STIX_DIR",
    "OPENTIDE_SPECIFICATIONS_ROOT",
}


def test_environment_names_every_variable_the_code_reads() -> None:
    """Each quoted ``OPENTIDE_*`` name in ``src/`` is in ``environment()`` or excused above.

    A quoted name catches ``os.environ.get("…")``, ``envvar="…"`` and a
    module constant such as ``PROGRESS_ENV = "…"`` alike.
    """
    from opentide.cli.services.introspect import environment

    src = Path(__file__).resolve().parents[2] / "src"
    pattern = re.compile(r"""["'](OPENTIDE_[A-Z][A-Z0-9_]*)["']""")
    read = {
        name
        for path in src.rglob("*.py")
        for name in pattern.findall(path.read_text(encoding="utf-8"))
    }
    documented = {entry["name"] for entry in environment()}
    assert "OPENTIDE_OUTPUT" in read
    assert read - _UNDOCUMENTED_ENV <= documented, sorted(read - _UNDOCUMENTED_ENV - documented)
    assert not _UNDOCUMENTED_ENV & documented
    assert _UNDOCUMENTED_ENV.issubset(read), "drop a name the code no longer reads"


def test_the_docs_table_lists_every_environment_variable() -> None:
    """The global-options table has a row for each ``OPENTIDE_*`` entry of ``environment()``."""
    from opentide.cli.services.introspect import environment

    docs = Path(__file__).resolve().parents[2] / "docs" / "cli" / "global-options.md"
    text = docs.read_text(encoding="utf-8")
    section = text.split("## Environment variables", 1)[1].split("\n## ", 1)[0]
    rows = set(re.findall(r"^\| `(OPENTIDE_[A-Z0-9_]+)` \|", section, re.MULTILINE))
    names = {entry["name"] for entry in environment() if entry["name"].startswith("OPENTIDE_")}
    assert names <= rows, sorted(names - rows)


@pytest.mark.parametrize(
    ("path", "name", "bad_argv"),
    [
        ("validate", "object_type", ["validate", "--type", "rulez"]),
        ("deploy", "strategy", ["deploy", "--dry-run", "--all", "--strategy", "STAGINGG"]),
        ("info", "section", ["info", "rulez"]),
    ],
)
def test_choices_the_command_checks_itself_are_listed(
    tree: dict, path: str, name: str, bad_argv: list[str]
) -> None:
    """The listed values are the ones the command names when it refuses another."""
    entry = _entry(tree, path)
    (param,) = [item for item in entry["options"] + entry["arguments"] if item["name"] == name]
    assert param["choices"]
    result = runner.invoke(app, ["--json", *bad_argv], env=_ENV)
    assert result.exit_code == 2, result.output
    message = json.loads(result.stdout)["failure"]["message"]
    for value in param["choices"]:
        assert value in message, (value, message)


def test_option_help_has_no_rich_escapes(tree: dict) -> None:
    helps = [
        option["help"]
        for entry in tree["commands"]
        for option in entry["options"]
        if option["help"]
    ]
    assert not [text for text in helps if "\\[" in text]
    skip = _option(_entry(tree, "deploy"), "--skip-unconfigured")
    assert "[[tenants]]" in skip["help"]


def test_commands_has_a_short_summary_and_an_examples_epilog(tree: dict) -> None:
    entry = _entry(tree, "commands")
    assert entry["summary"] == "List every command and option, for agents"
    assert len(entry["summary"]) <= 60
    assert entry["example"] == "opentide commands"

"""Shell completion of option values: each source, through Click's shell-complete API.

Completion reads object file headers, the bundled vocabulary and the platform
files; it never builds the registry. The import-graph budget is checked in
``test_lazy_commands.py`` with the other start-up tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer
import typer.main
from typer._click.shell_completion import CompletionItem
from typer._completion_classes import BashComplete

import opentide.cli as cli_package
from opentide.cli import completion
from opentide.cli.completion import attach, read_header

RULE_A = "00000000-0000-4000-8003-000000000001"
RULE_B = "00000000-0000-4000-8003-000000000002"
THREAT = "00000000-0000-4000-8001-000000000001"
OBJECTIVE = "00000000-0000-4000-8002-000000000001"
ORGANISATION = "00000000-0000-4000-8000-000000000099"


def _object(path: Path, uuid: str, name: str, *, schema: str = "rule::1.0") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"name: {name}\n\nmetadata:\n  uuid: {uuid}\n  schema: {schema}\n  version: 1\n\n"
        "description: |\n  uuid: not-this-one\n",
        encoding="utf-8",
    )


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace with two rules, a threat and an objective; splunk enabled."""
    root = tmp_path / "detections"
    _object(root / "objects/rules/sentinel-rule.yaml", RULE_A, "Sentinel KQL Rule")
    _object(root / "objects/rules/splunk-rule.yaml", RULE_B, '"Splunk: SPL Rule"')
    _object(root / "objects/threats/actor.yaml", THREAT, "Simulated Actor", schema="threat::1.0")
    _object(
        root / "objects/objectives/credentials.yml",
        OBJECTIVE,
        "Credential Access",
        schema="objective::1.0",
    )
    platforms = root / ".opentide/configurations/platforms"
    platforms.mkdir(parents=True)
    (platforms / "splunk.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    (platforms / "sentinel.toml").write_text("[platform]\nenabled = false\n", encoding="utf-8")
    # In-process tests pin the workspace through this variable (tests/conftest.py).
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.chdir(root)
    return root


def _complete(words: str) -> list[CompletionItem]:
    """Complete the last word of ``opentide <words>`` as a shell would."""
    args = words.split()
    incomplete = "" if words.endswith(" ") or not args else args.pop()
    group = typer.main.get_command(cli_package.app)
    return BashComplete(group, {}, "opentide", "_OPENTIDE_COMPLETE").get_completions(
        args, incomplete
    )


def _values(words: str) -> list[str]:
    return [item.value for item in _complete(words)]


def _helps(words: str) -> dict[str, str | None]:
    return {item.value: item.help for item in _complete(words)}


# --------------------------------------------------------------------------
# Object UUIDs and files
# --------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["validate", "share", "share push", "share retract"])
def test_uuid_completes_every_object_with_its_name(workspace: Path, command: str) -> None:
    helps = _helps(f"{command} --uuid ")
    assert helps == {
        RULE_A: "Sentinel KQL Rule (rule)",
        RULE_B: "Splunk: SPL Rule (rule)",
        THREAT: "Simulated Actor (threat)",
        OBJECTIVE: "Credential Access (objective)",
    }


def test_uuid_filters_by_prefix_and_type(workspace: Path) -> None:
    assert _values("validate --uuid 00000000-0000-4000-8001") == [THREAT]
    assert _values("validate --type objective --uuid ") == [OBJECTIVE]
    assert _values("share --type threat --type rule --uuid ") == [RULE_A, RULE_B, THREAT]


def test_validate_query_completes_rules_only(workspace: Path) -> None:
    assert _values("validate query --uuid ") == [RULE_A, RULE_B]
    assert _values("validate query --file ") == [
        "objects/rules/sentinel-rule.yaml",
        "objects/rules/splunk-rule.yaml",
    ]


def test_repo_option_points_completion_at_another_workspace(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(elsewhere))
    assert _values("validate --uuid ") == []
    assert _values(f"--repo {workspace} validate --uuid ") == [RULE_A, RULE_B, THREAT, OBJECTIVE]


def test_file_completes_object_paths_from_the_current_directory(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helps = _helps("validate --file objects/")
    assert helps == {
        "objects/rules/sentinel-rule.yaml": "Sentinel KQL Rule",
        "objects/rules/splunk-rule.yaml": "Splunk: SPL Rule",
        "objects/threats/actor.yaml": "Simulated Actor",
        "objects/objectives/credentials.yml": "Credential Access",
    }
    # Inside objects/rules, rules are relative to it and the rest to the workspace.
    monkeypatch.chdir(workspace / "objects" / "rules")
    assert _values("share --file ") == [
        "sentinel-rule.yaml",
        "splunk-rule.yaml",
        "objects/threats/actor.yaml",
        "objects/objectives/credentials.yml",
    ]


def test_file_falls_back_to_bare_names_then_to_the_shell(workspace: Path) -> None:
    assert _values("validate --file spl") == ["splunk-rule.yaml"]
    # Nothing matches: an empty answer lets bash and zsh complete file names.
    assert _values("validate --file nothing") == []
    assert _values("validate --file objects/nothing") == []


def test_object_folders_follow_paths_toml(workspace: Path) -> None:
    (workspace / ".opentide/configurations/paths.toml").write_text(
        '[paths.objects]\nrule = "detections/"\n', encoding="utf-8"
    )
    _object(workspace / "detections/moved.yaml", "00000000-0000-4000-8003-0000000000ff", "Moved")
    assert _values("validate --type rule --uuid ") == ["00000000-0000-4000-8003-0000000000ff"]
    (workspace / ".opentide/configurations/paths.toml").write_text("not = [toml", encoding="utf-8")
    assert _values("validate --type rule --uuid ") == [RULE_A, RULE_B]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"name: Plain\nmetadata:\n  uuid: {RULE_A}\n", (RULE_A, "Plain")),
        (f"name: 'Quoted # not a comment'\nuuid: \"{RULE_A}\"\n", (RULE_A, "Quoted # not a comment")),  # noqa: E501
        (f'# header\nname: "Esc \\" quote" # comment\nmetadata:\n  uuid: {RULE_A} # c\n', (RULE_A, 'Esc " quote')),  # noqa: E501
        ('name: "line\\nbreak \\u00e9\\x41\\\\"\n', (None, "line\nbreak éA\\")),
        ("name: 'Detect: user''s \"admin\"' # c\n", (None, 'Detect: user\'s "admin"')),
        # Only metadata's own uuid, never one nested deeper (an alphabetical dump puts it first).
        (f"name: Rule 1\nmetadata:\n  organisation:\n    uuid: {ORGANISATION}\n    name: Example Corp\n  uuid: {RULE_A}\n", (RULE_A, "Rule 1")),  # noqa: E501
        (f"name: Four spaces\nmetadata:\n    organisation:\n        uuid: {ORGANISATION}\n    uuid: {RULE_A}\n", (RULE_A, "Four spaces")),  # noqa: E501
        ("description: |\n  name: nested\nname: Late\nconfigurations:\n  uuid: wrong\n", (None, "Late")),  # noqa: E501
        ("name: |\n  block scalar\n", (None, None)),
        ("", (None, None)),
    ],
)  # fmt: skip
def test_read_header(tmp_path: Path, text: str, expected: tuple[str | None, str | None]) -> None:
    path = tmp_path / "object.yaml"
    path.write_text(text, encoding="utf-8")
    assert read_header(path) == expected


def test_read_header_of_a_missing_file(tmp_path: Path) -> None:
    assert read_header(tmp_path / "gone.yaml") == (None, None)


def test_rules_sharing_an_organisation_keep_their_own_uuids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``metadata.organisation.uuid`` first, then ``metadata.uuid``: three rules, three UUIDs."""
    rules = tmp_path / "objects/rules"
    rules.mkdir(parents=True)
    expected = []
    for number in range(1, 4):
        uuid = f"00000000-0000-4000-8003-00000000000{number}"
        expected.append((uuid, f"Rule {number} (rule)"))
        (rules / f"rule-{number}.yaml").write_text(
            f"name: Rule {number}\nmetadata:\n  organisation:\n    uuid: {ORGANISATION}\n"
            f"    name: Example Corp\n  uuid: {uuid}\n",
            encoding="utf-8",
        )
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    assert list(completion.object_uuids()(None, "")) == expected


def test_uuid_skips_a_header_that_is_not_a_uuid(workspace: Path) -> None:
    (workspace / "objects/rules/garbled.yaml").write_bytes(b"name: Garbled\nuuid: \xff\n")
    (workspace / "objects/rules/typo.yaml").write_text("name: Typo\nuuid: 1234\n", "utf-8")
    assert _values("validate --type rule --uuid ") == [RULE_A, RULE_B]


def test_file_never_offers_a_directory(workspace: Path) -> None:
    (workspace / "objects/rules/dir.yaml").mkdir()
    assert _values("validate --file objects/rules/") == [
        "objects/rules/sentinel-rule.yaml",
        "objects/rules/splunk-rule.yaml",
    ]
    assert _values("validate --file dir") == []


def test_file_reads_only_the_headers_of_matching_paths(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read: list[str] = []
    original = completion.read_header

    def counted(path: Path) -> tuple[str | None, str | None]:
        read.append(path.name)
        return original(path)

    monkeypatch.setattr(completion, "read_header", counted)
    assert _helps("validate --file objects/rules/spl") == {
        "objects/rules/splunk-rule.yaml": "Splunk: SPL Rule"
    }
    assert read == ["splunk-rule.yaml"]


def test_bash_gets_spaces_and_metacharacters_escaped(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Typer's bash script inserts candidates verbatim; zsh and fish quote them themselves."""
    _object(workspace / "objects/rules/team a my rule: v2 (old)&$x.yaml", RULE_A, "Spaced")
    (workspace / "objects/rules/sentinel-rule.yaml").unlink()
    words = "validate --file objects/rules/team"
    assert _values(words) == ["objects/rules/team a my rule: v2 (old)&$x.yaml"]
    monkeypatch.setenv("_OPENTIDE_COMPLETE", "complete_bash")
    assert _values(words) == ["objects/rules/team\\ a\\ my\\ rule:\\ v2\\ \\(old\\)\\&\\$x.yaml"]
    # Plain candidates are unchanged.
    assert set(_values("validate --type rule --uuid ")) == {RULE_A, RULE_B}
    assert completion.bash_word("T1059.001") == "T1059.001"
    assert completion.bash_word("it's") == "it\\'s"


def test_bash_skips_a_candidate_with_a_line_break(monkeypatch: pytest.MonkeyPatch) -> None:
    complete = completion._shell_complete(lambda ctx, incomplete: [("a\nb", ""), ("ok", "")])
    assert [item.value for item in complete(None, None, "")] == ["a\nb", "ok"]
    monkeypatch.setenv("_OPENTIDE_COMPLETE", "complete_bash")
    assert [item.value for item in complete(None, None, "")] == ["ok"]


# --------------------------------------------------------------------------
# Types, strategies, techniques, platforms
# --------------------------------------------------------------------------


def test_type_completes_object_kinds(workspace: Path) -> None:
    assert _helps("validate --type ") == {
        "rule": "objects/rules/",
        "threat": "objects/threats/",
        "objective": "objects/objectives/",
    }
    assert _values("share preview --type th") == ["threat"]


@pytest.mark.parametrize("command", ["deploy", "validate query"])
def test_strategy_completes_the_deployable_strategies(workspace: Path, command: str) -> None:
    helps = _helps(f"{command} --strategy ")
    assert list(helps) == ["PREVIEW", "RELEASE"]
    assert helps["PREVIEW"] == "Deployment from Pull/Merge Requests"
    assert _values(f"{command} --strategy re") == ["RELEASE"]


def test_technique_completes_attack_ids_with_titles(workspace: Path) -> None:
    helps = _helps("info --technique T1059")
    assert helps["T1059"] == "Command and Scripting Interpreter"
    assert helps["T1059.001"] == "Command and Scripting Interpreter: PowerShell"
    assert all(value.startswith("T1059") for value in helps)
    assert list(helps)[:2] == ["T1059", "T1059.001"]
    assert _values("info --technique t1059.00")[0] == "T1059.001"


def test_technique_reads_the_data_root_override(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    (data / "vocabulary").mkdir(parents=True)
    (data / "vocabulary" / "att&ck.vocab.toml").write_text(
        '[[keys]]\nid = "T9999"\nname = "Made Up \\u00e9"\n'
        '[[keys]]\nid = "T9999.001"\nname = "Made Up: Sub"\n'
        '[[keys]]\nid = "T1000"\nname = "Earlier"\n',
        encoding="utf-8",
    )
    assert _helps(f"--data {data} info --technique ") == {
        "T1000": "Earlier",
        "T9999": "Made Up é",
        "T9999.001": "Made Up: Sub",
    }
    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(tmp_path / "missing"))
    assert _values("info --technique ") == []


@pytest.mark.parametrize("command", ["deploy", "validate query", "info", "setup"])
def test_platform_lists_enabled_platforms_first(workspace: Path, command: str) -> None:
    items = _complete(f"{command} --platform ")
    assert items[0].value == "splunk"
    assert items[0].help == "enabled"
    assert {item.value for item in items[1:]} >= {"sentinel", "elastic", "defender_for_endpoint"}
    assert all(item.help is None for item in items[1:])
    assert _values(f"{command} --platform SENT") == ["sentinel", "sentinel_one"]


def test_platform_outside_a_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    values = _values("deploy --platform ")
    assert values[0] == "sentinel"
    assert len(values) == 8


def test_enabled_platforms_agree_with_ci_discovery(workspace: Path) -> None:
    from opentide.ci.discovery import discover_enabled_platforms

    platforms = workspace / ".opentide/configurations/platforms"
    (platforms / "elastic.toml").write_text("[platform]\nEnabled = TRUE\n", encoding="utf-8")
    (platforms / "notes.toml").write_text("enabled = true\n", encoding="utf-8")
    assert completion.enabled_platforms(workspace) == discover_enabled_platforms(workspace)
    assert completion.enabled_platforms(workspace) == ["elastic", "splunk"]


# --------------------------------------------------------------------------
# explain <code>
# --------------------------------------------------------------------------


def _explain_app() -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def explain(code: str | None = typer.Argument(None)) -> None:
        """Explain a diagnostic code."""

    @app.command()
    def other(code: str | None = typer.Argument(None)) -> None:
        """Another command with an argument named code."""

    return app


def _pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = tmp_path / "package-data"
    pages = data / "diagnostics"
    pages.mkdir(parents=True)
    (pages / "vocab_unknown.md").write_text(
        "# vocab_unknown\n\nA value is not in the vocabulary\nthe field uses.\n\n## Example\n",
        encoding="utf-8",
    )
    (pages / "duplicate_id.md").write_text(
        "# duplicate_id\n\nTwo object files carry the same UUID.\n", encoding="utf-8"
    )
    (pages / "README.txt").write_text("not a page\n", encoding="utf-8")
    monkeypatch.setattr(completion, "files", lambda package: data)
    return pages


def test_explain_completes_diagnostic_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pages(tmp_path, monkeypatch)
    group = typer.main.get_command(_explain_app())
    for name in ("explain", "other"):
        attach(group.commands[name], name)
    complete = BashComplete(group, {}, "opentide", "_OPENTIDE_COMPLETE").get_completions
    items = complete(["explain"], "")
    assert [(item.value, item.help) for item in items] == [
        ("duplicate_id", "Two object files carry the same UUID."),
        ("vocab_unknown", "A value is not in the vocabulary the field uses."),
    ]
    assert [item.value for item in complete(["explain"], "voc")] == ["vocab_unknown"]
    # Only explain's argument completes codes.
    assert complete(["other"], "") == []


def test_explain_completes_nothing_without_the_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(completion, "files", lambda package: tmp_path / "no-data")
    assert completion.diagnostic_codes(None, "") == []


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def test_a_failing_source_completes_nothing(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(root: Path, kinds: object = ()) -> object:
        raise RuntimeError("unreadable")

    monkeypatch.setattr(completion, "iter_objects", broken)
    assert _values("validate --uuid ") == []


def test_attach_keeps_a_parameter_s_own_completion() -> None:
    app = typer.Typer()

    def own(incomplete: str) -> list[str]:
        return ["mine"]

    @app.command()
    def run(uuid: str = typer.Option("", "--uuid", autocompletion=own)) -> None:
        """Run."""

    command = typer.main.get_command(app)
    attach(command, "run")
    items = BashComplete(command, {}, "run", "_RUN_COMPLETE").get_completions(["--uuid"], "")
    assert [item.value for item in items] == ["mine"]


def test_completion_never_builds_the_registry(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.core.registry import OpentideRegistry

    calls: list[str] = []
    monkeypatch.setattr(OpentideRegistry, "initialise", lambda self: calls.append("initialise"))
    for words in (
        "validate --uuid ",
        "validate --file ",
        "share --type ",
        "deploy --platform ",
        "deploy --strategy ",
        "info --technique T10",
    ):
        assert _values(words), words
    assert calls == []


# --------------------------------------------------------------------------
# The index: values complete without loading the command
# --------------------------------------------------------------------------

_INDEXED = sorted(
    (path, option) for path, options in completion.INDEXED_OPTIONS.items() for option in options
)


def _group() -> Any:
    return typer.main.get_command(cli_package.app)


def test_index_lists_every_option_a_loaded_command_completes() -> None:
    """A completed option missing from the index would load the engine on every Tab."""
    found: dict[tuple[str, ...], set[str]] = {}

    def walk(command: Any, path: tuple[str, ...]) -> None:
        for param in command.params:
            if param.param_type_name != "option":
                continue
            if completion._source_for(path, param) is None:
                continue
            found.setdefault(path, set()).update(param.opts)
            if "--platform" in param.opts:
                choices = [
                    str(getattr(choice, "value", choice)) for choice in completion._choices(param)
                ]
                assert choices == list(completion.PLATFORMS), path
        for name, child in (getattr(command, "commands", None) or {}).items():
            walk(child, (*path, name))

    group = _group()
    for name in group.list_commands(None):
        walk(group.get_command(None, name), (name,))
    assert found == {path: set(options) for path, options in completion.INDEXED_OPTIONS.items()}


def test_platform_and_strategy_copies_match_the_engine() -> None:
    from opentide.cli.enums import DetectionPlatform
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    assert tuple(platform.value for platform in DetectionPlatform) == completion.PLATFORMS
    assert (
        tuple((strategy.name, str(strategy.value)) for strategy in DEPLOYABLE_STRATEGIES)
        == completion.STRATEGIES
    )


def _from_index(words: str) -> list[tuple[str, str | None]] | None:
    args = words.split()
    incomplete = "" if words.endswith(" ") or not args else args.pop()
    found = completion.indexed_source(_group(), args, incomplete)
    if found is None:
        return None
    source, ctx, incomplete = found
    complete = completion._shell_complete(source)
    return [(item.value, item.help) for item in complete(ctx, None, incomplete)]


@pytest.mark.parametrize(
    ("path", "option"), _INDEXED, ids=[" ".join((*path, option)) for path, option in _INDEXED]
)
def test_index_answers_as_the_loaded_command_does(
    workspace: Path, path: tuple[str, ...], option: str
) -> None:
    words = f"{' '.join(path)} {option} "
    answer = _from_index(words)
    assert answer, words
    assert answer == [(item.value, item.help) for item in _complete(words)]


@pytest.mark.parametrize(
    "words",
    [
        "validate --type rule --uuid ",
        "validate --type=threat --file ",
        "share push --type objective --json --uuid 0",
        "--json validate --uuid=00000000-0000-4000-8003",
        "validate query --strategy pre",
        "--repo {repo} deploy --platform ",
    ],
)
def test_index_reads_the_options_already_typed(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, words: str
) -> None:
    other = tmp_path / "other"
    (other / ".opentide/configurations/platforms").mkdir(parents=True)
    (other / ".opentide/configurations/platforms/elastic.toml").write_text(
        "[platform]\nenabled = true\n", encoding="utf-8"
    )
    words = words.format(repo=other)
    answer = _from_index(words)
    assert answer
    assert answer == [(item.value, item.help) for item in _complete(words)]
    if "--repo" in words:
        assert answer[0] == ("elastic", "enabled")


@pytest.mark.parametrize(
    "words",
    [
        "validate --",  # an option name
        "validate --uu",
        "validate --check schema --uuid ",  # an option the index does not know
        "validate --uuid x query --uuid ",  # a positional word after the path
        "validate --file --uuid ",  # --file has no value of its own
        "lint --platform ",  # a command the index does not hold
        "validate -- --uuid ",
        "validate ",
        "",
    ],
)
def test_index_leaves_the_rest_to_click(workspace: Path, words: str) -> None:
    assert _from_index(words) is None


@pytest.mark.parametrize(
    ("shell", "env"),
    [
        ("zsh", {"_TYPER_COMPLETE_ARGS": "opentide validate --uuid "}),
        (
            "fish",
            {
                "_TYPER_COMPLETE_ARGS": "opentide deploy --platform ",
                "_TYPER_COMPLETE_FISH_ACTION": "get-args",
            },
        ),
        ("bash", {"COMP_WORDS": "opentide info --technique T1059.00", "COMP_CWORD": "3"}),
    ],
)
def test_each_shell_gets_the_answer_click_would_format(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shell: str,
    env: dict[str, str],
) -> None:
    from typer._click.shell_completion import get_completion_class

    monkeypatch.setenv("_OPENTIDE_COMPLETE", f"complete_{shell}")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    group = _group()
    with pytest.raises(SystemExit) as exited:
        completion.complete_from_index(group, "opentide", "_OPENTIDE_COMPLETE")
    assert exited.value.code == 0
    fast = capsys.readouterr().out
    shell_class = get_completion_class(shell)
    assert shell_class is not None
    slow = shell_class(group, {}, "opentide", "_OPENTIDE_COMPLETE").complete()
    assert fast.strip()
    assert fast.rstrip("\n") == slow


def test_complete_from_index_returns_for_anything_else(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    group = _group()
    monkeypatch.delenv("_OPENTIDE_COMPLETE", raising=False)
    completion.complete_from_index(group, "opentide", "_OPENTIDE_COMPLETE")
    for instruction in ("source_bash", "complete_tcsh"):
        monkeypatch.setenv("_OPENTIDE_COMPLETE", instruction)
        completion.complete_from_index(group, "opentide", "_OPENTIDE_COMPLETE")
    monkeypatch.setenv("_OPENTIDE_COMPLETE", "complete_bash")
    monkeypatch.setenv("COMP_WORDS", "opentide validate --")
    monkeypatch.setenv("COMP_CWORD", "2")
    completion.complete_from_index(group, "opentide", "_OPENTIDE_COMPLETE")
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------
# --install-completion, --show-completion, `opentide completion`
# --------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway home with a project in it as the current directory; no shell detected."""
    home = tmp_path / "home"
    (home / "proj").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("_TYPER_COMPLETE_TEST_DISABLE_SHELL_DETECTION", raising=False)
    monkeypatch.setattr("typer._completion_shared._get_shell_name", lambda: None)
    monkeypatch.chdir(home / "proj")
    return home


def _invoke(*args: str) -> Any:
    from typer.testing import CliRunner

    return CliRunner().invoke(
        cli_package.app, list(args), prog_name="opentide", env={"NO_COLOR": "1"}
    )


@pytest.mark.parametrize(
    ("shell", "path", "step"),
    [
        ("bash", "~/.bash_completions/opentide.sh", "→ source ~/.bashrc · or restart your shell"),
        ("zsh", "~/.zfunc/_opentide", "→ source ~/.zshrc · or restart your shell"),
        ("fish", "~/.config/fish/completions/opentide.fish", "→ exec fish · restart your shell"),
    ],
)
def test_install_completion_names_the_shell_the_path_and_the_next_step(
    home: Path, shell: str, path: str, step: str
) -> None:
    result = _invoke("--install-completion", shell)
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == [f"✓ Installed {shell} completion in {path}", step]
    assert (home / path.removeprefix("~/")).is_file()


def test_install_completion_inside_the_current_directory_is_relative_to_it(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(home)
    result = _invoke("--install-completion", "bash")
    assert result.stdout.splitlines()[0] == (
        "✓ Installed bash completion in .bash_completions/opentide.sh"
    )


def test_install_completion_quiet_and_json(home: Path) -> None:
    quiet = _invoke("--quiet", "--install-completion", "zsh")
    assert quiet.stdout.splitlines() == ["✓ Installed zsh completion in ~/.zfunc/_opentide"]
    document = json.loads(_invoke("--json", "--install-completion", "zsh").stdout)
    assert document["message"] == "Installed zsh completion in ~/.zfunc/_opentide"
    assert document["shell"] == "zsh"
    assert document["path"] == str(home / ".zfunc" / "_opentide")
    assert document["next_actions"] == [
        {"command": "source ~/.zshrc", "reason": "or restart your shell"}
    ]


@pytest.mark.parametrize("option", ["--install-completion", "--show-completion"])
@pytest.mark.parametrize("words", [["tcsh"], ["validate"], ["bash", "zsh"]])
def test_completion_options_refuse_a_word_that_is_not_one_shell(
    home: Path, option: str, words: list[str]
) -> None:
    result = _invoke(option, *words)
    assert result.exit_code == 2
    assert f"Use: opentide {option} [bash|zsh|fish|powershell|pwsh]" in result.stderr
    assert not (home / ".bashrc").exists()


@pytest.mark.parametrize("option", ["--install-completion", "--show-completion"])
def test_completion_options_ask_for_a_shell_they_cannot_detect(home: Path, option: str) -> None:
    result = _invoke(option)
    assert result.exit_code == 2
    assert f"Name it: opentide {option} [bash|" in result.stderr


def test_completion_options_use_the_detected_shell(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("typer._completion_shared._get_shell_name", lambda: "zsh")
    assert "#compdef opentide" in _invoke("--show-completion").stdout
    installed = _invoke("--install-completion")
    assert installed.stdout.splitlines()[0] == "✓ Installed zsh completion in ~/.zfunc/_opentide"


def test_typer_s_test_mode_passes_the_shell_as_the_value(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under this variable Typer builds both options to take a value instead of being flags."""
    monkeypatch.setenv("_TYPER_COMPLETE_TEST_DISABLE_SHELL_DETECTION", "1")
    result = _invoke("--show-completion", "fish")
    assert result.exit_code == 0
    assert "complete --command opentide" in result.stdout


@pytest.mark.parametrize(
    ("shell", "marker"),
    [
        ("zsh", "#compdef opentide"),
        ("fish", "complete --command opentide"),
        ("bash", "complete -o default -F"),
    ],
)
def test_show_completion_prints_the_named_shell_s_script(
    home: Path, shell: str, marker: str
) -> None:
    result = _invoke("--show-completion", shell)
    assert result.exit_code == 0
    assert marker in result.stdout
    assert "_OPENTIDE_COMPLETE" in result.stdout


@pytest.mark.parametrize("word", ["completion", "completions", "install-completion"])
def test_completion_as_a_command_points_at_the_options(word: str) -> None:
    result = _invoke(word)
    assert result.exit_code == 2
    assert (
        "help: did you mean 'opentide --install-completion'? "
        "'opentide --show-completion' prints the script instead"
    ) in result.stderr
    failure = json.loads(_invoke("--json", word).stdout)["failure"]
    assert failure["code"] == "usage_unknown_command"
    assert failure["suggestion"] == "--install-completion"

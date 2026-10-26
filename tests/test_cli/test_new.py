"""``opentide new``: template filling, naming, references and the no-prompt contract."""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from pydantic import BaseModel
from tests.result_models_support import assert_matches_model
from tests.test_cli.conftest import clear_runtime_caches, parse_cli_json
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services import new as new_service
from opentide.cli.services.new import (
    PLACEHOLDER_MARKER,
    Organisation,
    collect_fields,
    fill_template,
    index_template,
)
from opentide.core.io import parse_yaml

_SGR = re.compile(r"\x1b\[[0-9;]*m")

THREAT_UUID = "00000000-0000-4000-8001-000000000001"
ORG = {"uuid": "00000000-0000-4000-8000-000000000099", "name": "Example Corp"}

THREAT = f"""\
name: Seed Threat
metadata:
  uuid: {THREAT_UUID}
  schema: threat::1.0
  organisation:
    uuid: {ORG["uuid"]}
    name: {ORG["name"]}
"""

#: Git reads these in place of a global config.
GIT_AUTHOR = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "user.name",
    "GIT_CONFIG_VALUE_0": "Jane Analyst",
}


#: What ``CliContext.apply_environment()`` writes for the engine modules.
#: ``CliRunner`` restores only the variables passed in ``env=``.
_CLI_EXPORTS = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "OPENTIDE_DATA_ROOT", "NO_COLOR")


@contextmanager
def cli_state_restored() -> Iterator[None]:
    """Undo what a CLI run leaves in the process: its exports and the cached registry.

    A run given ``--repo`` but no ``env=`` left ``OPENTIDE_TIDE_WORKSPACE``
    set and the registry built from it. A later test in the same worker then
    generated schemas from configurations merged with
    ``tests/fixtures/generation`` and failed with ``KeyError: 'name'``.
    """
    saved = {name: os.environ.get(name) for name in _CLI_EXPORTS}
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        clear_runtime_caches()


@pytest.fixture(autouse=True)
def _restore_cli_state() -> Iterator[None]:
    with cli_state_restored():
        yield


@pytest.fixture(scope="module")
def prepared(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A sentinel workspace with generated templates and schemas, built once."""
    root = tmp_path_factory.mktemp("new") / "detections"
    runner = CliRunner()
    # Module-scoped, so it runs before any test's own restore: undo setup's
    # OPENTIDE_TIDE_WORKSPACE export here, or it outlives the module.
    with cli_state_restored():
        clear_runtime_caches()
        setup = runner.invoke(
            app,
            ["--json", "setup", "--yes", "--platform", "sentinel", "--path", str(root)],
            env={"OPENTIDE_REPO_ROOT": str(root.parent)},
        )
        assert setup.exit_code == 0, setup.stdout + setup.stderr
        clear_runtime_caches()
        env = {"OPENTIDE_REPO_ROOT": str(root), "OPENTIDE_TIDE_WORKSPACE": str(root)}
        generate = runner.invoke(
            app, ["--json", "--repo", str(root), "generate", "templates", "schemas"], env=env
        )
        assert generate.exit_code == 0, generate.stdout + generate.stderr
    return root


@pytest.fixture
def workspace(prepared: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "detections"
    shutil.copytree(prepared, root)
    (root / "objects" / "threats" / "seed-threat.yaml").write_text(THREAT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return root


def _new(root: Path, *args: str, json_output: bool = True, env: dict | None = None) -> Result:
    clear_runtime_caches()
    argv = ["--json"] if json_output else ["--no-color"]
    environment = {
        "OPENTIDE_REPO_ROOT": str(root),
        "OPENTIDE_TIDE_WORKSPACE": str(root),
        **GIT_AUTHOR,
        **(env or {}),
    }
    return CliRunner().invoke(app, [*argv, "--repo", str(root), "new", *args], env=environment)


# --------------------------------------------------------------------------- the command


def test_new_threat_json(workspace: Path) -> None:
    result = _new(workspace, "threat", "--name", "Credential Dumping")
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = parse_cli_json(result)
    path = workspace / "objects" / "threats" / "credential-dumping.yaml"
    assert payload["file_path"] == str(path)
    assert payload["path"] == "detections/objects/threats/credential-dumping.yaml"
    assert payload["command"] == "new threat"
    # The document matches NewResult and the schema `opentide commands` publishes.
    assert_matches_model(payload)
    assert payload["author"] == "Jane Analyst"
    assert payload["organisation"] == ORG
    assert payload["summary"] == {"created": 1, "placeholders": len(payload["placeholders"])}
    assert "threat.mitre_attack" in payload["placeholders"]
    assert payload["next_actions"] == [
        {"command": f"opentide --json validate --file {payload['path']}", "reason": "check it"}
    ]
    data = parse_yaml(path.read_text(encoding="utf-8"))
    assert data["name"] == "Credential Dumping"
    assert data["metadata"]["uuid"] == payload["uuid"]
    assert data["metadata"]["tlp"] == "amber"
    assert data["metadata"]["created"] == dt.datetime.now().astimezone().date().isoformat()
    assert data["metadata"]["author"] == "Jane Analyst"
    assert data["metadata"]["organisation"] == ORG
    # The template's comments for optional keys stay in the file.
    assert "#contributors:" in path.read_text(encoding="utf-8")


def test_new_human_output(workspace: Path) -> None:
    result = _new(workspace, "objective", "--name", "Detect It", json_output=False)
    assert result.exit_code == 0, result.stdout + result.stderr
    out = _SGR.sub("", result.stdout)
    assert "Created detections/objects/objectives/detect-it.yaml · " in out
    assert "placeholders to replace" in out
    assert f"note: each ends in '{PLACEHOLDER_MARKER}'; opentide lint lists them" in out
    # The note and the next step fit a 100-column terminal.
    assert max(len(line) for line in out.splitlines()) <= 100, out
    assert "→ opentide validate --file detections/objects/objectives/detect-it.yaml" in out


def test_outcome_separator_follows_the_stream_encoding(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import sys

    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    options = new_service.NewOptions(family="threat", name="Ascii Only")
    payload = new_service.scaffold_object(workspace, options)
    assert payload["message"].isascii(), payload["message"]
    assert " - " in payload["message"]


def test_json_new_without_a_kind_is_a_usage_error(workspace: Path) -> None:
    clear_runtime_caches()
    result = CliRunner().invoke(app, ["--json", "--repo", str(workspace), "new"])
    assert result.exit_code == 2
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "usage_error"
    assert payload["command"] == "new"


def test_bare_new_shows_its_help(workspace: Path) -> None:
    """Human mode keeps ``no_args_is_help``: the group adds no callback that could bypass it."""
    clear_runtime_caches()
    result = CliRunner().invoke(app, ["--no-color", "--repo", str(workspace), "new"])
    assert result.exit_code == 2
    assert "threat" in result.stdout and "rule" in result.stdout
    from opentide.cli.commands.new import new_app

    assert new_app.registered_callback is None


def test_a_run_without_env_leaves_no_workspace_export_behind(
    prepared: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--repo`` exports OPENTIDE_TIDE_WORKSPACE, which CliRunner does not undo.

    Left set (by ``prepared``'s setup run, or a test's own), it made a later
    test's schema generation merge ``tests/fixtures/generation`` and fail with
    ``KeyError: 'name'``.
    """
    from opentide.generation.pydantic_schemas import generate_schema_for_identifier

    assert os.environ.get("OPENTIDE_TIDE_WORKSPACE") != str(prepared.parent)
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    with cli_state_restored():
        clear_runtime_caches()
        CliRunner().invoke(app, ["--no-color", "--repo", str(workspace), "new"])
        assert os.environ["OPENTIDE_TIDE_WORKSPACE"] == str(workspace)
    assert "OPENTIDE_TIDE_WORKSPACE" not in os.environ
    schema = generate_schema_for_identifier("rule::1.1")
    assert "severity" in schema["properties"]


def test_new_objective_links_threats(workspace: Path) -> None:
    result = _new(workspace, "objective", "--name", "Linked", "--threat", THREAT_UUID)
    payload = parse_cli_json(result)
    data = parse_yaml(Path(payload["file_path"]).read_text(encoding="utf-8"))
    assert data["objective"]["threats"] == [THREAT_UUID]


def test_new_rule_with_platforms_warns_about_disabled_ones(workspace: Path) -> None:
    result = _new(
        workspace, "rule", "--name", "Rule", "--platform", "sentinel", "--platform", "splunk"
    )
    payload = parse_cli_json(result)
    assert_matches_model(payload)
    assert payload["platforms"] == ["sentinel", "splunk"]
    assert payload["warnings"] == [
        "splunk is not enabled in this workspace, so this block will not deploy; "
        "enable it with 'opentide setup platforms --splunk'"
    ]
    data = parse_yaml(Path(payload["file_path"]).read_text(encoding="utf-8"))
    sentinel = data["configurations"]["sentinel"]
    assert sentinel["enabled"] is True
    assert sentinel["status"] == "DESIGN"
    # What Sentinel's compile needs: a schedule and grouping.
    assert sentinel["scheduling"] == {"frequency": "1h", "lookback": "1h"}
    assert sentinel["grouping"] == {"event": "SingleAlert", "alert": {"enabled": False}}
    assert "configurations.sentinel.scheduling.frequency" in payload["placeholders"]
    assert "configurations.sentinel.grouping.event" not in payload["placeholders"]
    # Live in the template, so not left null for a deploy to read.
    assert data["response"] == {"alert_severity": "Informational"}
    assert data["configurations"]["splunk"]["status"] == "DESIGN"
    # Only the chosen blocks are written; a comment points at the template.
    text = Path(payload["file_path"]).read_text(encoding="utf-8")
    assert "#elastic:" not in text
    assert "#crowdstrike:" not in text
    pointer = "  # Other platforms: copy a block from .opentide/templates/rule.1.1.template.yaml"
    assert pointer in text.splitlines()


def test_name_collision_appends_the_uuid(workspace: Path) -> None:
    first = parse_cli_json(_new(workspace, "threat", "--name", "Seed Threat"))
    assert Path(first["file_path"]).name == f"seed-threat-{first['uuid'][:8]}.yaml"


def _lint(root: Path, *args: str) -> Result:
    clear_runtime_caches()
    env = {"OPENTIDE_REPO_ROOT": str(root), "OPENTIDE_TIDE_WORKSPACE": str(root)}
    return CliRunner().invoke(app, ["--json", "--repo", str(root), "lint", *args], env=env)


def test_placeholders_are_marked_and_fail_lint_strict(workspace: Path) -> None:
    payload = parse_cli_json(_new(workspace, "threat", "--name", "Marked Threat"))
    path = Path(payload["file_path"])
    marked = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.endswith(f"  {PLACEHOLDER_MARKER}")
    ]
    assert len(marked) == len(payload["placeholders"]), marked
    # The invented ATT&CK technique is marked, so it cannot pass as chosen coverage.
    assert any(line.lstrip().startswith("- T") for line in marked), marked

    plain = _lint(workspace, "--check", "placeholders")
    assert plain.exit_code == 0, plain.stdout + plain.stderr
    strict = _lint(workspace, "--strict", "--check", "placeholders")
    assert strict.exit_code == 1
    findings = [
        finding
        for finding in parse_cli_json(strict)["findings"]
        if finding["path"].endswith(path.name)
    ]
    assert len(findings) == len(marked)
    assert {(finding["code"], finding["severity"]) for finding in findings} == {
        ("placeholder", "warning")
    }


def test_rule_blocks_stay_disabled_without_an_inert_status(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(new_service, "inert_status", lambda workspace: None)
    payload = parse_cli_json(
        _new(workspace, "rule", "--name", "No Inert", "--platform", "sentinel")
    )
    assert any("INERT" in warning for warning in payload["warnings"])
    assert "configurations.sentinel.status" in payload["placeholders"]
    text = Path(payload["file_path"]).read_text(encoding="utf-8")
    assert parse_yaml(text)["configurations"]["sentinel"]["enabled"] is False
    status = next(line for line in text.splitlines() if line.strip().startswith("status:"))
    assert status.endswith(PLACEHOLDER_MARKER)


def test_platform_blocks_hold_detection_logic(workspace: Path) -> None:
    payload = parse_cli_json(
        _new(
            workspace,
            "rule",
            "--name",
            "Logic",
            "--platform",
            "sentinel_one",
            "--platform",
            "harfanglab",
        )
    )
    data = parse_yaml(Path(payload["file_path"]).read_text(encoding="utf-8"))
    blocks = data["configurations"]
    assert blocks["sentinel_one"]["condition"]["single_event"]["query"]
    assert "configurations.sentinel_one.condition.single_event.query" in payload["placeholders"]
    assert blocks["harfanglab"]["sigma"]
    assert any(
        path.startswith("configurations.harfanglab.sigma") for path in payload["placeholders"]
    )


def test_new_objects_start_on_the_latest_revision(workspace: Path) -> None:
    from opentide.models.schema_registry import latest_identifier

    payload = parse_cli_json(_new(workspace, "rule", "--name", "Latest"))
    assert payload["schema"] == latest_identifier("rule")
    data = parse_yaml(Path(payload["file_path"]).read_text(encoding="utf-8"))
    assert data["metadata"]["schema"] == latest_identifier("rule")


def test_new_refuses_outside_a_workspace(tmp_path: Path) -> None:
    empty = tmp_path / "home"
    empty.mkdir()
    result = _new(empty, "threat", "--name", "Stray")
    assert result.exit_code == 1
    failure = parse_cli_json(result)["failure"]
    assert failure["code"] == "workspace_not_found"
    assert list(empty.iterdir()) == []


def test_path_without_a_yaml_suffix_gets_one(workspace: Path) -> None:
    target = workspace / "objects" / "threats" / "oddfile"
    payload = parse_cli_json(_new(workspace, "threat", "--name", "Odd", "--path", str(target)))
    assert Path(payload["file_path"]) == target.with_name("oddfile.yaml")
    assert payload["next_actions"][0]["command"].endswith("oddfile.yaml")
    assert not target.exists()


def test_a_file_that_appears_while_filling_is_not_overwritten(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = workspace / "objects" / "threats" / "racer.yaml"
    fill = new_service.fill_template

    def racing_fill(*args: object, **kwargs: object) -> object:
        target.write_text("theirs\n", encoding="utf-8")
        return fill(*args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(new_service, "fill_template", racing_fill)
    result = _new(workspace, "threat", "--name", "Racer")
    assert result.exit_code == 1
    assert parse_cli_json(result)["failure"]["code"] == "path_exists"
    assert target.read_text(encoding="utf-8") == "theirs\n"


def test_path_folder_and_existing_file(workspace: Path, tmp_path: Path) -> None:
    folder = tmp_path / "elsewhere"
    folder.mkdir()
    placed = parse_cli_json(_new(workspace, "threat", "--name", "Placed", "--path", str(folder)))
    assert Path(placed["file_path"]) == folder / "placed.yaml"

    target = workspace / "objects" / "threats" / "seed-threat.yaml"
    refused = _new(workspace, "threat", "--name", "Other", "--path", str(target))
    assert refused.exit_code == 1
    failure = parse_cli_json(refused)["failure"]
    assert (failure["code"], failure["argument"]) == ("path_exists", "--path")
    assert target.read_text(encoding="utf-8") == THREAT


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("not-a-uuid", "usage_invalid_value"),
        (THREAT_UUID.replace("8001", "8999"), "reference_not_found"),
    ],
)
def test_unknown_objective_is_a_usage_error(workspace: Path, value: str, code: str) -> None:
    result = _new(workspace, "rule", "--name", "R", "--objective", value)
    assert result.exit_code == 2
    failure = parse_cli_json(result)["failure"]
    assert (failure["code"], failure["argument"]) == (code, "--objective")


@pytest.mark.parametrize(
    ("json_output", "env"),
    [(True, {}), (False, {}), (False, {"AI_AGENT": "test-agent"})],
    ids=["json", "plain", "agent"],
)
def test_missing_name_exits_two_without_prompting(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, json_output: bool, env: dict
) -> None:
    def no_prompt(*args: object, **kwargs: object) -> str:
        raise AssertionError("prompted")

    monkeypatch.setattr("opentide.cli.services.setup.interactive.ask_text", no_prompt)
    result = _new(workspace, "threat", json_output=json_output, env=env)
    assert result.exit_code == 2
    if json_output:
        failure = parse_cli_json(result)["failure"]
        assert (failure["code"], failure["argument"]) == ("usage_needs_input", "--name")
    else:
        assert "needs --name" in _SGR.sub("", result.stderr)


def test_human_mode_prompts_for_name_and_platforms(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.commands import new as new_command

    asked: list[str] = []
    monkeypatch.setattr(new_command, "_can_prompt", lambda: True)
    monkeypatch.setattr(
        "opentide.cli.services.setup.interactive.ask_text",
        lambda message, **_: asked.append(message) or "Prompted Rule",
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.interactive.ask_checkbox",
        lambda message, choices, **_: asked.append(message) or [choices[0][1]],
    )
    result = _new(workspace, "rule", json_output=False)
    assert result.exit_code == 0, result.stdout + result.stderr
    assert asked == ["Rule name", "Platform blocks (space to select, enter for none)"]
    data = parse_yaml((workspace / "objects" / "rules" / "prompted-rule.yaml").read_text())
    assert list(data["configurations"]) == ["sentinel"]


def test_empty_prompt_answer_is_refused(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.commands import new as new_command

    monkeypatch.setattr(new_command, "_can_prompt", lambda: True)
    monkeypatch.setattr("opentide.cli.services.setup.interactive.ask_text", lambda *a, **k: " ")
    assert _new(workspace, "threat", json_output=False).exit_code == 2


def test_no_git_author_is_a_warning(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("opentide.cli.services.new.git_author", lambda workspace: None)
    payload = parse_cli_json(_new(workspace, "threat", "--name", "Anonymous"))
    assert payload["author"] is None
    assert "No git user.name is set, so metadata.author is left out" in payload["warnings"]
    data = parse_yaml(Path(payload["file_path"]).read_text(encoding="utf-8"))
    assert "author" not in data["metadata"]


def test_missing_template_is_generated_first(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (workspace / ".opentide" / "templates" / "threat.1.0.template.yaml").unlink()
    payload = parse_cli_json(_new(workspace, "threat", "--name", "Regenerated"))
    assert payload["generated"] == ["templates"]
    # A step new took, not a warning: generate reports it as it runs.
    assert not any("Generated" in warning for warning in payload.get("warnings", []))


def test_generation_that_writes_nothing_is_an_error(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (workspace / ".opentide" / "templates" / "threat.1.0.template.yaml").unlink()
    monkeypatch.setattr(
        "opentide.cli.services.generation.run_generate", lambda cli, phases: {"message": "ok"}
    )
    result = _new(workspace, "threat", "--name", "Nothing")
    assert result.exit_code == 1
    assert parse_cli_json(result)["failure"]["code"] == "template_missing"


def test_failed_generation_is_reported(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (workspace / ".opentide" / "schemas" / "threat.1.0.schema.json").unlink()
    monkeypatch.setattr(
        "opentide.cli.services.generation.run_generate",
        lambda cli, phases: {"message": "schemas: boom", "status": "failed", "_exit_code": 1},
    )
    result = _new(workspace, "threat", "--name", "Nothing")
    assert result.exit_code == 1
    assert parse_cli_json(result)["message"] == "schemas: boom"


# --------------------------------------------------------------------------- helpers


def test_catalogue_organisation_is_the_most_common(tmp_path: Path) -> None:
    objects = tmp_path / "objects"
    (objects / "rules").mkdir(parents=True)
    for index, org in enumerate(["A", "B", "B", None]):
        body = f"metadata:\n  uuid: u{index}\n"
        if org:
            body += f"  organisation:\n    uuid: org-{org}\n    name: {org}\n"
        (objects / "rules" / f"r{index}.yaml").write_text(body, encoding="utf-8")
    (objects / "rules" / "broken.yaml").write_text("{: nope", encoding="utf-8")
    (objects / "rules" / "list.yaml").write_text("- a\n", encoding="utf-8")
    assert new_service.catalogue_organisation(objects) == Organisation("org-B", "B")
    assert new_service.catalogue_organisation(tmp_path / "missing") is None


def test_inert_status_reads_the_deployment_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "opentide.core.files.resolve_configurations",
        lambda workspace: {"deployment": {"statuses": [{"name": "LIVE", "strategy": "RELEASE"}]}},
    )
    assert new_service.inert_status(tmp_path) is None
    monkeypatch.setattr(
        "opentide.core.files.resolve_configurations",
        lambda workspace: {"deployment": {"statuses": "nope"}},
    )
    assert new_service.inert_status(tmp_path) is None


def test_git_author_without_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(new_service.shutil, "which", lambda name: None)
    assert new_service.git_author(tmp_path) is None


def test_target_path_with_a_file_path(tmp_path: Path) -> None:
    target = tmp_path / "custom.yaml"
    assert new_service.target_path(tmp_path, "Name", "abcdef12-0000", target) == target


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain words", "plain words"),
        ("amber+strict", "amber+strict"),
        ("yes", '"yes"'),
        ("- dash", '"- dash"'),
        ("a: b", '"a: b"'),
        ("#hash", '"#hash"'),
        (True, "true"),
        (3, "3"),
        (dt.date(2026, 1, 2), "2026-01-02"),
    ],
)
def test_scalar_quotes_what_yaml_would_misread(value: object, expected: str) -> None:
    assert new_service._scalar(value) == expected


class _Inner(BaseModel):
    flag: bool = False
    level: int | None = None


class _Item(BaseModel):
    label: str


class _Toy(BaseModel):
    name: str
    kind: str
    tags: list[str]
    items: list[_Item]
    block: _Inner
    empty: _Inner
    note: str | None = None


TOY_TEMPLATE = """\
name:
kind:
tags:
  -
items:
  - label:
block:
  #flag: false
  #level:
empty:
  #level:
#note:
"""


def test_fill_template_on_a_toy_model() -> None:
    fields = collect_fields(_Toy, wanted=[("note",)])
    schema = {"properties": {"kind": {"enum": ["first", "second"]}}}
    result = fill_template(
        TOY_TEMPLATE,
        fields,
        values={("name",): "Toy", ("note",): "hello"},
        schema=schema,
    )
    data = parse_yaml(result.text)
    assert data == {
        "name": "Toy",
        "kind": "first",
        "tags": ["..."],
        "items": [{"label": "..."}],
        "block": {"flag": False},
        "empty": {"level": 1},
        "note": "hello",
    }
    assert result.placeholders == ["kind", "tags", "items.label", "empty.level"]
    # A default the template shows is kept and is not a placeholder; the
    # other optional key stays commented.
    assert "  flag: false\n  #level:" in result.text
    # A block with no default gets one live key instead of ``{}``, so
    # uncommenting another key below it keeps the YAML valid.
    assert "  level: 1  # opentide:placeholder" in result.text
    marked = [line for line in result.text.splitlines() if line.endswith(PLACEHOLDER_MARKER)]
    assert marked == [
        f"kind: first  {PLACEHOLDER_MARKER}",
        f"  - ...  {PLACEHOLDER_MARKER}",
        f"  - label: ...  {PLACEHOLDER_MARKER}",
        f"  level: 1  {PLACEHOLDER_MARKER}",
    ]


class _Lists(BaseModel):
    values: list[str] | None = None


class _ListsOnly(BaseModel):
    holder: _Lists


def test_a_block_with_no_scalar_key_says_to_delete_the_braces() -> None:
    template = "holder:\n  #values:\n    #- \n"
    result = fill_template(template, collect_fields(_ListsOnly), values={}, schema={})
    assert parse_yaml(result.text) == {"holder": {}}
    assert "holder: {}  # delete {} before uncommenting a key" in result.text


def test_index_template_paths() -> None:
    entries = index_template(TOY_TEMPLATE.splitlines())
    paths = [(entry.role, entry.path) for entry in entries]
    assert ("item", ("tags",)) in paths
    assert ("key", ("items", "label")) in paths
    assert ("key", ("block", "flag")) in paths


def test_schema_choices_follow_refs_and_items() -> None:
    schema = {
        "$defs": {"Body": {"properties": {"values": {"items": {"enum": ["x", "y"]}}}}},
        "properties": {"body": {"anyOf": [{"$ref": "#/$defs/Body"}, {"type": "null"}]}},
    }
    assert new_service.schema_choices(schema, ("body", "values")) == ["x", "y"]
    assert new_service.schema_choices(schema, ("body", "missing")) == []

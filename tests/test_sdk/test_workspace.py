"""``opentide.Workspace`` and ``opentide.run_json`` (UC-5.2, #837): the facade bound one to one.

Each method is held to what the command line reports for the same workspace, so
the SDK cannot drift from ``opentide --json``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS

import opentide
from opentide import DeployPlan, LintReport, OpentideError, Validation, Workspace, run_json

EXAMPLE_UUID = "11111111-1111-4111-8111-111111111111"
EXAMPLE = f"name: Example\nmetadata:\n  uuid: {EXAMPLE_UUID}\n  schema: rule::1.1\n"


@pytest.fixture
def ws(tide_corpus_repo: Path) -> Workspace:
    return Workspace.open(tide_corpus_repo)


def test_the_names_are_the_packages() -> None:
    assert opentide.Workspace is Workspace
    assert {"Workspace", "run_json", "OpentideError"} <= set(dir(opentide))


def test_a_workspace_opens_on_disk(ws: Workspace, tide_corpus_repo: Path) -> None:
    assert ws.root.resolve() == tide_corpus_repo.resolve()
    assert repr(ws) == f"Workspace({str(ws.root)!r})"
    info = ws.info()
    assert info["counts"] == {"rules": 10, "threats": 1, "objectives": 1}
    cli = run_json(["--repo", str(tide_corpus_repo), "info"])
    assert cli["ok"] is True
    assert cli["counts"] == info["counts"]


def test_a_workspace_opens_in_memory() -> None:
    ws = Workspace.from_files("/ws", {"objects/rules/example.yaml": EXAMPLE})
    assert ws.root == Path("/ws")
    assert [rule["uuid"] for rule in ws.rules()] == [EXAMPLE_UUID]
    assert ws.objectives() == []
    assert ws.threats() == []


def test_rules_objectives_and_threats_are_the_catalogues_rows(ws: Workspace) -> None:
    rules = ws.rules()
    assert {rule["uuid"] for rule in rules} >= set(CORPUS_RULE_UUIDS.values())
    assert {rule["type"] for rule in rules} == {"rule"}
    catalogue = ws.catalog()
    rows = [row for row in catalogue["objects"] if row.get("type")]
    assert rules == [row for row in rows if row["type"] == "rule"]
    assert ws.objectives() == [row for row in rows if row["type"] == "objective"]
    assert ws.threats() == [row for row in rows if row["type"] == "threat"]
    assert len(ws.threats()) == 1


def test_validate_matches_the_command_line(ws: Workspace, tide_corpus_repo: Path) -> None:
    validation = ws.validate()
    assert isinstance(validation, Validation)
    assert (validation.failed, validation.exit_code) == (False, 0)
    cli = run_json(["--repo", str(tide_corpus_repo), "validate"])
    assert cli["ok"] is True
    assert validation.summary["objects"] == cli["summary"]["objects"]
    assert list(validation.checks) == list(cli["checks"])


def test_validate_takes_the_commands_flags() -> None:
    ws = Workspace.from_files(
        "/ws", {"objects/rules/a.yaml": "name: A\nmetadata:\n  uuid: not-a-uuid\n"}
    )
    validation = ws.validate(check="uuid-format", queries="off")
    assert list(validation.checks) == ["uuid-format"]
    assert validation.failed
    assert validation.exit_code == 1
    assert {issue["code"] for issue in validation.report["issues"]} == {"invalid_uuid"}
    narrowed = ws.validate(types=["threat"], queries="off")
    assert [issue["code"] for issue in narrowed.report["issues"]] == ["scope_no_match"]


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda ws: ws.validate(check="nope"), "unknown check `nope`"),
        (lambda ws: ws.validate(queries="loud"), "`loud` is not error, warn or off"),
        (lambda ws: ws.lint(checks=["nope"]), "unknown check `nope`"),
        (lambda ws: ws.deploy_plan(strategies=["NOW"]), "`NOW` is not PREVIEW or RELEASE"),
    ],
)
def test_an_option_the_command_line_refuses_raises_usage_invalid_choice(
    call: object, message: str
) -> None:
    ws = Workspace.from_files("/ws", {"objects/rules/example.yaml": EXAMPLE})
    with pytest.raises(OpentideError) as raised:
        call(ws)  # ty: ignore[call-non-callable]  # the parametrised lambdas
    assert raised.value.code == "usage_invalid_choice"
    assert message in raised.value.message


def test_lint_reports_as_lint_json(ws: Workspace) -> None:
    report = ws.lint(checks=["filenames"])
    assert isinstance(report, LintReport)
    assert report.checks == ["filenames"]
    assert report.status in {"completed", "issues"}
    assert report.exit_code in {0, 1}


def test_catalog_and_coverage(ws: Workspace, tide_corpus_repo: Path) -> None:
    catalogue = ws.catalog()
    assert {"objects", "edges", "signals"} <= catalogue.keys()
    coverage = ws.coverage("T1059")
    assert coverage["technique"] == "T1059"
    assert CORPUS_RULE_UUIDS["sentinel"] in coverage["rules"]


def test_deploy_plan_is_the_dry_run(ws: Workspace, tide_corpus_repo: Path) -> None:
    plan = ws.deploy_plan(strategies=["PREVIEW"])
    assert isinstance(plan, DeployPlan)
    assert plan.ok
    assert plan.document["dry_run"] is True
    assert plan.summary is not None
    cli = run_json(
        ["--repo", str(tide_corpus_repo), "deploy", "--dry-run", "--all", "--strategy", "PREVIEW"]
    )
    assert plan.summary == cli["summary"]
    selected = ws.deploy_plan(
        strategies=["PREVIEW"], uuids=[CORPUS_RULE_UUIDS["sentinel"]], platform="sentinel"
    )
    assert selected.ok
    assert list(selected.document["plan"]) == ["sentinel"]


def test_run_json_runs_a_command_and_reports_failures_as_data(ws: Workspace) -> None:
    tree = run_json(["commands"])
    assert tree["program"] == "opentide"
    info = ws.run_json(["info"])
    assert info["ok"] is True
    assert info["command"] == "info"
    failed = ws.run_json(["validate", "--check", "nope"])
    assert failed["ok"] is False
    assert failed["failure"]["code"]


def test_a_command_without_a_document_raises() -> None:
    with pytest.raises(OpentideError) as raised:
        run_json(["--version"])
    assert raised.value.code == "no_json_document"
    assert str(raised.value).startswith("no_json_document: ")


def test_a_workspace_whose_configuration_does_not_resolve_raises(tmp_path: Path) -> None:
    configurations = tmp_path / ".opentide" / "configurations"
    configurations.mkdir(parents=True)
    (configurations / "paths.toml").write_text("[paths\n", encoding="utf-8")
    (tmp_path / "objects").mkdir()
    with pytest.raises(OpentideError) as raised:
        Workspace.open(tmp_path)
    assert raised.value.code


def test_the_documents_keep_the_command_lines_key_order(
    ws: Workspace, tide_corpus_repo: Path
) -> None:
    plan = ws.deploy_plan(strategies=["PREVIEW"])
    cli = run_json(
        ["--repo", str(tide_corpus_repo), "deploy", "--dry-run", "--all", "--strategy", "PREVIEW"]
    )
    # The envelope hoists the result's keys to its top level, in its order.
    for key in ("plan", "payloads", "tenants"):
        assert json.dumps(plan.document[key]) == json.dumps(cli[key]), key


def _broken_workspace(parent: Path) -> Path:
    """A workspace on disk, under *parent*, whose one rule has an invalid UUID."""
    repo = parent / "repo"
    rules = repo / "objects" / "rules"
    rules.mkdir(parents=True)
    (rules / "a.yaml").write_text("name: A\nmetadata:\n  uuid: not-a-uuid\n", encoding="utf-8")
    return repo


def test_cwd_is_where_file_paths_are_read_from(tmp_path: Path) -> None:
    repo = _broken_workspace(tmp_path)
    target = "repo/objects/rules/a.yaml"
    from_parent = Workspace.open(repo, cwd=tmp_path)
    found = from_parent.validate(check="uuid-format", files=[target], queries="off")
    assert [issue["code"] for issue in found.report["issues"]] == ["invalid_uuid"]
    assert from_parent.lint(files=[target]).status == "issues"
    # From the workspace's own folder, the same path names no file.
    from_root = Workspace.open(repo)
    missed = from_root.validate(check="uuid-format", files=[target], queries="off")
    assert [issue["code"] for issue in missed.report["issues"]] == ["scope_no_match"]
    assert from_root.lint(files=[target]).unmatched == [target]


def test_validate_lint_and_deploy_plan_narrow_to_files_and_uuids(
    ws: Workspace, tide_corpus_repo: Path
) -> None:
    rule = next((tide_corpus_repo / "Objects" / "Detection Rules").glob("rule-0003-*.yaml"))
    path = str(rule.relative_to(tide_corpus_repo))
    assert ws.validate(files=[path], queries="off").summary["objects"] == 1
    by_uuid = ws.validate(uuids=[CORPUS_RULE_UUIDS["splunk"]], queries="off")
    assert by_uuid.summary["objects"] == 1
    assert ws.lint(files=[path]).summary["files"] == 1
    plan = ws.deploy_plan(strategies=["PREVIEW", "RELEASE"], files=[path], keep_deprecated=True)
    assert plan.ok
    assert list(plan.document["plan"]) == ["splunk"]


def test_the_native_workspace_names_its_root(tide_corpus_repo: Path) -> None:
    from opentide._native.sdk import Workspace as NativeWorkspace

    native = NativeWorkspace.open(str(tide_corpus_repo))
    assert repr(native) == f"Workspace({json.dumps(native.root)})"

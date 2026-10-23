"""CI sinks: annotations, job summaries, SARIF and Code Quality reports.

The sinks switch on under ``GITHUB_ACTIONS``, ``GITLAB_CI`` and ``TF_BUILD``,
which the root conftest removes for every test; the tests here set them. Text
is read with ANSI stripped, since GitHub Actions forces colour.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.explain import diagnostic_codes, load_page
from opentide.cli.ui import ci, reports, summary
from opentide.cli.ui.diagnostics import Diagnostic, Fix, TextEdit
from opentide.cli.ui.mode import OutputMode

SCHEMA = Path(__file__).resolve().parents[1] / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;[^\x1b]*\x1b\\")


def _typo(root: Path | None = None) -> Diagnostic:
    path = "objects/rules/sentinel-kql-rule.yaml"
    return Diagnostic(
        code="vocab_unknown",
        severity="error",
        message="Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry",
        path=path,
        file_path=None if root is None else root / path,
        line=8,
        column=8,
        end_column=14,
        field_path=("metadata", "tlp"),
        help="did you mean 'clear'?",
        fix=Fix(True, (TextEdit(8, 8, 14, "clear"),)),
    )


_WARNING = Diagnostic(
    code="filename_mismatch",
    severity="warning",
    message="File name does not match the name: rule, 50%",
    path="objects/rules/old.yaml",
    line=1,
)
_NOTE = Diagnostic(
    code="metadata_recommended",
    severity="note",
    message="metadata has no author",
    path="objects/rules/a.yaml",
)
_NO_FILE = Diagnostic(code="duplicate_id", severity="error", message="Two objects share an id")


# --------------------------------------------------------------------------
# GitHub Actions
# --------------------------------------------------------------------------


def test_github_escapes_data_and_properties() -> None:
    assert ci.github_escape_data("50%\r\nnext") == "50%25%0D%0Anext"
    assert ci.github_escape_property("a:b,c%\n") == "a%3Ab%2Cc%25%0A"


def test_github_annotation_has_every_position() -> None:
    assert ci.github_annotation(_typo()) == (
        "::error file=objects/rules/sentinel-kql-rule.yaml,line=8,endLine=8,col=8,"
        "endColumn=13,title=vocab_unknown::Value 'clearr' is not a valid 'tlp::1.0' "
        "vocabulary entry%0Ahelp: did you mean 'clear'?"
    )


def test_github_annotation_levels_and_missing_positions() -> None:
    assert ci.github_annotation(_WARNING) == (
        "::warning file=objects/rules/old.yaml,line=1,title=filename_mismatch::"
        "File name does not match the name: rule, 50%25"
    )
    assert ci.github_annotation(_NOTE).startswith(
        "::notice file=objects/rules/a.yaml,title=metadata_recommended::"
    )
    assert ci.github_annotation(_NO_FILE) == "::error title=duplicate_id::Two objects share an id"


def test_github_property_values_are_escaped() -> None:
    odd = Diagnostic(
        code="yaml_parse", severity="error", message="bad", path="objects/a,b:c.yaml", line=2
    )
    assert ci.github_annotation(odd) == (
        "::error file=objects/a%2Cb%3Ac.yaml,line=2,title=yaml_parse::bad"
    )


def test_a_command_without_properties_has_no_space() -> None:
    assert ci.github_command("warning", "careful") == "::warning::careful"


def test_annotation_paths_are_relative_to_the_checkout(tmp_path: Path) -> None:
    workspace = tmp_path / "detections"
    line = ci.github_annotation(_typo(workspace), root=tmp_path)
    assert "file=detections/objects/rules/sentinel-kql-rule.yaml," in line
    outside = ci.github_annotation(_typo(workspace), root=tmp_path / "elsewhere")
    assert "file=objects/rules/sentinel-kql-rule.yaml," in outside


# --------------------------------------------------------------------------
# Azure Pipelines
# --------------------------------------------------------------------------


def test_azure_escapes_data_and_properties() -> None:
    assert ci.azure_escape_data("50%\r\n") == "50%AZP25%0D%0A"
    assert ci.azure_escape_property("a;b]c") == "a%3Bb%5Dc"


def test_azure_annotation() -> None:
    assert ci.azure_annotation(_typo()) == (
        "##vso[task.logissue type=error;sourcepath=objects/rules/sentinel-kql-rule.yaml;"
        "linenumber=8;columnnumber=8;code=vocab_unknown;]Value 'clearr' is not a valid "
        "'tlp::1.0' vocabulary entry%0Ahelp: did you mean 'clear'?"
    )
    assert ci.azure_annotation(_NO_FILE) == (
        "##vso[task.logissue type=error;code=duplicate_id;]Two objects share an id"
    )
    assert ci.azure_annotation(_NOTE) is None


# --------------------------------------------------------------------------
# Which sinks run
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "provider"),
    [
        ({"GITHUB_ACTIONS": "true", "CI": "true"}, "github"),
        ({"GITLAB_CI": "true", "CI": "true"}, "gitlab"),
        ({"TF_BUILD": "True"}, "azure"),
        ({"CI": "true"}, None),
        ({"GITHUB_ACTIONS": "false"}, None),
        ({}, None),
    ],
)
def test_ci_provider(env: dict[str, str], provider: str | None) -> None:
    assert ci.ci_provider(env) == provider


@pytest.mark.parametrize(
    ("mode", "written"),
    [
        (OutputMode.PLAIN, 3),
        (OutputMode.AGENT, 3),
        (OutputMode.HUMAN, 3),
        (OutputMode.JSON, 0),
        (OutputMode.MCP, 0),
    ],
)
def test_annotations_are_off_in_json_and_mcp(mode: OutputMode, written: int) -> None:
    stream = io.StringIO()
    count = ci.emit_annotations(
        [_typo(), _WARNING, _NOTE], mode=mode, env={"GITHUB_ACTIONS": "true"}, stream=stream
    )
    assert count == written
    assert len(stream.getvalue().splitlines()) == written


def test_azure_writes_no_issue_for_a_note_and_gitlab_none_at_all() -> None:
    lines = ci.annotation_lines([_typo(), _NOTE], "azure")
    assert len(lines) == 1
    assert ci.annotation_lines([_typo(), _NOTE], "gitlab") == []
    stream = io.StringIO()
    env = {"GITLAB_CI": "true"}
    assert ci.emit_annotations([_typo()], mode=OutputMode.PLAIN, env=env, stream=stream) == 0
    assert stream.getvalue() == ""


def test_emit_annotations_reads_the_checkout_root(tmp_path: Path) -> None:
    stream = io.StringIO()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(tmp_path)}
    ci.emit_annotations([_typo(tmp_path / "ws")], mode=OutputMode.PLAIN, env=env, stream=stream)
    assert "file=ws/objects/rules/sentinel-kql-rule.yaml," in stream.getvalue()


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"GITHUB_ACTIONS": "true"}, "::warning title=no_rules::Nothing to deploy\n"),
        (
            {"TF_BUILD": "True"},
            "##vso[task.logissue type=warning;code=no_rules;]Nothing to deploy\n",
        ),
        ({"GITLAB_CI": "true"}, ""),
        ({}, ""),
    ],
)
def test_emit_warning(env: dict[str, str], expected: str) -> None:
    stream = io.StringIO()
    written = ci.emit_warning(
        "Nothing to deploy", title="no_rules", mode=OutputMode.PLAIN, env=env, stream=stream
    )
    assert written is bool(expected)
    assert stream.getvalue() == expected


def test_emit_warning_is_off_in_json_mode() -> None:
    stream = io.StringIO()
    env = {"GITHUB_ACTIONS": "true"}
    assert ci.emit_warning("x", mode=OutputMode.JSON, env=env, stream=stream) is False
    assert stream.getvalue() == ""


# --------------------------------------------------------------------------
# Job summaries
# --------------------------------------------------------------------------


def test_github_summary_is_appended(tmp_path: Path) -> None:
    target = tmp_path / "step_summary"
    target.write_text("earlier step\n", encoding="utf-8")
    env = {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(target)}
    written = ci.append_summary("### one", command="validate", mode=OutputMode.PLAIN, env=env)
    ci.append_summary("### two\n\n\n", command="lint", mode=OutputMode.PLAIN, env=env)
    assert written == target
    assert target.read_text(encoding="utf-8") == "earlier step\n### one\n\n### two\n\n"


def test_github_summary_needs_its_file() -> None:
    env = {"GITHUB_ACTIONS": "true"}
    assert ci.append_summary("x", command="validate", mode=OutputMode.PLAIN, env=env) is None


def test_gitlab_summary_lands_in_the_reports_folder(tmp_path: Path) -> None:
    env = {"GITLAB_CI": "true", "CI_PROJECT_DIR": str(tmp_path)}
    written = ci.append_summary("### x", command="validate", mode=OutputMode.PLAIN, env=env)
    assert written == tmp_path / "opentide-reports" / "summary.md"
    assert written.read_text(encoding="utf-8") == "### x\n\n"


def test_gitlab_summary_without_a_project_dir_uses_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    env = {"GITLAB_CI": "true"}
    written = ci.append_summary("### x", command="lint", mode=OutputMode.PLAIN, env=env)
    assert written == tmp_path / ci.GITLAB_SUMMARY


def test_azure_summary_is_a_file_per_run_and_a_logging_command(tmp_path: Path) -> None:
    env = {"TF_BUILD": "True", "AGENT_TEMPDIRECTORY": str(tmp_path)}
    stream = io.StringIO()
    first = ci.append_summary(
        "### a", command="validate query", mode=OutputMode.PLAIN, env=env, stream=stream
    )
    second = ci.append_summary(
        "### b", command="validate query", mode=OutputMode.PLAIN, env=env, stream=stream
    )
    assert first == tmp_path / "opentide-validate-query.md"
    assert second == tmp_path / "opentide-validate-query-2.md"
    assert stream.getvalue().splitlines() == [
        f"##vso[task.uploadsummary]{first}",
        f"##vso[task.uploadsummary]{second}",
    ]


def test_summary_is_off_in_json_mode_and_outside_ci(tmp_path: Path) -> None:
    target = tmp_path / "summary"
    env = {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(target)}
    assert ci.append_summary("x", command="validate", mode=OutputMode.JSON, env=env) is None
    assert ci.append_summary("x", command="validate", mode=OutputMode.PLAIN, env={}) is None
    assert not target.exists()


def test_an_unwritable_summary_never_fails_the_command(tmp_path: Path) -> None:
    env = {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(tmp_path)}
    assert ci.append_summary("x", command="validate", mode=OutputMode.PLAIN, env=env) is None


def test_findings_summary_is_a_table_linking_each_code() -> None:
    markdown = summary.diagnostics_summary(
        "opentide validate",
        "1 error in 1 file · 3 objects checked · 0.9s",
        [_typo(), _NO_FILE],
        kind="failed",
    )
    assert markdown == (
        "### ✗ opentide validate\n"
        "\n"
        "1 error in 1 file · 3 objects checked · 0.9s\n"
        "\n"
        "| Severity | Code | Location | Message |\n"
        "|---|---|---|---|\n"
        "| error | [`vocab_unknown`](https://opentide.org/docs/cli/diagnostics#vocab_unknown)"
        " | `objects/rules/sentinel-kql-rule.yaml:8:8` | Value 'clearr' is not a valid"
        " 'tlp::1.0' vocabulary entry — help: did you mean 'clear'? |\n"
        "| error | [`duplicate_id`](https://opentide.org/docs/cli/diagnostics#duplicate_id)"
        " |   | Two objects share an id |\n"
    )


def test_findings_summary_without_findings_is_the_outcome() -> None:
    markdown = summary.diagnostics_summary("opentide lint", "3 files clean", [], kind="ok")
    assert markdown == "### ✓ opentide lint\n\n3 files clean\n"


def test_findings_summary_stops_at_max_rows() -> None:
    many = [_WARNING] * (summary.MAX_ROWS + 5)
    markdown = summary.diagnostics_summary("opentide lint", "x", many, kind="warning")
    assert markdown.count("| warning |") == summary.MAX_ROWS
    assert markdown.endswith("… and 5 more in the job log.\n")


def test_findings_summary_takes_paths_from_the_caller() -> None:
    item = _typo()
    markdown = summary.diagnostics_summary(
        "opentide validate", "x", [item], kind="failed", paths={id(item): "ws/a.yaml"}
    )
    assert "`ws/a.yaml:8:8`" in markdown


def test_cells_and_code_spans_are_table_safe() -> None:
    assert summary.cell("a | b\nc") == "a \\| b<br>c"
    assert summary.cell("") == " "
    assert summary.code("x`y") == "``x`y``"
    assert summary.code("`x") == "`` `x ``"
    assert summary.heading("other", "opentide") == "### opentide"


def _deploy(**fields: Any) -> dict[str, Any]:
    return {
        "status": "completed",
        "message": "Deployment completed",
        "dry_run": True,
        "strategies": ["PREVIEW"],
        "plan": {"sentinel": ["u1", "u2"]},
        "tenants": {"sentinel": {"prod": ["u1", "u2"], "lab": ["u1"]}},
        "deployed": ["sentinel"],
        "payloads": {
            "sentinel": [
                {"uuid": "u1", "name": "Rule one"},
                {"uuid": "u2", "name": "Rule two", "status": "failed", "error": "bad KQL"},
            ]
        },
        **fields,
    }


def test_deploy_summary_shows_the_plan_per_tenant() -> None:
    markdown = summary.deploy_summary(_deploy())
    assert markdown.startswith("### ✓ opentide deploy --dry-run\n\nDeployment completed\n")
    assert "Strategies: `PREVIEW`" in markdown
    assert "| `sentinel` | prod | 2 |" in markdown
    assert "| `sentinel` | lab | 1 |" in markdown
    assert "<details><summary>sentinel: 2 rules</summary>" in markdown
    assert "- Rule one (`u1`)" in markdown
    assert "- Rule two (`u2`) — would fail: bad KQL" in markdown


def test_deploy_summary_of_a_real_run_shows_what_was_deployed() -> None:
    result = _deploy(
        dry_run=False,
        tenants=None,
        payloads=None,
        plan={"sentinel": ["u1"], "splunk": ["u3"]},
        deployed=["sentinel"],
        status="failed",
    )
    markdown = summary.deploy_summary(result)
    assert markdown.startswith("### ✗ opentide deploy\n")
    assert "| Platform | Result | Rules |" in markdown
    assert "| `sentinel` | deployed | 1 |" in markdown
    assert "| `splunk` | not deployed | 1 |" in markdown
    assert "<details><summary>sentinel: 1 rule</summary>" in markdown
    assert "- `u1`" in markdown


def test_deploy_summary_dry_run_without_tenants_and_long_plans() -> None:
    uuids = [f"u{index}" for index in range(summary.MAX_ROWS + 2)]
    markdown = summary.deploy_summary(_deploy(tenants={}, plan={"elastic": uuids}, payloads={}))
    assert f"| `elastic` | none | {len(uuids)} |" in markdown
    assert "- … and 2 more" in markdown


def test_deploy_summary_of_a_skip_has_no_table() -> None:
    markdown = summary.deploy_summary(
        {"status": "skipped", "message": "No rule to deploy", "dry_run": False, "plan": {}}
    )
    assert markdown == "### – opentide deploy\n\nNo rule to deploy\n"


def test_query_summary_counts_queries_per_tenant() -> None:
    markdown = summary.query_summary(
        {
            "platform": "sentinel",
            "status": "passed",
            "message": "Query validation passed for sentinel",
            "strategies": ["PREVIEW", "RELEASE"],
            "queries_per_tenant": {"prod": 12, "lab": 3},
            "warnings": ["Query validation reported warnings for sentinel"],
        }
    )
    assert markdown.startswith("### ! opentide validate query --platform sentinel\n")
    assert "| Tenant | Queries |" in markdown
    assert "| prod | 12 |" in markdown


# --------------------------------------------------------------------------
# SARIF and Code Quality
# --------------------------------------------------------------------------


def _sarif(diagnostics: list[Diagnostic]) -> dict[str, Any]:
    return reports.sarif_report(diagnostics, command="validate", version="1.2.3")


def test_sarif_matches_the_2_1_0_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    document = _sarif([_typo(), _WARNING, _NOTE, _NO_FILE])
    jsonschema.Draft4Validator(schema).validate(document)
    # Round-trips through JSON, as the file is written.
    jsonschema.Draft4Validator(schema).validate(json.loads(json.dumps(document)))


def test_sarif_rules_come_from_the_explain_pages() -> None:
    run = _sarif([_typo()])["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == diagnostic_codes()
    rule = next(rule for rule in rules if rule["id"] == "vocab_unknown")
    page = load_page("vocab_unknown")
    assert page is not None
    assert rule["shortDescription"] == {"text": page.summary}
    assert rule["help"]["markdown"] == page.markdown
    assert rule["helpUri"] == "https://opentide.org/docs/cli/diagnostics#vocab_unknown"
    assert rule["defaultConfiguration"] == {"level": "error"}
    assert rule["name"] == "VocabUnknown"
    assert run["automationDetails"] == {"id": "opentide/validate/"}
    assert run["tool"]["driver"]["version"] == "1.2.3"


def test_sarif_result_carries_position_fix_and_fingerprint() -> None:
    (result,) = _sarif([_typo(), _NO_FILE])["runs"][0]["results"]
    rules = _sarif([])["runs"][0]["tool"]["driver"]["rules"]
    assert rules[result["ruleIndex"]]["id"] == "vocab_unknown"
    assert result["level"] == "error"
    assert result["message"]["text"].endswith("\nhelp: did you mean 'clear'?")
    location = result["locations"][0]["physicalLocation"]
    assert location == {
        "artifactLocation": {"uri": "objects/rules/sentinel-kql-rule.yaml"},
        "region": {"startLine": 8, "startColumn": 8, "endColumn": 14},
    }
    (fix,) = result["fixes"]
    assert fix["description"]["text"] == "Replace with 'clear' (safe to apply without review)"
    (replacement,) = fix["artifactChanges"][0]["replacements"]
    assert replacement == {
        "deletedRegion": {"startLine": 8, "startColumn": 8, "endColumn": 14},
        "insertedContent": {"text": "clear"},
    }
    assert len(result["partialFingerprints"]["opentide/v1"]) == 64


def test_sarif_lists_a_code_that_has_no_page() -> None:
    odd = Diagnostic(code="brand_new", severity="warning", message="m", path="a.yaml")
    run = _sarif([odd])["runs"][0]
    rule = run["tool"]["driver"]["rules"][-1]
    assert rule == {
        "id": "brand_new",
        "name": "BrandNew",
        "helpUri": "https://opentide.org/docs/cli/diagnostics#brand_new",
    }
    (result,) = run["results"]
    assert result["ruleIndex"] == len(run["tool"]["driver"]["rules"]) - 1
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_sarif_region_without_columns() -> None:
    (result,) = _sarif([_WARNING])["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 1}
    assert "fixes" not in result


def test_codequality_issues() -> None:
    issues = reports.codequality_report([_typo(), _WARNING, _NOTE, _NO_FILE])
    assert [issue["severity"] for issue in issues] == ["major", "minor", "info"]
    first = issues[0]
    assert first["type"] == "issue"
    assert first["check_name"] == "vocab_unknown"
    assert first["description"] == (
        "Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry (help: did you mean 'clear'?)"
    )
    assert first["categories"] == ["Bug Risk"]
    assert first["location"] == {
        "path": "objects/rules/sentinel-kql-rule.yaml",
        "lines": {"begin": 8},
    }
    # A finding with no line still has the begin line GitLab requires.
    assert issues[2]["location"]["lines"] == {"begin": 1}


def test_fingerprints_are_stable_and_unique() -> None:
    twice = [_WARNING, _WARNING]
    first = [issue["fingerprint"] for issue in reports.codequality_report(twice)]
    again = [issue["fingerprint"] for issue in reports.codequality_report(twice)]
    assert first == again
    assert len(set(first)) == 2


def test_build_report_refuses_text() -> None:
    with pytest.raises(ValueError, match="not a report format"):
        reports.build_report(reports.ReportFormat.text, [], command="lint", version="0")
    assert (
        reports.build_report(reports.ReportFormat.codequality, [], command="lint", version="0")
        == []
    )


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def validate_result(repo: Path) -> Iterator[dict[str, Any]]:
    result: dict[str, Any] = {
        "report": {"ok": False, "issues": []},
        "status": "failed",
        "message": "Validation failed",
        "_exit_code": 1,
        "_failure_code": "issues_found",
        "_summary": {"objects": 3, "errors": 1, "warnings": 0, "files": 1},
        "_diagnostics": [_typo(repo)],
    }
    with patch("opentide.cli.commands.validate.run_validate", return_value=result):
        yield result


def _invoke(repo: Path, *argv: str) -> Result:
    return runner.invoke(app, ["--repo", str(repo), *argv])


def _text(result: Result) -> str:
    return _ANSI.sub("", result.stdout)


@pytest.mark.usefixtures("validate_result")
def test_validate_annotates_and_summarises_under_github_actions(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step_summary = repo / "step_summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    result = _invoke(repo, "validate")
    assert result.exit_code == 1, result.output
    lines = _text(result).splitlines()
    assert ci.github_annotation(_typo(repo)) in lines
    written = step_summary.read_text(encoding="utf-8")
    assert written.startswith("### ✗ opentide validate\n\n1 error in 1 file · 3 objects checked")
    assert "`objects/rules/sentinel-kql-rule.yaml:8:8`" in written


@pytest.mark.usefixtures("validate_result")
def test_validate_json_writes_no_annotation(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    step_summary = repo / "step_summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    result = _invoke(repo, "--json", "validate")
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["failure"]["code"] == "issues_found"
    assert not step_summary.exists()


@pytest.mark.usefixtures("validate_result")
def test_validate_report_to_stdout_is_the_whole_output(repo: Path) -> None:
    result = _invoke(repo, "validate", "--format", "sarif")
    assert result.exit_code == 1, result.output
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "vocab_unknown"


@pytest.mark.usefixtures("validate_result")
def test_validate_report_to_a_file_keeps_the_text(repo: Path) -> None:
    output = repo / "out" / "validate.codequality.json"
    result = _invoke(repo, "validate", "--format", "codequality", "--output", str(output))
    assert result.exit_code == 1, result.output
    assert "error[vocab_unknown]" in _text(result)
    (issue,) = json.loads(output.read_text(encoding="utf-8"))
    assert issue["check_name"] == "vocab_unknown"


@pytest.mark.usefixtures("validate_result")
def test_validate_json_with_a_report_file(repo: Path) -> None:
    output = repo / "validate.sarif"
    result = _invoke(repo, "--json", "validate", "--format", "sarif", "--output", str(output))
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["status"] == "failed"
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_a_report_on_json_stdout_is_a_usage_error(repo: Path, command: str) -> None:
    result = _invoke(repo, "--json", command, "--format", "sarif")
    assert result.exit_code == 2, result.output
    failure = json.loads(result.stdout)["failure"]
    assert failure["code"] == "usage_invalid_value"
    assert failure["argument"] == "--output"


def _lint_result(repo: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "path": str(repo),
        "findings": findings,
        "count": len(findings),
        "status": "issues" if findings else "passed",
        "message": "Catalogue lint found issues" if findings else "Catalogue lint passed",
        "_exit_code": 0,
        "_outcome": "1 finding in 1 file" if findings else "1 file clean",
    }


_LINT_FINDING = {
    "check": "filenames",
    "code": "filename_mismatch",
    "severity": "warning",
    "path": "objects/rules/old.yaml",
    "message": "File name does not match the object name",
    "expected": "new.yaml",
}


def test_lint_annotates_on_azure_and_writes_a_report(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("AGENT_TEMPDIRECTORY", str(repo / "agent"))
    output = repo / "lint.codequality.json"
    with patch(
        "opentide.cli.commands.lint.run_lint", return_value=_lint_result(repo, [_LINT_FINDING])
    ):
        result = _invoke(repo, "lint", "--format", "codequality", "--output", str(output))
    assert result.exit_code == 0, result.output
    text = _text(result)
    assert (
        "##vso[task.logissue type=warning;sourcepath=objects/rules/old.yaml;"
        "code=filename_mismatch;]File name does not match the object name%0A"
        "help: rename it to new.yaml"
    ) in text.splitlines()
    summary_file = repo / "agent" / "opentide-lint.md"
    assert f"##vso[task.uploadsummary]{summary_file}" in text
    assert summary_file.read_text(encoding="utf-8").startswith("### ! opentide lint\n")
    assert json.loads(output.read_text(encoding="utf-8"))[0]["severity"] == "minor"


def test_lint_codequality_on_stdout(repo: Path) -> None:
    with patch("opentide.cli.commands.lint.run_lint", return_value=_lint_result(repo, [])):
        result = _invoke(repo, "lint", "--format", "codequality")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == []


def test_lint_outside_ci_writes_no_sink(repo: Path) -> None:
    with patch(
        "opentide.cli.commands.lint.run_lint", return_value=_lint_result(repo, [_LINT_FINDING])
    ):
        result = _invoke(repo, "lint")
    assert result.exit_code == 0, result.output
    assert "::" not in _text(result)
    assert "##vso" not in _text(result)


def test_deploy_summarises_the_plan_on_gitlab(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_PROJECT_DIR", str(repo))
    with patch("opentide.cli.commands.deploy.run_deploy", return_value=_deploy()):
        result = _invoke(repo, "deploy", "--dry-run")
    assert result.exit_code == 0, result.output
    written = (repo / ci.GITLAB_SUMMARY).read_text(encoding="utf-8")
    assert written.startswith("### ✓ opentide deploy --dry-run\n")
    assert "| `sentinel` | prod | 2 |" in written


def test_validate_query_summarises_results(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    step_summary = repo / "step_summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    outcome = {
        "platform": "sentinel",
        "status": "passed",
        "message": "Query validation passed for sentinel",
        "queries_per_tenant": {"prod": 4},
    }
    with patch("opentide.cli.commands.validate.validate_query_platform", return_value=outcome):
        result = _invoke(repo, "validate", "query", "--platform", "sentinel", "--live")
    assert result.exit_code == 0, result.output
    assert "| prod | 4 |" in step_summary.read_text(encoding="utf-8")

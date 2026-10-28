"""CLI E2E: the analysis engine behind ``validate query``, ``validate --deep``, ``lsp check``.

The engine ships with ``pip install opentide``, compiled into the package
(``opentide._native``). These tests run it for real on the tutorial workspace: no stub
stands between the CLI and the Rust engine, except where a test hides the
engine to prove that a missing one fails rather than skips.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import TUTORIAL, hidden_modules, write_tutorial_objects

pytestmark = pytest.mark.cli_e2e

RULE = Path("objects/rules/sentinel-kql-rule.yaml")
OBJECTIVE_UUID = "00000000-0000-4000-8002-000000000001"
GIT_AUTHOR = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "user.name",
    "GIT_CONFIG_VALUE_0": "Tutorial Author",
}


@pytest.fixture
def tutorial(invoke_cli, tmp_path: Path) -> Path:
    fresh = tmp_path / "tutorial-detections"
    setup = invoke_cli(
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--platform",
        "splunk",
        "--path",
        str(fresh),
        repo=tmp_path,
    )
    assert_json_ok(setup)
    write_tutorial_objects(fresh, markdown=TUTORIAL.read_text(encoding="utf-8"))
    return fresh


@pytest.fixture
def no_engine() -> Iterator[None]:
    """The engine does not import, as in a damaged install."""
    from opentide.analysis import engine

    engine.cache_clear()
    with hidden_modules("opentide._native", purge=("opentide._native",)):
        yield
    engine.cache_clear()


def _set_query(path: Path, query: str) -> None:
    """Replace the first block-scalar ``query`` in *path* with *query*."""
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"^(?P<indent> *)query: \|[^\n]*\n(?P<body>(?:(?P=indent)  .*\n|\n)+)", text, re.MULTILINE
    )
    assert match is not None, text
    inner = match["indent"] + "  "
    body = "".join(f"{inner}{line}\n" for line in query.splitlines())
    path.write_text(text[: match.start("body")] + body + text[match.end("body") :], "utf-8")


def _new_rule(invoke_cli, repo: Path, platform: str, query: str) -> Path:
    result = invoke_cli(
        "new",
        "rule",
        "--name",
        f"Engine {platform}",
        "--platform",
        platform,
        "--objective",
        OBJECTIVE_UUID,
        repo=repo,
        extra_env=GIT_AUTHOR,
    )
    path = repo / assert_json_ok(result)["path"]
    _set_query(path, query)
    return path


# --------------------------------------------------------------------------
# validate query (offline)
# --------------------------------------------------------------------------


def test_a_bare_validate_query_checks_the_tutorial_rule_offline(invoke_cli, tutorial: Path) -> None:
    payload = assert_json_ok(invoke_cli("validate", "query", repo=tutorial))
    assert payload["mode"] == "offline"
    assert payload["status"] == "passed"
    assert payload["queries_validated"] == 1
    (query,) = payload["queries"]
    assert query["path"] == RULE.as_posix()
    assert (query["platform"], query["language"]) == ("sentinel", "kql")
    assert query["field_path"] == ["configurations", "sentinel", "query"]
    assert payload["diagnostics"] == []
    assert payload["summary"]["queries"] == 1
    assert set(payload["engine"]) == {"engine"}


def test_a_broken_query_fails_with_a_frame_at_its_place(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, "SecurityEvent\n| wher EventID == 4688")
    result = invoke_cli("validate", "query", repo=tutorial)
    assert result.exit_code == 1, result.output
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "issues_found"
    (finding,) = [item for item in payload["diagnostics"] if item["severity"] == "error"]
    assert finding["code"] == "kql_unknown_operator"
    assert finding["path"] == RULE.as_posix()
    lines = (tutorial / RULE).read_text(encoding="utf-8").splitlines()
    assert lines[finding["line"] - 1][finding["column"] - 1 :].startswith("wher")
    assert finding["help"] == "did you mean 'where'?"
    assert finding["explain"] == "opentide explain kql_unknown_operator"
    assert payload["next_actions"][0]["command"] == "opentide --json explain kql_unknown_operator"

    human = invoke_cli("validate", "query", repo=tutorial, json_output=False)
    assert human.exit_code == 1
    assert "error[kql_unknown_operator]: unknown tabular operator 'wher'" in human.output
    assert "✗ 1 error in 1 file · 1 query checked" in human.output


def test_a_slow_query_shape_warns_and_fails_only_under_strict(invoke_cli, tutorial: Path) -> None:
    _set_query(
        tutorial / RULE, "SecurityEvent\n| summarize count() by Account\n| where Account != ''"
    )
    human = invoke_cli("validate", "query", repo=tutorial, json_output=False)
    assert human.exit_code == 0, human.output
    assert "warning[kql_where_not_first]" in human.output
    assert "! 1 warning in 1 file · 1 query checked" in human.output
    strict = invoke_cli("validate", "query", "--strict", repo=tutorial)
    assert strict.exit_code == 1
    assert parse_cli_json(strict)["failure"]["code"] == "issues_found"


def test_platform_and_scope_flags_narrow_the_offline_check(invoke_cli, tutorial: Path) -> None:
    splunk = _new_rule(invoke_cli, tutorial, "splunk", "index=main | statz count")
    everything = parse_cli_json(invoke_cli("validate", "query", repo=tutorial))
    assert everything["queries_validated"] == 2
    assert everything["platforms"] == ["sentinel", "splunk"]
    assert {item["code"] for item in everything["diagnostics"]} >= {"spl_unknown_command"}

    sentinel = assert_json_ok(
        invoke_cli("validate", "query", "--platform", "sentinel", repo=tutorial)
    )
    assert sentinel["queries_validated"] == 1

    selected = parse_cli_json(invoke_cli("validate", "query", "--file", splunk.name, repo=tutorial))
    assert selected["scope"] == "selected"
    assert [item["path"] for item in selected["queries"]] == [
        splunk.relative_to(tutorial).as_posix()
    ]
    unmatched = invoke_cli("validate", "query", "--file", "nope.yaml", repo=tutorial)
    assert unmatched.exit_code == 1
    assert parse_cli_json(unmatched)["unmatched"] == ["nope.yaml"]


@pytest.mark.parametrize(
    ("argv", "code", "argument"),
    [
        (("--platform", "sentinel_one"), "usage_missing_option", "--live"),
        (("--live",), "usage_missing_option", "--platform"),
        (("--strategy", "PREVIEW"), "usage_error", "--strategy"),
        (("--wide",), "usage_error", "--wide"),
        (("--offline", "--live", "--platform", "sentinel"), "usage_error", "--offline"),
        (("--strict", "--live", "--platform", "sentinel"), "usage_error", "--strict"),
    ],
)
def test_offline_and_live_flags_that_do_not_combine_are_usage_errors(
    invoke_cli, tutorial: Path, argv: tuple[str, ...], code: str, argument: str
) -> None:
    result = invoke_cli("validate", "query", *argv, repo=tutorial)
    assert result.exit_code == 2, result.output
    failure = parse_cli_json(result)["failure"]
    assert (failure["code"], failure["argument"]) == (code, argument)


def test_crowdstrike_is_never_validated(invoke_cli, tutorial: Path) -> None:
    result = invoke_cli("validate", "query", "--platform", "crowdstrike", repo=tutorial)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["supported"] is False
    assert payload["valid"] is None


def test_a_missing_engine_fails_the_offline_check(
    invoke_cli, tutorial: Path, no_engine: None
) -> None:
    result = invoke_cli("validate", "query", repo=tutorial)
    assert result.exit_code == 1, result.output
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "engine_unavailable"
    assert payload["advice"] == "reinstall opentide: pip install --force-reinstall opentide"


# --------------------------------------------------------------------------
# validate --deep
# --------------------------------------------------------------------------


def test_validate_deep_adds_the_queries_check(invoke_cli, tutorial: Path) -> None:
    clean = assert_json_ok(invoke_cli("validate", "--deep", repo=tutorial))
    assert list(clean["checks"]) == [
        "id-uniqueness",
        "uuid-format",
        "schema",
        "configuration",
        "queries",
    ]
    assert clean["summary"]["queries"] == 1
    assert "queries" not in assert_json_ok(invoke_cli("validate", repo=tutorial))["summary"]

    _set_query(tutorial / RULE, "SecurityEvent\n| wher EventID == 4688")
    assert invoke_cli("validate", repo=tutorial).exit_code == 0, "deep is opt-in"
    deep = invoke_cli("validate", "--deep", repo=tutorial)
    assert deep.exit_code == 1
    payload = parse_cli_json(deep)
    assert payload["checks"]["queries"]["status"] == "failed"
    (issue,) = payload["report"]["issues"]
    assert issue["code"] == "kql_unknown_operator"
    assert issue["object_type"] == "rule"
    assert issue["context"]["language"] == "kql"
    assert issue["context"]["position"]["line"] == issue["line"]
    assert issue["field_path"] == ["configurations", "sentinel", "query"]

    alone = invoke_cli("validate", "--check", "queries", repo=tutorial)
    assert alone.exit_code == 1
    assert list(parse_cli_json(alone)["checks"]) == ["queries"]
    human = invoke_cli("validate", "--deep", repo=tutorial, json_output=False)
    assert re.search(r"✗ 1 error in 1 file · 3 objects checked · 1 query · [\d.]+s", human.output)


def test_validate_deep_and_check_are_one_or_the_other(invoke_cli, tutorial: Path) -> None:
    result = invoke_cli("validate", "--deep", "--check", "schema", repo=tutorial)
    assert result.exit_code == 2
    assert parse_cli_json(result)["failure"]["argument"] == "--deep"


def test_validate_deep_reports_a_missing_engine_as_an_error(
    invoke_cli, tutorial: Path, no_engine: None
) -> None:
    result = invoke_cli("validate", "--deep", repo=tutorial)
    assert result.exit_code == 1, result.output
    (issue,) = parse_cli_json(result)["report"]["issues"]
    assert issue["code"] == "engine_unavailable"
    assert "--force-reinstall" in issue["help"]


# --------------------------------------------------------------------------
# lsp check
# --------------------------------------------------------------------------


def test_lsp_check_uses_the_workspace_catalog_once_generated(invoke_cli, tutorial: Path) -> None:
    before = parse_cli_json(invoke_cli("lsp", "check", repo=tutorial))
    assert before["files_checked"] == 3
    assert before["catalog"]["source"] == "bundled"

    assert_json_ok(invoke_cli("generate", "schemas", repo=tutorial))
    catalogs = tutorial / ".opentide" / "lsp" / "catalogs" / "generated"
    assert (catalogs / "fields.json").is_file() and (catalogs / "deprecations.json").is_file()
    after = parse_cli_json(invoke_cli("lsp", "check", repo=tutorial))
    assert after["catalog"]["source"] == "workspace"
    assert after["catalog"]["problem"] is None

    (catalogs / "fields.json").write_text("{", encoding="utf-8")
    broken = parse_cli_json(invoke_cli("lsp", "check", repo=tutorial))
    assert broken["catalog"]["source"] == "bundled"
    assert broken["catalog"]["problem"].startswith("fields.json")
    assert any("run opentide generate schemas" in line for line in broken["warnings"])


def test_lsp_check_reads_a_query_file_by_its_extension(invoke_cli, tutorial: Path) -> None:
    query = tutorial / "hunting" / "lsass.kql"
    query.parent.mkdir()
    query.write_text("SecurityEvent\n| summarize count() by Account\n| where Account != ''\n")
    payload = assert_json_ok(invoke_cli("lsp", "check", str(query), repo=tutorial))
    (finding,) = payload["diagnostics"]
    assert (finding["code"], finding["severity"]) == ("kql_where_not_first", "warning")
    assert (finding["path"], finding["line"], finding["column"]) == ("hunting/lsass.kql", 3, 3)
    folder = assert_json_ok(invoke_cli("lsp", "check", str(query.parent), repo=tutorial))
    assert folder["files_checked"] == 1
    strict = invoke_cli("lsp", "check", "--strict", str(query), repo=tutorial)
    assert strict.exit_code == 1

    human = invoke_cli("lsp", "check", str(query), repo=tutorial, json_output=False)
    assert "! 1 warning in 1 file · 1 file checked" in human.output


def test_lsp_check_refuses_what_it_cannot_read(invoke_cli, tutorial: Path) -> None:
    notes = tutorial / "notes.txt"
    notes.write_text("SecurityEvent | take 1\n", encoding="utf-8")
    unknown = invoke_cli("lsp", "check", str(notes), repo=tutorial)
    assert unknown.exit_code == 2
    assert parse_cli_json(unknown)["failure"]["argument"] == "--language"
    assert_json_ok(invoke_cli("lsp", "check", "--language", "kql", str(notes), repo=tutorial))

    missing = invoke_cli("lsp", "check", str(tutorial / "nope.kql"), repo=tutorial)
    assert missing.exit_code == 2
    assert parse_cli_json(missing)["unmatched"] == [str(tutorial / "nope.kql")]
    language = invoke_cli("lsp", "check", "--language", "sql", str(notes), repo=tutorial)
    assert language.exit_code == 2


def test_lsp_check_fails_on_a_missing_engine(invoke_cli, tutorial: Path, no_engine: None) -> None:
    result = invoke_cli("lsp", "check", repo=tutorial)
    assert result.exit_code == 1
    assert parse_cli_json(result)["failure"]["code"] == "engine_unavailable"


# --------------------------------------------------------------------------
# Review findings: positions, scope and unreadable files
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", ['"ab"', '"é"', '"🔥🔥"'])
def test_positions_after_non_ascii_query_text_are_exact(
    invoke_cli, tutorial: Path, text: str
) -> None:
    """An emoji or accent before a finding must not move it (the injection map is per byte)."""
    _set_query(tutorial / RULE, f"SecurityEvent\n| where Account == {text} | wher EventID == 1")
    payload = parse_cli_json(invoke_cli("validate", "query", repo=tutorial))
    (finding,) = [item for item in payload["diagnostics"] if item["severity"] == "error"]
    line = (tutorial / RULE).read_text(encoding="utf-8").splitlines()[finding["line"] - 1]
    assert line[finding["column"] - 1 :].startswith("wher"), (finding, line)
    assert finding["end_column"] <= len(line) + 1


def test_a_query_starts_at_its_text_not_its_indentation(invoke_cli, tutorial: Path) -> None:
    payload = assert_json_ok(invoke_cli("validate", "query", repo=tutorial))
    (query,) = payload["queries"]
    line = (tutorial / RULE).read_text(encoding="utf-8").splitlines()[query["line"] - 1]
    assert line[query["column"] - 1 :].startswith("SecurityEvent"), (query, line)


def test_check_queries_alone_fails_a_target_that_matches_nothing(
    invoke_cli, tutorial: Path
) -> None:
    for flags in (("--file", "nope.yaml"), ("--uuid", "00000000-0000-4000-8003-00000000dead")):
        result = invoke_cli("validate", "--check", "queries", *flags, repo=tutorial)
        assert result.exit_code == 1, (flags, result.output)
        codes = [issue["code"] for issue in parse_cli_json(result)["report"]["issues"]]
        assert codes == ["scope_no_match"], flags


def test_check_queries_alone_reports_a_file_it_cannot_parse(invoke_cli, tutorial: Path) -> None:
    (tutorial / RULE).write_text("name: [unclosed\n", encoding="utf-8")
    result = invoke_cli("validate", "--check", "queries", repo=tutorial)
    assert result.exit_code == 1, result.output
    assert "yaml_parse" in {issue["code"] for issue in parse_cli_json(result)["report"]["issues"]}


@pytest.mark.parametrize("encoding", ["latin-1", "yaml"])
def test_offline_query_check_fails_a_rule_it_cannot_read(
    invoke_cli, tutorial: Path, encoding: str
) -> None:
    rule = tutorial / RULE
    if encoding == "latin-1":
        rule.write_bytes(
            rule.read_text(encoding="utf-8").replace("Rule", "Règle").encode("latin-1")
        )
    else:
        rule.write_text("name: [unclosed\n", encoding="utf-8")
    for argv in (("validate", "query"), ("validate", "query", "--file", RULE.name)):
        result = invoke_cli(*argv, repo=tutorial)
        assert result.exit_code == 1, (argv, result.output)
        (finding,) = parse_cli_json(result)["diagnostics"]
        assert (finding["code"], finding["path"]) == ("yaml_parse", RULE.as_posix())


def test_next_actions_keep_the_scope_and_strictness(invoke_cli, tutorial: Path) -> None:
    _set_query(
        tutorial / RULE, "SecurityEvent\n| summarize count() by Account\n| where Account != ''"
    )
    result = invoke_cli("validate", "query", "--strict", "--file", RULE.name, repo=tutorial)
    assert result.exit_code == 1
    again = parse_cli_json(result)["next_actions"][-1]["command"]
    assert again == f"opentide --json validate query --file {RULE.name} --strict"


def test_lsp_check_of_a_folder_leaves_non_object_yaml_alone(invoke_cli, tutorial: Path) -> None:
    workflow = tutorial / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("on: push\njobs: {}\n", encoding="utf-8")
    (tutorial / "docs").mkdir(exist_ok=True)
    (tutorial / "docs" / "mkdocs.yml").write_text("site_name: x\n", encoding="utf-8")
    payload = parse_cli_json(invoke_cli("lsp", "check", str(tutorial), repo=tutorial))
    assert payload["files_checked"] == 3
    assert not any(item["path"].startswith((".github", "docs")) for item in payload["diagnostics"])
    named = parse_cli_json(invoke_cli("lsp", "check", str(workflow), repo=tutorial))
    assert named["files_checked"] == 1, "a file named on the command line is always checked"

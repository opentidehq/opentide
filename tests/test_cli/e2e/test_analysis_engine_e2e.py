"""CLI E2E: the analysis engine behind ``validate`` (queries), ``validate query`` and ``lint``.

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
    assert "warnings" not in query, "style is lint's"
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


SLOW = "SecurityEvent\n| summarize count() by Account\n| where Account != ''"
BROKEN = "SecurityEvent\n| wher EventID == 4688"


def test_a_slow_query_shape_is_lints_finding_not_validates(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, SLOW)
    for argv in (("validate", "query"), ("validate", "query", "--strict"), ("validate",)):
        payload = assert_json_ok(invoke_cli(*argv, "--strict", repo=tutorial))
        assert "kql_where_not_first" not in str(payload), argv

    linted = invoke_cli("lint", "--check", "queries", repo=tutorial)
    assert linted.exit_code == 0, linted.output
    (finding,) = parse_cli_json(linted)["findings"]
    assert (finding["check"], finding["code"], finding["severity"]) == (
        "queries",
        "kql_where_not_first",
        "warning",
    )
    assert (finding["path"], finding["field_path"]) == (
        RULE.as_posix(),
        ["configurations", "sentinel", "query"],
    )
    lines = (tutorial / RULE).read_text(encoding="utf-8").splitlines()
    assert lines[finding["line"] - 1][finding["column"] - 1 :].startswith("where")
    assert invoke_cli("lint", "--check", "queries", "--strict", repo=tutorial).exit_code == 1
    human = invoke_cli("lint", repo=tutorial, json_output=False)
    assert "warning[kql_where_not_first]" in human.output, "the queries check runs by default"


def test_lint_reads_visibility_toml_on_every_run(invoke_cli, tutorial: Path) -> None:
    """#695: nothing is generated; an edit to visibility.toml applies at the next run."""
    _set_query(tutorial / RULE, "NTAIpDetails\n| take 1")
    visibility = tutorial / ".opentide" / "configurations" / "visibility.toml"
    source = '[[logsources]]\nname = "Flows"\ndescription = "d"\nsystem = "sentinel"\n'

    def codes() -> list[str]:
        linted = invoke_cli("lint", "--check", "queries", repo=tutorial)
        assert linted.exit_code == 0, linted.output
        return [finding["code"] for finding in parse_cli_json(linted)["findings"]]

    visibility.write_text(source + 'tables = ["NTANetAnalytics"]\n', encoding="utf-8")
    assert codes() == ["kql_table_not_declared"]
    visibility.write_text(source + 'tables = ["NTA*"]\n', encoding="utf-8")
    assert codes() == []


def test_lint_leaves_a_rejected_query_to_validate(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, BROKEN)
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", repo=tutorial))
    assert payload["findings"] == []


def test_lint_toml_turns_the_queries_check_off(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, SLOW)
    config = tutorial / ".opentide" / "configurations" / "lint.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("[queries]\nenabled = false\n", encoding="utf-8")
    payload = parse_cli_json(invoke_cli("lint", repo=tutorial))
    assert "queries" not in payload["checks"]
    assert not [item for item in payload["findings"] if item["check"] == "queries"]
    named = parse_cli_json(invoke_cli("lint", "--check", "queries", repo=tutorial))
    assert [item["code"] for item in named["findings"]] == ["kql_where_not_first"]


def test_lints_queries_check_fails_on_a_missing_engine(
    invoke_cli, tutorial: Path, no_engine: None
) -> None:
    result = invoke_cli("lint", repo=tutorial)
    assert result.exit_code == 1, result.output
    assert parse_cli_json(result)["failure"]["code"] == "engine_unavailable"
    assert_json_ok(invoke_cli("lint", "--check", "filenames", repo=tutorial))


def test_queries_warn_passes_a_rejected_query_unless_strict(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, BROKEN)
    result = invoke_cli("validate", "query", "--queries", "warn", repo=tutorial)
    assert result.exit_code == 0, result.output
    (finding,) = parse_cli_json(result)["diagnostics"]
    assert (finding["code"], finding["severity"]) == ("kql_unknown_operator", "warning")
    strict = invoke_cli("validate", "query", "--queries", "warn", "--strict", repo=tutorial)
    assert strict.exit_code == 1
    human = invoke_cli("validate", "query", "--queries", "warn", repo=tutorial, json_output=False)
    assert "warning[kql_unknown_operator]" in human.output
    assert "note: the platform rejects this query; --queries warn reports it as a warning" in (
        human.output
    )
    assert "! 1 warning in 1 file · 1 query checked" in human.output


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
        (("--strict", "--live", "--platform", "sentinel"), "usage_error", "--strict"),
        (("--queries", "warn", "--live", "--platform", "sentinel"), "usage_error", "--queries"),
        (("--queries", "off"), "usage_error", "--queries"),
        (("--live", "--platform", "sentinel", "--file", "lsass.kql"), "usage_error", "--file"),
        (("--changed", "--file", "lsass.kql"), "usage_error", None),
    ],
)
def test_offline_and_live_flags_that_do_not_combine_are_usage_errors(
    invoke_cli, tutorial: Path, argv: tuple[str, ...], code: str, argument: str
) -> None:
    result = invoke_cli("validate", "query", *argv, repo=tutorial)
    assert result.exit_code == 2, result.output
    failure = parse_cli_json(result)["failure"]
    assert (failure["code"], failure.get("argument")) == (code, argument)


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
# validate query --file QUERY_FILE
# --------------------------------------------------------------------------


def test_validate_query_reads_a_query_file_by_its_extension(invoke_cli, tutorial: Path) -> None:
    query = tutorial / "hunting" / "lsass.kql"
    query.parent.mkdir()
    query.write_text("SecurityEvent\n| wher EventID == 4688\n", encoding="utf-8")
    result = invoke_cli("validate", "query", "--file", str(query), repo=tutorial)
    assert result.exit_code == 1, result.output
    payload = parse_cli_json(result)
    assert payload["scope"] == "selected"
    (checked,) = payload["queries"]
    assert (checked["path"], checked["platform"], checked["language"]) == (
        "hunting/lsass.kql",
        None,
        "kql",
    )
    (finding,) = payload["diagnostics"]
    assert (finding["code"], finding["path"], finding["line"], finding["column"]) == (
        "kql_unknown_operator",
        "hunting/lsass.kql",
        2,
        3,
    )
    assert payload["next_actions"][-1]["command"] == (
        f"opentide --json validate query --file {query}"
    )

    query.write_text("SecurityEvent\n| summarize count() by Account\n| where Account != ''\n")
    clean = assert_json_ok(invoke_cli("validate", "query", "--file", str(query), repo=tutorial))
    assert clean["queries_validated"] == 1, "a query file alone checks no rule"
    assert clean["diagnostics"] == [], "its style is not validate's"

    both = assert_json_ok(
        invoke_cli("validate", "query", "--file", str(query), "--file", RULE.name, repo=tutorial)
    )
    assert both["queries_validated"] == 2


def test_validate_query_refuses_a_query_file_it_cannot_read(invoke_cli, tutorial: Path) -> None:
    missing = invoke_cli("validate", "query", "--file", "nope.kql", repo=tutorial)
    assert missing.exit_code == 2
    assert parse_cli_json(missing)["unmatched"] == ["nope.kql"]

    latin = tutorial / "latin.spl"
    latin.write_bytes("index=main Règle".encode("latin-1"))
    unreadable = invoke_cli("validate", "query", "--file", str(latin), repo=tutorial)
    assert unreadable.exit_code == 1
    assert parse_cli_json(unreadable)["error"].startswith(f"Cannot check {latin}")


# --------------------------------------------------------------------------
# validate: the queries check is a default check; --queries sets how it reports
# --------------------------------------------------------------------------


def test_validate_checks_queries_by_default(invoke_cli, tutorial: Path) -> None:
    clean = assert_json_ok(invoke_cli("validate", repo=tutorial))
    assert list(clean["checks"]) == [
        "id-uniqueness",
        "uuid-format",
        "schema",
        "configuration",
        "queries",
    ]
    assert clean["summary"]["queries"] == 1

    _set_query(tutorial / RULE, BROKEN)
    result = invoke_cli("validate", repo=tutorial)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
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
    human = invoke_cli("validate", repo=tutorial, json_output=False)
    assert re.search(r"✗ 1 error in 1 file · 3 objects checked · 1 query · [\d.]+s", human.output)


def test_queries_off_validates_everything_but_the_queries(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, BROKEN)
    payload = assert_json_ok(invoke_cli("validate", "--queries", "off", repo=tutorial))
    assert "queries" not in payload["checks"]
    assert "queries" not in payload["summary"]
    (tutorial / RULE).write_text(
        (tutorial / RULE).read_text(encoding="utf-8").replace("severity: ", "severity: X"),
        encoding="utf-8",
    )
    assert invoke_cli("validate", "--queries", "off", repo=tutorial).exit_code == 1, (
        "the other checks still run"
    )


def test_queries_warn_reports_a_rejected_query_as_a_warning(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, BROKEN)
    payload = assert_json_ok(invoke_cli("validate", "--queries", "warn", repo=tutorial))
    assert payload["checks"]["queries"]["status"] == "passed"
    assert payload["report"]["issues"] == []
    (warning,) = payload["report"]["warnings"]
    assert (warning["code"], warning["severity"]) == ("kql_unknown_operator", "warning")
    assert warning["context"]["reported_as_warning"] is True

    strict = invoke_cli("validate", "--queries", "warn", "--strict", repo=tutorial)
    assert strict.exit_code == 1
    again = parse_cli_json(strict)["next_actions"][-1]["command"]
    assert again == "opentide --json validate --queries warn"

    human = invoke_cli("validate", "--queries", "warn", repo=tutorial, json_output=False)
    assert human.exit_code == 0
    assert "warning[kql_unknown_operator]" in human.output
    assert "--queries warn reports it as a warning" in human.output


@pytest.mark.parametrize(
    "argv",
    [
        ("--queries", "warn", "--check", "schema"),
        ("--queries", "off", "--check", "queries"),
    ],
)
def test_queries_mode_and_check_that_contradict_are_usage_errors(
    invoke_cli, tutorial: Path, argv: tuple[str, ...]
) -> None:
    result = invoke_cli("validate", *argv, repo=tutorial)
    assert result.exit_code == 2, result.output
    assert parse_cli_json(result)["failure"]["argument"] == "--queries"


def test_a_placeholder_query_is_lints_finding_and_a_draft_still_validates(
    invoke_cli, tutorial: Path
) -> None:
    result = invoke_cli(
        "new",
        "rule",
        "--name",
        "Placeholder",
        "--platform",
        "splunk",
        "--objective",
        OBJECTIVE_UUID,
        repo=tutorial,
        extra_env=GIT_AUTHOR,
    )
    path = assert_json_ok(result)["path"]
    validated = assert_json_ok(invoke_cli("validate", "--file", path, repo=tutorial))
    assert validated["summary"].get("queries", 0) == 0, "'...' is not sent to the engine"
    query = assert_json_ok(invoke_cli("validate", "query", "--file", path, repo=tutorial))
    assert query["queries_validated"] == 0

    linted = parse_cli_json(invoke_cli("lint", repo=tutorial))
    mine = [item for item in linted["findings"] if item["path"] == path]
    assert {item["check"] for item in mine} == {"placeholders"}
    assert "query" in {item["message"].split()[0] for item in mine}

    # The query written, the marker forgotten: the query is checked again.
    _set_query(tutorial / path, "index=main | statz count")
    assert "# opentide:placeholder" in (tutorial / path).read_text(encoding="utf-8")
    failed = invoke_cli("validate", "--file", path, repo=tutorial)
    assert failed.exit_code == 1, failed.output
    codes = {issue["code"] for issue in parse_cli_json(failed)["report"]["issues"]}
    assert codes == {"spl_unknown_command"}


def test_validate_reports_a_missing_engine_unless_queries_are_off(
    invoke_cli, tutorial: Path, no_engine: None
) -> None:
    for mode in ("error", "warn"):
        result = invoke_cli("validate", "--queries", mode, repo=tutorial)
        assert result.exit_code == 1, (mode, result.output)
        (issue,) = parse_cli_json(result)["report"]["issues"]
        assert issue["code"] == "engine_unavailable"
        assert "--force-reinstall" in issue["help"]
    assert_json_ok(invoke_cli("validate", "--queries", "off", repo=tutorial))


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


def test_next_actions_keep_the_scope_mode_and_strictness(invoke_cli, tutorial: Path) -> None:
    _set_query(tutorial / RULE, BROKEN)
    result = invoke_cli(
        "validate", "query", "--strict", "--queries", "warn", "--file", RULE.name, repo=tutorial
    )
    assert result.exit_code == 1
    again = parse_cli_json(result)["next_actions"][-1]["command"]
    assert again == f"opentide --json validate query --file {RULE.name} --queries warn --strict"


# --------------------------------------------------------------------------
# Scope review: query files, the SDK, legacy query keys
# --------------------------------------------------------------------------


def test_a_query_file_takes_the_profile_of_its_platform(invoke_cli, tutorial: Path) -> None:
    """Defender's tables are Defender's: without its profile, a valid query failed."""
    query = tutorial / "hunting" / "DFE.KQL"
    query.parent.mkdir()
    query.write_text('DeviceProcessEvents | where FileName == "x.exe"\n', encoding="utf-8")
    payload = assert_json_ok(
        invoke_cli(
            "validate",
            "query",
            "--platform",
            "defender_for_endpoint",
            "--file",
            str(query),
            repo=tutorial,
        )
    )
    (checked,) = payload["queries"]
    assert (checked["platform"], checked["language"]) == ("defender_for_endpoint", "kql")
    # The upper-case extension is a query file too. Without a platform an
    # unknown table is a warning (lint's), so the query passes.
    plain = assert_json_ok(invoke_cli("validate", "query", "--file", str(query), repo=tutorial))
    assert plain["diagnostics"] == []
    # Defender's profile rejects a table outside its schema; the language alone does not.
    sentinel = tutorial / "hunting" / "sentinel.kql"
    sentinel.write_text("SecurityEvent | take 1\n", encoding="utf-8")
    rejected = invoke_cli(
        "validate",
        "query",
        "--platform",
        "defender_for_endpoint",
        "--file",
        str(sentinel),
        repo=tutorial,
    )
    assert rejected.exit_code == 1, rejected.output
    codes = [item["code"] for item in parse_cli_json(rejected)["diagnostics"]]
    assert codes == ["kql_unknown_table"]
    assert_json_ok(invoke_cli("validate", "query", "--file", str(sentinel), repo=tutorial))

    other = invoke_cli(
        "validate", "query", "--platform", "splunk", "--file", str(query), repo=tutorial
    )
    assert other.exit_code == 2, other.output
    failure = parse_cli_json(other)["failure"]
    assert failure["argument"] == "--file"


def test_an_empty_query_file_is_not_a_valid_query(invoke_cli, tutorial: Path) -> None:
    query = tutorial / "empty.kql"
    query.write_text("  \n", encoding="utf-8")
    result = invoke_cli("validate", "query", "--file", str(query), repo=tutorial)
    assert result.exit_code == 1, result.output
    assert parse_cli_json(result)["error"] == f"Cannot check {query}: it holds no query"


def test_the_sdk_validates_the_objects_it_is_given_not_the_queries_on_disk(
    invoke_cli, tutorial: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """validate_all_objects replaces the registry's objects: the queries check read
    the files instead, so a fixed in-memory rule failed on its broken file."""
    from tests.corpus_support import clear_runtime_caches

    from opentide.core.registry import Opentide
    from opentide.validation.pipeline import validate_all_objects

    _set_query(tutorial / RULE, BROKEN)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tutorial))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tutorial))
    monkeypatch.chdir(tutorial)
    clear_runtime_caches()
    Opentide.initialise()
    objects = Opentide.Index["objects"]
    assert validate_all_objects(objects) == {}


def test_an_empty_legacy_search_is_reported_once(invoke_cli, tutorial: Path) -> None:
    rule = _new_rule(invoke_cli, tutorial, "splunk", "index=main")
    text = rule.read_text(encoding="utf-8")
    start = text.index("    query: |")
    end = text.index("\n", text.index("index=main", start)) + 1
    rule.write_text(text[:start] + '    search: ""\n' + text[end:], encoding="utf-8")
    result = invoke_cli("validate", "--file", rule.name, repo=tutorial)
    assert result.exit_code == 1, result.output
    codes = [issue["code"] for issue in parse_cli_json(result)["report"]["issues"]]
    assert "spl_parse_error" not in codes, codes
    assert codes.count("schema_validation") >= 1


def test_a_query_that_starts_with_search_validates(invoke_cli, tutorial: Path) -> None:
    """Valid KQL the engine read as a parse error: validate failed a valid rule."""
    _set_query(tutorial / RULE, 'search in (SecurityEvent) "mimikatz"\n| take 10')
    payload = assert_json_ok(invoke_cli("validate", repo=tutorial))
    assert payload["summary"]["queries"] == 1
    _set_query(tutorial / RULE, 'search "mimikatz"')
    linted = parse_cli_json(invoke_cli("lint", "--check", "queries", repo=tutorial))
    assert [item["code"] for item in linted["findings"]] == ["kql_unscoped_search"]


def test_a_quoted_query_key_is_checked(invoke_cli, tutorial: Path) -> None:
    """``"query": |`` is the query to YAML and to the schema check: it was not checked."""
    rule = tutorial / RULE
    _set_query(rule, BROKEN)
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("    query: |", '    "query": |', 1), encoding="utf-8")
    result = invoke_cli("validate", repo=tutorial)
    assert result.exit_code == 1, result.output
    codes = [issue["code"] for issue in parse_cli_json(result)["report"]["issues"]]
    assert codes == ["kql_unknown_operator"]

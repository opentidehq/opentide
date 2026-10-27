"""``opentide query`` end to end: the real command, configuration and rules, a stand-in tenant.

The corpus Splunk configuration gets two tenants, and the platform runner is
replaced by one that answers per tenant, so every test drives the command as
a user does and checks what reaches stdout, stderr and the exit code.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest
from click.testing import Result
from tests.result_models_support import document_problems
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

from opentide.models.system_config import SystemConfig
from opentide.query.models import QueryColumn, QueryRefused, QueryRequest, QueryResult
from opentide.query.runner import QueryRunner

SPLUNK_RULE = "00000000-0000-4000-8003-000000000003"
SPLUNK_RULE_FILE = "Objects/Detection Rules/rule-0003-splunk-spl.yaml"


def _tenant(name: str) -> str:
    return f"""
[[tenants]]
name = "{name}"
description = "{name} search head"
[tenants.setup]
ssl = true
url = "{name}.splunk.example"
port = 8089
app = "search"
token = "token"
"""


class StandIn(QueryRunner):
    """Two rows per tenant; a tenant in ``refuse`` refuses the query."""

    languages: ClassVar[tuple[str, ...]] = ("spl",)

    def __init__(self) -> None:
        self.refuse: set[str] = set()
        self.requests: list[tuple[str, QueryRequest]] = []

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        self.requests.append((tenant.name, request))
        if tenant.name in self.refuse:
            raise QueryRefused(f"Splunk refused the search on {tenant.name}", detail="bad SPL")
        rows = tuple(
            {"host": f"{tenant.name}-{n}", "count": n, "tags": ["a", "b"]} for n in range(2)
        )
        return QueryResult(
            columns=(QueryColumn("host"), QueryColumn("count"), QueryColumn("tags")),
            rows=rows[: request.limit],
            truncated=request.limit < 2,
        )


@pytest.fixture
def splunk(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> StandIn:
    config = tide_corpus_repo / ".opentide/configurations/systems/splunk.toml"
    text = config.read_text(encoding="utf-8")
    config.write_text(text + _tenant("lab") + _tenant("prod"), encoding="utf-8")
    runner = StandIn()
    monkeypatch.setattr("opentide.query.service.load_runner", lambda platform: runner)
    return runner


@pytest.fixture
def query(invoke_cli: Callable[..., Result]) -> Callable[..., Result]:
    def _query(*args: str, json_output: bool = True, **kwargs: Any) -> Result:
        return invoke_cli("query", "--platform", "splunk", *args, json_output=json_output, **kwargs)

    return _query


def test_json_lists_each_tenants_rows(query: Callable[..., Result], splunk: StandIn) -> None:
    result = query("--tenant", "all", "--since", "7d", "--limit", "1", "index=main")
    payload = assert_json_ok(result)
    assert document_problems(payload) == []
    assert payload["command"] == "query"
    assert payload["source"] == "query" and payload["query"] == "index=main"
    assert payload["tenants"] == ["lab", "prod"]
    assert [r["tenant"] for r in payload["results"]] == ["lab", "prod"]
    assert payload["results"][0]["rows"] == [{"host": "lab-0", "count": 0, "tags": ["a", "b"]}]
    assert payload["results"][0]["truncated"] is True
    assert payload["row_count"] == 2
    assert payload["summary"] == {"tenants": 2, "rows": 2, "failed": 0}
    assert payload["message"] == "2 rows from 2 splunk tenants (limited to 1 per tenant)"
    request = splunk.requests[0][1]
    assert (request.text, request.limit, request.window.seconds) == ("index=main", 1, 604800)


def test_several_tenants_and_no_name_is_a_usage_error(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    result = query("index=main")
    assert result.exit_code == 2
    payload = parse_cli_json(result)
    assert document_problems(payload) == []
    assert "2 tenants (lab, prod)" in payload["message"]
    assert payload["failure"]["argument"] == "--tenant"
    assert payload["choices"] == ["lab", "prod", "all"]
    assert splunk.requests == []


def test_a_mistyped_tenant_suggests_the_configured_one(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    result = query("--tenant", "prdo", "index=main")
    assert result.exit_code == 2
    assert parse_cli_json(result)["failure"]["suggestion"] == "prod"


def test_a_refusing_tenant_fails_the_run_and_the_other_still_answers(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    splunk.refuse.add("lab")
    result = query("--tenant", "lab", "--tenant", "prod", "index=main")
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert document_problems(payload) == []
    lab, prod = payload["results"]
    assert lab == {
        "tenant": "lab",
        "status": "failed",
        "error": "Splunk refused the search on lab",
        "detail": "bad SPL",
        "warnings": [],
        "elapsed_ms": lab["elapsed_ms"],
    }
    assert prod["status"] == "ok" and prod["row_count"] == 2
    assert payload["failure"]["code"] == "command_failed"
    assert payload["detail"] == "bad SPL"


def test_rule_runs_the_query_deploy_sends(query: Callable[..., Result], splunk: StandIn) -> None:
    payload = assert_json_ok(query("--tenant", "lab", "--rule", SPLUNK_RULE))
    assert payload["source"] == "rule"
    assert payload["rule"]["uuid"] == SPLUNK_RULE
    sent = splunk.requests[0][1].text
    assert sent.startswith("index=main | head 1\n| eval MDR_UUID=")
    assert payload["rule"]["queries"] == [sent]


def test_file_reads_the_rule_from_disk(
    query: Callable[..., Result], splunk: StandIn, tide_corpus_repo: Path
) -> None:
    path = tide_corpus_repo / SPLUNK_RULE_FILE
    payload = assert_json_ok(query("--tenant", "lab", "--file", str(path)))
    assert payload["rule"]["name"] == "Splunk SPL Rule"


def test_file_takes_a_path_relative_to_the_repository(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    payload = assert_json_ok(query("--tenant", "lab", "--file", SPLUNK_RULE_FILE))
    assert payload["rule"]["uuid"] == SPLUNK_RULE


@pytest.mark.parametrize(
    ("args", "argument"),
    [
        (("--tenant", "lab", "--rule", "00000000-0000-4000-8003-00000000000x"), "--rule"),
        (("--tenant", "lab", "--file", "missing.yaml"), "--file"),
        (("--tenant", "lab", "--rule", SPLUNK_RULE, "index=main"), "--rule"),
        (("--tenant", "lab"), "QUERY"),
        (("--tenant", "lab", "--limit", "0", "x"), "--limit"),
        (("--tenant", "lab", "--language", "kql", "x"), "--language"),
        (("--tenant", "lab", "--since", "1h", "--from", "2026-10-01", "x"), "--since"),
    ],
)
def test_a_call_that_cannot_run_exits_2_and_names_the_flag(
    query: Callable[..., Result], splunk: StandIn, args: tuple[str, ...], argument: str
) -> None:
    result = query(*args)
    assert result.exit_code == 2, result.stdout
    payload = parse_cli_json(result)
    assert document_problems(payload) == []
    assert payload["failure"]["argument"] == argument
    assert splunk.requests == []


def test_a_rule_uuid_typo_suggests_the_rule(query: Callable[..., Result], splunk: StandIn) -> None:
    # One character dropped: no rule has this UUID, and the splunk rule's is the closest.
    result = query("--tenant", "lab", "--rule", SPLUNK_RULE[:-2] + "3")
    assert result.exit_code == 2
    assert parse_cli_json(result)["failure"]["suggestion"] == SPLUNK_RULE


def test_dash_reads_the_query_from_stdin(query: Callable[..., Result], splunk: StandIn) -> None:
    assert_json_ok(query("--tenant", "lab", "-", input="index=web | stats count\n"))
    assert splunk.requests[0][1].text == "index=web | stats count"


def test_query_file_reads_the_query(
    query: Callable[..., Result], splunk: StandIn, tmp_path: Path
) -> None:
    path = tmp_path / "hunt.spl"
    path.write_text("index=dns\n", encoding="utf-8")
    assert_json_ok(query("--tenant", "lab", "--query-file", str(path)))
    assert splunk.requests[0][1].text == "index=dns"


def test_the_table_names_the_tenant_and_shows_the_rows(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    result = query("--tenant", "all", "--columns", "host", "index=main", json_output=False)
    assert result.exit_code == 0, result.stderr
    assert "lab  2 rows" in result.stdout
    assert "prod-1" in result.stdout
    assert "count" not in result.stdout.split("lab  2 rows")[1].splitlines()[1]
    assert "4 rows from 2 splunk tenants" in result.stdout


def test_the_table_says_how_many_columns_it_hides(
    query: Callable[..., Result], splunk: StandIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("opentide.cli.commands.query.TABLE_COLUMNS", 1)
    result = query("--tenant", "lab", "index=main", json_output=False)
    assert "2 more columns: name them with --columns" in result.stdout


def test_jsonl_writes_only_rows_to_stdout(query: Callable[..., Result], splunk: StandIn) -> None:
    result = query("--tenant", "all", "--format", "jsonl", "index=main", json_output=False)
    assert result.exit_code == 0
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    assert lines[0] == {"_tenant": "lab", "host": "lab-0", "count": 0, "tags": ["a", "b"]}
    assert [line["_tenant"] for line in lines] == ["lab", "lab", "prod", "prod"]


def test_csv_writes_a_header_and_json_cells(query: Callable[..., Result], splunk: StandIn) -> None:
    result = query("--tenant", "lab", "--format", "csv", "index=main", json_output=False)
    assert result.exit_code == 0
    rows = list(csv.reader(io.StringIO(result.stdout)))
    assert rows[0] == ["_tenant", "host", "count", "tags"]
    assert rows[1] == ["lab", "lab-0", "0", '["a","b"]']
    assert len(rows) == 3


def test_a_failure_in_jsonl_goes_to_stderr_and_keeps_stdout_rows(
    query: Callable[..., Result], splunk: StandIn
) -> None:
    splunk.refuse.add("prod")
    result = query("--tenant", "all", "--format", "jsonl", "index=main", json_output=False)
    assert result.exit_code == 1
    assert [json.loads(line)["_tenant"] for line in result.stdout.splitlines()] == ["lab", "lab"]
    assert "Splunk refused the search on prod" in result.stderr


def test_a_platform_with_no_tenant_names_the_file(
    query: Callable[..., Result], tide_corpus_repo: Path
) -> None:
    result = query("index=main")
    assert result.exit_code == 2
    assert "no tenants configured" in parse_cli_json(result)["message"]

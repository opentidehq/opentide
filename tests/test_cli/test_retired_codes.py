"""A code nothing reports any more stays explainable (plan §3, invariant 3).

``crowdstrike_unsupported`` was retired with engine 0.12.0, which checks
CrowdStrike queries as CQL. A suppression list or SARIF baseline may still name
it, so explain, MCP explain, the SARIF rule catalogue and the diagnostics
reference keep it, saying it is retired.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from opentide import analysis
from opentide.cli import app
from opentide.cli.services.explain import REFERENCE_PAGE, diagnostic_codes
from opentide.cli.services.retired_codes import RETIRED_CODES
from opentide.cli.ui.reports import sarif_report
from opentide.mcp_server.tools import tool_explain

runner = CliRunner()

RETIRED = "crowdstrike_unsupported"


def test_the_engine_no_longer_reports_it() -> None:
    """What makes the rest of this file the retired mechanism's work, not the engine's."""
    assert RETIRED in RETIRED_CODES
    assert analysis.describe(RETIRED) is None
    assert RETIRED not in analysis.engine_codes()


@pytest.mark.parametrize("code", sorted(RETIRED_CODES))
def test_a_retired_code_is_not_reported_by_the_engine(code: str) -> None:
    assert code not in analysis.engine_codes(), f"{code} is reported again: unretire it"


def test_explain_prints_the_retired_page() -> None:
    result = runner.invoke(app, ["--no-color", "explain", RETIRED])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith(
        "# crowdstrike_unsupported\n\nRetired in engine 0.12.0; CrowdStrike queries are now "
        "checked as CQL: see the `cql_*` codes.\n"
    )
    payload = json.loads(runner.invoke(app, ["--json", "explain", RETIRED]).stdout)
    assert payload["ok"] is True
    assert payload["meaning"].startswith("Retired in engine 0.12.0")


def test_explain_lists_it() -> None:
    assert RETIRED in diagnostic_codes()
    payload = json.loads(runner.invoke(app, ["--json", "explain"]).stdout)
    assert RETIRED in {item["code"] for item in payload["codes"]}


def test_mcp_explain_finds_it() -> None:
    found = tool_explain(RETIRED)
    assert found["found"] is True
    assert found["code"] == RETIRED
    assert found["meaning"].startswith("Retired in engine 0.12.0")
    assert RETIRED in {item["code"] for item in tool_explain()["codes"]}


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_the_sarif_rule_catalogue_keeps_it(command: str) -> None:
    driver = sarif_report([], command=command, version="0")["runs"][0]["tool"]["driver"]
    (rule,) = [rule for rule in driver["rules"] if rule["id"] == RETIRED]
    assert rule["properties"] == {"tags": ["retired"]}
    assert rule["defaultConfiguration"] == {"level": "warning"}
    assert rule["shortDescription"]["text"].startswith("Retired in engine 0.12.0")
    live = [rule for rule in driver["rules"] if rule["id"] == "cql_unknown_function"]
    assert live and "properties" not in live[0]


def test_the_diagnostics_reference_keeps_its_section() -> None:
    from pathlib import Path

    reference = (Path(__file__).resolve().parents[2] / REFERENCE_PAGE).read_text(encoding="utf-8")
    assert "\n## crowdstrike_unsupported\n\nRetired in engine 0.12.0;" in reference

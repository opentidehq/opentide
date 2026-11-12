"""CLI E2E: info command snapshots."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok
from tests.test_cli.e2e.helpers import uncomment_tenants

pytestmark = pytest.mark.cli_e2e


def _stable_info_payload(payload: dict[str, object]) -> dict[str, object]:
    """Drop volatile paths and version strings from info JSON snapshots."""
    return {
        "counts": payload["counts"],
        "platforms": payload["platforms"],
    }


def test_info_json_snapshot(invoke_cli, snapshot) -> None:
    result = invoke_cli("info")
    payload = assert_json_ok(result)
    assert _stable_info_payload(payload) == snapshot(name="info_json")


def test_info_no_color_renders_platform_table(cli_runner, tide_corpus_repo, monkeypatch) -> None:
    from opentide.cli import app

    monkeypatch.setenv("TERM", "xterm-256color")
    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    plain = result.stdout
    assert "\x1b[" not in plain
    # Label and value columns, not a boxed "opentide Info" table; the counts are
    # the outcome line's, once (post-merge end-to-end run).
    assert "opentide Info" not in plain and "┏" not in plain
    assert "Parse errors" not in plain
    assert "14 rules" in plain
    rows = [" ".join(line.split()) for line in plain.splitlines()]
    assert any(row.startswith("version ") for row in rows)
    assert "Splunk Enterprise Security enabled · deploy, validate, query" in rows
    assert "HarfangLab enabled · deploy, query" in rows
    assert "Graylog enabled · deploy, validate, query" in rows
    assert "Google Security Operations enabled · deploy, validate, query" in rows


def test_info_coverage_matches_top_level_techniques(invoke_cli, corpus_rule_uuids) -> None:
    result = invoke_cli("info", "--technique", "T1059", "coverage")
    payload = assert_json_ok(result)
    coverage = payload["coverage"]
    assert coverage["technique"] == "T1059"
    assert coverage["count"] >= 1
    assert corpus_rule_uuids["sentinel"] in coverage["rules"]


SECRET_VALUE = "s3cr3t-value-never-printed"
UNSET_VALUE_VARIABLES = (
    "AZURE_WORKSPACE_ID",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_CLIENT_ID",
)


@pytest.mark.parametrize("args", [("info",), ("info", "--platform", "sentinel")])
def test_info_lists_tenants_and_their_variables_without_values(
    invoke_cli, tide_corpus_repo, monkeypatch, args: tuple[str, ...]
) -> None:
    """#754: each tenant, and whether each $VAR its setup names is set; never a value."""
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/platforms/sentinel.toml")
    for name in UNSET_VALUE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    result = invoke_cli(*args, extra_env={"AZURE_CLIENT_SECRET": SECRET_VALUE})
    payload = assert_json_ok(result)
    sentinel = next(plat for plat in payload["platforms"] if plat["name"] == "sentinel")
    assert sentinel["tenants"] == [
        {
            "name": "Tenant",
            "description": "Tenant Description",
            "strategies": ["PREVIEW", "RELEASE"],
            "manual": False,
            "variables": [
                *({"name": name, "set": False} for name in UNSET_VALUE_VARIABLES),
                {"name": "AZURE_CLIENT_SECRET", "set": True},
            ],
        }
    ]
    assert SECRET_VALUE not in result.stdout
    assert SECRET_VALUE not in result.stderr
    variables = [
        variable
        for plat in payload["platforms"]
        for tenant in plat["tenants"]
        for variable in tenant["variables"]
    ]
    assert all(set(variable) == {"name", "set"} for variable in variables)

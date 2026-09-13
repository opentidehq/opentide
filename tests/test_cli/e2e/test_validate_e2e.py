"""CLI E2E: validate command."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e


def test_validate_full_passes(invoke_cli) -> None:
    result = invoke_cli("validate")
    payload = assert_json_ok(result)
    assert payload["checks"]["schema"]["status"] == "passed"
    assert payload["report"]["ok"] is True


def test_validate_scoped_by_uuid(invoke_cli, corpus_rule_uuids) -> None:
    sentinel_uuid = corpus_rule_uuids["sentinel"]
    result = invoke_cli("validate", "--uuid", sentinel_uuid)
    payload = assert_json_ok(result)
    assert payload["report"]["ok"] is True


@pytest.mark.parametrize(
    ("platform", "expects_supported"),
    [
        ("sentinel", True),
        ("defender_for_endpoint", True),
        ("splunk", True),
        ("sentinel_one", True),
        ("carbon_black_cloud", True),
        ("crowdstrike", False),
        ("harfanglab", False),
    ],
)
def test_validate_query_platform_matrix(
    invoke_cli,
    mock_query_validators,
    platform: str,
    expects_supported: bool,
) -> None:
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        platform,
        "--plan",
        "FULL",
        "--wide",
    )
    if expects_supported:
        payload = assert_json_ok(result)
        assert payload.get("supported") is True
        assert payload.get("status") == "passed"
    else:
        assert result.exit_code != 0
        if "{" in result.stdout:
            body = parse_cli_json(result)
            assert body.get("supported") is False


def test_validate_query_without_plan_or_wide(invoke_cli, mock_query_validators) -> None:
    """Unset DEPLOYMENT_PLAN must not traceback on validate query (issue #164)."""
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        "sentinel",
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    payload = assert_json_ok(result)
    assert payload.get("supported") is True
    assert payload.get("status") == "passed"

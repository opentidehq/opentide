"""CLI E2E: configuration files are validated by their models on the load path (#374)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.conftest import parse_cli_json

pytestmark = pytest.mark.cli_e2e


def _write(repo: Path, name: str, text: str) -> None:
    path = repo / ".opentide" / "configurations" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_misspelt_deployment_key_names_the_file_and_key(invoke_cli, tide_corpus_repo: Path) -> None:
    _write(tide_corpus_repo, "deployment.toml", "[promotion]\nenabeld = false\n")
    result = invoke_cli("generate", "schemas")
    assert result.exit_code == 1, result.stdout + result.stderr
    message = parse_cli_json(result)["message"]
    assert "deployment.toml is invalid: promotion.enabeld: unknown key" in message


def test_unknown_tenant_key_does_not_echo_the_secret(invoke_cli, tide_corpus_repo: Path) -> None:
    secret = "literal-client-secret-0123"
    _write(
        tide_corpus_repo,
        "platforms/sentinel.toml",
        "\n".join(
            [
                "[platform]",
                "enabled = true",
                "[[tenants]]",
                'name = "Primary"',
                "[tenants.setup]",
                'resource_group = "rg"',
                'workspace_name = "ws"',
                'workspace_id = "$AZURE_WORKSPACE_ID"',
                'azure_tenant_id = "$AZURE_TENANT_ID"',
                'azure_subscription_id = "$AZURE_SUBSCRIPTION_ID"',
                'azure_client_id = "$AZURE_CLIENT_ID"',
                f'azure_client_secret = "{secret}"',
                f'azure_clientsecret = "{secret}"',
            ]
        )
        + "\n",
    )
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "sentinel", "--strategy", "PREVIEW", "--all"
    )
    output = result.stdout + result.stderr
    assert result.exit_code != 0, output
    assert "platforms/sentinel.toml is invalid" in output
    assert "tenants.0.setup.azure_clientsecret: unknown key" in output
    assert secret not in output


def test_validate_reports_what_deploy_would_refuse(invoke_cli, tide_corpus_repo: Path) -> None:
    _write(tide_corpus_repo, "deployment.toml", "[promotion]\nenabeld = false\n")
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["checks"]["configuration"]["status"] == "failed"
    assert payload["checks"]["schema"]["status"] == "passed"
    issues = [i for i in payload["report"]["issues"] if i["object_type"] == "configuration"]
    assert [(i["code"], i["field_path"], i["context"]["file"]) for i in issues] == [
        ("unknown_key", ["promotion", "enabeld"], "deployment.toml")
    ]


def test_validate_check_configuration_alone(invoke_cli) -> None:
    result = invoke_cli("validate", "--check", "configuration")
    assert result.exit_code == 0, result.stdout + result.stderr
    assert parse_cli_json(result)["checks"] == {
        "configuration": {"check": "configuration", "status": "passed"}
    }


_DECLARING = """\
[[logsources]]
name = "VNet flow logs"
description = "Traffic analytics."
system = "sentinel"
tables = ["NTANetAnalytics", "*_CL"]

[[logsources]]
name = "Endpoint telemetry"
description = "ECS endpoint data."
system = "elastic"
indices = ["logs-endpoint.events.*"]
ecs = true
"""


def test_generate_schemas_writes_the_declared_datasets(invoke_cli, tide_corpus_repo: Path) -> None:
    """#695: the names visibility.toml declares reach the workspace catalog."""
    _write(tide_corpus_repo, "visibility.toml", _DECLARING)
    result = invoke_cli("generate", "schemas")
    assert result.exit_code == 0, result.stdout + result.stderr
    catalogs = tide_corpus_repo / ".opentide" / "lsp" / "catalogs" / "generated"
    datasets = json.loads((catalogs / "datasets.json").read_text(encoding="utf-8"))
    assert datasets["platforms"] == {
        "elastic": {
            "indices": ["logs-endpoint.events.*"],
            "ecs_indices": ["logs-endpoint.events.*"],
        },
        "sentinel": {"tables": ["*_CL", "NTANetAnalytics"]},
    }


def test_a_dataset_field_of_another_system_fails_validate(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    _write(tide_corpus_repo, "visibility.toml", _DECLARING.replace('"sentinel"', '"splunk"'))
    result = invoke_cli("validate", "--check", "configuration")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["checks"]["configuration"]["status"] == "failed"
    issues = [i for i in payload["report"]["issues"] if i["object_type"] == "configuration"]
    assert [(i["code"], i["field_path"], i["context"]["file"]) for i in issues] == [
        ("schema_validation", ["logsources", "0", "tables"], "visibility.toml")
    ]
    assert "applies to a log source of sentinel, defender_for_endpoint" in issues[0]["message"]

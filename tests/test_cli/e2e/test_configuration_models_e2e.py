"""CLI E2E: configuration files are validated by their models on the load path (#374)."""

from __future__ import annotations

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

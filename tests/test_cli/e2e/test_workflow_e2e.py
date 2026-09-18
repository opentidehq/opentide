"""CLI E2E: first-user DetectionOps workflow without Python setup helpers.

Replays the published tutorial console path in order, asserting each
``opentide`` invocation exits 0 (or 1 on the intentional dangling-ref):

setup → generate (empty) → author → generate (populated) → validate → lint →
dangling ``detection_model`` (must fail) → restore → info → coverage →
validate query → deploy dry-run → docs → setup env/hooks.

This module uses in-process ``CliRunner``. The matching console-script chain
lives in ``test_workflow_subprocess_e2e.py``.

Does not inject DEPLOYMENT_PLAN=FULL or CI=true on deploy/query steps
(issue #164). Populated generate must survive object ``threat.actors``
(name / optional sighting / references).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = pytest.mark.cli_e2e


def test_first_user_cli_workflow(
    invoke_cli,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_query_validators,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)

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
        "--ci",
        "github",
        "--path",
        str(fresh),
        repo=tmp_path,
    )
    assert_json_ok(setup)
    assert (fresh / "objects" / "threats").is_dir()
    sentinel_toml = fresh / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert sentinel_toml.is_file()
    assert "enabled = true" in sentinel_toml.read_text(encoding="utf-8")
    workflow = fresh / ".github" / "workflows" / "opentide.yml"
    assert workflow.is_file()
    parsed = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert parsed is not None
    assert "opentide validate" in workflow.read_text(encoding="utf-8")

    empty_generate = invoke_cli("generate", repo=fresh)
    assert_json_ok(empty_generate)
    assert (fresh / ".opentide" / "schemas" / "rule.1.0.schema.json").is_file()
    rule_template = (fresh / ".opentide" / "templates" / "rule.1.0.template.yaml").read_text(
        encoding="utf-8"
    )
    assert "configurations: {}" not in rule_template
    assert "#sentinel:" in rule_template
    assert "null" not in rule_template
    loaded_template = yaml.safe_load(rule_template)
    tlp = loaded_template["metadata"]["tlp"]
    assert tlp in (None, "")
    assert not isinstance(tlp, dict)

    write_tutorial_objects(fresh)
    threat_yaml = (fresh / "objects" / "threats" / "simulated-actor.yaml").read_text(
        encoding="utf-8"
    )
    assert "actors:" in threat_yaml
    assert "name: att&ck::G0006" in threat_yaml
    assert "created: 2026-01-01" in threat_yaml
    assert 'created: "2026-01-01"' not in threat_yaml

    populated = invoke_cli("generate", repo=fresh)
    assert_json_ok(populated)
    export_path = fresh / ".opentide" / "exports" / "objects.export.json"
    assert export_path.is_file()
    catalog = json.loads(export_path.read_text(encoding="utf-8"))
    threat_row = next(
        row for row in catalog if row["uuid"] == "00000000-0000-4000-8001-000000000001"
    )
    assert "APT1" in threat_row["actors"] or "G0006" in threat_row["actors"]
    assert threat_row["created"] == "2026-01-01"

    validate = invoke_cli("validate", "--strict", repo=fresh)
    payload = assert_json_ok(validate)
    assert payload["report"]["ok"] is True

    lint = invoke_cli("lint", "--strict", repo=fresh)
    lint_payload = assert_json_ok(lint)
    assert lint_payload["count"] == 0

    rule_path = fresh / "objects" / "rules" / "sentinel-kql-rule.yaml"
    original_rule = rule_path.read_text(encoding="utf-8")
    good_ref = "detection_model: 00000000-0000-4000-8002-000000000001"
    dangling_ref = "detection_model: 00000000-0000-4000-8002-DEADBEEF0000"
    assert good_ref in original_rule
    rule_path.write_text(original_rule.replace(good_ref, dangling_ref), encoding="utf-8")
    broken = invoke_cli("validate", "--strict", repo=fresh)
    assert broken.exit_code == 1, broken.stdout + broken.stderr
    broken_payload = parse_cli_json(broken)
    assert broken_payload["ok"] is False
    assert "DEADBEEF0000" in broken.stdout
    rule_path.write_text(original_rule, encoding="utf-8")
    restored = invoke_cli("validate", "--strict", repo=fresh)
    restored_payload = assert_json_ok(restored)
    assert restored_payload["report"]["ok"] is True

    info = invoke_cli("info", repo=fresh)
    info_payload = assert_json_ok(info)
    assert info_payload["counts"]["threats"] == 1
    assert info_payload["counts"]["objectives"] == 1
    assert info_payload["counts"]["rules"] == 1

    coverage = invoke_cli("info", "--technique", "T1059", "coverage", repo=fresh)
    coverage_payload = assert_json_ok(coverage)
    assert coverage_payload["coverage"]["count"] >= 1
    assert "00000000-0000-4000-8003-000000000001" in coverage_payload["coverage"]["rules"]

    query = invoke_cli(
        "validate",
        "query",
        "--platform",
        "sentinel",
        repo=fresh,
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    query_payload = assert_json_ok(query)
    assert query_payload.get("supported") is True

    deployer = MagicMock()

    class _MockDeployTide:
        @property
        def mdr(self) -> dict[str, MagicMock]:
            return {"sentinel": deployer}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    deploy = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "sentinel",
        "--skip-promotion",
        repo=fresh,
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    deploy_payload = assert_json_ok(deploy)
    assert deploy_payload["dry_run"] is True
    assert "00000000-0000-4000-8003-000000000001" in deploy_payload["plan"]["sentinel"]
    deployer.deploy.assert_not_called()

    docs = invoke_cli("generate", "docs", repo=fresh)
    assert_json_ok(docs)
    threat_pages = [
        p for p in (fresh / "docs" / "threats").glob("*.md") if p.name.lower() != "readme.md"
    ]
    assert {p.name for p in threat_pages} == {"simulated-actor.md"}
    threat_doc = threat_pages[0].read_text(encoding="utf-8")
    assert "G0006" in threat_doc
    threat_index = (fresh / "docs" / "threats" / "README.md").read_text(encoding="utf-8")
    assert "simulated-actor.md" in threat_index
    assert "00000000-0000-4000-8001-000000000001.md" not in threat_index

    env = invoke_cli("setup", "env", str(fresh), "--yes", repo=fresh)
    assert_json_ok(env)
    assert (fresh / ".env.example").is_file()

    hooks = invoke_cli("setup", "hooks", str(fresh), "--yes", repo=fresh)
    assert_json_ok(hooks)
    assert (fresh / ".pre-commit-config.yaml").is_file()
